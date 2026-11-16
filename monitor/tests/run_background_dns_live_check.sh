#!/bin/bash
# One-user-authorized, one-round live DNS check. All local state is temporary.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
CW_TEST_PARENT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-background-dns-live.XXXXXX")
trap 'rm -rf "$CW_TEST_PARENT"' EXIT
CW_TEST_RUNTIME="$CW_TEST_PARENT/runtime"
CW_TEST_HOME="$CW_TEST_PARENT/home"
CW_TEST_CACHE="$CW_TEST_PARENT/module-cache"
mkdir -p "$CW_TEST_RUNTIME" "$CW_TEST_HOME" "$CW_TEST_CACHE"
chmod 700 "$CW_TEST_PARENT" "$CW_TEST_RUNTIME" "$CW_TEST_HOME"
ENGINE="$ROOT/../target/debug/claude-watch-engine"
[[ -x "$ENGINE" ]] || { printf 'Missing debug engine; run cargo build -p claude-watch-engine first.\n' >&2; exit 1; }
cp "$ROOT/Resources/netcoffee_probe.html" "$ROOT/Resources/netcoffee_probe.js" "$ROOT/Resources/netcoffee_probe.css" "$ROOT/Resources/ipleak_probe.html" "$ROOT/Resources/ipleak_probe.js" "$CW_TEST_RUNTIME/"
cp "$ENGINE" "$CW_TEST_RUNTIME/watch-engine"
chmod 700 "$CW_TEST_RUNTIME/watch-engine"
xcrun swiftc -swift-version 5 -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" -D BACKGROUND_LEAK_WORKER -D BACKGROUND_LEAK_WORKER_TEST -module-cache-path "$CW_TEST_CACHE" -framework AppKit -framework WebKit "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" "$ROOT/Sources/LeakCheckModels.swift" "$ROOT/Sources/NetCoffeeModels.swift" "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/Sources/IPLeakDNSRunner.swift" "$ROOT/Sources/IPLeakDNSRetryRunner.swift" "$ROOT/tools/BackgroundLeakWorker.swift" -o "$CW_TEST_RUNTIME/watch-leak-worker"
chmod 700 "$CW_TEST_RUNTIME/watch-leak-worker"
/usr/bin/codesign --force --sign - "$CW_TEST_RUNTIME/watch-leak-worker"
cat > "$CW_TEST_RUNTIME/BuildInfo.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>Architecture</key><string>arm64</string><key>RuntimeSchema</key><integer>2</integer><key>BackendVariant</key><string>rust-candidate</string><key>BackgroundEvidenceSchema</key><integer>2</integer></dict></plist>
PLIST
python3 - "$CW_TEST_RUNTIME" <<'PY'
import hashlib, plistlib, sys
from pathlib import Path
root = Path(sys.argv[1]); manifest = root / "BuildInfo.plist"
value = plistlib.loads(manifest.read_bytes())
names = ("watch-leak-worker", "watch-engine", "netcoffee_probe.html", "netcoffee_probe.js", "netcoffee_probe.css", "ipleak_probe.html", "ipleak_probe.js")
value["RuntimeHashes"] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
manifest.write_bytes(plistlib.dumps(value))
PY
python3 - "$CW_TEST_RUNTIME" "$CW_TEST_HOME" <<'PY'
import json, os, signal, subprocess, sys, time
from pathlib import Path
runtime, home = map(Path, sys.argv[1:])
env = dict(os.environ); env["HOME"] = str(home)
started = time.monotonic()
child = subprocess.Popen([str(runtime / "watch-leak-worker"), "--dns"], cwd=runtime, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
try: stdout, stderr = child.communicate(timeout=80)
except subprocess.TimeoutExpired:
    os.killpg(child.pid, signal.SIGTERM)
    try: stdout, stderr = child.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL); stdout, stderr = child.communicate()
    raise SystemExit("live DNS helper exceeded 80 seconds and was terminated")
elapsed = round((time.monotonic() - started) * 1000)
lines = stdout.splitlines()
if child.returncode != 0 or len(lines) != 1: raise SystemExit("live DNS helper did not return one bounded receipt")
receipt = json.loads(lines[0])
if receipt.get("kind") != "dns": raise SystemExit("live DNS helper returned the wrong result kind")
policy = {"http_count": sum(row.get("kind") == "http" for row in receipt.get("observations", [])),
          "resolver_count": sum(row.get("kind") == "resolver" for row in receipt.get("observations", [])),
          "error_stages": sorted({row.get("stage", "") for row in receipt.get("errors", [])}),
          "error_codes": sorted({row.get("code", "") for row in receipt.get("errors", [])})}
allowed = {"collector", "http", "dns", "dns_images", "dns_records", "geoip", "ice"}; timeline=[]
for line in stderr.splitlines():
    try: event=json.loads(line)
    except json.JSONDecodeError: continue
    phase, at = event.get("phase"), event.get("elapsed_ms")
    if phase in allowed and isinstance(at,(int,float)) and 0 <= at <= 75000:
        timeline.append({"phase":phase,"event":event.get("event") if event.get("event") in ("start", "complete", "failure") else None,"elapsed_ms":int(at)})
bridge = [line for line in stderr.splitlines() if line in ("IPLeak bridge: navigation allow", "IPLeak bridge: navigation reject", "IPLeak bridge: didFinish", "IPLeak bridge: navigation failed", "IPLeak bridge: provisional navigation failed", "IPLeak bridge: received message")]
print(json.dumps({"kind":"dns","status":receipt.get("status"),"elapsed_ms":elapsed,"http_count":policy["http_count"],"resolver_count":policy["resolver_count"],"error_stages":policy["error_stages"],"error_codes":policy["error_codes"],"phase_timeline":timeline,"bridge_events":bridge[:30],"temporary_home_mode":oct(home.stat().st_mode & 0o777)}, ensure_ascii=False, separators=(",",":")))
if receipt.get("status") != "complete" or not policy["http_count"] or not policy["resolver_count"]:
    raise SystemExit("live DNS observation did not complete; see the summary above")
PY
