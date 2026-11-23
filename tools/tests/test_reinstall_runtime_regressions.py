"""Exercise build entry points and the collector parent using private fixtures."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform == "darwin" and platform.machine() == "arm64", "macOS arm64 build entry")
class ReinstallBuildRegression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cw-build-entry-")
        self.root = Path(self.temp.name).resolve()
        for name in ("monitor/reinstall.sh", "monitor/network-backend.sh", "tools/build-rust-components.sh", "monitor/macos-minimum.txt", "tools/reinstall_log.py"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        (self.root / "Cargo.toml").write_text("[workspace]\n")
        self.trace = self.root / "calls.jsonl"
        cargo = self.root / "cargo-home/bin/cargo"
        cargo.parent.mkdir(parents=True)
        cargo.write_text(f"#!{sys.executable}\n" + r'''
import json, os, pathlib, sys
root = pathlib.Path(__file__).resolve().parents[2]
with (root / "calls.jsonl").open("a") as out:
    out.write(json.dumps({"kind":"cargo", "args":sys.argv[1:], "environment":{
        key:os.environ.get(key) for key in ("SDKROOT", "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER", "CC_aarch64_apple_darwin", "MACOSX_DEPLOYMENT_TARGET")}}) + "\n")
if os.environ.get("CW_FIXTURE_BUILD_FAILURE") == "1":
    print("fixture compiler failure", file=sys.stderr)
    raise SystemExit(23)
target = root / "target/aarch64-apple-darwin/release"
target.mkdir(parents=True, exist_ok=True)
engine = target / "claude-watch-engine"
engine.write_text("#!" + sys.executable + "\n" + ''' + repr(r'''
import json, pathlib, sys
target = pathlib.Path(__file__).resolve().parent
root = target.parents[2]
with (root / "calls.jsonl").open("a") as out:
    out.write(json.dumps({"kind":"engine", "args":sys.argv[1:]}) + "\n")
if sys.argv[1:] == ["--component-paths"]:
    print(json.dumps({key:str(target/name) for key,name in {
        "native_observer":"watch-native-observer", "process_control":"watch-process-control",
        "sandbox_launcher":"watch-sandbox-launcher", "gateway_broker":"watch-gateway-broker"}.items()}))
else:
    assert sys.argv[1] == "reinstall" and "--dry-run" in sys.argv
    print('{"status":"preview","fixture":true}')
''') + r''')
engine.chmod(0o700)
for name in ("watch-native-observer", "watch-process-control", "watch-sandbox-launcher", "watch-gateway-broker"):
    p = target / name
    p.write_text("#!/bin/sh\nexit 0\n")
    p.chmod(0o700)
''')
        cargo.chmod(0o700)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CW_", "WATCH_", "CARGO_TARGET_"))}
        fixture_home = self.root / "home"
        (fixture_home / "Library/Logs").mkdir(parents=True)
        self.env["HOME"] = str(fixture_home)
        self.env["CARGO_HOME"] = str(self.root / "cargo-home")
        self.env["CW_CARGO_BIN"] = str(cargo)

    def tearDown(self):
        self.temp.cleanup()

    def run_script(self, name, *args):
        return subprocess.run(["/bin/bash", str(self.root / name), *args], cwd=self.root,
                              env=self.env, capture_output=True, text=True, timeout=20)

    def test_bootstrap_and_packaging_use_identical_cargo_units_and_environment(self):
        bootstrap = self.run_script("monitor/reinstall.sh", "3.0.0", "378", "--dry-run")
        self.assertEqual(bootstrap.returncode, 0, bootstrap.stderr)
        stage = self.run_script("tools/build-rust-components.sh", "--output", str(self.root / "staging"))
        self.assertEqual(stage.returncode, 0, stage.stderr)
        calls = [json.loads(line) for line in self.trace.read_text().splitlines()]
        cargo = [call for call in calls if call["kind"] == "cargo"]
        self.assertEqual(len(cargo), 2)
        self.assertEqual(cargo[0], cargo[1], "bootstrap and packaging must resolve the same feature graph")
        for name in ("claude-watch-engine", "claude-watch-sandbox-launcher", "claude-watch-gateway-broker"):
            self.assertIn(name, cargo[0]["args"])
        self.assertIn("--locked", cargo[0]["args"])
        engine = [call for call in calls if call["kind"] == "engine"]
        self.assertEqual(engine[0]["args"], ["reinstall", "--version", "3.0.0", "--build", "378",
                                           "--project", str(self.root), "--dry-run"])
        manifest = json.loads((self.root / "staging/components.json").read_text())
        self.assertEqual(len(manifest["components"]), 5)
        summaries = list((Path(self.env["HOME"]) / "Library/Logs/ClaudeWatchInstaller").glob("reinstall-*/run.json"))
        self.assertEqual(len(summaries), 1)
        summary = json.loads(summaries[0].read_text())
        self.assertEqual(summary["status"], "passed")
        self.assertEqual([(p["phase"], p["exit_code"]) for p in summary["phases"] if p["status"] != "running"], [("build", 0), ("install", 0)])

    def test_reinstall_build_failure_keeps_one_compile_and_durable_failed_summary(self):
        self.env["CW_FIXTURE_BUILD_FAILURE"] = "1"
        result = self.run_script("monitor/reinstall.sh", "3.0.0", "378", "--dry-run")
        self.assertEqual(result.returncode, 23, result.stdout + "\n" + result.stderr)
        calls = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual([call["kind"] for call in calls], ["cargo"])
        summaries = list((Path(self.env["HOME"]) / "Library/Logs/ClaudeWatchInstaller").glob("reinstall-*/run.json"))
        self.assertEqual(len(summaries), 1)
        value = json.loads(summaries[0].read_text())
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["phases"][-1]["exit_code"], 23)
        self.assertIn("fixture compiler failure", (summaries[0].parent / "build.log").read_text())

    def test_retired_backend_stops_before_build_logging_or_installer(self):
        self.env["CW_NETWORK_BACKEND"] = "network-extension"
        result = self.run_script("monitor/reinstall.sh", "3.0.0", "378", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only nono/Seatbelt is available", result.stderr)
        self.assertFalse(self.trace.exists(), "retired backend must not compile or invoke the installer")
        self.assertFalse((Path(self.env["HOME"]) / "Library/Logs/ClaudeWatchInstaller").exists())

    def test_retired_profile_stops_before_build_or_installer(self):
        self.env["CW_HOST_PROFILE"] = "/unused/fixture.profile"
        result = self.run_script("monitor/reinstall.sh", "3.0.0", "378", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Retired NetworkExtension option", result.stderr)
        self.assertFalse(self.trace.exists(), "retired profile must not compile or invoke the installer")

    def test_build_only_does_not_stage_or_run_the_engine(self):
        build = self.run_script("tools/build-rust-components.sh", "--build-only")
        self.assertEqual(build.returncode, 0, build.stderr)
        calls = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual([call["kind"] for call in calls], ["cargo"])
        self.assertFalse((self.root / "staging").exists())


@unittest.skipUnless(sys.platform == "darwin", "native zsh supervisor")
class ListenerSupervisorRegression(unittest.TestCase):
    @contextlib.contextmanager
    def native_collector(self):
        with tempfile.TemporaryDirectory(prefix="cw-collector-events-", dir="/private/tmp") as private:
            path = Path(private) / "input"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                listener.settimeout(5)
                script = ROOT / "monitor/Resources/watch-native-collector.zsh"
                proc = subprocess.Popen(
                    ["/bin/zsh", "-f", str(script), "--collect", str(os.getpid())],
                    env=dict(os.environ, CW_NATIVE_LISTENER_SOCKET=str(path)),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                try:
                    peer, _ = listener.accept()
                    with peer:
                        peer.settimeout(5)
                        yield proc, peer, path.parent / "sample"
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate()
                        raise

    def read_native_frame(self, stream, collector_pid, sequence):
        fields = stream.readline(256).split()
        self.assertEqual(len(fields), 13)
        self.assertEqual(fields[0], b"CWLISTENER1")
        self.assertEqual(list(map(int, fields[1:4])), [os.getpid(), collector_pid, sequence])
        self.assertLessEqual(float(fields[4]), float(fields[5]))
        sizes = list(map(int, fields[9:13]))
        self.assertTrue(all(0 <= size <= 4000 * 512 for size in sizes))
        remaining = sum(sizes)
        while remaining:
            data = stream.read(min(65536, remaining))
            self.assertTrue(data, "incomplete native sample")
            remaining -= len(data)
        self.assertEqual(stream.read(1), b"\n")

    def test_collector_samples_only_on_request_and_stops_on_eof(self):
        with self.native_collector() as (proc, peer, sample):
            with peer.makefile("rb", buffering=0) as stream:
                self.assertFalse(select.select([peer], [], [], 0.2)[0], "unsolicited bootstrap frame")
                self.assertFalse((sample / "before").exists(), "sample started before bootstrap request")
                peer.sendall(b"S")
                self.read_native_frame(stream, proc.pid, 1)
                initial_stamp = (sample / "before").stat().st_mtime_ns
                self.assertFalse(select.select([peer], [], [], 2.6)[0], "unsolicited periodic frame")
                self.assertEqual((sample / "before").stat().st_mtime_ns, initial_stamp, "idle input was sampled")
                peer.sendall(b"S")
                self.read_native_frame(stream, proc.pid, 2)
                peer.shutdown(socket.SHUT_WR)
                self.assertEqual(stream.read(1), b"", "request EOF must close output")
                self.assertEqual(proc.wait(timeout=3), 0)
                self.assertFalse(sample.exists(), "collector must clean up its private evidence")

    def test_collector_rejects_unknown_request_without_sampling(self):
        with self.native_collector() as (proc, peer, sample):
            peer.sendall(b"X")
            self.assertNotEqual(proc.wait(timeout=3), 0)
            self.assertEqual(peer.recv(1), b"", "invalid request produced native evidence")
            self.assertFalse(sample.exists())

    def fixture(self, root, *, immediate_exit=False, trap_delay=False, stalled_collector=False):
        collector = root / "watch-native-collector.zsh"
        shutil.copy2(ROOT / "monitor/Resources/watch-native-collector.zsh", collector)
        if trap_delay:
            # A private scheduling seam: let the graceful child finish while
            # its parent's stop trap is still running, before wait resumes.
            source = collector.read_text()
            needle = "trap 'stop_supervised_worker' HUP INT TERM"
            self.assertEqual(source.count(needle), 1)
            collector.write_text(source.replace(needle, "trap 'stop_supervised_worker; /bin/sleep 0.15' HUP INT TERM"))
        if stalled_collector:
            needle = "  local seq=0"
            source = collector.read_text()
            self.assertEqual(source.count(needle), 1)
            collector.write_text(source.replace(needle, """
  zmodload zsh/zselect || exit 75
  print -r -- "$CW_NATIVE_LISTENER_SOCKET" > "$TMPDIR/connected"
  zselect -t 1500
""" + needle))
        collector.chmod(0o700)
        engine = root / "watch-engine"
        engine.write_text(f"#!{sys.executable}\n" + ("raise SystemExit(23)\n" if immediate_exit else r'''
from pathlib import Path
import os, signal, time
root = Path(__file__).resolve().parent
stopping = False
def stop(signum, frame):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
(root / "ready").write_text(str(os.getpid()))
until = time.monotonic() + 6
while not stopping and time.monotonic() < until:
    time.sleep(0.02)
if stopping:
    (root / "stopped").write_text(str(os.getpid()))
'''))
        if stalled_collector:
            engine.write_text(f"#!{sys.executable}\n" + """
from pathlib import Path
import time
marker = Path(__file__).parent / 'connected'
until = time.monotonic() + 3
while not marker.exists() and time.monotonic() < until:
    time.sleep(0.01)
raise SystemExit(23 if marker.exists() else 75)
""")
        engine.chmod(0o700)
        env = dict(os.environ, TMPDIR=str(root))
        return subprocess.Popen(["/bin/zsh", "-f", str(collector), "daemon", "--apply"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    def test_parent_term_reaches_only_its_owned_worker_and_waits_for_exit(self):
        with tempfile.TemporaryDirectory(prefix="cw-collector-stop-") as directory:
            root = Path(directory).resolve()
            ordinary = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
            parent = self.fixture(root, trap_delay=True)
            try:
                until = time.monotonic() + 3
                while not (root / "ready").is_file() and time.monotonic() < until:
                    time.sleep(0.02)
                self.assertTrue((root / "ready").is_file(), "owned worker must actually start")
                worker_pid = (root / "ready").read_text()
                parent.send_signal(signal.SIGTERM)
                parent.wait(timeout=2)
                self.assertEqual(parent.returncode, 0, "the graceful worker's real exit status must survive a trapped stop")
                self.assertTrue((root / "stopped").is_file(), "parent exit must not orphan its running worker")
                self.assertEqual((root / "stopped").read_text(), worker_pid)
                self.assertIsNone(ordinary.poll(), "an unrelated process must remain alive")
            finally:
                if parent.poll() is None:
                    parent.terminate()
                parent.communicate(timeout=10)
                ordinary.terminate()
                ordinary.wait(timeout=2)

    def test_independent_worker_exit_reaps_stalled_collector_and_endpoint(self):
        with tempfile.TemporaryDirectory(prefix="cw-collector-stalled-") as directory:
            root = Path(directory).resolve()
            parent = self.fixture(root, stalled_collector=True)
            try:
                stdout, stderr = parent.communicate(timeout=5)
                self.assertEqual(parent.returncode, 23, (stdout, stderr))
                socket = Path((root / "connected").read_text().strip())
                self.assertFalse(socket.parent.exists())
            finally:
                if parent.poll() is None:
                    parent.terminate()
                    parent.communicate(timeout=5)

    def test_normal_worker_exit_status_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="cw-collector-exit-") as directory:
            parent = self.fixture(Path(directory).resolve(), immediate_exit=True)
            stdout, stderr = parent.communicate(timeout=5)
            self.assertEqual(parent.returncode, 23, (stdout, stderr))


@unittest.skipUnless(sys.platform == "darwin", "native macOS observation helpers")
class NativeDaemonStartupRegression(unittest.TestCase):
    def native_runtime(self, root):
        engine = Path(os.environ.get("CW_REINSTALL_TEST_ENGINE", ROOT / "target/debug/claude-watch-engine"))
        if not engine.is_file():
            self.skipTest("build claude-watch-engine first; unified runner supplies this prerequisite")
        paths = subprocess.run([str(engine), "--component-paths"], capture_output=True, text=True, timeout=5)
        self.assertEqual(paths.returncode, 0, paths.stderr)
        components = json.loads(paths.stdout)
        runtime, home = root / "runtime", root / "home"
        runtime.mkdir(); home.mkdir()
        runtime_artifacts = {}
        for name, source in [("watch-engine", engine), ("watch-native-observer", Path(components["native_observer"])),
                             ("watch-process-control", Path(components["process_control"])),
                             ("watch-native-collector.zsh", ROOT / "monitor/Resources/watch-native-collector.zsh")]:
            shutil.copy2(source, runtime / name)
            (runtime / name).chmod(0o700)
            actual_hash = hashlib.sha256((runtime / name).read_bytes()).hexdigest()
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(actual_hash, source_hash)
            runtime_artifacts[name] = {"path":str(runtime / name), "sha256":actual_hash,
                                       "source_path":str(source), "source_sha256":source_hash}
        return runtime, home, runtime_artifacts

    def test_collector_disconnect_replaces_only_verified_child(self):
        with tempfile.TemporaryDirectory(prefix="cw-native-reconnect-", dir="/private/tmp") as directory:
            runtime, home, _ = self.native_runtime(Path(directory))
            env = {k: v for k, v in os.environ.items() if not k.startswith(("CW_", "WATCH_"))}
            env.update(HOME=str(home), TMPDIR=directory)
            parent = subprocess.Popen(["/bin/zsh", "-f", str(runtime / "watch-native-collector.zsh"),
                                       "--home", str(home), "daemon", "--apply", "--observe-only"],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            cache = home / "Library/Application Support/ClaudeWatch/state/native-listener.json"
            def wait_for(predicate):
                until = time.monotonic() + 12
                record = {}
                while time.monotonic() < until and parent.poll() is None:
                    if cache.exists():
                        record = json.loads(cache.read_bytes())
                        if predicate(record):
                            return record
                    time.sleep(0.025)
                self.fail(f"private worker stopped or failed to publish, status={parent.poll()}, cache error={record.get('error')}")
            def completed_sample(record):
                # A non-launchd test parent can receive the macOS header-only
                # netstat view. This code requires a complete authenticated
                # frame and intentionally leaves the VPN closed.
                return record.get("listener") or (record.get("error") or {}).get("code") == "native_listener_empty"
            def collector_identity(record):
                if record.get("listener"):
                    return record["listener"]["proof"]["collector"]
                response = subprocess.run([str(runtime / "watch-native-observer"), "inventory"], capture_output=True,
                                          text=True, timeout=12, check=True, env=env)
                children = [row for row in json.loads(response.stdout)["processes"]
                            if row["parent"] == parent.pid and row["executable"] == "/bin/zsh"]
                self.assertEqual(len(children), 1)
                return children[0]
            try:
                before = wait_for(completed_sample)
                actor = before["actor"]
                self.assertEqual(actor["supervisor"]["pid"], parent.pid)
                # Hold only this test's supervisor so its replacement cannot
                # overtake observation of the input's actual disconnect.
                parent.send_signal(signal.SIGSTOP)
                collector = collector_identity(before)
                self.assertEqual((collector["parent"], collector["executable"]), (parent.pid, "/bin/zsh"))
                check = subprocess.run([str(runtime / "watch-native-observer"), "arguments"],
                                       input=json.dumps({"schema":1, "round_id":"owned-collector-stop", "targets":[collector]}),
                                       text=True, capture_output=True, timeout=3, check=True, env=env)
                argument = json.loads(check.stdout)["argument_prefixes"][0]
                self.assertEqual(argument.get("identity"), collector)
                self.assertEqual(argument.get("arguments"), ["/bin/zsh", "-f", str(runtime / "watch-native-collector.zsh"),
                                                           "--collect", str(parent.pid)])
                os.kill(collector["pid"], signal.SIGTERM)
                failed = wait_for(lambda r: (r.get("error") or {}).get("code") == "native_listener_closed")
                self.assertIsNone(failed["listener"])
                self.assertEqual(failed["actor"], actor)
                parent.send_signal(signal.SIGCONT)
                after = wait_for(completed_sample)
                self.assertNotEqual(collector_identity(after), collector)
                self.assertEqual(after["actor"], actor)
                self.assertGreater(after["published_at"], failed["published_at"])
                if before.get("listener"):
                    self.assertTrue(after.get("listener"))
                    self.assertGreater(after["listener"]["evidence"]["finished"], before["listener"]["evidence"]["finished"])
                print("private native collector reconnect: original worker and supervisor retained, post-reconnect sample =",
                      "listener" if after.get("listener") else after["error"]["code"])
            finally:
                if parent.poll() is None:
                    parent.send_signal(signal.SIGCONT)
                    parent.terminate()
                parent.communicate(timeout=6)

    def test_private_daemon_keeps_publishing_during_partial_discovery_and_stops_its_original_worker(self):
        with tempfile.TemporaryDirectory(prefix="cw-native-startup-", dir="/private/tmp") as directory:
            root = Path(directory)
            runtime, home, runtime_artifacts = self.native_runtime(root)
            for index in range(24):
                bundle = home / f"Applications/Private {index:02}.app/Contents"
                (bundle / "MacOS").mkdir(parents=True)
                (bundle / "Info.plist").write_text('<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>example.ordinary</string><key>CFBundleExecutable</key><string>PrivateMain</string></dict></plist>')
                # File metadata only. None of these images is executed.
                (bundle / "MacOS/PrivateMain").write_bytes(b"private metadata fixture, never executed")
                (bundle / "MacOS/PrivateMain").chmod(0o700)
            # A permanently unreadable metadata record used to force repeated
            # synchronous scans and stall the whole publisher for >30 seconds.
            broken = home / "Applications/Unreadable Ordinary.app/Contents"
            broken.mkdir(parents=True)
            (broken / "Info.plist").write_text("not a property list")
            env = {key: value for key, value in os.environ.items() if not key.startswith(("CW_", "WATCH_"))}
            env["HOME"] = str(home)
            started = time.monotonic()
            parent = subprocess.Popen(["/bin/zsh", "-f", str(runtime / "watch-native-collector.zsh"),
                                       "--home", str(home), "daemon", "--apply", "--observe-only"],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            producer = None
            owned = {}
            def owned_rows():
                # Include zombies, which the native live-identity observer
                # intentionally excludes. Keep only this private process tree
                # or an already observed lifetime; no installed process is a
                # cleanup target or part of the recorded evidence.
                result = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,ppid=,uid=,lstart=,stat=,comm="],
                                        capture_output=True, text=True, timeout=2)
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = {}
                for line in result.stdout.splitlines():
                    fields = line.split(None, 9)
                    if len(fields) == 10 and fields[0].isdigit() and int(fields[2]) == os.getuid():
                        rows[int(fields[0])] = {"parent":int(fields[1]), "start":" ".join(fields[3:8]),
                                               "state":fields[8], "image":fields[9]}
                descendants = {parent.pid}
                if producer is not None:
                    descendants.add(producer["pid"])
                while True:
                    expanded = descendants | {pid for pid, row in rows.items() if row["parent"] in descendants}
                    if expanded == descendants:
                        break
                    descendants = expanded
                selected = {pid:row for pid, row in rows.items()
                            if pid in descendants or row["image"].startswith(str(runtime) + "/")
                            or (pid in owned and row["start"] == owned[pid]["start"])}
                owned.update(selected)
                return selected
            def identity():
                request = {"schema": 1, "round_id": "owned-startup-regression", "targets": [producer]}
                check = subprocess.run([str(runtime / "watch-native-observer"), "identities"], input=json.dumps(request),
                                       capture_output=True, text=True, env=env, timeout=5)
                self.assertEqual(check.returncode, 0, check.stderr)
                return json.loads(check.stdout)["identities"][0]
            try:
                state = home / "Library/Application Support/ClaudeWatch/state"
                snapshot_path = state / "runtime-snapshot.json"
                while not snapshot_path.is_file() and time.monotonic() - started < 15 and parent.poll() is None:
                    time.sleep(0.01)
                self.assertTrue(snapshot_path.is_file(), "first observation must meet the existing 15-second installation window")
                raw = json.loads(snapshot_path.read_text())
                snapshot, producer = raw["snapshot"], raw["producer"]
                publication_seconds = time.monotonic() - started
                self.assertEqual(snapshot["health"]["state"], "degraded")
                self.assertEqual(snapshot["initialObservation"]["application_discovery"], "pending")
                self.assertFalse(snapshot["grants_launch_permission"])
                self.assertIsNone(snapshot["proxy"])
                self.assertEqual(producer["uid"], os.getuid())
                self.assertEqual(producer["parent"], parent.pid)
                self.assertEqual(json.loads((state / "native-listener.json").read_text())["actor"]["worker"], producer)
                current = identity()
                self.assertEqual(current["state"], "ok")
                self.assertEqual(current["identity"], producer)
                readback = subprocess.run([str(runtime / "watch-engine"), "--home", str(home), "snapshot"],
                                          capture_output=True, text=True, env=env, timeout=5)
                self.assertEqual(readback.returncode, 0, readback.stderr)
                self.assertEqual(json.loads(readback.stdout)["health"]["state"], "unavailable", "unregistered private publisher must fail the normal launchd verifier")
                captures, proxy_samples, ages = set(), set(), []
                sampling_rounds = []
                sustained_started = time.monotonic()
                until = sustained_started + 16
                next_children = sustained_started
                while time.monotonic() < until and parent.poll() is None:
                    current = json.loads(snapshot_path.read_text())
                    self.assertEqual(current["producer"], producer)
                    view = current["snapshot"]
                    capture = view["capturedAt"]
                    if capture not in captures:
                        diag = view.get("samplingDiagnostics") or {}
                        network_at = diag.get("network_sampled_at")
                        sampling_rounds.append({
                            "since_bootstrap": round(capture - snapshot["capturedAt"], 2),
                            "network_since_bootstrap": round(network_at - snapshot["capturedAt"], 2) if network_at is not None else None,
                            "reused": diag.get("network_reused"),
                            "error": diag.get("publisher_error_code"),
                        })
                    captures.add(capture)
                    ages.append(time.time() - capture)
                    proxy = view.get("proxy") or {}
                    if isinstance(proxy.get("observedAt"), (float, int)):
                        proxy_samples.add(proxy["observedAt"])
                    self.assertLess(ages[-1], 8, "slow/partial application discovery must not stale the real publisher")
                    if time.monotonic() >= next_children:
                        owned_rows()
                        next_children = time.monotonic() + 2
                    time.sleep(0.1)
                self.assertIsNone(parent.poll(), "private daemon must remain alive throughout observation")
                self.assertGreaterEqual(len(captures), 6, "need sustained fresh rounds, not just the bootstrap heartbeat")
                self.assertGreaterEqual(len(proxy_samples), 2, f"need two actual proxy observations, not rereads stamped fresh; rounds={sampling_rounds}")
                sustained_seconds = time.monotonic() - sustained_started
                owned_rows()
                stopped = time.monotonic()
                parent.send_signal(signal.SIGTERM)
                stdout, stderr = parent.communicate(timeout=5)
                stop_seconds = time.monotonic() - stopped
                self.assertEqual(parent.returncode, 0, (stdout[-1000:], stderr[-1000:]))
                ended = identity()
                self.assertEqual((ended["state"], ended["code"]), ("unknown", "process_exited"))
                remaining = owned_rows()
                # The collector may be waiting for a request or finishing one.
                # Include actual descendant exit in the five-second stop budget.
                while remaining and time.monotonic() - stopped < 5:
                    time.sleep(0.05)
                    remaining = owned_rows()
                cleanup_seconds = time.monotonic() - stopped
                self.assertFalse(remaining, f"private descendants survived shutdown: {remaining}")
                self.assertLess(cleanup_seconds, 5, "private worker and descendants must finish within the existing stop budget")
                evidence = {"clock":"monotonic", "first_observation_seconds":publication_seconds,
                            "sustained_seconds":sustained_seconds, "snapshot_count":len(captures),
                            "proxy_sample_count":len(proxy_samples), "max_snapshot_wall_age_seconds":max(ages),
                            "parent_stop_seconds":stop_seconds, "all_owned_descendants_exit_seconds":cleanup_seconds,
                            "observed_owned_lifetimes":len(owned), "remaining_owned_descendants":len(remaining),
                            "runtime_artifacts":runtime_artifacts,
                            "boundary":"private observe-only daemon; no registered service or AI launch"}
                evidence_dir = os.environ.get("CW_CHANNEL_CONTRACT_DIR")
                if evidence_dir:
                    destination = Path(evidence_dir)
                    destination.mkdir(parents=True, exist_ok=True)
                    (destination / "private-daemon-lifecycle.json").write_text(json.dumps(evidence, indent=2) + "\n")
                print(f"private native daemon: first observation={publication_seconds:.3f}s; captures={len(captures)}; proxy samples={len(proxy_samples)}; max age={max(ages):.3f}s; stop={stop_seconds:.3f}s; original worker exit verified; no registered service or AI launch")
                print(f"private daemon lifecycle: {json.dumps(evidence, sort_keys=True)}")
            finally:
                if parent.poll() is None:
                    parent.terminate()
                    try:
                        parent.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        # Cleanup authority is restricted to our still kernel-
                        # verified child in this test's private runtime.
                        if producer is not None:
                            current = identity()
                            if current["state"] == "ok" and current["identity"] == producer:
                                os.kill(producer["pid"], signal.SIGKILL)
                        parent.kill()
                        parent.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
