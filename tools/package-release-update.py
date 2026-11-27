#!/usr/bin/env python3
"""Package a built Agent Watch .app bundle into a signed auto-update ZIP and manifest.

Produces two release artifacts strictly matching `crates/watch-runtime/src/update.rs`
and `crates/watch-runtime/src/update/permissions.rs`:
  1. `<archive-output>`: deterministic ZIP containing:
       - `app/Agent Watch.app/...`
       - `runtime/<component>` (byte-identical copies from `Contents/Resources/`)
  2. `<manifest-output>`: RSA-SHA256 signed JSON envelope:
       `{"manifest": "<base64-json>", "signature": "<base64-sig>"}`

Uses only Python stdlib + `/usr/bin/openssl`. Never writes private keys to output
directories or logs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

APP_BUNDLE_NAME = "Agent Watch.app"
RUNTIME_COMPONENTS = (
    "watch-engine",
    "watch-native-observer",
    "watch-admin.sh",
    "watch-process-control",
    "watch-sandbox-launcher",
    "watch-gateway-broker",
    "watch-vpn-core",
    "ControlledEntry",
    "watch-native-collector.zsh",
    "BuildIdentity.json",
    "BuildInfo.plist",
)
REQUIRED_COMPONENTS = (
    "watch-engine",
    "watch-native-observer",
    "watch-process-control",
    "watch-admin.sh",
    "BuildInfo.plist",
)
FORBIDDEN_NAMES = frozenset({"claude-watch.sh", "snapshot.sh", "switcher.py"})
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_bundle_entries(app_dir: Path) -> list[tuple[str, bytes]]:
    if app_dir.is_symlink() or not app_dir.is_dir():
        raise SystemExit(f"App bundle is not a regular directory: {app_dir}")
    resources_dir = app_dir / "Contents" / "Resources"
    if not resources_dir.is_dir():
        raise SystemExit(f"Missing Contents/Resources in app bundle: {app_dir}")

    entries: dict[str, bytes] = {}
    for root, dirs, files in os.walk(app_dir, followlinks=False):
        root_path = Path(root)
        dirs.sort()
        files.sort()
        for d in dirs:
            p = root_path / d
            if p.is_symlink():
                raise SystemExit(f"Refusing symlink directory inside app bundle: {p}")
        for f in files:
            p = root_path / f
            if p.is_symlink() or not p.is_file():
                raise SystemExit(f"Refusing symlink or special file inside app bundle: {p}")
            if p.suffix == ".py" or p.name in FORBIDDEN_NAMES:
                raise SystemExit(f"Refusing retired script inside app bundle: {p}")
            rel = p.relative_to(app_dir).as_posix()
            arc_name = f"app/{APP_BUNDLE_NAME}/{rel}"
            entries[arc_name] = p.read_bytes()

    info_key = f"app/{APP_BUNDLE_NAME}/Contents/Info.plist"
    if info_key not in entries:
        raise SystemExit("App bundle missing Contents/Info.plist")

    for name in RUNTIME_COMPONENTS:
        src = resources_dir / name
        if src.is_symlink():
            raise SystemExit(f"Refusing symlink runtime component: {src}")
        if src.is_file():
            data = src.read_bytes()
            bundled_key = f"app/{APP_BUNDLE_NAME}/Contents/Resources/{name}"
            if entries.get(bundled_key) != data:
                raise SystemExit(f"Bundled resource mismatch for {name}")
            entries[f"runtime/{name}"] = data
        elif name in REQUIRED_COMPONENTS:
            raise SystemExit(f"Missing required runtime component: {name}")

    return sorted(entries.items(), key=lambda item: item[0])


def write_deterministic_zip(archive_path: Path, entries: list[tuple[str, bytes]]) -> str:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for arc_name, data in entries:
            info = zipfile.ZipInfo(filename=arc_name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            # Regular file mode only (permissions.rs enforces fixed roles on extract).
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data)
    return sha256_bytes(archive_path.read_bytes())


def sign_and_verify(
    payload: bytes, private_key_path: Path, public_key_path: Path | None
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="cw-sign-") as tmp:
        tmp_dir = Path(tmp)
        payload_file = tmp_dir / "manifest.json"
        sig_file = tmp_dir / "manifest.sig"
        payload_file.write_bytes(payload)

        sign_proc = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key_path),
                "-out",
                str(sig_file),
                str(payload_file),
            ],
            capture_output=True,
            text=True,
        )
        if sign_proc.returncode != 0:
            raise SystemExit(f"OpenSSL signing failed: {sign_proc.stderr.strip()}")
        signature = sig_file.read_bytes()

        if public_key_path is not None:
            verify_proc = subprocess.run(
                [
                    "/usr/bin/openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(public_key_path),
                    "-signature",
                    str(sig_file),
                    str(payload_file),
                ],
                capture_output=True,
                text=True,
            )
            if verify_proc.returncode != 0:
                raise SystemExit(
                    f"Public key verification failed (private/public key mismatch): {verify_proc.stderr.strip()}"
                )
        return signature


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, type=Path, help="Path to built .app bundle")
    parser.add_argument("--version", required=True, help="Semantic version (e.g. 3.0.1)")
    parser.add_argument("--build", required=True, type=int, help="Positive integer build number")
    parser.add_argument("--architecture", default="arm64", help="Target architecture (default: arm64)")
    parser.add_argument("--archive-url", required=True, help="HTTPS download URL for the update ZIP")
    parser.add_argument("--archive-output", required=True, type=Path, help="Output path for update ZIP")
    parser.add_argument("--manifest-output", required=True, type=Path, help="Output path for signed manifest JSON")
    parser.add_argument("--private-key", required=True, type=Path, help="RSA private key PEM path")
    parser.add_argument("--public-key", type=Path, help="Optional RSA public key PEM path for self-verification")
    args = parser.parse_args()

    if not SEMVER_RE.match(args.version):
        raise SystemExit(f"Invalid semantic version: {args.version}")
    if args.build <= 0:
        raise SystemExit(f"Build number must be positive: {args.build}")
    if not args.archive_url.startswith("https://") or any(c.isspace() for c in args.archive_url):
        raise SystemExit(f"Archive URL must be a clean https:// URL: {args.archive_url}")
    if not args.private_key.is_file():
        raise SystemExit(f"Private key file not found: {args.private_key}")
    if args.public_key is not None and not args.public_key.is_file():
        raise SystemExit(f"Public key file not found: {args.public_key}")

    entries = collect_bundle_entries(args.app)
    archive_sha = write_deterministic_zip(args.archive_output, entries)
    files_map = {arc_name: sha256_bytes(data) for arc_name, data in entries}

    manifest_obj = {
        "schema": 1,
        "runtime_schema": 2,
        "admin_abi": 1,
        "version": args.version,
        "build": args.build,
        "architecture": args.architecture,
        "archive_url": args.archive_url,
        "archive_sha256": archive_sha,
        "files": files_map,
    }
    payload_bytes = json.dumps(manifest_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature_bytes = sign_and_verify(payload_bytes, args.private_key, args.public_key)

    envelope = {
        "manifest": base64.b64encode(payload_bytes).decode("ascii"),
        "signature": base64.b64encode(signature_bytes).decode("ascii"),
    }
    args.manifest_output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_output.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "status": "ok",
                "version": args.version,
                "build": args.build,
                "architecture": args.architecture,
                "files_count": len(files_map),
                "archive_sha256": archive_sha,
                "archive_output": str(args.archive_output),
                "manifest_output": str(args.manifest_output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
