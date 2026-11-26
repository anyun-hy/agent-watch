#!/usr/bin/env python3
"""Static boundary checks for the opt-in local Rust candidate packager."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "monitor" / "build.sh"
COMPONENTS = ROOT / "tools" / "build-rust-components.sh"
MONITOR_STORE = ROOT / "monitor" / "Sources" / "MonitorStore.swift"
SNAPSHOT_READER = ROOT / "monitor" / "Sources" / "MonitorSnapshotReader.swift"
SWITCHER_STORE = ROOT / "monitor" / "Sources" / "SwitcherStore.swift"


class RustCandidatePackagingTests(unittest.TestCase):
    def test_scripts_are_shell_syntax_valid(self):
        for script in (BUILD, COMPONENTS):
            result = subprocess.run(["/bin/bash", "-n", str(script)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_build_rejects_a_retired_backend_variant_before_building(self):
        for variant in ("not-a-variant", "stable"):
            result = subprocess.run(
                ["/bin/bash", str(BUILD)],
                env={**os.environ, "CW_BACKEND_VARIANT": variant},
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("only rust-candidate can be built", result.stderr)

    def test_candidate_rejects_non_arm64_before_building(self):
        result = subprocess.run(
            ["/bin/bash", str(BUILD)],
            env={**os.environ, "CW_BACKEND_VARIANT": "rust-candidate", "CW_BUILD_ARCH": "x86_64"},
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("arm64-only", result.stderr)

    def test_candidate_is_explicit_arm64_and_requires_component_manifest(self):
        text = BUILD.read_text(encoding="utf-8")
        self.assertIn('CW_BACKEND_VARIANT="${CW_BACKEND_VARIANT:-rust-candidate}"', text)
        self.assertIn('"$CW_BACKEND_VARIANT" != rust-candidate', text)
        self.assertIn('"$CW_BUILD_ARCH" != arm64', text)
        self.assertIn('RUST_COMPONENTS_MANIFEST', text)
        self.assertIn('Agent Watch.app', text)
        self.assertIn('Refusing to build into an installed application path.', text)
        self.assertIn('<key>BackendVariant</key><string>$CW_BACKEND_VARIANT</string>', text)
        # DNS/WebRTC evidence is collected in-process by the Rust engine. The
        # retired WebView helper must not be built, and the manifest must omit
        # BackgroundEvidenceSchema so v4.2.5 updaters skip the helper check.
        self.assertNotIn('BACKGROUND_LEAK_WORKER', text)
        self.assertNotIn('BackgroundEvidenceSchema', text)
        self.assertNotIn('BACKGROUND_EVIDENCE_SCHEMA', text)
        self.assertIn('rm -f "$APP/Contents/Resources/watch-leak-worker"', text)

    def test_retired_webview_probe_tests_are_gone(self):
        for retired in ("monitor/tests/run_background_leak_worker_runtime_test.sh",
                        "monitor/tests/run_background_dns_pipeline_test.sh",
                        "monitor/tests/run_background_leak_worker_test.sh",
                        "monitor/tools/BackgroundLeakWorker.swift"):
            self.assertFalse((ROOT / retired).exists(), retired)

    def test_component_builder_queries_paths_instead_of_hardcoding_native_sources(self):
        text = COMPONENTS.read_text(encoding="utf-8")
        self.assertIn('--bin claude-watch-engine', text)
        self.assertIn('--component-paths', text)
        self.assertIn('"native_observer", "process_control"', text)
        self.assertIn('requires an arm64 host', text)

    def test_gui_runners_only_accept_the_rust_backend(self):
        monitor = MONITOR_STORE.read_text(encoding="utf-8")
        snapshot_reader = SNAPSHOT_READER.read_text(encoding="utf-8")
        switcher = SWITCHER_STORE.read_text(encoding="utf-8")
        variant = (ROOT / "monitor/Sources/BundledBackendVariant.swift").read_text(encoding="utf-8")
        self.assertIn('values["BackendVariant"]', variant)
        self.assertIn('raw == "rust-candidate"', variant)
        # The Python backend is retired: no runner may keep a branch for it.
        self.assertNotIn('case "stable"', variant)
        self.assertIn('arguments: ["snapshot", "--without-channel-events"]', snapshot_reader)
        self.assertIn('SnapshotProcessTransport.run(', snapshot_reader)
        for runner in (snapshot_reader, switcher):
            self.assertIn('guard let variant = BundledBackendVariant.current() else {', runner)
            self.assertIn('case .rustCandidate:', runner)
            self.assertIn('forResource: "watch-engine"', runner)
        for source in (monitor, snapshot_reader, switcher):
            self.assertNotIn('case .stable:', source)
            self.assertNotIn('python3', source)


if __name__ == "__main__":
    unittest.main()
