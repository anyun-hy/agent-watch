"""No-execution architecture contracts for the bounded R04/C05 refactor."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROLLED = (ROOT / "crates/watch-runtime/src/controlled.rs").read_text(encoding="utf-8")
LAUNCH = (ROOT / "crates/watch-runtime/src/controlled/launch.rs").read_text(encoding="utf-8")
LEASES = (ROOT / "crates/watch-runtime/src/lease_store.rs").read_text(encoding="utf-8")
SESSIONS = (ROOT / "crates/watch-runtime/src/session_store.rs").read_text(encoding="utf-8")
MONITOR = (ROOT / "monitor/Sources/MonitorStore.swift").read_text(encoding="utf-8")
SNAPSHOT = (ROOT / "monitor/Sources/MonitorSnapshotReader.swift").read_text(encoding="utf-8")
CONTEXT = (ROOT / "monitor/Sources/DiagnosticContextTracker.swift").read_text(encoding="utf-8")
PAGE = (ROOT / "monitor/Sources/MonitorPage.swift").read_text(encoding="utf-8")
PROCESS = (ROOT / "monitor/Sources/AIProcessControl.swift").read_text(encoding="utf-8")
HELPER = (ROOT / "monitor/tools/ProcessHelper.swift").read_text(encoding="utf-8")


class ArchitectureBoundaries(unittest.TestCase):
    def test_engine_owns_broker_acquisition_and_enforcer_accepts_verified_listener(self):
        enforcer = (ROOT / "crates/watch-runtime/src/channel_enforcer.rs").read_text()
        engine = (ROOT / "crates/watch-engine/src/daemon_run.rs").read_text()
        self.assertNotIn("acquire_gateway_listener", enforcer)
        self.assertNotIn("start_launchd_proxy_listener", enforcer + engine)
        self.assertIn("acquire_gateway_listener()", engine)
        self.assertIn("start_verified_proxy_listener(verified, stop, now)", engine)

    def test_phase1_ui_only_requests_and_displays_backend_evidence(self):
        models = (ROOT / "monitor/Sources/LeakCheckModels.swift").read_text()
        store = (ROOT / "monitor/Sources/LeakCheckStore.swift").read_text()
        switcher = (ROOT / "monitor/Sources/SwitcherStore.swift").read_text()
        for retired in ["LeakPolicy", "refreshWebRTCIfNeeded", "awaitFreshDNSReceipt",
                        "recordDNSLeak", "recordWebRTCRisk", "runAccountSwitchWithDNSRefresh"]:
            self.assertNotIn(retired, models + store + switcher + MONITOR)
        for native_collector in ["IPLeakDNSRunner(", "IPLeakDNSRetryRunner(", "NetCoffeeLeakRunner("]:
            self.assertNotIn(native_collector, store + MONITOR)
        self.assertIn('SwitcherCommandRunner.run(["evidence", "refresh", "--apply"]', store)
        for retired in ["monitor/Sources/DNSRefreshBridge.swift",
                        "monitor/Sources/DNSLeakRecordReceipt.swift",
                        "crates/watch-runtime/src/leak_refresh.rs"]:
            self.assertFalse((ROOT / retired).exists(), retired)

    def test_guard_controller_only_projects_the_supervisor_frame(self):
        self.assertIn("mod launch;", CONTROLLED)
        self.assertIn("pub fn guard_tick<S: DesktopSystem>", CONTROLLED)
        self.assertIn("channel_policy_status::read_frame", CONTROLLED)
        for retired in ["FamilyChannelLedger", "guard_tick_family", "enforce_channel",
                        "guard-heartbeat.json", "read_process_real_uid", "atomic_json"]:
            self.assertNotIn(retired, CONTROLLED)

    def test_launch_and_lease_storage_have_one_owner(self):
        for key in ["pub fn launch<", "pub fn launch_cli", "fn observation_audit<"]:
            self.assertIn(key, LAUNCH)
        self.assertNotIn("begin_verified", LAUNCH)
        self.assertNotIn("desktop-pending", LAUNCH)
        self.assertNotIn("controlled::Controller", SESSIONS)
        self.assertIn("pub fn save_desktop(", LEASES)
        self.assertIn("LeaseStore", LAUNCH)

    def test_store_consumers_do_not_address_owned_state_files(self):
        runtime = ROOT / "crates/watch-runtime/src"
        consumers = {
            "background_evidence.rs": ["dns-leak-receipt.json", "webrtc-risk-receipt.json"],
            "session_store.rs": ["state/sessions/", "rust-{}.session"],
            "session_store/desktop_groups.rs": ["state/sessions/", "rust-{}.session"],
            "desktop_native.rs": ["state/target-discovery.json", "state/seatbelt-runtime.json"],
            "uninstall.rs": ["paths.accounts()", 'join("accounts.json")', 'join("ip-history.json")'],
        }
        for name, private_paths in consumers.items():
            source = (runtime / name).read_text().split("#[cfg(test)]")[0]
            for path in private_paths:
                self.assertNotIn(path, source, name)
        # Daemon test fixtures may still inspect persisted output directly.
        daemon = (ROOT / "crates/watch-engine/src/daemon_run.rs").read_text().split("mod tests {")[0]
        for path in ["state/target-discovery.json", "state/seatbelt-runtime.json",
                     "state/guard-service-heartbeat.json", "state/channel-protocol-coverage.json"]:
            self.assertNotIn(path, daemon)

    def test_monitor_presentation_is_not_its_snapshot_reader(self):
        self.assertIn("final class MonitorStore: ObservableObject", MONITOR)
        self.assertNotIn("enum SnapshotRunner", MONITOR)
        self.assertNotIn("enum Page:", MONITOR)
        self.assertNotIn("struct DiagnosticContextTracker", MONITOR)
        self.assertIn("enum SnapshotRunner", SNAPSHOT)
        self.assertIn("struct DiagnosticContextTracker", CONTEXT)
        self.assertIn("func tagReceiptContext(", CONTEXT)
        self.assertIn("enum Page: String, CaseIterable", PAGE)

    def test_process_policy_passes_bound_identity_not_bare_pid_to_effect(self):
        self.assertIn('["process-exit", "prepare", "--family"', PROCESS)
        self.assertIn('["process-exit", "apply", "--apply"]', PROCESS)
        for retired in ["AIProcessClosePolicy", "forceRemaining", "exitEvidence", "guard-close-desktop"]:
            self.assertNotIn(retired, PROCESS + HELPER)
        self.assertIn("static func applyToMatchingIdentity(", PROCESS)
        normal = (ROOT / "crates/watch-runtime/src/process_exit.rs").read_text().split("#[cfg(test)]")[0]
        self.assertIn("bound_lifetime_exited", normal)
        self.assertNotIn('.lock("operation"', normal)
        self.assertNotIn("ProcessDispositionDispatcher", normal)
        account = (ROOT / "crates/watch-runtime/src/account_native.rs").read_text()
        self.assertIn("self.desktop.quit(&self.storage.paths)?.confirm()", account)

    def test_all_production_signal_callbacks_revalidate_at_effect_boundary(self):
        self.assertIn("AIProcessNativeAction.applyToMatchingIdentity(expected", HELPER)
        self.assertNotIn("Darwin.kill", HELPER)
        self.assertNotIn("Darwin.kill($0", PROCESS)
        self.assertIn("NSRunningApplication(processIdentifier: $0)?.terminate()", HELPER)
        self.assertIn("TASK_AUDIT_TOKEN", PROCESS)
        self.assertIn("proc_pidpath_audittoken(&token, &path, UInt32(path.count))", PROCESS)
        self.assertIn("auditToken == other.auditToken", PROCESS)
        self.assertIn("expected.sameProcess(as: current)", PROCESS)


if __name__ == "__main__":
    unittest.main()
