use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    accounts::{AccountOs, AccountStore},
    storage::{Paths, StateStore},
};
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};
use uuid::Uuid;

struct Fake {
    running: bool,
    launch_fails: bool,
    clones: usize,
    fail_preflight: bool,
    fail_stage: Option<&'static str>,
    quits: usize,
}
impl AccountOs for Fake {
    fn claude_version(&mut self) -> Result<Option<String>> {
        Ok(Some("1.0".into()))
    }
    fn quit_claude(&mut self) -> Result<()> {
        self.quits += 1;
        self.running = false;
        Ok(())
    }
    fn claude_running(&mut self) -> Result<bool> {
        Ok(self.running)
    }
    fn launch_claude(&mut self) -> Result<()> {
        if self.launch_fails {
            Err(CoreError::new("launch_failed", "fixture"))
        } else {
            self.running = true;
            Ok(())
        }
    }
    fn preflight(&mut self) -> Result<()> {
        if self.fail_preflight {
            Err(CoreError::new("preflight_failed", "fixture"))
        } else {
            Ok(())
        }
    }
    fn clone_file(&mut self, source: &Path, target: &Path) -> Result<bool> {
        if self.running {
            return Err(CoreError::new("copied_while_running", "fixture"));
        }
        fs::copy(source, target).unwrap();
        self.clones += 1;
        Ok(true)
    }
    fn checkpoint(&mut self, stage: &str) -> Result<()> {
        if self.fail_stage == Some(stage) {
            Err(CoreError::new("stage_failed", "fixture"))
        } else {
            Ok(())
        }
    }
}
struct Fixture {
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!("cw-accounts-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        Self {
            home: fs::canonicalize(home).unwrap(),
        }
    }
    fn storage(&self) -> StateStore {
        StateStore::new(Paths::new(&self.home).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}
fn config() -> Config {
    Config {
        verified_claude_versions: vec!["1.0".into()],
        ..Config::default()
    }
}
fn file(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap()
}

struct ObservedDesktop {
    start: u64,
    crash_at: Option<&'static str>,
    replace_source_at: Option<&'static str>,
    edit_when_staged: Option<PathBuf>,
}
impl AccountOs for ObservedDesktop {
    fn current_desktop(&mut self) -> Result<claude_watch_core::processes::Identity> {
        Ok(claude_watch_core::processes::Identity {
            executable: "/Applications/Claude.app/Contents/MacOS/Claude".into(), pid: 40,
            start_seconds: self.start, start_microseconds: 47, uid: 501, parent: 1, start_stamp: String::new(),
        })
    }
    fn claude_version(&mut self) -> Result<Option<String>> { unreachable!() }
    fn quit_claude(&mut self) -> Result<()> { panic!("manual save must not quit the desktop") }
    fn claude_running(&mut self) -> Result<bool> { Ok(true) }
    fn launch_claude(&mut self) -> Result<()> { panic!("manual save must not launch the desktop") }
    fn preflight(&mut self) -> Result<()> { unreachable!() }
    fn checkpoint(&mut self, stage: &str) -> Result<()> {
        if stage == "save_staged" {
            if let Some(path) = self.edit_when_staged.take() { fs::write(path, "changed during save").unwrap(); }
        }
        if Some(stage) == self.replace_source_at { self.start += 1; }
        if Some(stage) == self.crash_at { panic!("simulated writer interruption at {stage}"); }
        Ok(())
    }
}
fn observed_store(f: &Fixture) -> AccountStore<ObservedDesktop> {
    AccountStore::new(f.storage(), ObservedDesktop { start: 70, crash_at: None, replace_source_at: None, edit_when_staged: None })
}
fn read_current(store: &mut AccountStore<ObservedDesktop>, label: &str) -> claude_watch_runtime::accounts::SaveCurrentAccount {
    let read = store.current_source().unwrap();
    assert_eq!(read["process_id"], 40);
    claude_watch_runtime::accounts::SaveCurrentAccount {
        source_token: read["source_token"].as_str().unwrap().to_owned(), account_label: label.into(),
    }
}

#[test]
fn manual_save_first_to_either_slot_and_keep_both_public_labels() {
    for (first, second) in [("A", "B"), ("B", "A")] {
        let fixture = Fixture::new();
        let mut store = observed_store(&fixture);
        let active = store.storage.paths.active().join("state");
        file(&active, "first");
        let read = read_current(&mut store, "First account");
        assert!(store.current_source().unwrap()["slot"].is_null());
        assert_eq!(store.save_current(first, &read).unwrap()["saved"], true);
        assert_eq!(store.current_source().unwrap()["slot"], first);
        assert_eq!(store.status().unwrap().current.as_deref(), Some(first));
        let first_profile = store.profile_path(first).unwrap().join("state");
        assert_eq!(fs::read_to_string(&first_profile).unwrap(), "first");
        assert!(!store.profile_path(second).unwrap().exists());
        file(&active, "second");
        let read = read_current(&mut store, "Second account");
        store.save_current(second, &read).unwrap();
        let read = read_current(&mut store, "Second updated");
        assert_eq!(store.save_current(first, &read).unwrap_err().code, "account_slot_occupied");
        store.save_current(second, &read).unwrap();
        let status = store.status().unwrap();
        assert_eq!(status.current.as_deref(), Some(second));
        for entry in status.accounts {
            let label = if entry.id == first { "First account" } else { "Second updated" };
            assert_eq!(entry.account_label.as_deref(), Some(label));
        }
        assert_eq!(fs::read_to_string(first_profile).unwrap(), "first");
        assert_eq!(fs::read_to_string(store.profile_path(second).unwrap().join("state")).unwrap(), "second");
        assert_eq!(fs::read_to_string(&active).unwrap(), "second");
        let mut switcher = AccountStore::new(fixture.storage(), Fake {
            running: true, launch_fails: false, clones: 0, fail_preflight: false, fail_stage: None, quits: 0,
        });
        for (target, data) in [(first, "first"), (second, "second")] {
            switcher.switch(target, &config(), false).unwrap();
            assert_eq!(fs::read_to_string(&active).unwrap(), data);
            for entry in switcher.status().unwrap().accounts {
                let expected = if entry.id == first { "First account" } else { "Second updated" };
                assert_eq!(entry.account_label.as_deref(), Some(expected));
            }
        }
    }
}

#[test]
fn manual_save_rejects_reused_pid_at_read_or_publication() {
    let fixture = Fixture::new();
    let mut store = observed_store(&fixture);
    file(&store.storage.paths.active().join("state"), "one");
    let read = read_current(&mut store, "First account");
    store.os.start += 1;
    assert_eq!(store.save_current("A", &read).unwrap_err().code, "account_source_changed");
    for phase in ["save_staged", "save_published"] {
        let read = read_current(&mut store, "First account");
        store.os.replace_source_at = Some(phase);
        assert_eq!(store.save_current("A", &read).unwrap_err().code, "account_source_changed");
        assert!(store.status().unwrap().accounts.iter().all(|s| !s.stored && !s.current));
        assert!(!store.storage.paths.journal().exists());
    }
}

#[test]
fn manual_save_discards_an_unstable_profile_and_preserves_both_live_and_archived_data() {
    let fixture = Fixture::new();
    let mut store = observed_store(&fixture);
    let active = store.storage.paths.active().join("state");
    file(&active, "saved");
    let read = read_current(&mut store, "First account");
    store.save_current("A", &read).unwrap();
    let read = read_current(&mut store, "New account");
    store.os.edit_when_staged = Some(active.clone());
    assert_eq!(store.save_current("B", &read).unwrap_err().code, "account_source_changed");
    assert_eq!(fs::read_to_string(active).unwrap(), "changed during save");
    assert_eq!(fs::read_to_string(store.profile_path("A").unwrap().join("state")).unwrap(), "saved");
    assert!(!store.profile_path("B").unwrap().exists());
    assert_eq!(store.status().unwrap().current.as_deref(), Some("A"));
}

#[test]
fn manual_save_interruption_restores_only_archives_or_finishes_published_marker() {
    for phase in ["save_staged", "save_published", "save_marked"] {
        let fixture = Fixture::new();
        let mut store = observed_store(&fixture);
        let active = store.storage.paths.active().join("state");
        file(&active, "old");
        let read = read_current(&mut store, "Old label");
        store.save_current("B", &read).unwrap();
        file(&active, "new");
        let read = read_current(&mut store, "New label");
        store.os.crash_at = Some(phase);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.save_current("B", &read))).is_err());
        assert!(store.storage.paths.journal().exists());
        store.os.crash_at = None;
        store.recover().unwrap();
        let committed = phase == "save_marked";
        let status = store.status().unwrap();
        assert_eq!(status.accounts[1].account_label.as_deref(), Some(if committed { "New label" } else { "Old label" }));
        assert_eq!(fs::read_to_string(store.profile_path("B").unwrap().join("state")).unwrap(), if committed { "new" } else { "old" });
        assert_eq!(fs::read_to_string(active).unwrap(), "new");
        assert!(!status.recovery_required);
    }
}

#[test]
fn legacy_import_first_save_switch_and_status_are_isolated() {
    let f = Fixture::new();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/B/Cookie"), "B");
    file(&legacy.join("current"), "B");
    let mut store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    assert!(store.import_legacy(&legacy, false).unwrap().accounts[1].stored);
    assert_eq!(
        store
            .import_legacy(&legacy, true)
            .unwrap()
            .current
            .as_deref(),
        Some("B")
    );
    file(&store.storage.paths.active().join("Cookie"), "live-A");
    // A is a first-save only when state is absent; imported B remains current and does not overwrite it.
    assert_eq!(store.status().unwrap().current.as_deref(), Some("B"));
    let result = store.switch("B", &config(), false).unwrap();
    assert_eq!(result.current, "B");
    assert_eq!(
        fs::read_to_string(store.profile_path("B").unwrap().join("Cookie")).unwrap(),
        "B"
    );
}

#[test]
fn rejects_symlink_and_failed_launch_recovers_original_profile() {
    let f = Fixture::new();
    let storage = f.storage();
    file(&storage.paths.active().join("Cookie"), "A");
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/B/Cookie"), "B");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.import_legacy(&legacy, true).unwrap();
    symlink("Cookie", store.storage.paths.active().join("link")).unwrap();
    assert_eq!(
        store.switch("B", &config(), false).unwrap_err().code,
        "unsupported_account_entry"
    );
    fs::remove_file(store.storage.paths.active().join("link")).unwrap();
    store.os.launch_fails = true;
    assert_eq!(
        store.switch("B", &config(), false).unwrap_err().code,
        "launch_failed"
    );
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "A"
    );
    assert!(!store.storage.paths.journal().exists());
}

#[test]
fn compatibility_and_preflight_fail_before_snapshot_or_quit() {
    let f = Fixture::new();
    let storage = f.storage();
    file(&storage.paths.active().join("Cookie"), "A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    assert_eq!(
        store
            .switch("A", &Config::default(), false)
            .unwrap_err()
            .code,
        "account_compatibility_unverified"
    );
    assert!(!store.storage.paths.accounts().join("A").exists());
    assert_eq!(store.os.quits, 0);
    store.os.fail_preflight = true;
    assert_eq!(
        store.switch("A", &config(), false).unwrap_err().code,
        "preflight_failed"
    );
    assert!(!store.storage.paths.accounts().join("A").exists());
    assert_eq!(store.os.quits, 0);
}

#[test]
fn first_save_quits_before_copy_relaunches_a_and_can_initialize_b() {
    let f = Fixture::new();
    let storage = f.storage();
    file(&storage.paths.active().join("Cookie"), "live-A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: true,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    // Fake clone_file rejects a running source, so success proves quit happened
    // before first-save copying; the successful operation also goes through launch.
    store.switch("A", &config(), false).unwrap();
    assert_eq!(store.os.quits, 1);
    assert!(store.os.running);
    assert_eq!(store.status().unwrap().current.as_deref(), Some("A"));
    assert_eq!(
        fs::read_to_string(store.profile_path("A").unwrap().join("Cookie")).unwrap(),
        "live-A"
    );
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "live-A"
    );

    let g = Fixture::new();
    let storage = g.storage();
    file(&storage.paths.active().join("Cookie"), "live-A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: true,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.switch("B", &config(), false).unwrap();
    assert_eq!(store.status().unwrap().current.as_deref(), Some("B"));
    assert!(!store.profile_path("B").unwrap().exists());
    assert_eq!(
        fs::read_to_string(store.profile_path("A").unwrap().join("Cookie")).unwrap(),
        "live-A"
    );
    assert!(fs::read_dir(store.storage.paths.active())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn initialized_same_target_needs_no_version_ack_and_first_save_rollback_removes_new_state() {
    let f = Fixture::new();
    let storage = f.storage();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/A/Cookie"), "A");
    file(&legacy.join("current"), "A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.import_legacy(&legacy, true).unwrap();
    assert_eq!(
        store
            .switch("A", &Config::default(), false)
            .unwrap()
            .current,
        "A"
    );
    assert_eq!(store.os.quits, 0);

    let g = Fixture::new();
    let storage = g.storage();
    file(&storage.paths.active().join("Cookie"), "A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: Some("installed"),
            quits: 0,
        },
    );
    assert_eq!(
        store.switch("A", &config(), false).unwrap_err().code,
        "stage_failed"
    );
    assert!(!store.storage.paths.base().join("accounts.json").exists());
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "A"
    );
}

#[test]
fn schema_three_recovery_refuses_external_state_rewrite() {
    let f = Fixture::new();
    let storage = f.storage();
    storage.initialize().unwrap();
    let token = "0123456789abcdef0123456789abcdef";
    let work = storage
        .paths
        .accounts()
        .join(format!(".transaction-{token}"));
    file(&storage.paths.active().join("Cookie"), "new");
    file(&work.join("previous-active/Cookie"), "old");
    storage
        .atomic_json(
            &storage.paths.base().join("accounts.json"),
            &serde_json::json!({"schema":1,"current":"B"}),
        )
        .unwrap();
    storage
        .atomic_json(
            &storage.paths.journal(),
            &serde_json::json!({"schema":3,"token":token,"phase":"installed","target":"B",
                "workspace":work,"previous":{"schema":1,"current":"A"},"state_existed":true,
                "records":{"active_before":null,"slot_before":null,"slot":null}}),
        )
        .unwrap();
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    assert_eq!(store.recover().unwrap_err().code, "recovery_conflict");
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "new"
    );
    assert!(store.storage.paths.journal().exists());
}

#[test]
fn transaction_stage_failures_restore_active_and_remove_journal() {
    for stage in [
        "prepared",
        "old_moved",
        "installed",
        "launched",
        "archived",
        "committed",
    ] {
        let f = Fixture::new();
        let storage = f.storage();
        file(&storage.paths.active().join("Cookie"), "A");
        let legacy = f.home.join(".claude-switcher");
        file(&legacy.join("accounts/B/Cookie"), "B");
        let mut store = AccountStore::new(
            storage,
            Fake {
                running: false,
                launch_fails: false,
                clones: 0,
                fail_preflight: false,
                fail_stage: Some(stage),
                quits: 0,
            },
        );
        store.import_legacy(&legacy, true).unwrap();
        let error = store.switch("B", &config(), false).unwrap_err();
        assert_eq!(error.code, "stage_failed", "{stage}");
        assert_eq!(
            fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
            if stage == "committed" { "B" } else { "A" },
            "{stage}"
        );
        assert!(!store.storage.paths.journal().exists(), "{stage}");
    }
}

#[test]
fn status_is_read_only_and_legacy_journals_reject_redirects() {
    let f = Fixture::new();
    let store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    let value = store.status().unwrap().value();
    assert_eq!(value["login_verified"], false);
    assert!(!store.storage.paths.accounts().exists());
    // A malformed old record must not make recovery follow its supplied paths.
    store.storage.initialize().unwrap();
    store.storage.atomic_json(&store.storage.paths.journal(),&serde_json::json!({"schema":1,"token":"0123456789abcdef0123456789abcdef","stage":"/tmp/no","old":"/tmp/no","previous":{"current":"A"}})).unwrap();
    let mut store = store;
    assert_eq!(store.recover().unwrap_err().code, "invalid_journal");
}

#[test]
fn schema_one_two_and_three_recovery_shapes_are_bounded() {
    for schema in [1, 2] {
        let f = Fixture::new();
        let storage = f.storage();
        storage.initialize().unwrap();
        let token = "0123456789abcdef0123456789abcdef";
        let parent = storage.paths.active().parent().unwrap().to_path_buf();
        file(&storage.paths.active().join("Cookie"), "new");
        file(
            &parent
                .join(format!(".claude-watch-old-{token}"))
                .join("Cookie"),
            "old",
        );
        storage.atomic_json(&storage.paths.journal(),&serde_json::json!({"schema":schema,"token":token,"stage":parent.join(format!(".claude-watch-stage-{token}")),"old":parent.join(format!(".claude-watch-old-{token}")),"previous":{"current":"A"},"phase":"installed"})).unwrap();
        let mut store = AccountStore::new(
            storage,
            Fake {
                running: false,
                launch_fails: false,
                clones: 0,
                fail_preflight: false,
                fail_stage: None,
                quits: 0,
            },
        );
        store.recover().unwrap();
        assert_eq!(
            fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
            "old"
        );
        assert!(store
            .storage
            .paths
            .accounts()
            .join(format!("recovered-{token}"))
            .is_dir());
    }
    let f = Fixture::new();
    let storage = f.storage();
    storage.initialize().unwrap();
    let token = "fedcba9876543210fedcba9876543210";
    let work = storage
        .paths
        .accounts()
        .join(format!(".transaction-{token}"));
    file(&storage.paths.active().join("Cookie"), "new");
    file(&work.join("previous-active/Cookie"), "old");
    storage.atomic_json(&storage.paths.journal(),&serde_json::json!({"schema":3,"token":token,"previous":{"current":"A"},"phase":"installed"})).unwrap();
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.recover().unwrap();
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "old"
    );
}

#[test]
fn import_conflicts_and_nested_legacy_links_do_not_publish_partial_slots() {
    let f = Fixture::new();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/A/nested/data"), "A");
    symlink("data", legacy.join("accounts/A/nested/link")).unwrap();
    let mut store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    assert_eq!(
        store.import_legacy(&legacy, true).unwrap_err().code,
        "unsupported_account_entry"
    );
    assert!(!store.storage.paths.accounts().join("A").exists());
    fs::remove_file(legacy.join("accounts/A/nested/link")).unwrap();
    store.import_legacy(&legacy, true).unwrap();
    assert_eq!(
        store.import_legacy(&legacy, true).unwrap_err().code,
        "import_conflict"
    );
}

#[test]
fn same_target_idempotence_intercepted_on_external_switcher_conflict() {
    let f = Fixture::new();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/A/Cookie"), "A-data");
    file(&legacy.join("accounts/B/Cookie"), "B-data");
    file(&legacy.join("current"), "A");

    let mut store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    // Initial import: sets Watch current to A and anchors ~/.claude-switcher/current
    store.import_legacy(&legacy, true).unwrap();
    assert_eq!(store.status().unwrap().current.as_deref(), Some("A"));
    assert_eq!(store.status().unwrap().legacy_conflict, None);

    // Simulate upstream switcher switching to B outside of Watch
    file(&legacy.join("current"), "B");

    // Requesting switch to "A" (target == Watch current) must NOT short-circuit
    // with Ok("A"). It MUST detect the split brain and return external_switcher_conflict.
    let err = store.switch("A", &config(), false).unwrap_err();
    assert_eq!(err.code, "external_switcher_conflict");

    // Status also reflects the conflict in read-only diagnostics
    let status = store.status().unwrap();
    let conflict = status.legacy_conflict.expect("should have conflict");
    assert_eq!(conflict["code"], "external_switcher_conflict");
    assert_eq!(conflict["watch_current"], "A");
    assert_eq!(conflict["legacy_current"], "B");
}

#[test]
fn aba_roundtrip_switch_is_intercepted_by_mtime_anchor() {
    let f = Fixture::new();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/A/Cookie"), "A-data");
    file(&legacy.join("accounts/B/Cookie"), "B-data");
    file(&legacy.join("current"), "A");

    let mut store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.import_legacy(&legacy, true).unwrap();
    assert_eq!(store.status().unwrap().current.as_deref(), Some("A"));
    assert_eq!(store.status().unwrap().legacy_conflict, None);

    // Live profile exists
    file(&store.storage.paths.active().join("Cookie"), "live-A");

    // Now simulate upstream switcher executing A -> B -> A round-trip:
    // ~/.claude-switcher/current content is still "A", but the file is rewritten!
    std::thread::sleep(std::time::Duration::from_millis(50));
    fs::remove_file(legacy.join("current")).unwrap();
    file(&legacy.join("current"), "A");

    // Attempting to switch to B should detect that ~/.claude-switcher/current was modified externally
    let err = store.switch("B", &config(), false).unwrap_err();
    assert_eq!(err.code, "external_switcher_conflict");
}

#[test]
fn external_lock_and_custom_slot_conflict() {
    let f = Fixture::new();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/A/Cookie"), "A-data");
    file(&legacy.join("accounts/B/Cookie"), "B-data");
    file(&legacy.join("current"), "A");

    let mut store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.import_legacy(&legacy, true).unwrap();

    // 1. External lock file blocks switch
    file(&legacy.join("cli-operation.lock"), "busy");
    let err = store.switch("B", &config(), false).unwrap_err();
    assert_eq!(err.code, "external_switcher_locked");
    assert_eq!(
        store.status().unwrap().legacy_conflict.unwrap()["code"],
        "external_switcher_locked"
    );
    fs::remove_file(legacy.join("cli-operation.lock")).unwrap();

    // 2. Upstream custom slot "C" (not A or B) blocks switch
    file(&legacy.join("current"), "C");
    let err = store.switch("B", &config(), false).unwrap_err();
    assert_eq!(err.code, "external_switcher_conflict");
    let conflict = store.status().unwrap().legacy_conflict.unwrap();
    assert_eq!(conflict["code"], "external_switcher_conflict");
    assert_eq!(conflict["legacy_current"], "C");
}

#[test]
fn consecutive_watch_switches_do_not_self_deadlock_when_legacy_is_idle() {
    let f = Fixture::new();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/A/Cookie"), "A-data");
    file(&legacy.join("accounts/B/Cookie"), "B-data");
    file(&legacy.join("current"), "A");

    let mut store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.import_legacy(&legacy, true).unwrap();
    file(&store.storage.paths.active().join("Cookie"), "live-A");

    // 1. Watch switches A -> B while ~/.claude-switcher/current remains "A" untouched
    assert_eq!(store.switch("B", &config(), false).unwrap().current, "B");
    store.os.running = false;
    assert_eq!(store.status().unwrap().legacy_conflict, None);

    // 2. Idempotent switch to B succeeds
    assert_eq!(store.switch("B", &config(), false).unwrap().current, "B");

    // 3. Consecutive Watch switch B -> A succeeds without false SplitBrainConflict
    assert_eq!(store.switch("A", &config(), false).unwrap().current, "A");
    store.os.running = false;
    assert_eq!(store.status().unwrap().legacy_conflict, None);

    // 4. Wholesale external replacement of active directory while idle is blocked
    let active = store.storage.paths.active();
    fs::remove_dir_all(&active).unwrap();
    file(&active.join("Cookie"), "foreign-profile");
    assert_eq!(
        store.switch("B", &config(), false).unwrap_err().code,
        "external_change"
    );
    assert_eq!(
        store.status().unwrap().legacy_conflict.unwrap()["code"],
        "external_change"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn switch_and_manual_save_use_native_clonefile_without_sharing_mutations() {
    use std::os::unix::fs::MetadataExt;

    struct NativeCloneOs {
        running: bool,
    }
    impl AccountOs for NativeCloneOs {
        fn current_desktop(&mut self) -> Result<claude_watch_core::processes::Identity> {
            Ok(claude_watch_core::processes::Identity {
                executable: "/Applications/Claude.app/Contents/MacOS/Claude".into(),
                pid: 41,
                start_seconds: 100,
                start_microseconds: 12,
                uid: 501,
                parent: 1,
                start_stamp: String::new(),
            })
        }
        fn claude_version(&mut self) -> Result<Option<String>> {
            Ok(Some("1.0".into()))
        }
        fn quit_claude(&mut self) -> Result<()> {
            self.running = false;
            Ok(())
        }
        fn claude_running(&mut self) -> Result<bool> {
            Ok(self.running)
        }
        fn launch_claude(&mut self) -> Result<()> {
            self.running = true;
            Ok(())
        }
        fn preflight(&mut self) -> Result<()> {
            Ok(())
        }
        fn clone_file(&mut self, source: &Path, target: &Path) -> Result<bool> {
            claude_watch_runtime::accounts::clone_regular_file(source, target)
        }
    }

    let f = Fixture::new();
    let mut store = AccountStore::new(f.storage(), NativeCloneOs { running: false });
    let active_cookie = store.storage.paths.active().join("Cookies");
    file(&active_cookie, "account-a-initial");

    // 1. Switch A -> B archives live A using native APFS clonefile.
    let switched = store.switch("B", &config(), false).unwrap();
    assert_eq!(switched.current, "B");
    assert_eq!(switched.copied.len(), 1);
    assert_eq!(switched.copied[0].strategy, "clone");
    assert_eq!(switched.copied[0].cloned_files, 1);
    assert_eq!(switched.copied[0].copied_files, 0);

    // 2. Manual save of B uses native clonefile and keeps COW isolation.
    file(&active_cookie, "account-b-live");
    let source = store.current_source().unwrap();
    let saved = store
        .save_current(
            "B",
            &claude_watch_runtime::accounts::SaveCurrentAccount {
                source_token: source["source_token"].as_str().unwrap().to_owned(),
                account_label: "b@example.invalid".into(),
            },
        )
        .unwrap();
    assert_eq!(saved["saved"], true);

    let slot_b_cookie = store.profile_path("B").unwrap().join("Cookies");
    assert_ne!(
        fs::symlink_metadata(&active_cookie).unwrap().ino(),
        fs::symlink_metadata(&slot_b_cookie).unwrap().ino()
    );
    file(&active_cookie, "account-b-mutated-later");
    assert_eq!(fs::read_to_string(&slot_b_cookie).unwrap(), "account-b-live");

    // 3. Switch back B -> A clones both archived A into active and live B into archive.
    let back = store.switch("A", &config(), false).unwrap();
    assert_eq!(back.current, "A");
    assert_eq!(back.copied.len(), 2);
    assert!(back.copied.iter().all(|m| m.strategy == "clone" && m.cloned_files == 1 && m.copied_files == 0));
    assert_eq!(fs::read_to_string(&active_cookie).unwrap(), "account-a-initial");
}
