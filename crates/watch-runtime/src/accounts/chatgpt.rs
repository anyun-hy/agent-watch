//! The unified ChatGPT desktop client can start with its own Electron data and
//! app-server home. A/B bindings identify complete profiles and their publicly
//! reported account labels. Session data stays in the original profile.
pub mod identity;
mod login;

use crate::{commands::ReadRunner, native::Observer, storage::StateStore};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::Identity,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::PathBuf, process::Command};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            Some("A") => Ok(Self::A),
            Some("B") => Ok(Self::B),
            _ => Err(CoreError::new(
                "invalid_account",
                "请选择 ChatGPT 账号 A 或 B",
            )),
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }
    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
    fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Selection {
    schema: u8,
    pub(crate) slot: Slot,
    pub(crate) process: Identity,
    // v1 used the slot name as its physical profile. v2 permits naming the
    // existing profile on the first manual save, without touching its files.
    #[serde(default)]
    profile: Option<Slot>,
    #[serde(default)]
    labels: [Option<String>; 2],
}

fn state_path(store: &StateStore) -> PathBuf {
    account_root(store).join("slots.json")
}

impl Selection {
    pub(crate) fn profile(&self) -> Slot {
        self.profile.unwrap_or(self.slot)
    }
    fn physical_slot(&self, name: Slot) -> Slot {
        if self.slot == name {
            self.profile()
        } else {
            self.profile().other()
        }
    }
}

pub(crate) fn selection(store: &StateStore) -> Result<Option<Selection>> {
    let bytes = match store.read_bytes(&state_path(store), 32 * 1024)? {
        Some(value) => value,
        None => {
            let legacy = store.paths.base().join("chatgpt-account.json");
            let Some(value) = store.read_bytes(&legacy, 32 * 1024)? else {
                return Ok(None);
            };
            value
        }
    };
    let invalid = || {
        CoreError::new(
            "chatgpt_account_state_invalid",
            "ChatGPT 桌面账号记录无法读取",
        )
    };
    let value: Selection =
        serde_json::from_value(crate::storage::strict_json(&bytes)?).map_err(|_| invalid())?;
    if !matches!((value.schema, value.profile), (1, None) | (2, Some(_)))
        || !value.process.valid()
        || value.labels.iter().flatten().any(|label| {
            label.is_empty() || label.len() > 320 || label.chars().any(char::is_control)
        })
    {
        return Err(invalid());
    }
    Ok(Some(value))
}

pub(crate) fn record(store: &StateStore, slot: Slot, process: &Identity) -> Result<()> {
    let previous = selection(store)?;
    let profile = previous.as_ref().map_or(slot, |s| s.physical_slot(slot));
    write_selection(
        store,
        &Selection {
            schema: 2,
            slot,
            process: process.clone(),
            profile: Some(profile),
            labels: previous.map(|s| s.labels).unwrap_or_default(),
        },
    )
}

fn write_selection(store: &StateStore, selection: &Selection) -> Result<()> {
    store.private_dir(&account_root(store))?;
    store.atomic_json(&state_path(store), &json!(selection))
}

fn account_root(store: &StateStore) -> PathBuf {
    store
        .paths
        .home
        .join("Library/Application Support/Claude Watch Accounts/ChatGPT")
}

fn secondary_root(store: &StateStore) -> PathBuf {
    // This is application login data. A Watch reinstall resets its own switcher
    // settings, not either desktop account's data.
    account_root(store).join("B")
}

pub struct Profile {
    slot: Slot,
    secondary_root: PathBuf,
}

impl Profile {
    pub(crate) fn prepare(store: &StateStore, slot: Slot) -> Result<Self> {
        let slot = selection(store)?.map_or(slot, |s| s.physical_slot(slot));
        let secondary_root = secondary_root(store);
        if slot == Slot::B {
            store.private_dir(&secondary_root.join("codex"))?;
            store.private_dir(&secondary_root.join("user-data"))?;
        }
        Ok(Self {
            slot,
            secondary_root,
        })
    }

    pub(crate) fn configure(&self, launcher: &mut Command, arguments: &mut Vec<String>) {
        match self.slot {
            Slot::A => {
                // Start ChatGPT with its normal Desktop/Dock defaults.
                launcher
                    .env_remove("CODEX_HOME")
                    .env_remove("CODEX_ELECTRON_USER_DATA_PATH");
            }
            Slot::B => {
                let user_data = self.secondary_root.join("user-data");
                launcher
                    .env("CODEX_HOME", self.secondary_root.join("codex"))
                    .env("CODEX_ELECTRON_USER_DATA_PATH", &user_data);
                arguments.push(format!("--user-data-dir={}", user_data.display()));
            }
        }
    }
}

pub fn status<R: ReadRunner>(store: &StateStore, runner: &R) -> Result<Value> {
    status_receipt(store, runner, None)
}

fn status_receipt<R: ReadRunner>(
    store: &StateStore,
    runner: &R,
    login: Option<&[login::Reading]>,
) -> Result<Value> {
    let selection = selection(store)?;
    let selected = selection.as_ref().map(|saved| saved.slot);
    // Recheck the same libproc identity used to admit the desktop root at launch.
    // Its last confirmed profile remains selected after the process exits.
    let current = selection
        .as_ref()
        .filter(|saved| process_is_live(runner, &saved.process))
        .map(|saved| saved.slot);
    let accounts = [Slot::A, Slot::B].map(|slot| {
        let physical = selection.as_ref().map_or(slot, |s| s.physical_slot(slot));
        let label = selection
            .as_ref()
            .and_then(|s| s.labels[slot.index()].as_deref());
        let mut row = login::slot_info(
            store,
            physical,
            current == Some(slot),
            login.unwrap_or_default(),
        );
        row["id"] = json!(slot);
        row["saved"] = json!(label.is_some());
        row["account_label"] = json!(label);
        row
    });
    Ok(
        json!({"schema":1, "product":"chatgpt", "selected": selected, "current": current, "recovery_required":false,
        "login_checked":login.is_some(), "accounts":accounts,
        "detail":"两个槽位分别打开自己的桌面资料。登录后可读取当前账号并保存到槽位。"}),
    )
}

/// An explicit account-page read may consult the selected desktop client's
/// local sign-in provider. The monitor's regular status path never starts it.
pub fn status_with_login<R: ReadRunner>(store: &StateStore, runner: &R) -> Result<Value> {
    let readings = login::check_slots(store, runner);
    // Check process identity and directory identities after the slower provider reads.
    status_receipt(store, runner, Some(&readings))
}

fn process_is_live<R: ReadRunner>(runner: &R, process: &Identity) -> bool {
    let round = uuid::Uuid::new_v4().to_string();
    Observer { runner }
        .identities(std::slice::from_ref(process), &round)
        .is_ok_and(|live| live.contains_key(&process.pid))
}

fn directory_has_data(store: &StateStore, path: &std::path::Path) -> Result<bool> {
    let path = store.guarded(path)?;
    match std::fs::read_dir(path) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(CoreError::new(
            "chatgpt_profile_unreadable",
            "无法核对目标槽位已有的桌面资料",
        )),
    }
}

fn old_profile_occupied(store: &StateStore, physical: Slot) -> Result<bool> {
    // Older versions created these profiles before explicit saves existed.
    // Even an unsigned-in profile can contain history and preferences.
    let directories = match physical {
        Slot::A => vec![
            store.paths.home.join(".codex"),
            store.paths.home.join("Library/Application Support/ChatGPT"),
            store.paths.home.join("Library/Application Support/Codex"),
        ],
        Slot::B => vec![
            secondary_root(store).join("codex"),
            secondary_root(store).join("user-data"),
        ],
    };
    for path in directories {
        if directory_has_data(store, &path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn save<R: ReadRunner>(
    store: &StateStore,
    runner: &R,
    destination: Slot,
    token: &str,
) -> Result<Value> {
    save_verified(store, runner, destination, token, identity::read)
}

fn save_verified<R: ReadRunner>(
    store: &StateStore,
    runner: &R,
    destination: Slot,
    token: &str,
    read: impl FnOnce(&StateStore, &R) -> Result<Value>,
) -> Result<Value> {
    let changed = || {
        CoreError::new(
            "chatgpt_source_changed",
            "当前 ChatGPT 账号或桌面实例已变化，请重新读取账号",
        )
    };
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(changed());
    }
    let _operation = store.lock("operation", None)?;
    let _launch = store.lock("launch", None)?;
    let receipt = read(store, runner)?;
    if receipt["state"] != "logged_in" || receipt["source_token"].as_str() != Some(token) {
        return Err(changed());
    }
    let physical = Slot::parse(receipt["profile"].as_str()).map_err(|_| changed())?;
    let process: Identity =
        serde_json::from_value(receipt["process"].clone()).map_err(|_| changed())?;
    let email = receipt["email"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 320 && !s.chars().any(char::is_control))
        .ok_or_else(changed)?;
    let previous = selection(store)?;
    // Each of the two logical slots opens one complete physical profile.
    // The mapping is a permutation, so its inverse uses the same lookup.
    let source = previous
        .as_ref()
        .map_or(physical, |s| s.physical_slot(physical));
    if receipt["slot"] != source.label() {
        return Err(changed());
    }
    let mut labels = previous.map(|s| s.labels).unwrap_or_default();
    let occupied = || {
        CoreError::new(
            "chatgpt_slot_occupied",
            &format!(
                "槽位 {} 已有其他账号或桌面资料，请保留该槽位并选择原槽位保存。",
                destination.label()
            ),
        )
    };
    if source != destination {
        if labels[destination.index()].is_some() || old_profile_occupied(store, physical.other())? {
            return Err(occupied());
        }
        if labels[source.index()]
            .as_ref()
            .is_some_and(|old| !old.eq_ignore_ascii_case(email))
        {
            return Err(CoreError::new(
                "chatgpt_saved_identity_changed",
                "当前资料登录的账号与原槽位已保存的账号不同，请核对后再保存。",
            ));
        }
        labels[source.index()] = None;
    } else if labels[destination.index()]
        .as_ref()
        .is_some_and(|old| !old.eq_ignore_ascii_case(email))
    {
        return Err(occupied());
    }
    if !process_is_live(runner, &process) {
        return Err(changed());
    }
    labels[destination.index()] = Some(email.to_owned());
    write_selection(
        store,
        &Selection {
            schema: 2,
            slot: destination,
            process,
            profile: Some(physical),
            labels,
        },
    )?;
    let message = if source == destination {
        format!("当前 ChatGPT 账号已保存到槽位 {}。", destination.label())
    } else {
        format!(
            "当前 ChatGPT 账号已保存到槽位 {}，槽位 {} 可用于另一个账号。",
            destination.label(),
            source.label()
        )
    };
    Ok(
        json!({"status":"ok","product":"chatgpt","account":destination,"saved":true,"current":destination,
        "selected":destination,"account_label":email,"message":message}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    struct LiveProcess(Identity);
    impl ReadRunner for LiveProcess {
        fn run(
            &self,
            cmd: crate::commands::ReadCommand,
            bytes: &[u8],
            _: std::time::Duration,
            _: usize,
        ) -> Result<crate::commands::Output> {
            use crate::commands::{ObserverAction, Output, ReadCommand};
            assert!(matches!(
                cmd,
                ReadCommand::Observer(ObserverAction::Identities)
            ));
            let input: Value = serde_json::from_slice(bytes).unwrap();
            let now = crate::native::now();
            let response = json!({"schema":1,"status":"ok","uid":self.0.uid,"round_id":input["round_id"],
                "started_at":now,"finished_at":now,"identities":[{"pid":input["targets"][0]["pid"],"state":"ok","identity":self.0}]});
            Ok(Output {
                status: 0,
                stdout: serde_json::to_vec(&response).unwrap(),
                stderr: vec![],
            })
        }
    }

    #[test]
    fn chatgpt_account_save_binds_verified_original_to_b_and_preserves_both_launch_profiles() {
        let home = std::env::temp_dir().join(format!("cw-chatgpt-bind-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        let process = Identity {
            pid: 100,
            parent: 1,
            uid: 501,
            executable: "/fixture/ChatGPT".into(),
            start_seconds: 201,
            start_microseconds: 98,
            start_stamp: "201.000098".into(),
        };
        let live = LiveProcess(process.clone());
        let token = "c".repeat(64);
        let mut verified = json!({"state":"logged_in","email":"first@example.invalid","slot":"A","profile":"A",
            "process":process,"source_token":token});
        // Existing releases picked A automatically. That record is not an explicit save.
        let legacy = store.paths.base().join("chatgpt-account.json");
        store
            .atomic_json(&legacy, &json!({"schema":1,"slot":"A","process":process}))
            .unwrap();
        let original = home.join(".codex");
        fs::create_dir(&original).unwrap();
        fs::write(original.join("fixture"), "original session").unwrap();
        let secondary = secondary_root(&store).join("user-data");
        store.private_dir(&secondary).unwrap();
        fs::write(secondary.join("fixture"), "old B data").unwrap();

        let original_save = |runner: &LiveProcess, input: &str| {
            save_verified(&store, runner, Slot::B, input, |_, _| Ok(verified.clone()))
        };
        assert_eq!(
            original_save(&live, &"a".repeat(64)).unwrap_err().code,
            "chatgpt_source_changed"
        );
        assert_eq!(
            original_save(&live, &token).unwrap_err().code,
            "chatgpt_slot_occupied"
        );
        assert_eq!(
            fs::read_to_string(secondary.join("fixture")).unwrap(),
            "old B data"
        );
        fs::remove_file(secondary.join("fixture")).unwrap();
        let mut changed = process.clone();
        changed.start_microseconds += 1;
        assert_eq!(
            original_save(&LiveProcess(changed), &token)
                .unwrap_err()
                .code,
            "chatgpt_source_changed"
        );
        let switch_lock = store.lock("launch", None).unwrap();
        assert_eq!(original_save(&live, &token).unwrap_err().code, "busy");
        drop(switch_lock);
        assert!(!state_path(&store).exists());
        let receipt = original_save(&live, &token).unwrap();
        assert_eq!(receipt["saved"], true);
        assert_eq!(receipt["current"], "B");
        let status = status(&store, &live).unwrap();
        assert_eq!(status["accounts"][0]["saved"], false);
        assert_eq!(
            status["accounts"][1]["account_label"],
            "first@example.invalid"
        );
        assert_eq!(status["accounts"][1]["current"], true);
        let fresh = Profile::prepare(&store, Slot::A).unwrap();
        assert_eq!(fresh.slot, Slot::B);
        let preserved = Profile::prepare(&store, Slot::B).unwrap();
        assert_eq!(preserved.slot, Slot::A);
        assert_eq!(
            fs::read_to_string(original.join("fixture")).unwrap(),
            "original session"
        );

        record(&store, Slot::A, &process).unwrap();
        verified["slot"] = json!("A");
        verified["profile"] = json!("B");
        verified["email"] = json!("second@example.invalid");
        assert_eq!(
            save_verified(&store, &live, Slot::B, &token, |_, _| Ok(verified.clone()))
                .unwrap_err()
                .code,
            "chatgpt_slot_occupied"
        );
        save_verified(&store, &live, Slot::A, &token, |_, _| Ok(verified)).unwrap();
        record(&store, Slot::B, &process).unwrap();
        let status = super::status(&store, &live).unwrap();
        assert_eq!(
            status["accounts"][0]["account_label"],
            "second@example.invalid"
        );
        assert_eq!(
            status["accounts"][1]["account_label"],
            "first@example.invalid"
        );
        assert_eq!(selection(&store).unwrap().unwrap().profile(), Slot::A);
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn chatgpt_account_profiles_keep_original_and_secondary_sessions_separate() {
        let home =
            std::env::temp_dir().join(format!("cw-chatgpt-profiles-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        let original = store.paths.home.join(".codex");
        fs::create_dir(&original).unwrap();
        fs::write(original.join("fixture-session"), b"original").unwrap();

        let separate = secondary_root(&store);
        for slot in [Slot::B, Slot::A, Slot::B] {
            let profile = Profile::prepare(&store, slot).unwrap();
            let mut child = Command::new("/unused/fixture");
            let mut args = vec![];
            profile.configure(&mut child, &mut args);
            let env: std::collections::BTreeMap<_, _> = child
                .get_envs()
                .map(|(key, value)| (key.to_str().unwrap(), value.map(PathBuf::from)))
                .collect();
            if slot == Slot::B {
                let data = separate.join("user-data");
                let backend = separate.join("codex");
                assert_eq!(env["CODEX_ELECTRON_USER_DATA_PATH"], Some(data.clone()));
                assert_eq!(env["CODEX_HOME"], Some(backend.clone()));
                assert_eq!(args, [format!("--user-data-dir={}", data.display())]);
                assert_eq!(
                    fs::metadata(&backend).unwrap().permissions().mode() & 0o777,
                    0o700
                );
                let marker = backend.join("fixture-session");
                if !marker.exists() {
                    fs::write(&marker, b"secondary").unwrap();
                }
                assert_eq!(fs::read(marker).unwrap(), b"secondary");
            } else {
                assert!(
                    env["CODEX_HOME"].is_none() && env["CODEX_ELECTRON_USER_DATA_PATH"].is_none()
                );
                assert!(args.is_empty());
            }
            assert_eq!(
                fs::read(original.join("fixture-session")).unwrap(),
                b"original"
            );
        }
        fs::rename(separate.join("codex"), separate.join("saved-test-home")).unwrap();
        symlink(&original, separate.join("codex")).unwrap();
        assert!(Profile::prepare(&store, Slot::B).is_err());
        fs::remove_dir_all(home).unwrap();
    }
}
