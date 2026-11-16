//! Process-identity leases and restart-safe observation history.
//! These records classify observations; they never authorize a desktop launch.
use crate::storage::StateStore;
use claude_watch_core::{
    error::{CoreError, Result},
    processes::{self, Identity, Kind, Lease, Provider, Target},
    session::Desktop,
};
use serde_json::json;
use std::{collections::BTreeMap, fs, path::PathBuf};

pub struct LeaseStore {
    pub storage: StateStore,
}
impl LeaseStore {
    /// The lease record names the supervised service, parsed back by the
    /// lease store's provider table.
    pub fn save_desktop(
        &self,
        desktop: &Desktop,
        stamp: &str,
        now: f64,
        provider: Provider,
    ) -> Result<()> {
        let _lock = self.storage.lock("leases", None)?;
        self.write_desktop(desktop, stamp, now, provider)
    }
    fn write_desktop(&self, desktop: &Desktop, stamp: &str, now: f64, provider: Provider) -> Result<()> {
        if stamp.contains(['|', '\n', '\r']) || stamp.is_empty() {
            return Err(CoreError::new(
                "desktop_identity_unavailable",
                "主进程启动时间未能确认",
            ));
        }
        let name = match provider {
            Provider::Claude => "claude",
            Provider::Codex => "codex",
            Provider::Chatgpt => "chatgpt",
            Provider::Openai => "openai",
        };
        let path = self.desktop_path(desktop.pid);
        self.storage.atomic_bytes(
            &path,
            format!(
                "desktop|{name}|{}|{}|0|-|{}\n",
                desktop.pid,
                stamp,
                now.floor()
            )
            .as_bytes(),
            0o600,
        )
    }

    fn desktop_path(&self, pid: u32) -> PathBuf {
        self.directory().join(format!("rust-{pid}.session"))
    }
    /// Keep lease replacement and rollback under one lock through session commit.
    /// The caller retains its operation/session locks; this Store owns lease files.
    pub(crate) fn commit_desktops<T>(&self, bindings: &[(Desktop, String)], now: f64, provider: Provider,
        commit: impl FnOnce() -> Result<T>) -> Result<T> {
        let _lock = self.storage.lock("leases", None)?;
        let previous: Vec<_> = bindings.iter().map(|(desktop, _)| {
            let path = self.desktop_path(desktop.pid);
            self.storage.read_bytes(&path, 16 * 1024).map(|bytes| (path, bytes))
        }).collect::<Result<_>>()?;
        let result = (|| {
            for (desktop, stamp) in bindings { self.write_desktop(desktop, stamp, now, provider)?; }
            commit()
        })();
        if result.is_err() {
            let mut failed = false;
            for (path, old) in previous {
                let restored = match old {
                    Some(bytes) => self.storage.atomic_bytes(&path, &bytes, 0o600),
                    None => self.storage.guarded(&path).and_then(|path| match fs::remove_file(path) {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(_) => Err(CoreError::new("revalidation_lease_rollback_failed", "观察记录撤销失败")),
                    }),
                };
                failed |= restored.is_err();
            }
            if failed { return Err(CoreError::new("revalidation_lease_rollback_failed", "观察记录未全部恢复")); }
        }
        result
    }

    pub fn save_cli(&self, provider: Provider, owner: &Identity, created: f64) -> Result<CliLease> {
        let id = self.save(
            &Lease {
                provider,
                root: owner.clone(),
                owner: Some(owner.clone()),
                cli: true,
            },
            created,
        )?;
        Ok(CliLease {
            storage: self.storage.clone(),
            id,
            owner: owner.clone(),
            provider,
            active: true,
        })
    }
    fn remove_cli(&self, id: &str, owner: &Identity, provider: Provider) -> Result<()> {
        if id.len() != 32 || !id.bytes().all(|v| v.is_ascii_hexdigit()) {
            return Err(CoreError::new("invalid_lease", "观察记录编号无效"));
        }
        let _lock = self.storage.lock("leases", None)?;
        let path = self.directory().join(format!("{id}.json"));
        let Some(before) = self.storage.read_bytes(&path, 16384)? else {
            return Ok(());
        };
        let value = crate::storage::strict_json(&before)?;
        let lease: Lease = serde_json::from_value(value["lease"].clone())
            .map_err(|_| CoreError::new("invalid_lease", "观察记录损坏，未删除"))?;
        if lease.provider != provider
            || !lease.cli
            || !lease.root.same_process(owner)
            || !lease.owner.as_ref().is_some_and(|p| p.same_process(owner))
            || self.storage.read_bytes(&path, 16384)?.as_ref() != Some(&before)
        {
            return Err(CoreError::new(
                "lease_cleanup_conflict",
                "观察记录已被替换，未删除其他会话",
            ));
        }
        fs::remove_file(path)
            .map_err(|_| CoreError::new("lease_cleanup_failed", "本次观察记录无法清理"))
    }
    pub fn revoke_all(&self) -> Result<()> {
        let _lock = self.storage.lock("leases", None)?;
        let directory = self.directory();
        self.storage.guarded(&directory)?;
        let entries = match fs::read_dir(&directory) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(CoreError::new("lease_read_failed", "会话目录不可读取")),
        };
        for entry in entries {
            let path = entry
                .map_err(|_| CoreError::new("lease_read_failed", "会话记录不可读取"))?
                .path();
            if matches!(
                path.extension().and_then(|v| v.to_str()),
                Some("session" | "json")
            ) {
                self.storage.guarded(&path)?;
                if fs::symlink_metadata(&path)
                    .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
                {
                    fs::remove_file(&path)
                        .map_err(|_| CoreError::new("lease_revoke_failed", "会话关联无法撤销"))?;
                }
            }
        }
        Ok(())
    }
    fn directory(&self) -> PathBuf {
        self.storage.paths.watch().join("state/sessions")
    }
    pub fn save(&self, lease: &Lease, created: f64) -> Result<String> {
        if !lease.root.valid()
            || !created.is_finite()
            || created < 0.0
            || (lease.cli && !lease.owner.as_ref().is_some_and(Identity::valid))
        {
            return Err(CoreError::new("invalid_lease", "会话身份无效"));
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let _lock = self.storage.lock("leases", None)?;
        self.storage.atomic_json(
            &self.directory().join(format!("{id}.json")),
            &json!({"schema":1,"lease":lease,"created_at":created}),
        )?;
        Ok(id)
    }
    pub fn load(
        &self,
        inventory: &BTreeMap<u32, Identity>,
        uid: u32,
        complete: bool,
    ) -> Result<Vec<Lease>> {
        // Complete reads may delete stale records. Serialize them with every writer.
        let _lock = if complete { Some(self.storage.lock("leases", None)?) } else { None };
        let directory = self.directory();
        self.storage.guarded(&directory)?;
        let entries = match fs::read_dir(&directory) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(_) => return Err(CoreError::new("lease_read_failed", "会话目录不可读取")),
        };
        let mut leases = Vec::new();
        for (index, entry) in entries.enumerate() {
            if index >= 4096 {
                return Err(CoreError::new("lease_limit", "会话记录超过上限"));
            }
            let path = entry
                .map_err(|_| CoreError::new("lease_read_failed", "会话目录项不可读取"))?
                .path();
            let extension = path.extension().and_then(|v| v.to_str()).unwrap_or("");
            if !matches!(extension, "json" | "session") {
                continue;
            }
            let bytes = self.storage.read_bytes(&path, 16384)?.unwrap_or_default();
            let lease = if extension == "json" {
                let value = crate::storage::strict_json(&bytes)?;
                if value["schema"] != 1 {
                    return Err(CoreError::new("invalid_lease", "会话记录版本无效"));
                }
                serde_json::from_value::<Lease>(value["lease"].clone()).ok()
            } else {
                std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|text| legacy_lease(text, inventory, uid))
            };
            if let Some(lease) = lease.filter(|v| v.valid(inventory, uid)) {
                leases.push(lease);
            } else if complete {
                // Delete only the exact stale record read this round; preserve a
                // concurrent writer's replacement and all partially observed leases.
                if self.storage.read_bytes(&path, 16384)?.as_deref() == Some(bytes.as_slice()) {
                    fs::remove_file(&path).map_err(|_| {
                        CoreError::new("lease_cleanup_failed", "过期会话记录无法清理")
                    })?;
                }
            }
        }
        Ok(leases)
    }
    pub fn launcher_targets(leases: &[Lease]) -> Vec<Target> {
        leases
            .iter()
            .filter(|v| v.cli)
            .map(|lease| Target {
                identity: lease.root.clone(),
                kind: match lease.provider {
                    Provider::Claude => Kind::ClaudeLauncher,
                    Provider::Codex => Kind::CodexLauncher,
                    Provider::Chatgpt => Kind::ChatgptLauncher,
                    Provider::Openai => Kind::OpenaiLauncher,
                },
            })
            .collect()
    }
    pub fn tracked(&self) -> Result<Vec<Target>> {
        let value = self.storage.read_json(
            &self.storage.paths.watch().join("state/tracked-rust.json"),
            json!({"schema":1,"targets":[]}),
        )?;
        if value["schema"] != 1 {
            return Err(CoreError::new("invalid_tracked", "进程历史版本无效"));
        }
        let targets: Vec<Target> = serde_json::from_value(value["targets"].clone())
            .map_err(|_| CoreError::new("invalid_tracked", "进程历史格式无效"))?;
        if targets.len() > 65536 || targets.iter().any(|v| !v.identity.valid()) {
            return Err(CoreError::new("invalid_tracked", "进程历史身份无效"));
        }
        Ok(targets)
    }
    pub fn save_tracked(&self, targets: &[Target], complete: bool) -> Result<()> {
        if complete {
            let _lock = self.storage.lock("leases", None)?;
            self.storage.atomic_json(
                &self.storage.paths.watch().join("state/tracked-rust.json"),
                &json!({"schema":1,"targets":targets}),
            )?;
        }
        Ok(())
    }
}

pub struct CliLease {
    storage: StateStore,
    id: String,
    owner: Identity,
    provider: Provider,
    active: bool,
}
impl CliLease {
    pub fn clear(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        LeaseStore {
            storage: self.storage.clone(),
        }
        .remove_cli(&self.id, &self.owner, self.provider)
    }
}
impl Drop for CliLease {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use crate::storage::Paths;

    #[test]
    fn desktop_commit_keeps_lock_and_restores_disk_on_failure() {
        let home = std::env::temp_dir().join(format!("cw-lease-boundary-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let storage = StateStore::new(Paths::new(&home).unwrap());
        let leases = LeaseStore { storage: storage.clone() };
        let first = Desktop { pid: 3001, start_seconds: 100, start_microseconds: 1 };
        let second = Desktop { pid: 3002, start_seconds: 100, start_microseconds: 2 };
        let bindings: Vec<(Desktop, String)> = vec![(first.clone(), "first-start".into()), (second.clone(), "second-start".into())];
        let inventory: BTreeMap<_, _> = bindings.iter().map(|(desktop, stamp)| {
            (desktop.pid, Identity {
                pid: desktop.pid, parent: 1, uid: 501, executable: "/fixture/desktop".into(),
                start_seconds: desktop.start_seconds, start_microseconds: desktop.start_microseconds,
                start_stamp: stamp.clone(),
            })
        }).collect();
        leases.save_desktop(&first, "first-start", 1000.0, Provider::Claude).unwrap();
        let original = fs::read(leases.desktop_path(first.pid)).unwrap();
        let other = LeaseStore { storage: StateStore::new(Paths::new(&home).unwrap()) };
        let result = leases.commit_desktops(&bindings, 1001.0, Provider::Claude, || {
            assert_eq!(other.save_desktop(&first, "first-start", 1002.0, Provider::Claude).unwrap_err().code, "busy");
            assert_eq!(other.load(&BTreeMap::new(), 501, true).unwrap_err().code, "busy");
            // A separate process observes the same file lock, including during commit.
            let code = "import fcntl,sys\nf=open(sys.argv[1],'r+b')\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(3)\nsys.exit(0)";
            let output = std::process::Command::new("python3").args(["-c", code])
                .arg(storage.paths.base().join("leases.lock")).output().unwrap();
            assert_eq!(output.status.code(), Some(3));
            Err::<(), _>(CoreError::new("fixture_commit_failed", "fixture"))
        });
        assert_eq!(result.unwrap_err().code, "fixture_commit_failed");
        assert_eq!(fs::read(leases.desktop_path(first.pid)).unwrap(), original);
        assert!(!leases.desktop_path(second.pid).exists());
        assert_eq!(other.load(&inventory, 501, true).unwrap().len(), 1);

        let mut invalid = bindings.clone();
        invalid[1].1 = "invalid|stamp".into();
        assert_eq!(leases.commit_desktops(&invalid, 1002.0, Provider::Claude,
            || -> Result<()> { panic!("partial lease write cannot commit the session") }).unwrap_err().code, "desktop_identity_unavailable");
        assert_eq!(fs::read(leases.desktop_path(first.pid)).unwrap(), original);
        assert!(!leases.desktop_path(second.pid).exists());

        leases.commit_desktops(&bindings, 1003.0, Provider::Claude, || Ok(())).unwrap();
        drop(leases);
        let restarted = LeaseStore { storage: StateStore::new(Paths::new(&home).unwrap()) };
        assert_eq!(restarted.load(&inventory, 501, true).unwrap().len(), 2);
        assert!(restarted.load(&BTreeMap::new(), 501, false).unwrap().is_empty());
        assert_eq!(restarted.load(&inventory, 501, true).unwrap().len(), 2,
            "an incomplete process sample must preserve persisted leases");
        assert!(restarted.load(&BTreeMap::new(), 501, true).unwrap().is_empty());
        assert!(!restarted.desktop_path(first.pid).exists());
        fs::remove_dir_all(home).unwrap();
    }
}

fn legacy_lease(text: &str, inventory: &BTreeMap<u32, Identity>, uid: u32) -> Option<Lease> {
    let mut fields = text.trim().split('|').collect::<Vec<_>>();
    if fields.len() == 6 {
        fields.insert(1, "claude");
    }
    if fields.len() != 7 || !matches!(fields[0], "cli" | "desktop") {
        return None;
    }
    let provider = match fields[1] {
        "claude" => Provider::Claude,
        "codex" => Provider::Codex,
        "chatgpt" => Provider::Chatgpt,
        "openai" => Provider::Openai,
        _ => return None,
    };
    let lookup = |pid: &str, stamp: &str| -> Option<Identity> {
        let current = inventory.get(&pid.parse::<u32>().ok()?)?;
        (current.uid == uid
            && processes::normalized_stamp(&current.start_stamp)
                == processes::normalized_stamp(stamp))
        .then(|| current.clone())
    };
    let root = lookup(fields[2], fields[3])?;
    let cli = fields[0] == "cli";
    let owner = if cli {
        Some(lookup(fields[4], fields[5])?)
    } else {
        None
    };
    Some(Lease {
        provider,
        root,
        owner,
        cli,
    })
}
