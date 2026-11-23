use super::*;
use crate::{commands::ReadRunner, native::Observer};
use claude_watch_core::processes::Identity;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;

const CLAUDE_MAIN: &str = "/Applications/Claude.app/Contents/MacOS/Claude";

/// Match the same official main executable as the native account-menu reader.
pub fn observe_claude_source<R: ReadRunner>(runner: &R) -> Result<Identity> {
    let observer = Observer { runner };
    let inventory = observer.inventory()?;
    let mut mains = inventory
        .processes
        .values()
        .map(|row| &row.identity)
        .filter(|id| id.uid == inventory.uid && id.valid() && id.executable == CLAUDE_MAIN);
    let one = mains.next();
    if inventory.complete && mains.next().is_none() {
        if let Some(id) = one {
            let args = observer.arguments(std::slice::from_ref(id), &Uuid::new_v4().to_string())?;
            let standard_profile = args.get(&id.pid).is_some_and(|args| {
                !args.truncated
                    && !args.tokens.is_empty()
                    && !args.tokens.iter().any(|arg| {
                        matches!(
                            arg.split('=').next(),
                            Some("--user-data-dir" | "--profile-directory")
                        )
                    })
            });
            if !standard_profile {
                return Err(err(
                    "account_source_unavailable",
                    "无法确认当前 Claude 使用标准资料目录，未绑定槽位",
                ));
            }
            return Ok(id.clone());
        }
    }
    Err(err(
        "account_source_unavailable",
        "请打开 Claude 的主窗口，再读取当前账号",
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveCurrentAccount {
    pub source_token: String,
    pub account_label: String,
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.trim() == label
        && label.chars().count() <= 160
        && !label.chars().any(char::is_control)
}

type FileId = [u64; 2];
struct SourceProof {
    token: String,
    process: Identity,
    directory: FileId,
    slot: Option<String>,
}
fn directory_id(store: &StateStore, path: &Path) -> Result<Option<FileId>> {
    store.guarded(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(Some([meta.dev(), meta.ino()])),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        _ => Err(err("unsafe_path", "账号资料路径不是普通目录")),
    }
}

fn digest(value: &Value) -> Result<String> {
    let raw = serde_json::to_vec(value).map_err(|_| err("invalid_state", "账号状态无法编码"))?;
    Ok(hex_digest(sha2::Sha256::digest(raw).as_slice()))
}

// Only archives and the small slot marker participate. The running application's
// profile is never moved, replaced or restored by this transaction.
#[derive(Serialize, Deserialize)]
struct SaveJournal {
    schema: u8,
    kind: String,
    token: String,
    target: String,
    previous_state: String,
    previous_slot: Option<FileId>,
    staged_slot: Option<FileId>,
}

impl<O: AccountOs> AccountStore<O> {
    fn state_value(&self) -> Result<Value> {
        self.storage.read_json(&self.state_path(), Value::Null)
    }

    pub(super) fn saved_label(&self, id: &str) -> Option<String> {
        let bytes = self
            .storage
            .read_bytes(&self.slot(id).join("account-label.json"), 2048)
            .ok()??;
        let label: String = serde_json::from_slice(&bytes).ok()?;
        valid_label(&label).then_some(label)
    }

    fn source_proof(&mut self) -> Result<SourceProof> {
        let state = self.state_value()?;
        let slot = self.state()?;
        if state["current"].as_str() != slot.as_deref() {
            return Err(err(
                "account_source_changed",
                "Claude 资料槽位正在变化，请重新读取",
            ));
        }
        self.check_external_ownership(slot.as_deref())?;
        let process = self.os.current_desktop()?;
        let active = directory_id(&self.storage, &self.storage.paths.active())?
            .ok_or_else(|| err("account_source_missing", "当前 Claude 的本地资料不存在"))?;
        let source = json!([
            process.pid,
            process.uid,
            process.start_seconds,
            process.start_microseconds,
            process.executable,
            active,
            state,
            directory_id(&self.storage, &self.slot("A"))?,
            directory_id(&self.storage, &self.slot("B"))?
        ]);
        Ok(SourceProof {
            token: digest(&source)?,
            process,
            directory: active,
            slot,
        })
    }

    pub fn current_source(&mut self) -> Result<Value> {
        if self.storage.paths.journal().exists() {
            return Err(err(
                "recovery_required",
                "先完成当前账号操作或恢复未完成事务",
            ));
        }
        let source = self.source_proof()?;
        Ok(json!({"source_token":source.token,"process_id":source.process.pid,"slot":source.slot}))
    }

    pub fn save_current(&mut self, slot: &str, read: &SaveCurrentAccount) -> Result<Value> {
        Self::valid(slot)?;
        if !valid_label(&read.account_label) || read.source_token.len() != 64 {
            return Err(err("invalid_account_source", "请重新读取当前 Claude 账号"));
        }
        let _lock = self.storage.lock("operation", None)?;
        let stale = || {
            err(
                "account_source_changed",
                "Claude 实例或账号资料已变化，请重新读取当前账号",
            )
        };
        let source = self.source_proof()?;
        if source.token != read.source_token {
            return Err(stale());
        }
        let destination = self.slot(slot);
        let previous_slot = directory_id(&self.storage, &destination)?;
        if previous_slot.is_some() {
            if self.state()?.as_deref() != Some(slot) {
                return Err(err(
                    "account_slot_occupied",
                    "该槽位已有另一份账号资料，请选择空槽或当前槽",
                ));
            }
            self.validate(slot)?;
        }
        let mut journal = SaveJournal {
            schema: 1,
            kind: "save_current".into(),
            token: Uuid::new_v4().simple().to_string(),
            target: slot.into(),
            previous_state: digest(&self.state_value()?)?,
            previous_slot,
            staged_slot: None,
        };
        let path = self.storage.paths.journal();
        let work = self
            .storage
            .paths
            .accounts()
            .join(format!(".save-{}", journal.token));
        let stage = work.join("slot");
        let profile = stage.join("profile");
        let active = self.storage.paths.active();
        let record = |journal: &SaveJournal| {
            serde_json::to_value(journal).map_err(|_| err("invalid_state", "账号保存记录无效"))
        };
        self.storage.atomic_json(&path, &record(&journal)?)?;
        let saved = (|| {
            self.storage.private_dir(&stage)?;
            let (_, files) = self.copy_verified_tree(&active, &profile)?;
            self.write_manifest(&stage, &files, "manual-save")?;
            self.storage.atomic_json(
                &stage.join("account-label.json"),
                &json!(read.account_label),
            )?;
            journal.staged_slot = directory_id(&self.storage, &stage)?;
            self.storage.atomic_json(&path, &record(&journal)?)?;
            self.os.checkpoint("save_staged")?;
            if tree_manifest(&active)? != files || self.source_proof()?.token != source.token {
                return Err(stale());
            }
            if previous_slot.is_some() {
                fs::rename(&destination, work.join("previous-slot")).map_err(io)?;
            }
            fs::rename(&stage, &destination).map_err(io)?;
            self.os.checkpoint("save_published")?;
            if !self.os.current_desktop()?.same_process(&source.process)
                || directory_id(&self.storage, &active)? != Some(source.directory)
                || digest(&self.state_value()?)? != journal.previous_state
            {
                return Err(stale());
            }
            self.check_external_ownership(self.state()?.as_deref())?;
            let (_, anchor) = self.observe_legacy_switcher()?;
            self.save_state(Some(slot), Some(&journal.token), anchor.as_ref())?;
            self.os.checkpoint("save_marked")
        })();
        // Re-read the on-disk record even on error. A marker already written
        // means commit; any earlier interruption restores only our archive.
        self.recover_manual_save(&self.storage.read_json(&path, Value::Null)?)?;
        if self.state_value()?["transaction_id"].as_str() != Some(journal.token.as_str()) {
            saved?;
            return Err(stale());
        }
        Ok(
            json!({"status":"ok","saved":true,"account":slot,"message": format!("已将当前 Claude 资料保存到账号 {slot}。")}),
        )
    }

    pub(super) fn recover_manual_save(&self, record: &Value) -> Result<()> {
        let conflict = || {
            err(
                "recovery_conflict",
                "账号资料在保存期间发生变化，已保留存档供核对",
            )
        };
        let j: SaveJournal = serde_json::from_value(record.clone()).map_err(|_| conflict())?;
        Self::valid(&j.target)?;
        if j.schema != 1
            || j.kind != "save_current"
            || j.token.len() != 32
            || !j.token.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(conflict());
        }
        let work = self
            .storage
            .paths
            .accounts()
            .join(format!(".save-{}", j.token));
        let stage = work.join("slot");
        let backup = work.join("previous-slot");
        let destination = self.slot(&j.target);
        let existing = directory_id(&self.storage, &destination)?;
        let old = directory_id(&self.storage, &backup)?;
        let state = self.state_value()?;
        if old.is_some() && old != j.previous_slot {
            return Err(conflict());
        }
        if state["transaction_id"].as_str() == Some(&j.token) {
            if state["current"].as_str() != Some(&j.target)
                || existing.is_none()
                || existing != j.staged_slot
            {
                return Err(conflict());
            }
        } else {
            if digest(&state)? != j.previous_state {
                return Err(conflict());
            }
            if existing.is_some() && existing == j.staged_slot {
                if stage.exists() || old != j.previous_slot {
                    return Err(conflict());
                }
                fs::rename(&destination, &stage).map_err(io)?;
            } else if existing.is_some() && existing != j.previous_slot {
                return Err(conflict());
            }
            if old.is_some() {
                if destination.exists() {
                    return Err(conflict());
                }
                fs::rename(&backup, &destination).map_err(io)?;
            }
            if directory_id(&self.storage, &destination)? != j.previous_slot {
                return Err(conflict());
            }
        }
        if work.exists() {
            fs::remove_dir_all(work).map_err(io)?;
        }
        fs::remove_file(self.storage.paths.journal()).map_err(io)
    }
}
