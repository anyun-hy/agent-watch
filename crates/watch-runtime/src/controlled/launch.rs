//! Controlled entry auditing and identity leases. The supervisor owns sessions.
use super::*;
use crate::accounts::chatgpt::{self, Profile, Slot};
use claude_watch_core::processes::{Kind, Lease};

impl Controller {
    fn record_launch(&self, target: LaunchTarget, pid: u32, now: f64) -> Option<Value> {
        crate::events::EventStore::new(self.storage.clone())
            .append(
                "controlled-launch",
                crate::events::EventFields {
                    operation: Some(target.as_str().into()),
                    pid: Some(pid),
                    status: Some("ok".into()),
                    ..Default::default()
                },
                now,
            )
            .err()
            .map(|e| json!({"code":e.code,"message":e.message}))
    }
    pub fn launch<S: DesktopSystem>(&self, system: &mut S) -> Result<Value> {
        if system.launch_target().cli() {
            return Err(CoreError::new("invalid_target_entry", "CLI必须使用带生命周期的共享入口"));
        }
        let _launch = self.storage.lock("launch", None)?;
        self.launch_observation(system, None)
    }
    pub fn switch_chatgpt_account<S: DesktopSystem>(&self, system: &mut S, slot: Slot) -> Result<Value> {
        if system.launch_target() != LaunchTarget::ChatgptDesktop || !system.supports_chatgpt_profiles() {
            return Err(CoreError::new("unsupported_chatgpt_profile", "请选择新版 ChatGPT 桌面应用以使用 A/B 账号"));
        }
        let _operation = self.storage.lock("operation", None)?;
        let _launch = self.storage.lock("launch", None)?;
        self.launch_observation(system, Some(slot))
    }
    fn require_launch_backend<S: DesktopSystem>(system: &mut S) -> Result<()> {
        if !system.backend_healthy()? {
            return Err(CoreError::new(
                "backend_unhealthy",
                "采集后台未有效运行，未启动",
            ));
        }
        Ok(())
    }
    fn observation_audit<S: DesktopSystem>(
        &self,
        system: &mut S,
        owner: &ProcessIdentity,
    ) -> Result<Value> {
        let target = system.launch_target();
        let audit = system.full_audit()?;
        let current = system.egress();
        let now = system.now();
        let risk = ReceiptStore {
            storage: self.storage.clone(),
        }
        .session_risk(
            audit["context_id"].as_str().unwrap_or(""),
            current["ip"].as_str(),
            now,
        );
        session::verify_launch(&audit, &current, &risk, now, target)?;
        if !system.backend_healthy()? || !system.observation_owner()?.same_process(owner) {
            return Err(CoreError::new(
                "launcher_context_changed",
                "预检期间后台或启动器身份变化，未启动",
            ));
        }
        Ok(audit)
    }
    fn launch_observation<S: DesktopSystem>(&self, system: &mut S, requested: Option<Slot>) -> Result<Value> {
        // Collection is an independent launch requirement. A missing
        // heartbeat can rule out launch before scanning the full inventory.
        // Keep both target scans and the post-audit backend/owner recheck.
        Self::require_launch_backend(system)?;
        let target = system.launch_target();
        let owner = system.observation_owner()?;
        if !owner.valid() {
            return Err(CoreError::new(
                "launcher_identity_unavailable",
                "启动器身份未确认",
            ));
        }
        let roots = system.observation_roots()?;
        let profiles = system.supports_chatgpt_profiles();
        let saved = if profiles { chatgpt::selection(&self.storage)? } else { None };
        let slot = requested.or_else(|| saved.as_ref().map(|s| s.slot)).or(profiles.then_some(Slot::A));
        let previous = match (roots.as_slice(), requested) {
            ([], _) => None,
            ([running], Some(wanted)) if running.kind == Kind::OpenaiMain => {
                if saved.as_ref().is_some_and(|s| s.slot == wanted && s.process.same_process(&running.identity)) {
                    return Ok(json!({"status":"ok", "product":"chatgpt", "account":wanted, "current":wanted,
                        "selected":wanted, "login_verified":false, "authorization_scope":"observation", "pid":running.identity.pid,
                        "message":format!("ChatGPT 已在使用账号 {} 的桌面资料。", wanted.label())}));
                }
                Some(running)
            }
            (_, Some(_)) => return Err(CoreError::new("chatgpt_instance_ambiguous", "存在多个桌面实例，无法确定要切换的窗口")),
            (_, None) => return Err(CoreError::new("target_already_running",
                "目标已在运行（未受控实例 running_unprotected），不能补登记观察或受控会话")),
        };
        system.check_desktop_compatibility()?;
        crate::setup_progress::emit(crate::setup_progress::Phase::CollectEvidence);
        let mut audit = self.observation_audit(system, &owner)?;
        if slot.is_some() {
            system.check_desktop_compatibility()?;
        }
        let profile = slot.map(|slot| Profile::prepare(&self.storage, slot)).transpose()?;
        if let Some(running) = previous {
            // Only ask the original window to quit after preflight and profile preparation succeed.
            let before_quit = system.observation_roots()?;
            if !matches!(before_quit.as_slice(), [same] if same.kind == running.kind && same.identity.same_process(&running.identity)) {
                return Err(CoreError::new("target_identity_changed", "ChatGPT 实例已变化，请重新选择账号"));
            }
            system.quit_chatgpt_for_switch(running)?;
            audit = self.observation_audit(system, &owner)?;
        }
        if !system.observation_roots()?.is_empty() {
            return Err(CoreError::new(
                "target_already_running",
                "预检期间目标已由其他入口启动，未补登记观察会话",
            ));
        }
        crate::setup_progress::emit(crate::setup_progress::Phase::VerifyLaunchConditions);
        let profile_pid = if let Some(profile) = &profile {
            Some(system.open_chatgpt_profile(profile)?)
        } else {
            system.open_desktop()?;
            None
        };
        crate::setup_progress::emit(crate::setup_progress::Phase::OpenApplication);
        let deadline = system.monotonic() + Duration::from_secs(10);
        while system.monotonic() < deadline {
            let roots = system.observation_roots()?;
            if roots.len() == 1 {
                let root = &roots[0];
                if profile_pid.is_some_and(|pid| pid != root.identity.pid)
                    || !target.accepts(root.kind)
                    || root.identity.uid != owner.uid
                    || !root.identity.valid()
                {
                    return Err(CoreError::new(
                        "target_identity_mismatch",
                        "目标身份不匹配，未登记观察会话",
                    ));
                }
                let verified = system.observation_roots()?;
                if system.monotonic() >= deadline
                    || verified.len() != 1
                    || !verified[0].identity.same_process(&root.identity)
                    || verified[0].kind != root.kind
                {
                    return Err(CoreError::new(
                        "target_identity_changed",
                        "目标身份变化或超时，未登记观察会话",
                    ));
                }
                crate::lease_store::LeaseStore {
                    storage: self.storage.clone(),
                }
                .save(
                    &Lease {
                        provider: root.kind.provider(),
                        root: root.identity.clone(),
                        owner: None,
                        cli: false,
                    },
                    system.now(),
                )?;
                let logging_error = self.record_launch(target, root.identity.pid, system.now());
                if let Some(slot) = slot {
                    chatgpt::record(&self.storage, slot, &root.identity)?;
                    if requested.is_some() {
                        return Ok(json!({"status":"ok","product":"chatgpt","account":slot,"current":slot,"selected":slot,"pid":root.identity.pid,
                            "login_verified":false,"authorization_scope":"observation","logging_error":logging_error,
                            "message":format!("已用槽位 {} 的资料打开 ChatGPT，联网状态以监管执行回执为准。", slot.label())}));
                    }
                }
                return Ok(
                    json!({"status":"ok","target":target,"provider":root.kind.provider(),"authorization_scope":"observation","pid":root.identity.pid,"audit":audit,"logging_error":logging_error,
                    "message":"已启动并登记目标进程，联网状态以监管执行回执为准"}),
                );
            }
            system.wait(deadline.saturating_sub(system.monotonic()));
        }
        Err(CoreError::new(
            "target_start_unconfirmed",
            "启动窗口内未确认唯一目标主进程；未授权，也未结束应用",
        ))
    }
    pub fn launch_cli<S: DesktopSystem>(
        &self,
        system: &mut S,
        args: &[String],
    ) -> Result<CliOutcome> {
        let target = system.launch_target();
        let provider = target
            .cli_provider()
            .ok_or_else(|| CoreError::new("invalid_target_entry", "目标不是CLI"))?;
        let operation = self.storage.lock("operation", None)?;
        let launch = self.storage.lock("launch", None)?;
        let owner = system.observation_owner()?;
        if !owner.valid() {
            return Err(CoreError::new(
                "launcher_identity_unavailable",
                "CLI启动器身份未确认",
            ));
        }
        Self::require_launch_backend(system)?;
        self.observation_audit(system, &owner)?;
        system.prepare_cli()?;
        if let Some(code) = system.cli_interrupted() {
            return Ok(CliOutcome {
                exit_code: code,
                diagnostic: None,
            });
        }
        let mut lease = crate::lease_store::LeaseStore {
            storage: self.storage.clone(),
        }
        .save_cli(provider, &owner, system.now())?;
        if let Some(code) = system.cli_interrupted() {
            let diagnostic = lease.clear().err().map(|e| e.message);
            return Ok(CliOutcome {
                exit_code: code,
                diagnostic,
            });
        }
        let mut child = system.spawn_cli(args)?;
        let _ = self.record_launch(target, owner.pid, system.now());
        drop(launch);
        drop(operation);
        let (code, mut diagnostic) = match child.wait() {
            Ok(code) => (code, None),
            Err(e) => (4, Some(e.message)),
        };
        if let Err(e) = lease.clear() {
            diagnostic = Some(e.message);
        }
        let _ = crate::events::EventStore::new(self.storage.clone()).append(
            "controlled-exit",
            crate::events::EventFields {
                operation: Some(target.as_str().into()),
                pid: Some(owner.pid),
                status: Some("exited".into()),
                code: Some(code.to_string()),
                ..Default::default()
            },
            system.now(),
        );
        Ok(CliOutcome {
            exit_code: code,
            diagnostic,
        })
    }
}
