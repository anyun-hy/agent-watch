//! Explicit process exit service shared by manual UI requests and account switching.
//! Normal exit never escalates; force requires an explicit plan and CLI confirmation.
use crate::{commands::ReadRunner, native, sampler::{ProcessRound, Sampler}, storage::Paths};
use claude_watch_core::{error::{CoreError, Result}, policy::PolicyCatalog,
    processes::{MatchReason, ProcessIdentityRef, ProcessRole, Target}};
use claude_watch_system::{ProcessKernelIdentity, BoundSignalResult, bound_lifetime_exited, inspect_process_identity};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, time::{Duration, Instant}};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitTarget {
    pub process: ProcessKernelIdentity,
    pub desktop_main: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPlan {
    pub schema: u32,
    #[serde(default)]
    pub force: bool,
    pub request_id: String,
    pub family: String,
    pub desktop_only: bool,
    pub uid: u32,
    pub created_at: f64,
    pub protected: BTreeSet<u32>,
    pub targets: Vec<ExitTarget>,
}
#[derive(Debug, Serialize)]
pub struct ExitResult {
    pub pid: u32,
    pub process_state: String,
    pub request_sent_at: Option<f64>,
}
#[derive(Debug, Serialize)]
pub struct ExitReceipt {
    pub schema: u32,
    pub request_id: String,
    pub family: String,
    pub complete: bool,
    pub results: Vec<ExitResult>,
    pub remaining: Vec<u32>,
    pub code: String,
    pub message: String,
}
impl ExitReceipt {
    pub fn confirm(&self) -> Result<()> {
        if self.complete { Ok(()) } else { Err(CoreError::new(&self.code, &self.message)) }
    }
}

/// The same direct classification roots also feed the read-only CLI projection.
pub fn classified_roots(round: &ProcessRound) -> impl Iterator<Item = &Target> {
    round.targets.iter().filter(|target| {
        matches!(target.kind.role(), ProcessRole::DesktopMain | ProcessRole::DesktopHelper | ProcessRole::Cli)
            && round.match_evidence.get(&target.identity.pid).is_some_and(|e|
                e.identity.same_process(&target.identity) && e.parent.is_none()
                && e.root.as_ref() == Some(&ProcessIdentityRef::from(&target.identity))
                && matches!(e.reason, MatchReason::SupportedCliAlias | MatchReason::KnownCliLayout
                    | MatchReason::VerifiedBundle | MatchReason::VerifiedBundleComponent
                    | MatchReason::ScriptEntry | MatchReason::ManagedAppServer))
    })
}

pub fn prepare<R: ReadRunner>(runner: &R, paths: &Paths, family: &str, desktop_only: bool,
    protect_pid: Option<u32>) -> Result<ExitPlan> {
    let round = Sampler::new(runner, paths.clone()).processes()?;
    let mut protected = BTreeSet::from([1, std::process::id()]);
    if let Some(pid) = protect_pid { protected.insert(pid); }
    let mut pid = std::process::id();
    for _ in 0..64 {
        let Some(identity) = inspect_process_identity(pid) else { break; };
        if identity.ppid <= 1 || !protected.insert(identity.ppid) { break; }
        pid = identity.ppid;
    }
    prepare_round(&round, family, desktop_only, protected, inspect_process_identity)
}

fn prepare_round(round: &ProcessRound, family: &str, desktop_only: bool, protected: BTreeSet<u32>,
    mut inspect: impl FnMut(u32) -> Option<ProcessKernelIdentity>) -> Result<ExitPlan> {
    if !matches!(family, "claude" | "openai") || round.uid != claude_watch_system::effective_uid()
        || !round.complete || round.match_evidence.values().any(|e| e.reason == MatchReason::InstallationPending) {
        return Err(CoreError::new("process_inventory_incomplete", "进程归属不完整，未生成退出计划"));
    }
    let roots: Vec<_> = classified_roots(round).collect();
    let family_of = |target: &Target| PolicyCatalog::family_for(target.kind.provider()).map(|f| f.id);
    let mut selected: BTreeSet<_> = roots.iter().filter(|t| family_of(t) == Some(family)
        && (!desktop_only || t.identity.executable.contains(".app/Contents/")))
        .map(|t| t.identity.pid).filter(|pid| !protected.contains(pid)).collect();
    loop {
        let before = selected.len();
        for p in round.identities.values() {
            if p.uid == round.uid && p.pid > 1 && !protected.contains(&p.pid)
                && selected.contains(&p.parent)
                && !roots.iter().any(|t| t.identity.pid == p.pid && family_of(t) != Some(family)) {
                selected.insert(p.pid);
            }
        }
        if before == selected.len() { break; }
    }
    if selected.len() > 128 { return Err(CoreError::new("process_exit_limit", "退出目标数量超过单次限制")); }
    let mut targets = Vec::new();
    for pid in selected {
        let expected = round.identities.get(&pid).ok_or_else(|| CoreError::new("process_identity_unavailable", "进程身份缺失"))?;
        let Some(process) = inspect(pid) else {
            if claude_watch_system::is_process_definitely_dead(pid) { continue; }
            return Err(CoreError::new("process_identity_unavailable", "无法绑定当前进程身份"));
        };
        if process.uid != round.uid || process.start_seconds != expected.start_seconds
            || process.start_microseconds != expected.start_microseconds
            || process.executable_path != expected.executable {
            return Err(CoreError::new("process_identity_changed", "生成计划期间进程身份变化"));
        }
        targets.push(ExitTarget { process, desktop_main: roots.iter().any(|t|
            t.identity.pid == pid && t.kind.role() == ProcessRole::DesktopMain) });
    }
    targets.sort_by_key(|target| (!target.desktop_main, target.process.pid));
    Ok(ExitPlan { schema: 1, force: false, request_id: uuid::Uuid::new_v4().to_string(), family: family.into(),
        desktop_only, uid: round.uid, created_at: native::now(), protected, targets })
}

pub fn execute<R: ReadRunner>(runner: &R, paths: &Paths, plan: &ExitPlan,
    request_appkit: impl FnMut(&ProcessKernelIdentity) -> Result<bool>) -> Result<ExitReceipt> {
    execute_with_inventory(plan, Duration::from_secs(15),
        || prepare(runner, paths, &plan.family, plan.desktop_only, None), request_appkit)
}

fn execute_with_inventory(plan: &ExitPlan, timeout: Duration,
    mut inventory: impl FnMut() -> Result<ExitPlan>,
    mut request_appkit: impl FnMut(&ProcessKernelIdentity) -> Result<bool>) -> Result<ExitReceipt> {
    let now = native::now();
    if plan.schema != 1 || uuid::Uuid::parse_str(&plan.request_id).is_err()
        || plan.uid != claude_watch_system::effective_uid() || plan.targets.len() > 128
        || !(0.0..=120.0).contains(&(now - plan.created_at))
        || plan.targets.iter().map(|t| t.process.pid).collect::<BTreeSet<_>>().len() != plan.targets.len()
        || plan.targets.iter().any(|t| t.process.uid != plan.uid || t.process.pid <= 1 || plan.protected.contains(&t.process.pid)) {
        return Err(CoreError::new("invalid_exit_plan", "退出计划无效或已过期，请重新核对"));
    }
    let fresh = inventory()?;
    let results = execute_targets(&plan.targets, timeout, |target| {
        if !fresh.targets.iter().any(|t| same_process(&t.process, &target.process) && t.desktop_main == target.desktop_main) {
            return Ok(BoundSignalResult::IdentityChanged);
        }
        if plan.force {
            Ok(claude_watch_system::signal_bound_process(&target.process))
        } else if target.desktop_main {
            request_appkit(&target.process).map(|accepted|
                if accepted { BoundSignalResult::Sent } else { BoundSignalResult::Failed })
        } else { Ok(claude_watch_system::terminate_bound_process(&target.process)) }
    }, bound_lifetime_exited);
    // Never expand the authorized target set during execution; new roots are
    // reported here and keep account switching from copying an active profile.
    let after = inventory();
    let remaining = after.as_ref().map(|p| p.targets.iter()
        .filter(|t| !plan.protected.contains(&t.process.pid) && !bound_lifetime_exited(&t.process))
        .map(|t| t.process.pid).collect()).unwrap_or_default();
    Ok(receipt(plan, results, remaining, after.is_err()))
}

fn same_process(a: &ProcessKernelIdentity, b: &ProcessKernelIdentity) -> bool {
    a.pid == b.pid && a.uid == b.uid && a.start_seconds == b.start_seconds
        && a.start_microseconds == b.start_microseconds && a.audit_token == b.audit_token
        && a.executable_path == b.executable_path
}

/// A profile switch addresses one verified Desktop window. Its AppKit quit can
/// be cancelled by the user. Standalone CLIs and other editions are outside it.
pub(crate) fn quit_desktop_instance(expected: &claude_watch_core::processes::Identity,
    mut request_appkit: impl FnMut(&ProcessKernelIdentity) -> Result<bool>) -> Result<()> {
    let changed = || CoreError::new("target_identity_changed", "ChatGPT 实例已变化，未请求退出");
    let live = inspect_process_identity(expected.pid).ok_or_else(changed)?;
    if !expected.valid() || live.uid != claude_watch_system::effective_uid()
        || live.uid != expected.uid || live.start_seconds != expected.start_seconds
        || live.start_microseconds != expected.start_microseconds || live.executable_path != expected.executable {
        return Err(changed());
    }
    let results = execute_targets(&[ExitTarget { process: live, desktop_main: true }], Duration::from_secs(15),
        |target| Ok(if request_appkit(&target.process)? { BoundSignalResult::Sent } else { BoundSignalResult::Failed }),
        bound_lifetime_exited);
    if matches!(results[0].process_state.as_str(), "already_exited" | "confirmed_exit_after_request") {
        Ok(())
    } else {
        Err(CoreError::new("chatgpt_quit_unconfirmed", "ChatGPT 尚未退出。请处理桌面端的未保存提示后重试。"))
    }
}

fn execute_targets(targets: &[ExitTarget], timeout: Duration,
    mut request: impl FnMut(&ExitTarget) -> Result<BoundSignalResult>,
    exited: impl Fn(&ProcessKernelIdentity) -> bool) -> Vec<ExitResult> {
    let deadline = Instant::now() + timeout;
    let mut results: Vec<_> = targets.iter().map(|target| {
        let mut row = ExitResult { pid: target.process.pid, process_state: "already_exited".into(), request_sent_at: None };
        if !exited(&target.process) {
            row.process_state = match if Instant::now() < deadline { request(target) }
                else { Err(CoreError::new("exit_deadline", "退出请求已超时")) } {
                Ok(BoundSignalResult::Sent) => { row.request_sent_at = Some(native::now()); "timeout" },
                Ok(BoundSignalResult::AlreadyExited) => "already_exited",
                Ok(BoundSignalResult::IdentityChanged) => "identity_mismatch",
                Ok(BoundSignalResult::Failed) => "request_rejected",
                Err(_) => "request_unconfirmed",
            }.into();
        }
        row
    }).collect();
    let requested = targets.iter().zip(&results).filter_map(|(target, row)|
        row.request_sent_at.map(|_| target.process.pid)).collect();
    wait_for_exits(requested, deadline, || {
        let mut waiting = false;
        for (target, row) in targets.iter().zip(&mut results) {
            if row.request_sent_at.is_some() && row.process_state == "timeout" {
                if exited(&target.process) { row.process_state = "confirmed_exit_after_request".into(); }
                else { waiting = true; }
            }
        }
        !waiting
    });
    results
}

/// Register before inspecting completion so an exit in between cannot be lost.
/// A kernel notification only prompts the caller to verify the original lifetime.
pub(crate) fn wait_for_exits(pids: Vec<u32>, deadline: Instant, mut complete: impl FnMut() -> bool) {
    if pids.is_empty() { return; }
    let queue = claude_watch_system::process_events::ProcessEvents::new().ok();
    if let Some(events) = &queue {
        for pid in pids { let _ = events.watch_exit(pid); }
    }
    while !complete() && Instant::now() < deadline {
        if queue.as_ref().is_none_or(|events| events.wait(Some(deadline)).is_err()) {
            // If event registration is unavailable, do one final identity check
            // at the original deadline. It must never manufacture a receipt.
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        }
    }
}

fn receipt(plan: &ExitPlan, results: Vec<ExitResult>, remaining: Vec<u32>, unavailable: bool) -> ExitReceipt {
    let complete = !unavailable && remaining.is_empty() && results.iter().all(|r|
        matches!(r.process_state.as_str(), "already_exited" | "confirmed_exit_after_request"));
    let code = if complete { "" } else if unavailable { "process_identity_unavailable" } else { "target_exit_unconfirmed" };
    let already = results.iter().filter(|r| r.process_state == "already_exited").count();
    let confirmed = results.iter().filter(|r| r.process_state == "confirmed_exit_after_request").count();
    let message = format!("请求前已退出 {already} 项，本次请求后确认退出 {confirmed} 项。{}",
        if complete { "目标已全部退出。" } else { "仍有进程运行或身份无法确认，未确认全部退出。" });
    ExitReceipt { schema: 1, request_id: plan.request_id.clone(), family: plan.family.clone(),
        complete, results, remaining, code: code.into(), message }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{accounts::{AccountOs, AccountStore}, storage::StateStore};
    use std::{fs, io::Read, path::PathBuf, process::{Child, Command, Stdio}};

    struct Owned(Child);
    impl Drop for Owned { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    fn child(ignore_term: bool) -> (Owned, ExitTarget) {
        let command = if ignore_term { "trap '' TERM; printf 1; read value" } else { "printf 1; read value" };
        let mut child = Owned(Command::new("/bin/sh").args(["-c", command])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap());
        child.0.stdout.as_mut().unwrap().read_exact(&mut [0]).unwrap();
        let process = inspect_process_identity(child.0.id()).unwrap();
        (child, ExitTarget { process, desktop_main: false })
    }
    fn make_plan(target: ExitTarget) -> ExitPlan {
        ExitPlan { schema: 1, force: false, request_id: uuid::Uuid::new_v4().to_string(), family: "claude".into(),
            desktop_only: false, uid: target.process.uid, created_at: native::now(),
            protected: BTreeSet::new(), targets: vec![target] }
    }
    fn normal(target: &ExitTarget) -> Result<BoundSignalResult> {
        Ok(claude_watch_system::terminate_bound_process(&target.process))
    }
    fn export(name: &str, plan: &ExitPlan, receipt: &ExitReceipt) {
        if let Some(dir) = std::env::var_os("CW_PHASE3_EVIDENCE_DIR") {
            fs::write(PathBuf::from(dir).join(name), serde_json::to_vec_pretty(
                &serde_json::json!({"plan":plan,"receipt":receipt})).unwrap()).unwrap();
        }
    }

    #[test]
    fn explicit_force_plan_terminates_a_term_ignoring_process_without_appkit() {
        use std::os::unix::process::ExitStatusExt;
        let (mut owned, target) = child(true);
        let mut plan = make_plan(target.clone());
        plan.force = true;
        let result = execute_with_inventory(&plan, Duration::from_secs(1), || Ok(plan.clone()),
            |_| panic!("explicit force cannot use normal AppKit termination")).unwrap();
        assert_eq!(result.results[0].process_state, "confirmed_exit_after_request");
        assert!(result.complete);
        assert_eq!(owned.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn normal_exit_distinguishes_prior_exit_confirmed_request_and_unconfirmed_timeout() {
        let (mut owned, target) = child(false);
        let plan = make_plan(target.clone());
        let result = execute_targets(&plan.targets, Duration::from_secs(1), normal, bound_lifetime_exited);
        assert_eq!(result[0].process_state, "confirmed_exit_after_request");
        assert!(result[0].request_sent_at.is_some());
        // Do not reap: the kernel's zombie/identity observation must suffice.
        assert!(bound_lifetime_exited(&target.process));
        let success = receipt(&plan, result, vec![], false);
        success.confirm().unwrap(); export("normal-exit.json", &plan, &success);
        let prior = execute_targets(&plan.targets, Duration::ZERO, |_| panic!("already exited: no request"), bound_lifetime_exited);
        assert_eq!(prior[0].process_state, "already_exited");
        assert!(prior[0].request_sent_at.is_none());
        export("prior-exit.json", &plan, &receipt(&plan, prior, vec![], false));
        owned.0.wait().unwrap();

        let (mut alive, target) = child(true);
        let plan = make_plan(target.clone());
        let timeout = execute_targets(&plan.targets, Duration::from_millis(40), normal, bound_lifetime_exited);
        assert_eq!(timeout[0].process_state, "timeout");
        assert!(timeout[0].request_sent_at.is_some());
        assert!(alive.0.try_wait().unwrap().is_none(), "normal exit cannot escalate to force");
        let failed = receipt(&plan, timeout, vec![target.process.pid], false);
        assert!(failed.confirm().is_err()); export("timeout-exit.json", &plan, &failed);

        let unknown = execute_targets(&plan.targets, Duration::ZERO, |_| panic!("expired budget"), |_| false);
        assert_eq!(unknown[0].process_state, "request_unconfirmed");
        assert!(!receipt(&plan, unknown, vec![], true).complete);
        let mut reused = target.clone(); reused.process.start_seconds -= 1;
        let prior = execute_targets(&[reused], Duration::ZERO, |_| panic!("reused PID cannot be signalled"), bound_lifetime_exited);
        assert_eq!(prior[0].process_state, "already_exited");
        let mut changed = target; changed.process.audit_token[7] ^= 1;
        let mismatch = execute_targets(&[changed], Duration::from_millis(40), normal, bound_lifetime_exited);
        assert_eq!(mismatch[0].process_state, "identity_mismatch");
        assert!(alive.0.try_wait().unwrap().is_none());
    }

    #[test]
    fn normal_exit_appkit_ack_is_not_exit_and_new_or_unknown_targets_block_completion() {
        let (_owned, mut target) = child(true);
        target.desktop_main = true;
        let plan = make_plan(target);
        let accepted = execute_with_inventory(&plan, Duration::from_millis(40), || Ok(plan.clone()), |_| Ok(true)).unwrap();
        assert!(!accepted.complete);
        assert_eq!(accepted.results[0].process_state, "timeout", "AppKit acknowledgement is not exit evidence");
        let mut empty = plan.clone(); empty.targets.clear();
        let appeared = execute_with_inventory(&empty, Duration::ZERO, || Ok(plan.clone()), |_| panic!("new target not authorized")).unwrap();
        assert!(!appeared.complete);
        assert_eq!(appeared.remaining, vec![plan.targets[0].process.pid]);
        let mut reads = 0;
        let unknown = execute_with_inventory(&empty, Duration::ZERO, || {
            reads += 1;
            if reads == 1 { Ok(empty.clone()) } else { Err(CoreError::new("unavailable", "fixture")) }
        }, |_| panic!("empty plan")).unwrap();
        assert!(!unknown.complete);
        assert_eq!(unknown.code, "process_identity_unavailable");
    }

    #[test]
    fn normal_exit_selection_preserves_manual_cli_and_account_desktop_scope() {
        use claude_watch_core::processes::{Identity, Kind, MatchEvidence};
        let uid = claude_watch_system::effective_uid();
        let row = |pid, parent, executable: &str| Identity { pid, parent, uid,
            executable: executable.into(), start_seconds: 100, start_microseconds: 1, start_stamp: String::new() };
        let identities = [row(10,1,"/fixture/Claude.app/Contents/MacOS/Claude"), row(11,10,"/fixture/helper"),
            row(20,1,"/fixture/claude-cli"), row(30,10,"/fixture/codex"), row(31,30,"/fixture/helper"),
            row(40,10,"/fixture/monitor"), Identity {uid:uid+1,..row(50,10,"/fixture/foreign")}];
        let targets = vec![Target {identity:identities[0].clone(),kind:Kind::ClaudeMain},
            Target {identity:identities[2].clone(),kind:Kind::ClaudeCode},
            Target {identity:identities[3].clone(),kind:Kind::CodexCli}];
        let mut round = ProcessRound { id:"fixture".into(),uid,
            match_evidence:targets.iter().map(|t|(t.identity.pid,MatchEvidence::direct(&t.identity,
                if t.kind == Kind::ClaudeMain { MatchReason::VerifiedBundle } else { MatchReason::KnownCliLayout }))).collect(),
            targets, identities:identities.into_iter().map(|p|(p.pid,p)).collect(), roles:serde_json::json!({}),
            unavailable:vec![],diagnostic_reasons:Default::default(),confirmed_exited_count:0,
            complete:true,observed_at:native::now(),discovery:None,system_processes:None };
        let inspect = |pid| { let p = &round.identities[&pid]; Some(ProcessKernelIdentity {pid,ppid:p.parent,
            uid:p.uid,start_seconds:p.start_seconds,start_microseconds:p.start_microseconds,
            executable_path:p.executable.clone(),audit_token:[0;8]}) };
        let manual = prepare_round(&round,"claude",false,BTreeSet::from([40]),inspect).unwrap();
        assert_eq!(manual.targets.iter().map(|t|t.process.pid).collect::<Vec<_>>(),vec![10,11,20]);
        let account = prepare_round(&round,"claude",true,BTreeSet::from([40]),inspect).unwrap();
        assert_eq!(account.targets.iter().map(|t|t.process.pid).collect::<Vec<_>>(),vec![10,11]);
        assert!(account.targets[0].desktop_main && !account.targets[1].desktop_main);
        round.complete = false;
        assert!(prepare_round(&round,"claude",false,BTreeSet::new(), |_| panic!("incomplete inventory")).is_err());
    }

    struct Root(PathBuf);
    impl Drop for Root { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    struct SwitchingOs { storage: StateStore, plan: ExitPlan }
    impl AccountOs for SwitchingOs {
        fn claude_version(&mut self) -> Result<Option<String>> { Ok(Some("fixture".into())) }
        fn preflight(&mut self) -> Result<()> { Ok(()) }
        fn quit_claude(&mut self) -> Result<()> {
            assert!(self.storage.lock("operation", None).is_err(), "AccountStore must already hold operation");
            execute_with_inventory(&self.plan, Duration::from_millis(80), || Ok(self.plan.clone()),
                |_| panic!("owned CLI does not use AppKit"))?.confirm()
        }
        fn claude_running(&mut self) -> Result<bool> { Ok(!bound_lifetime_exited(&self.plan.targets[0].process)) }
        fn launch_claude(&mut self) -> Result<()> { Ok(()) } // no actual AI launch
    }
    #[test]
    fn account_switch_holds_operation_once_and_copies_only_after_confirmed_exit() {
        for refuses in [false, true] {
            let root = Root(std::env::temp_dir().join(format!("cw-phase3-{}", uuid::Uuid::new_v4())));
            fs::create_dir(&root.0).unwrap();
            let storage = StateStore::new(Paths::new(&root.0).unwrap());
            fs::create_dir_all(storage.paths.active()).unwrap();
            fs::write(storage.paths.active().join("fixture.txt"), "original").unwrap();
            let (_owned, target) = child(refuses);
            let os = SwitchingOs { storage: storage.clone(), plan: make_plan(target) };
            let mut accounts = AccountStore::new(storage.clone(), os);
            let config = claude_watch_core::config::Config { verified_claude_versions: vec!["fixture".into()], ..Default::default() };
            let switched = accounts.switch("B", &config, false);
            if refuses {
                assert_eq!(switched.unwrap_err().code, "target_exit_unconfirmed");
                assert_eq!(fs::read_to_string(storage.paths.active().join("fixture.txt")).unwrap(), "original");
                assert!(!storage.paths.journal().exists(), "no transaction or copy before exit confirmation");
            } else { assert_eq!(switched.unwrap().current, "B"); }
            assert!(storage.lock("operation", None).is_ok(), "transaction releases its lock");
        }
    }
}
