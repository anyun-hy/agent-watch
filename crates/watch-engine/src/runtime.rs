//! Command dispatch policy shared by the executable and isolated contracts.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    accounts::AccountStore,
    audit_store::{AuditOptions, AuditScope, AuditStore},
    channel_policy_status::StatusFrame,
    commands::SystemRunner,
    config_store::{policy_digest, ConfigStore},
    desktop_native::NativeDesktop,
    macos::{Authority, Macos},
    monitor_snapshot, native,
    network_client::{NetworkClient, UreqTransport},
    platform_mutator::NativePlatformMutator,
    region_catalog::load_system_catalog,
    services,
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
static LISTENER_STREAM: std::sync::OnceLock<
    Arc<claude_watch_runtime::native_listener::ListenerStream>,
> = std::sync::OnceLock::new();
pub(crate) fn listener_stream() -> Option<Arc<claude_watch_runtime::native_listener::ListenerStream>> {
    LISTENER_STREAM.get().cloned()
}
pub type Host = Macos<Arc<SystemRunner>, UreqTransport, NativePlatformMutator>;
/// Commands which may mutate local or system state always require the parser's
/// explicit `--apply` acknowledgement before an adapter is invoked.
pub fn require_apply(request: &Request) -> Result<()> {
    let writes = matches!(
        (request.command.as_str(), request.action.as_deref()),
        ("config", Some("set"))
            | ("account", Some("switch" | "save" | "recover"))
            | ("setup", Some("apply" | "recover"))
            | ("protection", Some("apply"))
    ) || matches!(
        request.command.as_str(),
        "restore-settings" | "services" | "launch" | "dns-leak-record" | "webrtc-risk-record"
    ) || (request.command == "update" && request.flag("recover"));
    if writes {
        request.require_apply()
    } else {
        Ok(())
    }
}
pub fn runner() -> Result<Arc<SystemRunner>> {
    let executable = std::env::current_exe()
        .map_err(|_| CoreError::new("executable_unavailable", "无法定位运行组件"))?;
    let packaged = executable
        .parent()
        .ok_or_else(|| CoreError::new("invalid_executable", "运行组件目录无效"))?
        .join("watch-native-observer");
    let mut runner = if packaged.is_file() {
        SystemRunner::new(&packaged)?
    } else if cfg!(debug_assertions) {
        SystemRunner::development()?
    } else {
        return Err(CoreError::new(
            "native_observer_missing",
            "缺少已打包的原生采样组件",
        ));
    };
    if let Some(stream) = LISTENER_STREAM.get() {
        runner = runner.with_listener_stream(stream.clone());
    }
    Ok(Arc::new(runner))
}
pub fn initialize_native_listener(request: &Request) -> Result<()> {
    match std::env::var("CW_NATIVE_LISTENER_STREAM") {
        Err(std::env::VarError::NotPresent) => return Ok(()),
        Ok(v) if v == "1" && matches!(request.command.as_str(), "daemon" | "proxy-check") => {}
        _ => {
            return Err(CoreError::new(
                "native_listener_arguments",
                "系统采样通道仅用于固定后台或只读代理检查",
            ))
        }
    }
    let runner = runner()?;
    let exe = std::env::current_exe()
        .map_err(|_| CoreError::new("executable_unavailable", "无法定位原生组件"))?;
    let stream =
        claude_watch_runtime::native_listener::ListenerStream::start(runner, &exe)?;
    LISTENER_STREAM
        .set(stream)
        .map_err(|_| CoreError::new("native_listener_already_initialized", "采样通道已初始化"))
}
pub fn host(paths: Paths, authority: Authority) -> Result<Host> {
    let storage = StateStore::new(paths);
    let network = NetworkClient::new(Arc::new(UreqTransport), None)
        .map_err(|e| CoreError::new(&e.code, &e.detail))?
        .with_state_store(storage.clone());
    let mutator = NativePlatformMutator::new(storage.clone())?;
    Ok(Macos { request_evidence: true,
        runner: Arc::new(
            Arc::try_unwrap(runner()?)
                .map_err(|_| CoreError::new("runner_shared", "采样器初始化冲突"))?
                .with_listener_cache(storage.clone()),
        ),
        network,
        storage,
        authority,
        mutator,
        probes: Arc::new(claude_watch_runtime::online_probes::NativeProbes),
    })
}
pub(crate) fn process_component() -> Result<PathBuf> {
    let executable = std::env::current_exe()
        .map_err(|_| CoreError::new("executable_unavailable", "无法定位运行组件"))?;
    let candidate = executable.parent().unwrap().join("watch-process-control");
    if candidate.is_file() {
        Ok(candidate)
    } else if cfg!(debug_assertions) {
        native::built_process_control_path()
            .map(Into::into)
            .ok_or_else(|| CoreError::new("process_component_missing", "缺少原生进程组件"))
    } else {
        Err(CoreError::new(
            "process_component_missing",
            "缺少原生进程组件",
        ))
    }
}
fn project_session_heartbeat(
    status: &mut Value,
    session_id: &str,
    running: Option<bool>,
    heartbeat: &Value,
) {
    let matching = heartbeat["session_id"].as_str() == Some(session_id);
    let applicable = matching && heartbeat["stop_state"] != "session_changed";
    if status["phase"] != "ended"
        && applicable
        && heartbeat["persistence_error"] == "state_io_failed"
        && heartbeat["session_guard"]["reason"]["code"] == "egress_risk_persist_failed"
    {
        status["state"] = json!("locked");
        status["phase"] = json!("locked");
        status["reason"] = heartbeat["session_guard"]["reason"].clone();
    }
    if status["state"] == "locked" {
        if running == Some(false) {
            status["stop_state"] = json!("confirmed");
        } else if applicable {
            if heartbeat["stop_state"] != "confirmed" {
                status["stop_state"] = heartbeat["stop_state"].clone();
                status["stop_error"] = heartbeat["stop_error"].clone();
            }
        }
    }
}

pub fn session_view(host: &Host) -> Value {
    let now = native::now();
    let frame = claude_watch_runtime::channel_policy_status::read_frame(&host.storage);
    let evidence = (ConfigStore { storage: host.storage.clone() }).load().ok()
        .map(|config| claude_watch_runtime::channel_policy_status::guard_summary(&frame, &config, now))
        .unwrap_or(Value::Null);
    session_view_from_frame(host, &frame, &evidence, now)
}

fn session_view_from_frame(host: &Host, frame: &Value, evidence: &Value, now: f64) -> Value {
    let row = evidence["families"].as_array().and_then(|rows| rows.iter().find(|row| row["family"] == "claude"))
        .unwrap_or(&Value::Null);
    let state = &frame["families"]["claude"];
    let running = (row["channel_permit"].is_object() && row["channel_permit"]["reason_code"] != "channel_inventory_incomplete")
        .then(|| !state["active_member_pids"].as_array().is_none_or(Vec::is_empty)
            || !state["unmanaged_member_pids"].as_array().is_none_or(Vec::is_empty));
    match SessionStore::new(host.storage.clone()).load(now) {
        Ok(Some(s)) => {
            let mut status = claude_watch_core::session::status(&s, now, running);
            project_session_heartbeat(&mut status, &s.session_id, running, row);
            if row["session_id"] == s.session_id && row["session_guard"]["current"].is_object() {
                status["current"] = row["session_guard"]["current"].clone();
            }
            status
        }
        Ok(None) => json!({"state":if running==Some(false){"idle"}else{"missing"},
            "detail":if running==Some(false){"后台保护待命，无需操作"}else{"尚无受控启动会话"}}),
        Err(e) => json!({"state":"unknown","reason":{"code":e.code,"detail":e.message}}),
    }
}
fn background_service_detail(row: &Value) -> &'static str {
        let verified = row["execution_verified"] == true;
        match (
            row["id"].as_str().unwrap_or(""),
            row["state"].as_str().unwrap_or(""),
        ) {
            ("guard", "running") => "保护心跳与后台身份已确认",
            (_, "inactive") => "该后台任务已停用",
            ("updater", "unavailable") => "尚未配置本项目发布源或固定公钥",
            ("original", "scheduled") if verified => "原版独立运行，已确认最近巡检回执",
            ("original", "scheduled") => "原版任务已注册，最近巡检回执尚未确认；由原版独立管理",
            ("guard", "pending") => "保护后台运行中，正在等待有效保护证据",
            ("watchdog", "scheduled") if verified => "任务已注册，且已确认最近时区巡检回执",
            ("watchdog", "scheduled") => "任务已注册，等待或尚未确认最近执行回执",
            (_, "scheduled") => "任务已注册并按计划运行",
            (_, "mismatch") => "实际后台状态与已保存意愿不同",
            (_, "error") => "实际后台健康未通过核对",
            _ => "尚未取得完整后台运行证据",
        }
}
fn enrich_background_services(value: &mut Value) {
    let at = value["observed_at"].clone();
    for row in value["services"].as_array_mut().into_iter().flatten() {
        let detail = background_service_detail(row);
        if row["detail"].as_str().is_none_or(str::is_empty) {
            row["detail"] = json!(detail);
        }
        row["last_checked"] = at.clone();
    }
}
fn background(host: &Host) -> Result<Value> {
    let config = (ConfigStore { storage: host.storage.clone() }).load()?;
    let now = native::now();
    let frame = claude_watch_runtime::channel_policy_status::read_frame(&host.storage);
    let frame = StatusFrame::new(&frame, &config, now);
    let evidence = frame.guard_summary();
    background_from_frame(host, &config, &frame, &evidence, now)
}
fn background_from_frame(host: &Host, config: &claude_watch_core::config::Config, frame: &StatusFrame<'_>, evidence: &Value, now: f64) -> Result<Value> {
    let health = host.backend_health_from_frame(frame, evidence);
    let mut value = services::service_status_with_health(host, config, health, now)?;
    enrich_background_services(&mut value);
    value["session_guard"] = session_view_from_frame(host, frame.value(), evidence, now);
    Ok(value)
}
pub fn dispatch_read(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if ![
        "self-check",
        "snapshot",
        "status",
        "service-status",
        "check",
        "checkdetail",
        "environment",
        "proxy-check",
        "dns-check",
    ]
    .contains(&request.command.as_str())
    {
        return Ok(None);
    }
    if request.command == "environment"
        && (request.flag("confirm-baseline")
            || request.action.as_deref() == Some("confirm-baseline"))
    {
        return Ok(None);
    }
    let mut host = host(paths, Authority::ReadOnly)?;
    match request.command.as_str() {
        "self-check" => {
            use claude_watch_runtime::commands::{ReadCommand, ReadRunner};
            use std::time::Duration;
            let current = std::env::current_exe()
                .map_err(|_| CoreError::new("runtime_incomplete", "无法定位运行组件"))?;
            let resources = current
                .parent()
                .ok_or_else(|| CoreError::new("runtime_incomplete", "运行组件路径无效"))?;
            let out = host.runner.run(
                ReadCommand::Plist(resources.join("BuildInfo.plist")),
                &[],
                Duration::from_secs(5),
                1024 * 1024,
            )?;
            if out.status != 0 {
                return Err(CoreError::new("runtime_incomplete", "缺少运行组件校验清单"));
            }
            let manifest = claude_watch_runtime::storage::strict_json(&out.stdout)?;
            if manifest["Architecture"] != "arm64" {
                return Err(CoreError::new(
                    "architecture_mismatch",
                    "运行组件不是 arm64",
                ));
            }
            let mut required = vec![
                "watch-engine",
                "watch-native-observer",
                "watch-process-control",
                "watch-admin.sh",
                "watch-native-collector.zsh",
            ];
            if claude_watch_runtime::background_evidence::supported_manifest(&manifest)? {
                required.extend_from_slice(claude_watch_runtime::background_evidence::extra_files(
                    &manifest,
                )?);
            }
            if manifest["NetworkBackend"] == "seatbelt"
                || manifest["RuntimeHashes"]["watch-sandbox-launcher"].is_string()
            {
                required.push("watch-sandbox-launcher");
            }
            if manifest["RuntimeHashes"]["ControlledEntry"].is_string() {
                required.push("ControlledEntry");
            }
            for name in required {
                let path = resources.join(name);
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|_| CoreError::new("runtime_incomplete", "缺少原生运行组件"))?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > 128 * 1024 * 1024
                {
                    return Err(CoreError::new("runtime_incomplete", "原生组件文件格式无效"));
                }
                let bytes = std::fs::read(path)
                    .map_err(|_| CoreError::new("runtime_incomplete", "原生运行组件不可读取"))?;
                if manifest["RuntimeHashes"][name] != claude_watch_runtime::storage::sha256(&bytes)
                {
                    return Err(CoreError::new(
                        "runtime_hash_mismatch",
                        "原生组件校验未通过",
                    ));
                }
            }
            ConfigStore {
                storage: host.storage.clone(),
            }
            .load()?;
            AccountStore::new(host.storage.clone(), super::ReadOnlyAccounts).status()?;
            Ok(Some(
                json!({"status":"ok","schema":1,"engine":"rust","component_integrity":true,"checks":14,"grants_launch_permission":false}),
            ))
        }
        "snapshot" => {
            let at = native::now();
            Ok(Some(
                monitor_snapshot::read(&host.storage, host.runner.as_ref(), !request.flag("without-channel-events"))
                    .unwrap_or_else(|e| monitor_snapshot::empty(&host.storage, at, &e.message)),
            ))
        }
        "service-status" => Ok(Some(background(&host)?)),
        "status" => {
            let config_store = ConfigStore {
                storage: host.storage.clone(),
            };
            let config = config_store.load()?;
            let legacy_openai_force_review = config_store.legacy_force_pending()?;
            let mut audit = host.storage.read_json(
                &host.storage.paths.base().join("last-audit.json"),
                Value::Null,
            )?;
            if audit["policy"] != policy_digest(&config.value()?)? {
                audit = Value::Null
            }
            let accounts = AccountStore::new(host.storage.clone(), super::ReadOnlyAccounts)
                .status()?
                .value();
            let chatgpt_accounts = claude_watch_runtime::accounts::chatgpt::status(&host.storage, &host.runner)
                .unwrap_or_else(|err| json!({"error":err.message}));
            let env = host.environment().ok();
            let ai_versions =
                claude_watch_runtime::ai_versions::inspect(&host.storage, host.runner.as_ref());
            let claude_version = if !ai_versions.claude.desktop.selected_version.is_empty() {
                ai_versions.claude.desktop.selected_version.as_str()
            } else {
                env.as_ref()
                    .and_then(|v| v.pointer("/claude_app/version"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            };
            let claude_build = if !ai_versions.claude.desktop.selected_build.is_empty() {
                ai_versions.claude.desktop.selected_build.as_str()
            } else {
                env.as_ref()
                    .and_then(|v| v.pointer("/claude_app/build"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            };
            let chatgpt_version = if !ai_versions.chatgpt.desktop.selected_version.is_empty() {
                ai_versions.chatgpt.desktop.selected_version.as_str()
            } else {
                env.as_ref()
                    .and_then(|v| v.pointer("/chatgpt_app/version"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            };
            let chatgpt_build = if !ai_versions.chatgpt.desktop.selected_build.is_empty() {
                ai_versions.chatgpt.desktop.selected_build.as_str()
            } else {
                env.as_ref()
                    .and_then(|v| v.pointer("/chatgpt_app/build"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            };
            let now = native::now();
            let frame = claude_watch_runtime::channel_policy_status::read_frame(&host.storage);
            let frame = StatusFrame::new(&frame, &config, now);
            let evidence = frame.guard_summary();
            let policy_sync_state = frame.policy_sync_state();
            let service_status = background_from_frame(&host, &config, &frame, &evidence, now)?;
            Ok(Some(
                json!({"status":"ok","config":config.value()?,"legacy_openai_force_review":legacy_openai_force_review,"accounts":accounts,"chatgpt_accounts":chatgpt_accounts,"audit":audit,"service_status":service_status,"netcoffee_lookup":audit["netcoffee_lookup"],"source_notices":audit.get("source_notices").unwrap_or(&json!([])),
                "policy_sync_state": policy_sync_state,
                "repair":host.storage.read_json(&host.storage.paths.base().join("last-repair.json"),Value::Null)?,"guard":evidence,
                "update_recovery_required":host.storage.paths.base().join("update-transaction.json").exists(),"update_status":claude_watch_runtime::update::read_update_status(&host.storage),"setup_recovery_required":host.storage.paths.base().join("setup-transaction.json").exists()||host.storage.paths.base().join("service-transaction.json").exists()||host.storage.paths.watch().join("agent-install-transaction.json").exists(),"proxy_groups":[],
                "claude_version":claude_version,
                "claude_build":claude_build,
                "chatgpt_version":chatgpt_version,
                "chatgpt_build":chatgpt_build,
                "ai_versions":ai_versions}),
            ))
        }
        "check" | "checkdetail" | "environment" | "proxy-check" | "dns-check" => {
            let environment = request.command == "environment";
            let scope = match request.command.as_str() {
                "proxy-check" => AuditScope::Proxy,
                "dns-check" => AuditScope::Dns,
                _ => AuditScope::Full,
            };
            let persist = if environment {
                request.flag("record")
            } else {
                !request.flag("no-report")
            };
            let zones = if scope == AuditScope::Full {
                load_system_catalog()
            } else {
                Default::default()
            };
            let store = AuditStore::new(host.storage.clone());
            let options = AuditOptions {
                online: request.flag("online"),
                persist,
                // Previews use the same freshness and collection as launch,
                // while the response below still grants no launch permission.
                launch: matches!(request.command.as_str(), "check" | "checkdetail"),
            };
            // The same stage announcements the launch path uses, so a launch
            // requirements preview shows which part of the check is running
            // rather than sitting still until the whole audit finishes.
            if !environment && scope == AuditScope::Full {
                claude_watch_runtime::setup_progress::emit(
                    claude_watch_runtime::setup_progress::Phase::CollectEvidence,
                );
            }
            let (audit, guard_diagnostics) = if environment {
                store.collect_environment(&mut host, &zones, request.launch_target(), options)?
            } else if scope == AuditScope::Full {
                (
                    store.collect_launch_preview(&mut host, &zones, request.launch_target(), options)?,
                    None,
                )
            } else {
                (
                    store.collect_scope(&mut host, &zones, scope, options)?,
                    None,
                )
            };
            if !environment && scope == AuditScope::Full {
                claude_watch_runtime::setup_progress::emit(
                    claude_watch_runtime::setup_progress::Phase::VerifyLaunchConditions,
                );
            }
            Ok(Some(if environment {
                let mut receipt = claude_watch_runtime::environment_display::receipt(
                    &host.storage,
                    audit,
                    session_view(&host),
                    persist,
                )?;
                if let Some(trace) = guard_diagnostics {
                    if let Ok(value) = serde_json::to_value(trace) {
                        receipt["guard_diagnostics"] = value;
                    }
                }
                receipt
            } else {
                audit
            }))
        }
        _ => unreachable!(),
    }
}

/// One recovery entry coordinates the existing component services. It does
/// not invent a second transaction format or override account/update recovery.
pub fn recover_maintenance(request: &Request, paths: Paths) -> Result<Value> {
    request.require_apply()?;
    let mut host = host(paths, Authority::ExplicitPermit)?;
    let storage = host.storage.clone();
    let mut restored = Vec::new();
    if storage
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists()
    {
        // Only the coordinated recovery entry holds this internal capability.
        // Account/update recovery may not cross an unfinished agent install.
        let _operation = storage.lock("operation", Some("maintenance"))?;
        let uid = host.environment()?["uid"]
            .as_u64()
            .and_then(|u| u32::try_from(u).ok())
            .filter(|u| *u > 0)
            .ok_or_else(|| CoreError::new("uid_unavailable", "当前用户身份未确认"))?;
        let value = claude_watch_runtime::agent_install::recover(
            &storage,
            uid,
            &mut claude_watch_runtime::release_native::SystemExecutor,
        )?;
        if value["status"] == "partial" {
            return Ok(value);
        }
        restored.push(json!({"component":"agent","result":value}));
    }
    if storage
        .paths
        .base()
        .join("service-transaction.json")
        .exists()
    {
        let value = services::recover(&storage, &mut host)?;
        if value["status"] == "partial" {
            return Ok(value);
        }
        restored.push(json!({"component":"services","result":value}));
    }
    if storage.paths.base().join("setup-transaction.json").exists() {
        let value = claude_watch_runtime::onboarding::recover(&storage, &mut host)?;
        if value["status"] == "partial" {
            return Ok(value);
        }
        restored.push(json!({"component":"setup","result":value}));
    }
    Ok(
        json!({"status":"ok","recovered":restored,"message":"已检查并恢复环境、服务和原生后台安装事务"}),
    )
}

/// Native command boundary. Parsing and explicit apply checks happen before
/// constructing any adapter capable of controlling the desktop.
pub enum OperationOutcome {
    Receipt(Value),
    CliExit(claude_watch_runtime::controlled::CliOutcome),
}
pub(crate) fn dispatch_launch(
    request: &Request,
    storage: &StateStore,
    desktop: &mut impl claude_watch_runtime::controlled::DesktopSystem,
) -> Result<OperationOutcome> {
    let controller = claude_watch_runtime::controlled::Controller::new(storage.clone());
    if request.launch_target().cli() {
        Ok(OperationOutcome::CliExit(controller.launch_cli(desktop, &request.child_args)?))
    } else {
        let _operation = storage.lock("operation", None)?;
        Ok(OperationOutcome::Receipt(controller.launch(desktop)?))
    }
}
pub(crate) fn native_desktop_for_request<R: claude_watch_runtime::commands::ReadRunner>(
    request: &Request,
    storage: &StateStore,
    runner: R,
    process_helper: PathBuf,
    authority: Authority,
) -> Result<NativeDesktop<R>> {
    let mut desktop = NativeDesktop::new(runner, process_helper, authority)?;
    desktop.set_discovery(claude_watch_runtime::target_discovery::DiscoveryHandle::for_home(&storage.paths.home));
    if request.command == "launch" {
        let target = request.launch_target();
        if target.cli() {
            desktop.select_cli(target, &storage.paths.home)?;
        } else if let Some(path) = request.value("target-bundle") {
            desktop.select_target_source(target, std::path::Path::new(path))?;
        } else {
            desktop.select_target(target)?;
        }
    }
    Ok(desktop)
}
#[allow(dead_code)]
pub fn managed_entry_bundle_id(target: claude_watch_core::processes::LaunchTarget) -> &'static str {
    claude_watch_runtime::managed_entry::DesktopManagedEntrySpec::entry_bundle_id_for(target)
}
pub fn dispatch_operations(request: &Request, paths: Paths) -> Result<Option<OperationOutcome>> {
    use claude_watch_runtime::{
        account_native::AccountRuntimeHost, audit_store::AuditSystem, controlled::Controller,
        desktop_native::DesktopRuntime, receipt_store::ReceiptStore,
    };
    use std::time::Instant;
    if request.command == "process-exit" {
        use claude_watch_runtime::process_exit::{self, ExitPlan};
        let runner = runner()?;
        if request.action.as_deref() == Some("prepare") {
            let protected = request.value("protect-pid").map(|value| value.parse::<u32>()
                .map_err(|_| CoreError::new("invalid_arguments", "保护进程参数无效"))).transpose()?;
            let mut plan = process_exit::prepare(&runner, &paths, request.value("family").unwrap_or(""), false, protected)?;
            plan.force = request.flag("force");
            return Ok(Some(OperationOutcome::Receipt(serde_json::to_value(plan)
                .map_err(|_| CoreError::new("invalid_exit_plan", "退出计划编码失败"))?)));
        }
        request.require_apply()?;
        let plan: ExitPlan = serde_json::from_value(super::bounded_input(65536)?)
            .map_err(|_| CoreError::new("invalid_exit_plan", "退出计划格式无效"))?;
        if plan.force != request.flag("force") {
            return Err(CoreError::new("exit_action_mismatch", "确认的退出方式与计划不一致"));
        }
        let helper = process_component()?;
        let receipt = process_exit::execute(&runner, &paths, &plan,
            |process| claude_watch_runtime::desktop_native::request_appkit_quit(&helper, process))?;
        return Ok(Some(OperationOutcome::Receipt(serde_json::to_value(receipt)
            .map_err(|_| CoreError::new("invalid_exit_receipt", "退出回执编码失败"))?)));
    }
    if request.command == "evidence" {
        use claude_watch_core::evidence::{EvidenceAction, EvidenceRequest};
        let input: EvidenceRequest = serde_json::from_value(super::bounded_input(8192)?)
            .map_err(|_| CoreError::new("invalid_evidence_request", "检测请求格式无效"))?;
        input.validate()?;
        let expected_action = if request.action.as_deref() == Some("refresh") {
            request.require_apply()?;
            EvidenceAction::Refresh
        } else { EvidenceAction::Inspect };
        if input.action != expected_action { return Err(CoreError::new("invalid_evidence_request", "检测动作不一致")); }
        let result = claude_watch_runtime::evidence_client::request_daemon_evidence(
            &paths, &input, std::time::Duration::from_secs(claude_watch_core::evidence::REQUEST_TIMEOUT_SECONDS))?;
        return Ok(Some(OperationOutcome::Receipt(result)));
    }
    let account_action = request.command == "account"
        && matches!(request.action.as_deref(), Some("switch" | "recover" | "import"));
    let confirm_baseline = request.command == "environment" && request.flag("confirm-baseline");
    if !account_action
        && !confirm_baseline
        && !matches!(
            request.command.as_str(),
            "launch" | "guard-tick" | "dns-leak-record" | "webrtc-risk-record"
        )
    {
        return Ok(None);
    }
    if request.command != "guard-tick"
        && !(request.command == "account" && request.action.as_deref() == Some("import"))
    {
        request.require_apply()?;
    }
    let mut host = host(paths, Authority::ExplicitPermit)?;
    let storage = host.storage.clone();
    if confirm_baseline {
        let confirmed_path = storage.paths.base().join("confirmed-environment.json");
        let mut confirmed = storage.read_json(&confirmed_path, Value::Null)?;
        if confirmed.is_null() || !confirmed.is_object() {
            return Err(CoreError::new("baseline_missing", "未找到已确认环境基准文件"));
        }
        let target_ip = if let Some(ip) = request.value("ip") {
            ip.to_owned()
        } else {
            let last_detect = storage
                .read_json(&storage.paths.base().join("last-environment-detection.json"), Value::Null)
                .unwrap_or(Value::Null);
            let observed_ip = last_detect
                .pointer("/display_facts/online/trace/ip")
                .and_then(Value::as_str)
                .unwrap_or("");
            if observed_ip.is_empty() {
                let egress = host.network.fast_egress();
                egress
                    .data
                    .as_ref()
                    .and_then(|d| d.get("ip"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()
            } else {
                observed_ip.to_owned()
            }
        };
        let valid_target_ip = claude_watch_core::network::public_unicast(&target_ip)
            .ok_or_else(|| CoreError::new("invalid_ip", "实测出口 IP 无效或非公网单播 IP"))?;

        let node_name = request.value("node").map(str::to_owned).or_else(|| {
            let last_detect = storage
                .read_json(&storage.paths.base().join("last-environment-detection.json"), Value::Null)
                .unwrap_or(Value::Null);
            last_detect
                .pointer("/display_facts/local/tag/api/selected_node")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });

        confirmed["values"]["ip"] = json!(valid_target_ip);
        if let Some(node) = node_name {
            if !node.is_empty() {
                confirmed["values"]["node"] = json!(node);
            }
        }
        confirmed["confirmed_at"] = json!(native::now());
        if confirmed.get("sources").and_then(Value::as_object).is_some() {
            confirmed["sources"]["ip"] = json!("主公手动核准新出口基准");
        }
        storage.atomic_json(&confirmed_path, &confirmed)?;

        // 同步清理/解除已停止旧会话上的 IP 阻断锁，避免旧会话阻碍新启动
        let session_path = storage.paths.session();
        if session_path.is_file() {
            if let Ok(mut session) = storage.read_json(&session_path, Value::Null) {
                let state = session.get("state").and_then(Value::as_str).unwrap_or("");
                if state == "locked" || state == "ended" {
                    session["state"] = json!("ended");
                    session["baseline"]["ip"] = json!(valid_target_ip);
                    let _ = storage.atomic_json(&session_path, &session);
                }
            }
        }

        return Ok(Some(OperationOutcome::Receipt(json!({
            "status": "ok",
            "confirmed_ip": valid_target_ip,
            "message": format!("已成功核准出口基准为 {}", valid_target_ip)
        }))));
    }
    if matches!(
        request.command.as_str(),
        "dns-leak-record" | "webrtc-risk-record"
    ) {
        let value = super::bounded_input(request.input_limit())?;
        let probe = value.get("probe").unwrap_or(&value);
        let expected = value.get("expected_context").and_then(Value::as_str);
        let expected_ip = value.get("expected_ip").and_then(Value::as_str);
        let mut probe_val = probe.clone();
        if let Some(ip) = expected_ip {
            probe_val["expected_ip"] = json!(ip);
        }
        let config = ConfigStore {
            storage: storage.clone(),
        }
        .load()?;
        let local = AuditSystem::local(&host, &config)?;
        let receipts = ReceiptStore { storage };
        if request.command == "dns-leak-record" {
            let receipt = receipts.record_dns(&probe_val, &local, expected, native::now())?;
            let context = receipt["context"].as_str().unwrap_or("");
            let current =
                receipts.dns_status(context, false, native::now(), |at| format!("{at:.0}"));
            return Ok(Some(OperationOutcome::Receipt(
                json!({"status":"ok","context_id":receipt["context"],"sampled_at":receipt["finished_at"],"dns_row":claude_watch_core::receipts::dns_row(&current),"receipt":receipt}),
            )));
        }
        return Ok(Some(OperationOutcome::Receipt(
            json!({"status":"ok","receipt":receipts.record_webrtc(&probe_val,&local,expected,native::now())?}),
        )));
    }
    let authority = if request.flag("apply") || request.command == "guard-tick" {
        Authority::ExplicitPermit
    } else {
        Authority::ReadOnly
    };
    let process_helper = process_component()?;
    #[cfg(all(test, target_os = "macos"))]
    if request.command == "launch" && super::entry_ready_fixture::is_fixture_child() {
        return super::entry_ready_fixture::fixture_launch(
            request, &storage, host.runner.clone(), process_helper, authority,
        ).map(Some);
    }
    let mut desktop = native_desktop_for_request(request, &storage, host.runner.clone(), process_helper, authority)?;
    if account_action && request.value("product") == Some("chatgpt") {
        let slot = claude_watch_runtime::accounts::chatgpt::Slot::parse(request.target.as_deref())?;
        desktop.select_chatgpt_account_client()?;
        let mut runtime = DesktopRuntime { desktop: &mut desktop, network: host.network.clone(),
            system: &mut host, storage: storage.clone(), started: Instant::now(), cli: None };
        let result = Controller::new(storage).switch_chatgpt_account(&mut runtime, slot)?;
        return Ok(Some(OperationOutcome::Receipt(result)));
    }
    if account_action {
        let config = ConfigStore {
            storage: storage.clone(),
        }
        .load()?;
        let legacy = storage.paths.home.join(".claude-switcher");
        let native = AccountRuntimeHost {
            storage: storage.clone(),
            controller: Controller::new(storage.clone()),
            desktop,
            network: host.network.clone(),
            system: host,
        };
        let mut accounts = AccountStore::new(storage, native);
        return Ok(Some(OperationOutcome::Receipt(
            match request.action.as_deref() {
                Some("switch") => accounts
                    .switch(
                        request
                            .target
                            .as_deref()
                            .ok_or_else(|| CoreError::new("invalid_account", "需要账号 A 或 B"))?,
                        &config,
                        request.flag("ack-unverified-version"),
                    )?
                    .value(),
                Some("recover") => {
                    accounts.recover()?;
                    json!({"status":"ok","accounts":accounts.status()?.value()})
                }
                Some("import") => accounts
                    .import_legacy(&legacy, request.flag("apply"))?
                    .value(),
                _ => unreachable!(),
            },
        )));
    }
    let mut desktop_runtime = DesktopRuntime {
        desktop: &mut desktop,
        network: host.network.clone(),
        system: &mut host,
        storage: storage.clone(),
        started: Instant::now(),
        cli: None,
    };
    if request.command == "launch" {
        Ok(Some(dispatch_launch(request, &storage, &mut desktop_runtime)?))
    } else {
        Ok(Some(OperationOutcome::Receipt(
            Controller::new(storage).guard_tick(&mut desktop_runtime)?,
        )))
    }
}

#[cfg(test)]
mod session_heartbeat_projection_tests {
    use super::*;
    fn heartbeat(id: &str, stop: &str) -> Value {
        json!({"session_id":id,"persistence_error":"state_io_failed", "stop_state":stop,
            "stop_error":"quit_failed", "session_guard":{"reason":{"code":"egress_risk_persist_failed","detail":"risk"}}})
    }
    #[test]
    fn projection_binds_risk_and_stop_to_current_session_and_observation() {
        let safe = json!({"state":"safe"});
        let mut other = safe.clone();
        project_session_heartbeat(&mut other, "new", Some(true), &heartbeat("old", "failed"));
        assert_eq!(other, safe);
        let mut superseded = safe.clone();
        project_session_heartbeat(
            &mut superseded,
            "same",
            Some(true),
            &heartbeat("same", "session_changed"),
        );
        assert_eq!(superseded, safe);
        let mut failed = safe.clone();
        project_session_heartbeat(
            &mut failed,
            "same",
            Some(true),
            &heartbeat("same", "failed"),
        );
        assert_eq!(failed["state"], "locked");
        assert_eq!(failed["stop_state"], "failed");
        for running in [Some(true), None] {
            let mut current = safe.clone();
            project_session_heartbeat(
                &mut current,
                "same",
                running,
                &heartbeat("same", "confirmed"),
            );
            assert_eq!(current["state"], "locked");
            assert!(current.get("stop_state").is_none());
        }
        let mut stopped = safe.clone();
        project_session_heartbeat(
            &mut stopped,
            "same",
            Some(false),
            &heartbeat("same", "confirmed"),
        );
        assert_eq!(stopped["stop_state"], "confirmed");
        let mut ended = json!({"state":"idle","phase":"ended"});
        project_session_heartbeat(
            &mut ended,
            "same",
            Some(false),
            &heartbeat("same", "failed"),
        );
        assert_eq!(
            ended["state"], "idle",
            "a stale failure cannot resurrect an ended session"
        );
    }

    #[test]
    fn service_detail_mapping_is_truthful_and_distinguishes_receipt() {
        let rows = vec![
            json!({"id": "guard", "state": "running", "execution_verified": true}),
            json!({"id": "original", "state": "scheduled", "execution_verified": false}),
            json!({"id": "original", "state": "scheduled", "execution_verified": true}),
            json!({"id": "guard", "state": "pending", "execution_verified": false}),
            json!({"id": "watchdog", "state": "scheduled", "execution_verified": true}),
            json!({"id": "watchdog", "state": "scheduled", "execution_verified": false}),
            json!({"id": "other", "state": "inactive", "execution_verified": false}),
        ];
        let details: Vec<&str> = rows.iter().map(background_service_detail).collect();

        assert_eq!(
            details,
            vec![
                "保护心跳与后台身份已确认",
                "原版任务已注册，最近巡检回执尚未确认；由原版独立管理",
                "原版独立运行，已确认最近巡检回执",
                "保护后台运行中，正在等待有效保护证据",
                "任务已注册，且已确认最近时区巡检回执",
                "任务已注册，等待或尚未确认最近执行回执",
                "该后台任务已停用",
            ]
        );
    }

    #[test]
    fn service_wire_runs_the_public_background_enrichment() {
        let Ok(dir) = std::env::var("CW_SERVICE_WIRE_FIXTURES") else { return; };
        let dir = std::path::PathBuf::from(dir);
        let output = dir.join("public");
        std::fs::create_dir_all(&output).unwrap();
        for name in ["live-stale-unready.json","original-fresh.json"] {
            let mut value: Value = serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap();
            enrich_background_services(&mut value);
            assert!(value["backend_diagnostics"]["reason"].is_string());
            for row in value["services"].as_array().unwrap() {
                assert!(row["detail"].as_str().is_some_and(|s| !s.is_empty()));
                assert_eq!(row["last_checked"],value["observed_at"]);
            }
            std::fs::write(output.join(name),serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        }
    }
}
