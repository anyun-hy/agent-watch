use claude_watch_core::{
    cli::Request,
    config::valid_loopback_proxy,
    error::{CoreError, Result},
    release_source::resolve_update_source,
};
use claude_watch_runtime::{
    app_lifecycle::{AppLifecycle, LifecyclePaths, APP_NAME},
    config_store::ConfigStore,
    native::{self, Observer},
    release_native::{FixedCommand, FixedCommandExecutor, NativeRelease, SystemExecutor},
    storage::{Paths, StateStore},
    update::{
        record_update_status, ConfiguredTransport, UpdatePaths, Updater, VerifiedUpdateStage,
    },
};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

fn preferred_update_proxy(config: &claude_watch_core::config::Config) -> Option<String> {
    let candidates = [
        config
            .vpn_expectation
            .as_ref()
            .filter(|e| e.configured)
            .map(|e| e.proxy_url.as_str()),
        Some(config.proxy_url.as_str()),
    ];
    for candidate in candidates.into_iter().flatten() {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && valid_loopback_proxy(trimmed) {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn validate_staged_dir(base: &Path, raw: &str) -> Result<PathBuf> {
    let candidate = PathBuf::from(raw);
    if !candidate.is_absolute() {
        return Err(CoreError::new("invalid_update_stage", "暂存目录必须是绝对路径"));
    }
    let canonical_base = fs::canonicalize(base)
        .map_err(|_| CoreError::new("invalid_update_stage", "无法定位状态根目录"))?;
    let meta = fs::symlink_metadata(&candidate)
        .map_err(|_| CoreError::new("invalid_update_stage", "更新暂存目录不存在"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(CoreError::new("invalid_update_stage", "更新暂存目录无效"));
    }
    let canonical_stage = fs::canonicalize(&candidate)
        .map_err(|_| CoreError::new("invalid_update_stage", "无法核验更新暂存目录"))?;
    if canonical_stage.parent() != Some(canonical_base.as_path()) {
        return Err(CoreError::new(
            "invalid_update_stage",
            "更新暂存目录不属于本工具受控目录",
        ));
    }
    let name = canonical_stage
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if !name.starts_with("update-stage-") {
        return Err(CoreError::new("invalid_update_stage", "更新暂存目录名称无效"));
    }
    Ok(canonical_stage)
}

pub(crate) fn sweep_stale_update_stages(base: &Path) {
    let max_age = Duration::from_secs(30 * 60);
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with("update-stage-") {
            continue;
        }
        let is_stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= max_age);
        if is_stale {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn install_verified_app(
    storage: &StateStore,
    paths: &Paths,
    uid: u32,
    stage_dir: &Path,
    relaunch: bool,
) -> Result<Value> {
    let staged_app = stage_dir.join("payload/app").join(APP_NAME);
    if !staged_app.is_dir() {
        let _ = fs::remove_dir_all(stage_dir);
        return Err(CoreError::new(
            "release_incomplete",
            "已校验的更新应用目录缺失",
        ));
    }
    // When upgrading from v4.2.5/v4.2.6, the old updater extracts newly introduced
    // signed executables (`watch-vpn-core`) with mode 0600; restore 0700 here before
    // `AppLifecycle::apply` installs the verified bundle.
    let staged_vpn_core = staged_app.join("Contents/Resources/watch-vpn-core");
    if let Ok(meta) = fs::symlink_metadata(&staged_vpn_core) {
        if meta.is_file() && !meta.file_type().is_symlink() {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&staged_vpn_core, fs::Permissions::from_mode(0o700));
        }
    }
    let _operation = storage.lock("operation", None)?;
    let mut lifecycle = AppLifecycle {
        paths: LifecyclePaths {
            installed: PathBuf::from("/Applications").join(APP_NAME),
            trash: paths.home.join(".Trash"),
            protected_data: paths.watch(),
        },
        os: NativeRelease::production(&paths.home, uid),
    };
    let install_result = lifecycle.apply(&staged_app);
    let _ = fs::remove_dir_all(stage_dir);
    let identity = match install_result {
        Ok(identity) => identity,
        Err(error) => {
            record_update_status(
                storage,
                &json!({
                    "schema": 1,
                    "checked_at": native::now(),
                    "status": "failed",
                    "error_code": error.code,
                    "message": format!("应用更新替换未完成：{}", error.message),
                }),
            );
            return Err(error);
        }
    };
    let now = native::now();
    record_update_status(
        storage,
        &json!({
            "schema": 1,
            "checked_at": now,
            "status": "current",
            "current_version": identity.version,
            "current_build": identity.build.parse::<u64>().ok(),
            "message": "应用与后台已完成更新并保留全部配置与账号"
        }),
    );
    if relaunch {
        let _ = SystemExecutor.run(FixedCommand {
            program: "/usr/bin/open".into(),
            args: vec![
                "-a".into(),
                PathBuf::from("/Applications")
                    .join(APP_NAME)
                    .display()
                    .to_string(),
            ],
            timeout: Duration::from_secs(10),
        });
    }
    Ok(json!({
        "status": "ok",
        "version": identity.version,
        "build": identity.build,
        "architecture": identity.architecture,
        "gateway_cleanup_pending": lifecycle.os.gateway_cleanup_warning().is_some(),
        "gateway_cleanup_warning": lifecycle.os.gateway_cleanup_warning(),
        "message": "应用与后台已更新并保留全部配置与账号；无需重新初始化。"
    }))
}

fn spawn_detached_staged_install(
    paths: &Paths,
    stage_dir: &Path,
    relaunch: bool,
) -> Result<()> {
    // Prefer the verified staged runtime binary outside `/Applications/Agent Watch.app`
    // so moving the old app bundle to Trash and resetting TCC never perturbs the
    // running installer process.
    let staged_exe = stage_dir.join("payload/runtime/watch-engine");
    let exe = if staged_exe.is_file() {
        staged_exe
    } else {
        std::env::current_exe()
            .map_err(|_| CoreError::new("update_handoff_failed", "无法定位更新执行引擎"))?
    };
    let mut cmd = Command::new(exe);
    cmd.args([
        "--home",
        paths
            .home
            .to_str()
            .ok_or_else(|| CoreError::new("update_handoff_failed", "用户目录路径无效"))?,
        "update",
        "--install-staged",
        stage_dir
            .to_str()
            .ok_or_else(|| CoreError::new("update_handoff_failed", "暂存目录路径无效"))?,
        "--apply",
    ]);
    if relaunch {
        cmd.arg("--relaunch");
    }
    let log_dir = paths.watch().join("logs");
    let _ = fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("update-install.log");
    let stdout_cfg = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null());
    let stderr_cfg = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null());
    cmd.stdin(Stdio::null())
        .stdout(stdout_cfg)
        .stderr(stderr_cfg);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Isolate into its own session so terminating the Monitor GUI never
        // terminates the authoritative installer handoff process.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd.spawn()
        .map_err(|_| CoreError::new("update_handoff_failed", "无法启动独立更新安装进程"))?;
    Ok(())
}

pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if request.command != "update" {
        return Ok(None);
    }
    let storage = StateStore::new(paths.clone());
    let config = ConfigStore {
        storage: storage.clone(),
    }
    .load()?;
    let runner = crate::runtime::runner()?;
    let environment = Observer {
        runner: runner.as_ref(),
    }
    .environment()?;
    let uid = environment["uid"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| CoreError::new("uid_unavailable", "当前用户身份未确认"))?;

    if let Some(raw_stage) = request.value("install-staged") {
        request.require_apply()?;
        let stage_dir = validate_staged_dir(&paths.base(), raw_stage)?;
        // Give the parent GUI IPC response a brief window to flush before stopping the app.
        std::thread::sleep(Duration::from_millis(350));
        return Ok(Some(install_verified_app(
            &storage,
            &paths,
            uid,
            &stage_dir,
            request.flag("relaunch"),
        )?));
    }

    if request.flag("recover") {
        request.require_apply()?;
        let _operation = storage.lock("operation", Some("update"))?;
        let mut updater = Updater {
            paths: UpdatePaths {
                base: paths.base(),
                app: PathBuf::from("/Applications").join(APP_NAME),
                watch: paths.watch(),
                backend: paths.watch().join("claude-watch.sh"),
            },
            os: NativeRelease::production(&paths.home, uid),
            transport: ConfiguredTransport { proxy_url: None },
        };
        let reauthorization = updater.recover()?;
        return Ok(Some(if reauthorization {
            json!({"status":"partial","reauthorization_required":true,"message":"应用和后台已恢复；辅助功能授权可能已被清除，请在系统提示中重新授权。"})
        } else {
            json!({"status":"ok","reauthorization_required":false,"message":"已恢复更新事务"})
        }));
    }

    if request.flag("auto") && !config.auto_update {
        return Ok(Some(
            json!({"status":"disabled","message":"自动更新未启用"}),
        ));
    }

    let Some(source) = resolve_update_source(&config.update_url, &config.update_public_key) else {
        return Ok(Some(
            json!({"status":"unavailable","message":"尚未配置本项目发布源和固定公钥；未发起下载"}),
        ));
    };

    sweep_stale_update_stages(&paths.base());

    let mut updater = Updater {
        paths: UpdatePaths {
            base: paths.base(),
            app: PathBuf::from("/Applications").join(APP_NAME),
            watch: paths.watch(),
            backend: paths.watch().join("claude-watch.sh"),
        },
        os: NativeRelease::production(&paths.home, uid),
        transport: ConfiguredTransport {
            proxy_url: preferred_update_proxy(&config),
        },
    };

    // Unattended scheduled checks (`--auto`) and read-only checks (no `--apply`)
    // never pop administrator dialogs or interrupt an open GUI; they check the
    // signed manifest and persist the redacted status for UI display.
    if !request.flag("apply") || request.flag("auto") {
        let mut receipt = updater.check(&source.url, &source.public_key, false)?;
        receipt["source_builtin"] = json!(source.is_builtin);
        if request.flag("auto") && receipt["status"] == "available" {
            receipt["interactive_install_required"] = json!(true);
            receipt["message"] = json!(format!(
                "{}；请在 Agent Watch 界面点击「下载并安装更新」完成替换",
                receipt["message"].as_str().unwrap_or("发现新版本")
            ));
        }
        record_update_status(
            &storage,
            &json!({
                "schema": 1,
                "checked_at": native::now(),
                "status": receipt["status"],
                "version": receipt["version"],
                "build": receipt["build"],
                "current_version": receipt["current_version"],
                "current_build": receipt["current_build"],
                "source_builtin": source.is_builtin,
                "message": receipt["message"]
            }),
        );
        return Ok(Some(receipt));
    }

    // Interactive apply: download and cryptographically verify the signed release
    // FIRST while the running app stays untouched, then hand off to the single
    // authoritative `AppLifecycle::apply` (preserving all user data and updating
    // Seatbelt root gateway component pins atomically).
    match updater.fetch_and_verify_staging(&source.url, &source.public_key)? {
        VerifiedUpdateStage::Current {
            current_version,
            current_build,
        } => {
            let receipt = json!({
                "status": "current",
                "version": current_version,
                "build": current_build,
                "source_builtin": source.is_builtin,
                "message": "当前已是最新版本"
            });
            record_update_status(
                &storage,
                &json!({
                    "schema": 1,
                    "checked_at": native::now(),
                    "status": "current",
                    "version": current_version,
                    "build": current_build,
                    "source_builtin": source.is_builtin,
                    "message": "当前已是最新版本"
                }),
            );
            Ok(Some(receipt))
        }
        VerifiedUpdateStage::Available {
            stage_dir,
            release,
            ..
        } => {
            if request.flag("detach") {
                if let Err(error) =
                    spawn_detached_staged_install(&paths, &stage_dir, request.flag("relaunch"))
                {
                    let _ = fs::remove_dir_all(&stage_dir);
                    return Err(error);
                }
                return Ok(Some(json!({
                    "status": "installing",
                    "version": release.version,
                    "build": release.build,
                    "source_builtin": source.is_builtin,
                    "message": "更新包已通过签名校验，正在退出监控窗口并安装新版（保留全部配置与账号）…"
                })));
            }
            Ok(Some(install_verified_app(
                &storage,
                &paths,
                uid,
                &stage_dir,
                request.flag("relaunch"),
            )?))
        }
    }
}
