//! Unified desktop wrapper entry (`io.local.watchpanel.entry.<target-id>`) and
//! CLI shim entry (`claude` / `codex`) sharing the same Rust supervision,
//! `nono` Seatbelt launcher (`watch-sandbox-launcher`), and `SandboxLaunchRegistry`.
//!
//! Key invariants:
//! - Never modifies or re-signs the original `.app` bundle or original CLI installation.
//! - If an unmanaged instance of the target is already running (`D02`), returns
//!   `already_running_unmanaged` with `ManagedInstanceState::RunningUnprotected`
//!   and never falsely marks the process as protected or kills it.
//! - Direct `fork`/`exec` children inherit the irreversible Seatbelt profile (`D03`),
//!   Unix domain socket network relays are blocked by `(deny network*)` (`D05`),
//!   and any out-of-tree `NSWorkspace`/`LaunchServices` process not registered in
//!   `SandboxLaunchRegistry` is surfaced as `RunningUnprotected` (`D04`).
//! - A staged CLI shim forwards the original arguments to the engine's controlled
//!   launch command and supplies its own path for target discovery to exclude.

use crate::sandbox_launch::SandboxLaunchRegistry;
use claude_watch_core::{
    channel::PolicyVersion,
    controlled_launch::{
        ControlledLaunchRequest, ManagedInstanceState, ManagedLaunchInstance, ProxyAdaptationKind,
    },
    error::{CoreError, Result},
    processes::LaunchTarget,
    vpn::VpnEpoch,
};
use claude_watch_system::sha256_file_hex;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopManagedEntrySpec {
    pub entry_bundle_id: String,
    pub target: LaunchTarget,
    pub target_bundle_path: PathBuf,
    pub target_bundle_id: String,
    pub target_executable: PathBuf,
    pub target_fingerprint: String,
    pub proxy_adaptation: ProxyAdaptationKind,
}

impl DesktopManagedEntrySpec {
    /// Returns true when the `.app` bundle contains the Chromium/OpenAI Aperitif
    /// helper and library (`Codex (Aperitif)` + `libaperitif.dylib`), which reapply
    /// Seatbelt during initialization and abort when launched under Watch's Seatbelt.
    pub fn bundle_has_aperitif_components(bundle: &Path) -> bool {
        let Ok(canon_bundle) = fs::canonicalize(bundle) else {
            return false;
        };
        let framework = canon_bundle
            .join("Contents/Frameworks/Codex Framework.framework/Versions/Current");
        let in_bundle_file = |relative: &str| {
            let Ok(path) = fs::canonicalize(framework.join(relative)) else {
                return false;
            };
            path.starts_with(&canon_bundle) && fs::metadata(&path).is_ok_and(|m| m.is_file())
        };
        in_bundle_file("Helpers/Codex (Aperitif).app/Contents/MacOS/Codex (Aperitif)")
            && in_bundle_file("Libraries/libaperitif.dylib")
    }

    pub(crate) fn may_match_seatbelt_conflict(bundle_id: &str, executable: &Path) -> bool {
        // Preview should not hash an unrelated large Codex executable unless it
        // either matches the known build 28661 binary size, is missing (so
        // managed_spec reports its identity error), or carries Aperitif inside the bundle.
        if bundle_id != "com.openai.codex" {
            return false;
        }
        if fs::metadata(executable).map_or(true, |m| m.len() == 71_008) {
            return true;
        }
        executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .is_some_and(Self::bundle_has_aperitif_components)
    }

    /// Blocks `com.openai.codex` desktop builds whose embedded Aperitif helper
    /// reapplies Seatbelt during initialization (observed on builds 28661 and 29513).
    pub fn check_seatbelt_compatibility(&self) -> Result<()> {
        const MAIN: &str = "00305cecf34970bd6fffcd108812bb88888fbb89447ffb7d3bf966a43319a13f";
        const HELPER: &str = "564867489d1ebcb6aec6965face332478ae9d73d6fc1f2af8c9fbc496751c53d";
        const LIBRARY: &str = "16aa60f1543a10bac31341548349ae7af5e4b7ce637e20a103dc66f4147b43f5";
        if self.target_bundle_id != "com.openai.codex" {
            return Ok(());
        }
        if self.target_fingerprint == MAIN {
            let framework = self.target_bundle_path.join("Contents/Frameworks/Codex Framework.framework/Versions/Current");
            let verify = |relative: &str, size: u64, sha: &str| {
                let path = fs::canonicalize(framework.join(relative)).ok()?;
                if !path.starts_with(&self.target_bundle_path) { return None; }
                if fs::metadata(&path).ok()?.len() != size { return Some(false); }
                crate::executable_verification::VerificationKey::new_regular(path.to_str()?, sha)?.verify()
            };
            let helper = verify("Helpers/Codex (Aperitif).app/Contents/MacOS/Codex (Aperitif)", 51_568, HELPER);
            let library = verify("Libraries/libaperitif.dylib", 85_456, LIBRARY);
            return match (helper, library) {
                (Some(true), Some(true)) => Err(CoreError::new("desktop_sandbox_incompatible",
                    "此 ChatGPT 构建（28661）的 Aperitif 辅助进程与当前 Seatbelt 启动方式冲突，已阻止启动。")),
                _ => Err(CoreError::new("desktop_compatibility_unverified",
                    "此 ChatGPT 主程序与已知构建相同，Aperitif 组件的身份未能确认，请核对应用更新是否已完成。")),
            };
        }
        if Self::bundle_has_aperitif_components(&self.target_bundle_path) {
            return Err(CoreError::new(
                "desktop_sandbox_incompatible",
                "此 ChatGPT / Codex 桌面构建包含 Aperitif 辅助进程组件，与当前 Seatbelt 启动方式冲突，已阻止启动。",
            ));
        }
        Ok(())
    }

    pub fn entry_bundle_id_for(target: LaunchTarget) -> &'static str {
        match target {
            LaunchTarget::ClaudeDesktop => "io.local.watchpanel.entry.claude-desktop",
            LaunchTarget::CodexDesktop => "io.local.watchpanel.entry.codex-desktop",
            LaunchTarget::ChatgptDesktop => "io.local.watchpanel.entry.chatgpt-desktop",
            LaunchTarget::ClaudeCli => "io.local.watchpanel.entry.claude-cli",
            LaunchTarget::CodexCli => "io.local.watchpanel.entry.codex-cli",
        }
    }

    /// Resolves a desktop `.app` bundle by reading its `Contents/Info.plist`
    /// (`CFBundleIdentifier` and `CFBundleExecutable`) without mutating any file
    /// inside the original `.app`.
    pub fn resolve_from_app_bundle(
        target: LaunchTarget,
        app_bundle: &Path,
        expected_bundle_id: &str,
        cf_bundle_executable: &str,
    ) -> Result<Self> {
        if cf_bundle_executable.trim().is_empty()
            || cf_bundle_executable.contains(['/', '\\'])
            || matches!(cf_bundle_executable, "." | "..")
        {
            return Err(CoreError::new(
                "invalid_bundle_executable",
                "目标 .app 的 CFBundleExecutable 无效",
            ));
        }
        let canon_bundle = fs::canonicalize(app_bundle).map_err(|_| {
            CoreError::new("target_bundle_missing", "目标桌面应用 .app 目录不存在")
        })?;
        let exe_path = canon_bundle
            .join("Contents/MacOS")
            .join(cf_bundle_executable);
        let canon_exe = fs::canonicalize(&exe_path).map_err(|_| {
            CoreError::new("target_executable_missing", "目标桌面应用主程序不存在")
        })?;
        if !canon_exe.starts_with(canon_bundle.join("Contents/MacOS")) {
            return Err(CoreError::new(
                "target_executable_outside_bundle",
                "目标桌面应用主程序不在 Contents/MacOS 范围内",
            ));
        }
        let meta = fs::metadata(&canon_exe).map_err(|_| {
            CoreError::new("target_executable_unreadable", "目标桌面应用主程序无法读取")
        })?;
        if !meta.is_file() || (meta.permissions().mode() & 0o111 == 0) {
            return Err(CoreError::new(
                "target_executable_not_executable",
                "目标桌面应用主程序缺少可执行权限",
            ));
        }
        let fingerprint = sha256_file_hex(&canon_exe).ok_or_else(|| {
            CoreError::new("target_fingerprint_failed", "无法计算目标桌面应用主程序 SHA-256")
        })?;
        let adaptation = match target {
            LaunchTarget::ClaudeDesktop
            | LaunchTarget::CodexDesktop
            | LaunchTarget::ChatgptDesktop => {
                ProxyAdaptationKind::EnvAndElectronSwitches
            }
            _ => ProxyAdaptationKind::EnvOnly,
        };
        Ok(Self {
            entry_bundle_id: Self::entry_bundle_id_for(target).to_string(),
            target,
            target_bundle_path: canon_bundle,
            target_bundle_id: expected_bundle_id.to_string(),
            target_executable: canon_exe,
            target_fingerprint: fingerprint,
            proxy_adaptation: adaptation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningProcessSnapshot {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub start_seconds: u64,
    pub start_microseconds: u32,
    pub executable: String,
    pub bundle_id: Option<String>,
}

/// Captures a live kernel snapshot of all processes owned by the current effective UID.
pub fn snapshot_running_processes() -> Result<Vec<RunningProcessSnapshot>> {
    let uid = claude_watch_system::effective_uid();
    let mut out = Vec::new();
    for pid in claude_watch_system::list_user_pids(uid) {
        if let Some(info) = claude_watch_system::inspect_process_identity(pid) {
            if info.uid == uid {
                out.push(RunningProcessSnapshot {
                    pid: info.pid,
                    ppid: info.ppid,
                    uid: info.uid,
                    start_seconds: info.start_seconds,
                    start_microseconds: info.start_microseconds,
                    executable: info.executable_path,
                    bundle_id: None,
                });
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DesktopEntryPreparation {
    /// No unmanaged instance is running; ready to launch through `watch-sandbox-launcher`.
    ReadyToLaunch {
        request: ControlledLaunchRequest,
    },
    /// An unmanaged instance is already running (`D02`).
    /// Must NOT claim protection and must NOT terminate the user's running window.
    AlreadyRunningUnmanaged {
        code: String,
        state: ManagedInstanceState,
        unmanaged_pids: Vec<u32>,
        message: String,
    },
}

/// Evaluates running processes for the target desktop app (`D02`, `D03`, `D04`):
/// - Any running process matching the target bundle/executable that is NOT a
///   verified `ManagedLaunchInstance` (or a direct child in its process tree with
///   matching `executor_boot_id` and `policy_version`) is classified as
///   `ManagedInstanceState::RunningUnprotected`.
/// - If any unmanaged instance is already running, refuses to silently attach
///   and returns `DesktopEntryPreparation::AlreadyRunningUnmanaged` (`already_running_unmanaged`).
pub fn prepare_desktop_managed_launch(
    spec: &DesktopManagedEntrySpec,
    running_processes: &[RunningProcessSnapshot],
    registry: &SandboxLaunchRegistry,
    executor_boot_id: &str,
    policy_version: &PolicyVersion,
    vpn_epoch: Option<VpnEpoch>,
    gateway_addr: SocketAddr,
    args: Vec<String>,
) -> Result<DesktopEntryPreparation> {
    let managed_instances = registry.instances();
    let mut unmanaged_pids = Vec::new();
    let canon_target_str = spec.target_executable.to_string_lossy();

    for proc_info in running_processes {
        let matches_target = proc_info.bundle_id.as_deref() == Some(spec.target_bundle_id.as_str())
            || proc_info.executable == canon_target_str;
        if !matches_target {
            continue;
        }
        let is_verified_managed = managed_instances.iter().any(|inst| {
            inst.has_verified_protection(executor_boot_id, policy_version)
                && ((inst.pid == proc_info.pid
                    && inst.uid == proc_info.uid
                    && inst.start_seconds == proc_info.start_seconds
                    && inst.start_microseconds == proc_info.start_microseconds)
                    || inst.controlled_subtree_pids.contains(&proc_info.pid)
                    || inst.pid == proc_info.ppid)
        });
        if !is_verified_managed {
            unmanaged_pids.push(proc_info.pid);
        }
    }

    if !unmanaged_pids.is_empty() {
        return Ok(DesktopEntryPreparation::AlreadyRunningUnmanaged {
            code: "already_running_unmanaged".into(),
            state: ManagedInstanceState::RunningUnprotected,
            unmanaged_pids,
            message: "检测到未受控的已有应用实例正在运行（running_unprotected）；不会假冒已保护，请先自行退出原实例后再从受控入口启动".into(),
        });
    }

    let req = ControlledLaunchRequest {
        entry_id: spec.entry_bundle_id.clone(),
        target: spec.target,
        target_executable: canon_target_str.into_owned(),
        target_fingerprint: spec.target_fingerprint.clone(),
        args,
        cwd: None,
        proxy_adaptation: spec.proxy_adaptation,
        gateway_endpoint: gateway_addr.to_string(),
        policy_version: policy_version.clone(),
        vpn_epoch,
        launch_nonce: format!("nonce-{}", Uuid::new_v4()),
        executor_boot_id: executor_boot_id.to_string(),
        script_entry: None,
        script_fingerprint: None,
        interpreter: None,
        interpreter_fingerprint: None,
        script_source: None,
    };
    req.validate()?;
    Ok(DesktopEntryPreparation::ReadyToLaunch { request: req })
}

/// Classifies a discovered process for monitor/truthful reporting (`D02`, `D03`, `D04`):
/// - Direct `fork`/`exec` children of a verified `ManagedLaunchInstance` inherit the
///   Seatbelt sandbox (`ExecVerified`).
/// - Out-of-tree processes (such as `NSWorkspace` / `LaunchServices` launches whose parent
///   is `launchd` PID 1 and which have no verified registration in `SandboxLaunchRegistry`)
///   are reported as `ManagedInstanceState::RunningUnprotected` (`running_unprotected`).
pub fn classify_process_protection_state(
    proc_info: &RunningProcessSnapshot,
    managed_instances: &[ManagedLaunchInstance],
    executor_boot_id: &str,
    policy_version: &PolicyVersion,
) -> ManagedInstanceState {
    for inst in managed_instances {
        if !inst.has_verified_protection(executor_boot_id, policy_version) {
            continue;
        }
        if inst.pid == proc_info.pid
            && inst.uid == proc_info.uid
            && inst.start_seconds == proc_info.start_seconds
            && inst.start_microseconds == proc_info.start_microseconds
        {
            return ManagedInstanceState::ExecVerified;
        }
        // Direct fork/exec child of the sandboxed main process inherits Seatbelt (`D03`),
        // whereas NSWorkspace / LaunchServices spawns under launchd (ppid == 1) and does NOT (`D04`).
        if proc_info.ppid > 1
            && (proc_info.ppid == inst.pid
                || inst.controlled_subtree_pids.contains(&proc_info.ppid)
                || inst.controlled_subtree_pids.contains(&proc_info.pid))
        {
            return ManagedInstanceState::ExecVerified;
        }
    }
    ManagedInstanceState::RunningUnprotected
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedScriptContext {
    pub target_executable: String,
    pub target_fingerprint: String,
    pub script_entry: Option<String>,
    pub script_fingerprint: Option<String>,
    pub interpreter: Option<String>,
    pub interpreter_fingerprint: Option<String>,
}

pub fn is_script_file(path: &Path) -> bool {
    let mut bytes = [0; 2];
    fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok()
        && bytes == *b"#!"
        || path
            .extension()
            .is_some_and(|v| v == "js" || v == "mjs" || v == "cjs")
}

pub fn resolve_script_launcher_context(
    real_exe: &Path,
    real_sha: &str,
    search_paths: &[PathBuf],
) -> Result<ResolvedScriptContext> {
    if !is_script_file(real_exe) {
        return Ok(ResolvedScriptContext {
            target_executable: real_exe.to_string_lossy().into_owned(),
            target_fingerprint: real_sha.to_string(),
            script_entry: None,
            script_fingerprint: None,
            interpreter: None,
            interpreter_fingerprint: None,
        });
    }

    let mut bytes = Vec::new();
    let mut f = fs::File::open(real_exe)
        .map_err(|e| CoreError::new("script_read_failed", &format!("无法打开脚本文件: {e}")))?;
    let _ = f.read_to_end(&mut bytes);

    let first_line = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.lines().next())
        .and_then(|l| l.strip_prefix("#!"))
        .map(str::trim);

    let interp_name = if let Some(line) = first_line {
        let mut words = line.split_whitespace();
        let first = words.next().ok_or_else(|| {
            CoreError::new("unsupported_launcher", "脚本 shebang 格式无效")
        })?;
        if first == "/usr/bin/env" {
            let mut next = words.next().ok_or_else(|| {
                CoreError::new("unsupported_launcher", "脚本 shebang /usr/bin/env 缺少解释器参数")
            })?;
            if next == "-S" {
                next = words.next().ok_or_else(|| {
                    CoreError::new("unsupported_launcher", "脚本 shebang -S 缺少解释器参数")
                })?;
            }
            next
        } else {
            first
        }
    } else if real_exe.extension().is_some_and(|v| v == "js" || v == "mjs" || v == "cjs") {
        "node"
    } else {
        return Err(CoreError::new(
            "unsupported_launcher",
            "脚本缺少有效 shebang 或受支持的文件扩展名",
        ));
    };

    let base_name = Path::new(interp_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(interp_name);
    if !["node", "nodejs", "bun", "sh", "bash"].contains(&base_name) {
        return Err(CoreError::new(
            "unsupported_launcher",
            &format!("不支持此形式的脚本型 CLI 解释器: {base_name}"),
        ));
    }

    let default_paths = [
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ];

    let interp_path = if Path::new(interp_name).is_absolute() {
        let p = PathBuf::from(interp_name);
        if !p.is_file() {
            return Err(CoreError::new(
                "unsupported_launcher",
                &format!("未找到绝对路径解释器: {interp_name}"),
            ));
        }
        fs::canonicalize(p).map_err(|e| CoreError::new("unsupported_launcher", &format!("无法解析解释器路径: {e}")))?
    } else {
        search_paths
            .iter()
            .chain(default_paths.iter())
            .map(|dir| dir.join(interp_name))
            .find(|cand| {
                if let Ok(meta) = fs::metadata(cand) {
                    meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
                } else {
                    false
                }
            })
            .and_then(|p| fs::canonicalize(p).ok())
            .ok_or_else(|| {
                CoreError::new(
                    "unsupported_launcher",
                    &format!("在搜索路径中未找到受支持的解释器: {interp_name}"),
                )
            })?
    };

    let interp_sha = sha256_file_hex(&interp_path).ok_or_else(|| {
        CoreError::new("unsupported_launcher", "无法计算解释器 SHA-256 指纹")
    })?;

    Ok(ResolvedScriptContext {
        target_executable: real_exe.to_string_lossy().into_owned(),
        target_fingerprint: real_sha.to_string(),
        script_entry: Some(real_exe.to_string_lossy().into_owned()),
        script_fingerprint: Some(real_sha.to_string()),
        interpreter: Some(interp_path.to_string_lossy().into_owned()),
        interpreter_fingerprint: Some(interp_sha),
    })
}

/// Stages a managed desktop wrapper `.app` bundle (`io.local.watchpanel.entry.<target>`)
/// in `output_dir` without modifying the original target `.app`.
pub fn stage_desktop_entry_bundle(
    output_dir: &Path,
    spec: &DesktopManagedEntrySpec,
    watch_engine_bin: &Path,
    launcher_bin: &Path,
    controlled_entry_macho: Option<&Path>,
) -> Result<PathBuf> {
    let app_display_name = match spec.target {
        LaunchTarget::ClaudeDesktop => "Claude (Controlled).app",
        LaunchTarget::CodexDesktop => "Codex (Controlled).app",
        LaunchTarget::ChatgptDesktop => "ChatGPT (Controlled).app",
        _ => {
            return Err(CoreError::new(
                "invalid_desktop_entry_target",
                "桌面受控入口仅支持桌面端 AI 目标",
            ))
        }
    };
    let bundle_dir = output_dir.join(app_display_name);
    let macos_dir = bundle_dir.join("Contents/MacOS");
    fs::create_dir_all(&macos_dir)
        .map_err(|_| CoreError::new("stage_entry_mkdir_failed", "无法创建受控桌面入口目录"))?;
    let state_dir = {
        let mut cur = output_dir.to_path_buf();
        let mut found_watch_root = None;
        loop {
            if cur.file_name().and_then(|n| n.to_str()) == Some("entries") {
                found_watch_root = cur.parent().map(|p| p.to_path_buf());
                break;
            }
            if !cur.pop() {
                break;
            }
        }
        if let Some(watch_root) = found_watch_root {
            watch_root.join("state")
        } else if let Some(parent) = output_dir.parent() {
            parent.join("state")
        } else {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join("Library/Application Support/ClaudeWatch/state")
        }
    };
    let info_plist = desktop_entry_plist(spec, app_display_name, watch_engine_bin, launcher_bin, &state_dir, None);
    fs::write(bundle_dir.join("Contents/Info.plist"), info_plist)
        .map_err(|_| CoreError::new("stage_entry_plist_failed", "无法写入受控入口 Info.plist"))?;
    let exe_dst = macos_dir.join("ControlledEntry");
    if let Some(macho) = controlled_entry_macho.filter(|p| p.is_file()) {
        fs::copy(macho, &exe_dst)
            .map_err(|_| CoreError::new("stage_entry_copy_failed", "无法复制 ControlledEntry 二进制"))?;
    } else {
        let script = format!(
            "#!/bin/sh\nexport CW_TARGET={}\nexport CW_WATCH_BIN={}\nexec {} launch --target {} --target-bundle {} --apply \"$@\"\n",
            shell_word(spec.target.as_str()),
            shell_word(&watch_engine_bin.to_string_lossy()),
            shell_word(&watch_engine_bin.to_string_lossy()),
            shell_word(spec.target.as_str()),
            shell_word(&spec.target_bundle_path.to_string_lossy()),
        );
        fs::write(&exe_dst, script)
            .map_err(|_| CoreError::new("stage_entry_script_failed", "无法写入受控入口启动器"))?;
    }
    let mut perms = fs::metadata(&exe_dst)
        .map_err(|_| CoreError::new("stage_entry_stat_failed", "无法读取受控入口权限"))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&exe_dst, perms)
        .map_err(|_| CoreError::new("stage_entry_chmod_failed", "无法设置受控入口执行权限"))?;
    Ok(bundle_dir)
}

pub(crate) fn desktop_entry_plist(spec: &DesktopManagedEntrySpec, app_display_name: &str,
    watch_engine_bin: &Path, launcher_bin: &Path, state_dir: &Path, home: Option<&Path>) -> String {
    let home_key = home.map_or_else(String::new, |home|
        format!("<key>CWWatchHomePath</key><string>{}</string>", xml_text(&home.to_string_lossy())));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>{}</string>
    <key>CFBundleName</key>
    <string>{}</string>
    <key>CFBundleExecutable</key>
    <string>ControlledEntry</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CWTarget</key>
    <string>{}</string>
    <key>CWTargetBundlePath</key>
    <string>{}</string>
    <key>CWTargetBundleId</key>
    <string>{}</string>
    <key>CWTargetExecutable</key>
    <string>{}</string>
    <key>CWTargetFingerprint</key>
    <string>{}</string>
    <key>CWWatchBin</key>
    <string>{}</string>
    <key>CWSandboxLauncherBin</key>
    <string>{}</string>
    <key>CWWatchStateDirPath</key>
    <string>{}</string>
    {home_key}
</dict>
</plist>
"#,
        xml_text(&spec.entry_bundle_id),
        app_display_name.trim_end_matches(".app"),
        spec.target.as_str(),
        xml_text(&spec.target_bundle_path.to_string_lossy()),
        xml_text(&spec.target_bundle_id),
        xml_text(&spec.target_executable.to_string_lossy()),
        xml_text(&spec.target_fingerprint),
        xml_text(&watch_engine_bin.to_string_lossy()),
        xml_text(&launcher_bin.to_string_lossy()),
        xml_text(&state_dir.to_string_lossy()),
    )
}

fn xml_text(value:&str)->String { value.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;").replace('\'',"&apos;") }
fn shell_word(value:&str)->String { format!("'{}'",value.replace('\'',"'\\''")) }

/// Stages a managed CLI shim (`claude` or `codex`) in `bin_dir` that sets
/// `CW_SHIM_EXECUTABLE` (to prevent `PATH` self-recursion) and invokes `watch_engine_bin`.
pub fn stage_cli_entry_shim(
    bin_dir: &Path,
    target: LaunchTarget,
    watch_engine_bin: &Path,
) -> Result<PathBuf> {
    let (cli_name, target_flag) = match target {
        LaunchTarget::ClaudeCli => ("claude", "claude-cli"),
        LaunchTarget::CodexCli => ("codex", "codex-cli"),
        _ => {
            return Err(CoreError::new(
                "invalid_cli_shim_target",
                "CLI 受控入口仅支持 claude-cli 或 codex-cli",
            ))
        }
    };
    fs::create_dir_all(bin_dir)
        .map_err(|_| CoreError::new("stage_shim_mkdir_failed", "无法创建受控 CLI shim 目录"))?;
    let shim_path = bin_dir.join(cli_name);
    let entry_id = DesktopManagedEntrySpec::entry_bundle_id_for(target);
    let script = format!(
        "#!/bin/sh\n# CLAUDE WATCH MANAGED CLI ENTRY SHIM v1\n# ENTRY_ID: {entry_id}\n# TARGET: {target_flag}\nexport CW_SHIM_EXECUTABLE=\"$0\"\nexec \"{}\" launch --target \"{}\" --apply -- \"$@\"\n",
        watch_engine_bin.display(),
        target_flag,
    );
    fs::write(&shim_path, script)
        .map_err(|_| CoreError::new("stage_shim_write_failed", "无法写入受控 CLI shim"))?;
    let mut perms = fs::metadata(&shim_path)
        .map_err(|_| CoreError::new("stage_shim_stat_failed", "无法读取受控 CLI shim 权限"))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&shim_path, perms)
        .map_err(|_| CoreError::new("stage_shim_chmod_failed", "无法设置受控 CLI shim 执行权限"))?;
    Ok(shim_path)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedManagedEntriesReceipt {
    pub staging_root: String,
    pub desktop_bundles: Vec<String>,
    pub cli_shims: Vec<String>,
    pub watch_engine_bin: String,
    pub launcher_bin: String,
}

/// Stages deliverable desktop wrapper `.app` bundles and CLI shims (`claude`, `codex`)
/// into `staging_root` (`<watch_dir>/entries/{apps,bin}`) and writes `entries-manifest.json`
/// without mutating `/Applications`, global `PATH`, or Dock.
pub fn stage_deliverable_entries(
    staging_root: &Path,
    desktop_specs: &[DesktopManagedEntrySpec],
    watch_engine_bin: &Path,
    launcher_bin: &Path,
    controlled_entry_macho: Option<&Path>,
) -> Result<StagedManagedEntriesReceipt> {
    let apps_dir = staging_root.join("apps");
    let bin_dir = staging_root.join("bin");
    fs::create_dir_all(&apps_dir)
        .map_err(|_| CoreError::new("stage_entries_mkdir_failed", "无法创建受控桌面入口目录"))?;
    fs::create_dir_all(&bin_dir)
        .map_err(|_| CoreError::new("stage_entries_mkdir_failed", "无法创建受控 CLI 入口目录"))?;

    let mut desktop_bundles = Vec::new();
    for spec in desktop_specs {
        let bundle = stage_desktop_entry_bundle(
            &apps_dir,
            spec,
            watch_engine_bin,
            launcher_bin,
            controlled_entry_macho,
        )?;
        desktop_bundles.push(bundle.to_string_lossy().into_owned());
    }

    let mut cli_shims = Vec::new();
    for cli_target in [LaunchTarget::ClaudeCli, LaunchTarget::CodexCli] {
        let shim = stage_cli_entry_shim(&bin_dir, cli_target, watch_engine_bin)?;
        cli_shims.push(shim.to_string_lossy().into_owned());
    }

    let receipt = StagedManagedEntriesReceipt {
        staging_root: staging_root.to_string_lossy().into_owned(),
        desktop_bundles,
        cli_shims,
        watch_engine_bin: watch_engine_bin.to_string_lossy().into_owned(),
        launcher_bin: launcher_bin.to_string_lossy().into_owned(),
    };
    let manifest_json = serde_json::to_vec_pretty(&receipt)
        .map_err(|_| CoreError::new("stage_entries_manifest_failed", "无法序列化受控入口清单"))?;
    fs::write(staging_root.join("entries-manifest.json"), manifest_json)
        .map_err(|_| CoreError::new("stage_entries_manifest_failed", "无法写入受控入口清单"))?;
    Ok(receipt)
}


