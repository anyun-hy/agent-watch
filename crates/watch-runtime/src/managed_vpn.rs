//! Managed isolated VPN core (`watch-vpn-core`, bundled `sing-box` arm64) lifecycle,
//! cryptographic verification, stdin config feeding, runtime state publication,
//! authoritative `VpnObservation` synthesis, and node connectivity probing.
//!
//! Security & isolation invariants:
//! - Never enables TUN, never modifies macOS system proxy, never alters system DNS.
//! - Never pins a fixed hardware interface (follows macOS routing across Wi-Fi/Ethernet/Hotspot).
//! - Feeds compiled JSON config strictly via stdin pipe (no plaintext temp config files,
//!   zero credentials in process argv).
//! - Verifies `watch-vpn-core` against `BuildInfo.plist["ManagedVpnCoreHash"]` before exec.

use crate::{
    native,
    native_leak_probes,
    storage::{sha256, strict_json, StateStore},
    vpn_vault::VpnVaultStore,
};
use claude_watch_core::{
    error::{CoreError, Result},
    vpn::{
        ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnExpectation,
        VpnObservation,
    },
    vpn_profile::{compile_singbox_config, NodeProbeStats, NormalizedOutboundNode},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const MANAGED_VPN_CORE_BINARY: &str = "watch-vpn-core";
pub const MANAGED_VPN_SOURCE: &str = "managed-vpn";
pub const MANAGED_VPN_OBSERVATION_TTL_SECONDS: f64 = 60.0;
const STARTUP_WAIT_BUDGET: Duration = Duration::from_millis(3500);
const TCP_PROBE_TIMEOUT: Duration = Duration::from_millis(180);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCoreBinary {
    pub path: PathBuf,
    pub sha256: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ManagedVpnRuntimeState {
    pub schema: u32,
    pub mode: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_identity: Option<claude_watch_system::ProcessKernelIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    #[serde(default)]
    pub updated_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

pub fn runtime_state_path(storage: &StateStore) -> PathBuf {
    storage.paths.watch().join("state/managed-vpn-state.json")
}

pub fn write_runtime_state(storage: &StateStore, state: &ManagedVpnRuntimeState) {
    let dir = storage.paths.watch().join("state");
    let _ = storage.private_dir(&dir);
    if let Ok(val) = serde_json::to_value(state) {
        let _ = storage.atomic_json(&runtime_state_path(storage), &val);
    }
}

pub fn read_runtime_state(storage: &StateStore) -> ManagedVpnRuntimeState {
    let path = runtime_state_path(storage);
    let fallback = ManagedVpnRuntimeState {
        schema: 1,
        mode: "external".into(),
        state: "inactive".into(),
        ..ManagedVpnRuntimeState::default()
    };
    if !path.exists() {
        return fallback;
    }
    let raw = storage.read_json(&path, json!({})).unwrap_or(Value::Null);
    let parsed: ManagedVpnRuntimeState = serde_json::from_value(raw).unwrap_or(fallback.clone());
    if parsed.state.is_empty() {
        fallback
    } else {
        parsed
    }
}

/// Sweep any orphaned `watch-vpn-core` left behind by an unclean daemon crash (`SIGKILL`).
/// Uses kernel-bound `ProcessKernelIdentity` (`uid`, `start_seconds`, `start_microseconds`,
/// `audit_token`, and `executable_path` ending in `watch-vpn-core`) so a recycled PID
/// belonging to another process can never be signaled.
pub fn sweep_orphan_managed_vpn(storage: &StateStore) -> bool {
    let st = read_runtime_state(storage);
    let Some(ref identity) = st.kernel_identity else {
        return false;
    };
    let is_our_core = Path::new(&identity.executable_path)
        .file_name()
        .and_then(|n| n.to_str())
        == Some(MANAGED_VPN_CORE_BINARY);
    if !is_our_core {
        return false;
    }
    let mut swept = false;
    match claude_watch_system::terminate_bound_process(identity) {
        claude_watch_system::BoundSignalResult::Sent => {
            swept = true;
            let deadline = Instant::now() + Duration::from_millis(200);
            while Instant::now() < deadline {
                if claude_watch_system::bound_lifetime_exited(identity) {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
            if !claude_watch_system::bound_lifetime_exited(identity) {
                let _ = claude_watch_system::signal_bound_process(identity);
            }
        }
        claude_watch_system::BoundSignalResult::AlreadyExited => {
            swept = true;
        }
        claude_watch_system::BoundSignalResult::IdentityChanged
        | claude_watch_system::BoundSignalResult::Failed => {}
    }
    if swept && st.state == "running" {
        write_runtime_state(
            storage,
            &ManagedVpnRuntimeState {
                schema: 1,
                mode: st.mode,
                state: "inactive".into(),
                updated_at: native::now(),
                ..ManagedVpnRuntimeState::default()
            },
        );
    }
    swept
}

/// Returns the active loopback HTTP endpoint (`http://127.0.0.1:<port>`) if the
/// managed VPN daemon tunnel is running and its port responds right now.
pub fn active_upstream_endpoint(storage: &StateStore) -> Option<String> {
    let st = read_runtime_state(storage);
    if st.state != "running" {
        return None;
    }
    let ep = st.upstream_endpoint.as_deref()?;
    let addr = parse_loopback_addr(ep)?;
    TcpStream::connect_timeout(&addr, TCP_PROBE_TIMEOUT).ok()?;
    Some(ep.to_string())
}

fn parse_loopback_addr(endpoint: &str) -> Option<SocketAddr> {
    let trimmed = endpoint
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let addr: SocketAddr = trimmed.parse().ok()?;
    addr.ip().is_loopback().then_some(addr)
}

fn read_plist_managed_core_hash(plist_path: &Path) -> Option<String> {
    if !plist_path.is_file() {
        return None;
    }
    let out = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(plist_path)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let doc = strict_json(&out.stdout).ok()?;
    let hash = doc["ManagedVpnCoreHash"].as_str()?.trim().to_ascii_lowercase();
    (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hash)
}

/// Verifies a candidate `watch-vpn-core` binary path against an expected SHA-256 digest
/// (if present in its sibling `BuildInfo.plist`). Rejects symlinks and non-executable files.
pub fn verify_core_candidate(
    binary: &Path,
    plist: Option<&Path>,
    source: &str,
) -> Result<VerifiedCoreBinary> {
    let meta = fs::symlink_metadata(binary).map_err(|_| {
        CoreError::new(
            "managed_vpn_core_missing",
            "未找到内置独立 VPN 内核组件（watch-vpn-core），请更新至完整版本",
        )
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(CoreError::new(
            "managed_vpn_core_invalid",
            "内置独立 VPN 内核路径无效或为符号链接",
        ));
    }
    let mode = meta.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(CoreError::new(
            "managed_vpn_core_not_executable",
            "内置独立 VPN 内核缺少可执行权限",
        ));
    }
    let bytes = fs::read(binary).map_err(|_| {
        CoreError::new(
            "managed_vpn_core_unreadable",
            "无法读取内置独立 VPN 内核组件",
        )
    })?;
    let actual_hash = sha256(&bytes);
    if let Some(plist_path) = plist {
        let expected = read_plist_managed_core_hash(plist_path).ok_or_else(|| {
            CoreError::new(
                "managed_vpn_core_unverified",
                "构建清单缺少内置独立 VPN 内核校验哈希（ManagedVpnCoreHash）",
            )
        })?;
        if actual_hash != expected {
            return Err(CoreError::new(
                "managed_vpn_core_hash_mismatch",
                "内置独立 VPN 内核哈希与签名清单不匹配，已拒绝启动",
            ));
        }
    }
    Ok(VerifiedCoreBinary {
        path: binary.to_path_buf(),
        sha256: actual_hash,
        source: source.to_string(),
    })
}

/// Locate and cryptographically verify `watch-vpn-core` across Watch's controlled roots.
pub fn locate_verified_core(storage: &StateStore) -> Result<VerifiedCoreBinary> {
    let runtime_dir = storage.paths.watch().join("runtime");
    let app_resources = PathBuf::from("/Applications/Agent Watch.app/Contents/Resources");
    let sibling_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));

    let mut candidates: Vec<(PathBuf, PathBuf, &str)> = vec![
        (
            runtime_dir.join(MANAGED_VPN_CORE_BINARY),
            runtime_dir.join("BuildInfo.plist"),
            "runtime",
        ),
        (
            app_resources.join(MANAGED_VPN_CORE_BINARY),
            app_resources.join("BuildInfo.plist"),
            "app_bundle",
        ),
    ];
    if let Some(dir) = sibling_dir {
        candidates.push((
            dir.join(MANAGED_VPN_CORE_BINARY),
            dir.join("BuildInfo.plist"),
            "sibling",
        ));
    }

    let mut last_err = CoreError::new(
        "managed_vpn_core_missing",
        "未找到内置独立 VPN 内核组件（watch-vpn-core）",
    );
    for (bin, plist, label) in candidates {
        if !bin.exists() {
            continue;
        }
        match verify_core_candidate(&bin, Some(&plist), label) {
            Ok(verified) => return Ok(verified),
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

pub fn core_availability_summary(storage: &StateStore) -> Value {
    match locate_verified_core(storage) {
        Ok(core) => json!({
            "available": true,
            "source": core.source,
            "sha256_prefix": &core.sha256[..12.min(core.sha256.len())],
        }),
        Err(err) => json!({
            "available": false,
            "error_code": err.code,
            "message": err.message,
        }),
    }
}

/// Running isolated `watch-vpn-core` (`sing-box`) child process bound strictly to
/// an ephemeral `127.0.0.1` loopback port. Automatically terminated and reaped on Drop.
pub struct ManagedVpnProcess {
    child: Child,
    pid: u32,
    kernel_identity: Option<claude_watch_system::ProcessKernelIdentity>,
    port: u16,
    node_id: String,
    node_name: String,
    node_revision: String,
    protocol_label: String,
    provider_kind: String,
    started_at: f64,
}

impl ManagedVpnProcess {
    pub fn start(
        core: &VerifiedCoreBinary,
        node: &NormalizedOutboundNode,
    ) -> Result<Self> {
        let port = allocate_loopback_port()?;
        let config_json = compile_singbox_config(node, port)?;
        let config_bytes = serde_json::to_vec(&config_json).map_err(|_| {
            CoreError::new("managed_vpn_config_encode", "内置 VPN 配置序列化失败")
        })?;
        Self::start_with_args(core, node, port, &["run", "-c", "stdin"], &config_bytes)
    }

    pub fn start_with_args(
        core: &VerifiedCoreBinary,
        node: &NormalizedOutboundNode,
        port: u16,
        args: &[&str],
        stdin_payload: &[u8],
    ) -> Result<Self> {
        let mut child = Command::new(&core.path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| {
                CoreError::new(
                    "managed_vpn_spawn_failed",
                    "无法启动内置独立 VPN 内核进程",
                )
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(stdin_payload);
            let _ = stdin.flush();
            // Explicitly drop stdin so sing-box observes EOF on `-c stdin`.
        }

        let pid = child.id();
        let kernel_identity = claude_watch_system::inspect_process_identity(pid);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().map_err(|_| {
            CoreError::new("managed_vpn_port_invalid", "本地端口无效")
        })?;
        let deadline = Instant::now() + STARTUP_WAIT_BUDGET;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                let stderr_snippet = read_bounded_stderr(&mut child);
                let detail = if stderr_snippet.is_empty() {
                    format!("内置 VPN 内核启动后即退出（退出码 {:?}）", status.code())
                } else {
                    format!("内置 VPN 内核启动失败：{stderr_snippet}")
                };
                return Err(CoreError::new("managed_vpn_start_failed", &detail));
            }
            if TcpStream::connect_timeout(&addr, Duration::from_millis(80)).is_ok() {
                return Ok(Self {
                    child,
                    pid,
                    kernel_identity,
                    port,
                    node_id: node.id.clone(),
                    node_name: node.name.clone(),
                    node_revision: node.fingerprint_digest(),
                    protocol_label: node.protocol_label(),
                    provider_kind: node.provider_kind.as_str().to_string(),
                    started_at: native::now(),
                });
            }
            thread::sleep(Duration::from_millis(30));
        }

        let _ = child.kill();
        let _ = child.wait();
        let stderr_snippet = read_bounded_stderr(&mut child);
        let detail = if stderr_snippet.is_empty() {
            "内置 VPN 内核启动超时（本地回环端口未就绪）".into()
        } else {
            format!("内置 VPN 内核启动超时：{stderr_snippet}")
        };
        Err(CoreError::new("managed_vpn_start_timeout", &detail))
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    pub fn node_revision(&self) -> &str {
        &self.node_revision
    }

    pub fn protocol_label(&self) -> &str {
        &self.protocol_label
    }

    pub fn provider_kind(&self) -> &str {
        &self.provider_kind
    }

    pub fn started_at(&self) -> f64 {
        self.started_at
    }

    pub fn upstream_endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn is_healthy(&mut self) -> bool {
        if self.child.try_wait().ok().flatten().is_some() {
            return false;
        }
        let Ok(addr) = format!("127.0.0.1:{}", self.port).parse::<SocketAddr>() else {
            return false;
        };
        TcpStream::connect_timeout(&addr, TCP_PROBE_TIMEOUT).is_ok()
    }

    pub fn to_runtime_state(&self, now: f64) -> ManagedVpnRuntimeState {
        ManagedVpnRuntimeState {
            schema: 1,
            mode: "managed".into(),
            state: "running".into(),
            pid: Some(self.pid),
            kernel_identity: self.kernel_identity.clone(),
            node_id: Some(self.node_id.clone()),
            node_name: Some(self.node_name.clone()),
            protocol_label: Some(self.protocol_label.clone()),
            upstream_endpoint: Some(self.upstream_endpoint()),
            started_at: Some(self.started_at),
            updated_at: now,
            error_code: None,
            error_message: None,
        }
    }

    pub fn to_observation(
        &self,
        now: f64,
        sample_seq: u64,
        epoch: VpnEpoch,
    ) -> VpnObservation {
        VpnObservation {
            source: MANAGED_VPN_SOURCE.into(),
            source_instance: Some(format!("managed-vpn:pid:{}:node:{}", self.pid, self.node_id)),
            source_revision: Some(self.node_revision.clone()),
            upstream_endpoint: Some(self.upstream_endpoint()),
            upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
            running_mode: ObservedField::Known("global".into()),
            tun_enabled: ObservedField::Known(false),
            system_proxy_enabled: ObservedField::Known(false),
            selected_group: ObservedField::Known(self.provider_kind.clone()),
            selected_node: ObservedField::Known(self.node_name.clone()),
            proxy_chain: ObservedField::Known(vec![self.node_name.clone()]),
            rules_digest: ObservedField::Unknown("managed_tunnel_single_outbound".into()),
            sample_started_at: now,
            observed_at: now,
            valid_until: now + MANAGED_VPN_OBSERVATION_TTL_SECONDS,
            consistency: ObservationConsistency::RevisionVerified,
            source_error: None,
            sample_seq,
            epoch,
        }
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ManagedVpnProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn build_managed_error_observation(
    reason_code: &str,
    now: f64,
    sample_seq: u64,
    epoch: VpnEpoch,
) -> VpnObservation {
    VpnObservation {
        source: MANAGED_VPN_SOURCE.into(),
        source_instance: None,
        source_revision: None,
        upstream_endpoint: None,
        upstream_protocol: ObservedField::Unknown(reason_code.into()),
        running_mode: ObservedField::Unknown(reason_code.into()),
        tun_enabled: ObservedField::Known(false),
        system_proxy_enabled: ObservedField::Known(false),
        selected_group: ObservedField::Unknown(reason_code.into()),
        selected_node: ObservedField::Unknown(reason_code.into()),
        proxy_chain: ObservedField::Unknown(reason_code.into()),
        rules_digest: ObservedField::Unknown(reason_code.into()),
        sample_started_at: now,
        observed_at: now,
        valid_until: now,
        consistency: ObservationConsistency::Unavailable(reason_code.into()),
        source_error: Some(reason_code.into()),
        sample_seq,
        epoch,
    }
}

pub fn build_managed_expectation_for_observation(
    selected_node_id: &str,
    selected_node_name: &str,
    obs: &VpnObservation,
) -> Option<VpnExpectation> {
    if obs.source != MANAGED_VPN_SOURCE || obs.source_error.is_some() {
        return None;
    }
    let expected_suffix = format!(":node:{selected_node_id}");
    if !obs
        .source_instance
        .as_deref()
        .is_some_and(|inst| inst.ends_with(&expected_suffix))
    {
        return None;
    }
    let endpoint = obs
        .upstream_endpoint
        .as_deref()
        .and_then(claude_watch_core::vpn::normalize_loopback_http_endpoint)?;
    let expected_node = (!selected_node_name.trim().is_empty())
        .then(|| selected_node_name.to_string());
    Some(VpnExpectation {
        configured: true,
        proxy_mode: MANAGED_VPN_SOURCE.into(),
        proxy_url: endpoint,
        proxy_group: String::new(),
        running_mode: Some("global".into()),
        require_tun: Some(false),
        require_system_proxy: Some(false),
        expected_node,
        expected_chain: Vec::new(),
        expected_rules_digest: None,
    })
}

/// Measure real proxy latency and egress IP/country for a managed VPN node.
/// Reuses the currently running daemon tunnel if it matches `node.id`; otherwise
/// spins up a short-lived ephemeral `ManagedVpnProcess` and cleans it up immediately.
pub fn probe_managed_node(
    storage: &StateStore,
    node: &NormalizedOutboundNode,
) -> Result<NodeProbeStats> {
    let checked_at = native::now();
    let active_state = read_runtime_state(storage);
    let reuse_endpoint = if active_state.state == "running"
        && active_state.node_id.as_deref() == Some(node.id.as_str())
    {
        active_state
            .upstream_endpoint
            .as_deref()
            .filter(|ep| parse_loopback_addr(ep).and_then(|a| TcpStream::connect_timeout(&a, TCP_PROBE_TIMEOUT).ok()).is_some())
            .map(str::to_owned)
    } else {
        None
    };

    let mut ephemeral: Option<ManagedVpnProcess> = None;
    let proxy_url = if let Some(ep) = reuse_endpoint {
        ep
    } else {
        let core = locate_verified_core(storage)?;
        let proc = ManagedVpnProcess::start(&core, node)?;
        let ep = proc.upstream_endpoint();
        ephemeral = Some(proc);
        ep
    };

    let started = Instant::now();
    let trace_res = fetch_cloudflare_trace_via_proxy(&proxy_url);
    let latency_ms = started.elapsed().as_millis() as u64;
    drop(ephemeral);

    let stats = match trace_res {
        Ok((ip, country)) => {
            let geo = native_leak_probes::lookup_geo_cached(&ip, Some(&proxy_url));
            NodeProbeStats {
                latency_ms: Some(latency_ms),
                egress_ip: Some(ip),
                country: geo
                    .as_ref()
                    .and_then(|g| g.country.clone())
                    .or(country),
                region: geo.as_ref().and_then(|g| g.region.clone()),
                isp: geo.as_ref().and_then(|g| g.isp.clone()),
                checked_at: Some(checked_at),
                error: None,
            }
        }
        Err(err) => NodeProbeStats {
            latency_ms: None,
            egress_ip: None,
            country: None,
            region: None,
            isp: None,
            checked_at: Some(checked_at),
            error: Some(err.message),
        },
    };

    let _ = VpnVaultStore::new(storage.clone()).record_probe_stats(&node.id, stats.clone());
    Ok(stats)
}

fn fetch_cloudflare_trace_via_proxy(proxy_url: &str) -> Result<(String, Option<String>)> {
    let proxy = ureq::Proxy::new(proxy_url)
        .map_err(|_| CoreError::new("managed_vpn_probe_failed", "本地代理地址无效"))?;
    let agent = ureq::Agent::config_builder()
        .proxy(Some(proxy))
        .timeout_global(Some(Duration::from_secs(8)))
        .build()
        .new_agent();

    let mut last_err = String::from("连通测试超时或握手失败");
    for url in [
        "https://1.1.1.1/cdn-cgi/trace",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ] {
        match agent.get(url).call() {
            Ok(resp) => {
                let mut text = String::new();
                if resp.into_body().into_reader().take(16 * 1024).read_to_string(&mut text).is_ok() {
                    let mut ip = None;
                    let mut loc = None;
                    for line in text.lines() {
                        if let Some(v) = line.strip_prefix("ip=") {
                            let v = v.trim();
                            if !v.is_empty() {
                                ip = Some(v.to_string());
                            }
                        } else if let Some(v) = line.strip_prefix("loc=") {
                            let v = v.trim().to_ascii_uppercase();
                            if v.len() == 2 {
                                loc = Some(v);
                            }
                        }
                    }
                    if let Some(ip) = ip {
                        return Ok((ip, loc));
                    }
                }
            }
            Err(err) => {
                last_err = err.to_string().chars().take(120).collect();
            }
        }
    }
    Err(CoreError::new("managed_vpn_probe_failed", &last_err))
}

fn allocate_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| {
        CoreError::new("managed_vpn_port_unavailable", "无法分配本地回环端口")
    })?;
    let port = listener
        .local_addr()
        .map_err(|_| CoreError::new("managed_vpn_port_unavailable", "无法读取本地回环端口"))?
        .port();
    drop(listener);
    Ok(port)
}

fn read_bounded_stderr(child: &mut Child) -> String {
    let Some(err) = child.stderr.take() else {
        return String::new();
    };
    let mut buf = Vec::new();
    let _ = err.take(512).read_to_end(&mut buf);
    let raw = String::from_utf8_lossy(&buf);
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
        .chars()
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use claude_watch_core::{
        vpn::{compare_vpn, VpnMatch},
        vpn_profile::{parse_nodes_from_text, ManagedVpnProviderKind},
    };

    #[test]
    fn verify_core_candidate_rejects_bad_hash_and_symlink() {
        let root = std::env::temp_dir().join(format!("cw-core-verify-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let bin = root.join("watch-vpn-core");
        fs::write(&bin, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
        let good_hash = sha256(b"#!/bin/sh\nexit 0\n");

        let plist = root.join("BuildInfo.plist");
        fs::write(
            &plist,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>ManagedVpnCoreHash</key><string>{good_hash}</string></dict></plist>"#
            ),
        )
        .unwrap();

        let verified = verify_core_candidate(&bin, Some(&plist), "test").unwrap();
        assert_eq!(verified.sha256, good_hash);

        // Tampered hash must be rejected.
        fs::write(
            &plist,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>ManagedVpnCoreHash</key><string>0000000000000000000000000000000000000000000000000000000000000000</string></dict></plist>"#,
        )
        .unwrap();
        assert_eq!(
            verify_core_candidate(&bin, Some(&plist), "test").unwrap_err().code,
            "managed_vpn_core_hash_mismatch"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_observation_matches_derived_expectation_and_rejects_wrong_node() {
        let yaml = r#"
name: UK Synthetic Reality
type: vmess
server: 203.0.113.10
port: 443
uuid: 00000000-0000-4000-8000-000000000001
flow: xtls-rprx-vision
tls: true
servername: www.example.com
reality-opts:
  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  short-id: 0123456789abcdef
client-fingerprint: chrome
"#;
        let node = &parse_nodes_from_text(yaml, ManagedVpnProviderKind::Custom, None).unwrap()[0];
        let now = 1_800_000_000.0;
        let obs = VpnObservation {
            source: MANAGED_VPN_SOURCE.into(),
            source_instance: Some(format!("managed-vpn:pid:4242:node:{}", node.id)),
            source_revision: Some(node.fingerprint_digest()),
            upstream_endpoint: Some("http://127.0.0.1:49999".into()),
            upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
            running_mode: ObservedField::Known("global".into()),
            tun_enabled: ObservedField::Known(false),
            system_proxy_enabled: ObservedField::Known(false),
            selected_group: ObservedField::Known("custom".into()),
            selected_node: ObservedField::Known(node.name.clone()),
            proxy_chain: ObservedField::Known(vec![node.name.clone()]),
            rules_digest: ObservedField::Unknown("managed_tunnel_single_outbound".into()),
            sample_started_at: now,
            observed_at: now,
            valid_until: now + 60.0,
            consistency: ObservationConsistency::RevisionVerified,
            source_error: None,
            sample_seq: 1,
            epoch: VpnEpoch::new("boot-1", 1),
        };
        let exp = build_managed_expectation_for_observation(&node.id, &node.name, &obs).unwrap();
        assert_eq!(exp.require_tun, Some(false));
        assert_eq!(exp.require_system_proxy, Some(false));
        assert_eq!(compare_vpn(&exp, &obs, now), VpnMatch::Matched);

        // Wrong node ID refuses to build an expectation (fail closed).
        assert!(build_managed_expectation_for_observation("node-other", "Other", &obs).is_none());

        // Error observation fails closed.
        let err_obs =
            build_managed_error_observation("managed_vpn_exited", now, 2, VpnEpoch::new("boot-1", 2));
        assert!(matches!(compare_vpn(&exp, &err_obs, now), VpnMatch::Unknown { .. }));

        // Runtime state roundtrip on temp storage.
        let root = std::env::temp_dir().join(format!("cw-managed-st-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let st = ManagedVpnRuntimeState {
            schema: 1,
            mode: "managed".into(),
            state: "inactive".into(),
            updated_at: now,
            ..ManagedVpnRuntimeState::default()
        };
        write_runtime_state(&store, &st);
        assert_eq!(read_runtime_state(&store).state, "inactive");
        fs::remove_dir_all(root).unwrap();
    }
}
