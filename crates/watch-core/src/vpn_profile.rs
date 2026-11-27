//! Pure managed-VPN node parser, validator, redactor, and minimal `sing-box` compiler.
//!
//! Zero I/O, zero unsafe code, zero direct-egress fallback. Supports:
//! - Clash / Mihomo YAML single-node snippets and `proxies:` subscriptions
//!   (including automatic normalization of Clash `type: vmess` metadata that carries
//!   `reality-opts` or `flow: xtls-rprx-*` into true `VLESS Reality`).
//! - Standard share URIs (`vless://`, `vmess://`, `trojan://`, `ss://`,
//!   `hysteria2://` / `hy2://`, `tuic://`, `socks5://`, `http(s)://`).
//! - Base64-encoded subscription payloads and structured JSON node manifests.

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use url::Url;

const MAX_IMPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_IMPORT_NODES: usize = 256;
const ALLOWED_FINGERPRINTS: [&str; 9] = [
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
];

fn invalid(detail: impl Into<String>) -> CoreError {
    let msg = detail.into();
    CoreError::new("invalid_vpn_profile", &msg)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VpnSourceMode {
    /// Supervise an existing host VPN client (TAG / Clash / Surge) read-only.
    #[default]
    External,
    /// Run Watch's own isolated, non-TUN loopback VPN tunnel (`watch-vpn-core`).
    Managed,
}

impl VpnSourceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::External => "external",
            Self::Managed => "managed",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "external" => Ok(Self::External),
            "managed" => Ok(Self::Managed),
            _ => Err(invalid("VPN 通道模式必须为 external 或 managed")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManagedVpnProviderKind {
    /// Provided by the operator's built-in remote VPN service endpoint.
    BuiltinService,
    /// User-imported custom node or subscription.
    #[default]
    Custom,
}

impl ManagedVpnProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuiltinService => "builtin_service",
            Self::Custom => "custom",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "builtin_service" | "builtin" | "service" => Ok(Self::BuiltinService),
            "custom" | "manual" => Ok(Self::Custom),
            _ => Err(invalid("节点来源必须为 builtin_service 或 custom")),
        }
    }
}

/// Non-sensitive managed VPN selection persisted inside `config.json`.
/// All secrets (UUIDs, passwords, Reality keys, subscription URLs/tokens) live
/// exclusively in `vpn-vault.json` (`0600`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ManagedVpnConfig {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selected_node_name: String,
    #[serde(default)]
    pub provider_kind: ManagedVpnProviderKind,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expected_country: String,
    /// Reserved extension slot for future per-AI-family independent egress routing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub per_family_node_ids: BTreeMap<String, String>,
}

impl ManagedVpnConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref id) = self.selected_node_id {
            if !valid_node_id(id) {
                return Err(invalid("内置 VPN 节点标识无效"));
            }
        }
        if self.selected_node_name.chars().count() > 256
            || self.selected_node_name.chars().any(char::is_control)
        {
            return Err(invalid("内置 VPN 节点名称无效"));
        }
        if !self.expected_country.is_empty()
            && (self.expected_country.len() != 2
                || !self.expected_country.bytes().all(|b| b.is_ascii_uppercase()))
        {
            return Err(invalid("内置 VPN 预期国家必须为两位大写代码"));
        }
        if self.per_family_node_ids.len() > 16 {
            return Err(invalid("分家族节点绑定数量超出上限"));
        }
        for (family, id) in &self.per_family_node_ids {
            if family.is_empty()
                || family.len() > 32
                || !family.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                || !valid_node_id(id)
            {
                return Err(invalid("分家族节点绑定格式无效"));
            }
        }
        Ok(())
    }
}

pub fn valid_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundProtocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
    Socks5,
    Http,
}

impl OutboundProtocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Vless => "VLESS",
            Self::Vmess => "VMess",
            Self::Trojan => "Trojan",
            Self::Shadowsocks => "Shadowsocks",
            Self::Hysteria2 => "Hysteria2",
            Self::Tuic => "TUIC",
            Self::Socks5 => "SOCKS5",
            Self::Http => "HTTP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityConfig {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub short_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TransportConfig {
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedOutboundNode {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub provider_kind: ManagedVpnProviderKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub protocol: OutboundProtocol,
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default)]
    pub alter_id: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_note: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeProbeStats {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Public, secret-free node summary safe for UI rendering, CLI JSON, and snapshots.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedactedNodeSummary {
    pub id: String,
    pub name: String,
    pub provider_kind: ManagedVpnProviderKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub protocol: OutboundProtocol,
    pub protocol_label: String,
    pub server_masked: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    pub reality: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<NodeProbeStats>,
}

impl NormalizedOutboundNode {
    pub fn protocol_label(&self) -> String {
        let mut parts = vec![self.protocol.label().to_string()];
        if let Some(ref tls) = self.tls {
            if tls.reality.is_some() {
                parts.push("Reality".into());
            } else if tls.enabled {
                parts.push("TLS".into());
            }
        }
        if let Some(ref flow) = self.flow {
            if flow.contains("vision") {
                parts.push("Vision".into());
            }
        }
        if let Some(ref tr) = self.transport {
            if !tr.kind.is_empty() && tr.kind != "tcp" {
                parts.push(tr.kind.to_ascii_uppercase());
            }
        }
        parts.join(" · ")
    }

    pub fn redacted_summary(&self, probe: Option<NodeProbeStats>) -> RedactedNodeSummary {
        let sni = self
            .tls
            .as_ref()
            .filter(|t| !t.server_name.is_empty())
            .map(|t| t.server_name.clone());
        let fingerprint = self.tls.as_ref().and_then(|t| t.fingerprint.clone());
        let reality = self.tls.as_ref().is_some_and(|t| t.reality.is_some());
        RedactedNodeSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            provider_kind: self.provider_kind,
            source_id: self.source_id.clone(),
            protocol: self.protocol,
            protocol_label: self.protocol_label(),
            server_masked: mask_server(&self.server, self.port),
            port: self.port,
            sni,
            fingerprint,
            flow: self.flow.clone(),
            reality,
            protocol_note: self.protocol_note.clone(),
            probe,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_node_id(&self.id) {
            return Err(invalid("节点 ID 格式无效"));
        }
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
            return Err(invalid("节点名称无效"));
        }
        validate_remote_server(&self.server)?;
        if self.port == 0 {
            return Err(invalid("节点端口无效（必须为 1–65535）"));
        }
        match self.protocol {
            OutboundProtocol::Vless | OutboundProtocol::Vmess => {
                let uuid = self
                    .uuid
                    .as_deref()
                    .filter(|v| valid_uuid_like(v))
                    .ok_or_else(|| invalid("VLESS / VMess 节点缺少有效的 UUID"))?;
                if uuid.len() > 64 {
                    return Err(invalid("UUID 长度超限"));
                }
            }
            OutboundProtocol::Trojan | OutboundProtocol::Hysteria2 => {
                let pw = self.password.as_deref().unwrap_or("").trim();
                if pw.is_empty() || pw.len() > 256 || pw.chars().any(char::is_control) {
                    return Err(invalid("Trojan / Hysteria2 节点缺少有效密码"));
                }
            }
            OutboundProtocol::Shadowsocks => {
                let method = self.method.as_deref().unwrap_or("").trim();
                let pw = self.password.as_deref().unwrap_or("").trim();
                if method.is_empty()
                    || method.len() > 64
                    || !method
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(invalid("Shadowsocks 加密方式无效"));
                }
                if pw.is_empty() || pw.len() > 256 || pw.chars().any(char::is_control) {
                    return Err(invalid("Shadowsocks 密码无效"));
                }
            }
            OutboundProtocol::Tuic => {
                if !self.uuid.as_deref().is_some_and(valid_uuid_like) {
                    return Err(invalid("TUIC 节点缺少有效的 UUID"));
                }
                let pw = self.password.as_deref().unwrap_or("").trim();
                if pw.is_empty() || pw.len() > 256 || pw.chars().any(char::is_control) {
                    return Err(invalid("TUIC 节点缺少有效密码"));
                }
            }
            OutboundProtocol::Socks5 | OutboundProtocol::Http => {
                for field in [self.username.as_deref(), self.password.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    if field.len() > 256 || field.chars().any(char::is_control) {
                        return Err(invalid("代理账号或密码包含非法字符"));
                    }
                }
            }
        }
        if let Some(ref flow) = self.flow {
            if flow.len() > 64
                || !flow
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(invalid("flow 参数格式无效"));
            }
        }
        if let Some(ref tls) = self.tls {
            if !tls.server_name.is_empty() {
                validate_hostname(&tls.server_name)
                    .map_err(|_| invalid("TLS SNI / servername 格式无效"))?;
            }
            if let Some(ref fp) = tls.fingerprint {
                if !ALLOWED_FINGERPRINTS.contains(&fp.as_str()) {
                    return Err(invalid(format!("不支持的 uTLS 指纹：{fp}")));
                }
            }
            if let Some(ref reality) = tls.reality {
                if reality.public_key.len() < 20
                    || reality.public_key.len() > 128
                    || !reality
                        .public_key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'+' || b == b'/' || b == b'=')
                {
                    return Err(invalid("Reality public-key 格式无效"));
                }
                if !reality.short_id.is_empty()
                    && (reality.short_id.len() > 16
                        || !reality.short_id.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(invalid("Reality short-id 必须为不超过 16 位的十六进制字符串"));
                }
                if tls.server_name.is_empty() {
                    return Err(invalid("Reality 节点必须提供 SNI / servername"));
                }
            }
        }
        if let Some(ref tr) = self.transport {
            if !matches!(
                tr.kind.as_str(),
                "" | "tcp" | "ws" | "grpc" | "httpupgrade" | "h2" | "http"
            ) {
                return Err(invalid(format!("不支持的传输层类型：{}", tr.kind)));
            }
            for s in [&tr.path, &tr.host, &tr.service_name] {
                if s.len() > 512 || s.chars().any(char::is_control) {
                    return Err(invalid("传输层路径或主机名无效"));
                }
            }
        }
        Ok(())
    }

    pub fn fingerprint_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.protocol.label().as_bytes());
        h.update(b"|");
        h.update(self.server.as_bytes());
        h.update(b"|");
        h.update(self.port.to_string().as_bytes());
        h.update(b"|");
        h.update(self.name.as_bytes());
        if let Some(ref u) = self.uuid {
            h.update(b"|u:");
            h.update(u.as_bytes());
        }
        if let Some(ref p) = self.password {
            h.update(b"|p:");
            h.update(p.as_bytes());
        }
        if let Some(ref f) = self.flow {
            h.update(b"|f:");
            h.update(f.as_bytes());
        }
        if let Some(ref tls) = self.tls {
            h.update(b"|sni:");
            h.update(tls.server_name.as_bytes());
            if let Some(ref r) = tls.reality {
                h.update(b"|pbk:");
                h.update(r.public_key.as_bytes());
                h.update(b"|sid:");
                h.update(r.short_id.as_bytes());
            }
        }
        let digest = h.finalize();
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

pub fn mask_server(server: &str, port: u16) -> String {
    if let Ok(ip) = server.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.*.*:{port}", o[0], o[1])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}:*::*:{port}", s[0], s[1])
            }
        }
    } else {
        let labels: Vec<&str> = server.split('.').collect();
        if labels.len() >= 3 {
            format!("*.{}.{}:{port}", labels[labels.len() - 2], labels[labels.len() - 1])
        } else {
            format!("{server}:{port}")
        }
    }
}

fn validate_remote_server(server: &str) -> Result<()> {
    let trimmed = server.trim();
    if trimmed.is_empty() || trimmed.len() > 253 || trimmed.chars().any(char::is_control) {
        return Err(invalid("节点服务器地址为空或格式无效"));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        let disallowed = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || v4.is_link_local()
                    || v4 == Ipv4Addr::new(0, 0, 0, 0)
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    || v6 == Ipv6Addr::LOCALHOST
            }
        };
        if disallowed {
            return Err(invalid("节点服务器地址不能为回环、广播或未指定地址"));
        }
        return Ok(());
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
        return Err(invalid("节点服务器地址不能指向本机域名"));
    }
    validate_hostname(trimmed)
}

fn validate_hostname(host: &str) -> Result<()> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 || trimmed.contains("..") {
        return Err(invalid("域名格式无效"));
    }
    for label in trimmed.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(invalid("域名包含非法字符"));
        }
    }
    Ok(())
}

fn valid_uuid_like(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn make_node_id(protocol: OutboundProtocol, server: &str, port: u16, name: &str, secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(protocol.label().as_bytes());
    h.update(b":");
    h.update(server.as_bytes());
    h.update(b":");
    h.update(port.to_string().as_bytes());
    h.update(b":");
    h.update(name.as_bytes());
    h.update(b":");
    h.update(secret.as_bytes());
    let d = h.finalize();
    let mut hex = String::with_capacity(12);
    for b in &d[..6] {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("node-{hex}")
}

/// Compile a validated node into a minimal, non-TUN, zero-direct-client-route `sing-box` 1.11 JSON config.
///
/// Security guarantees enforced by construction:
/// 1. No `tun` inbound and `set_system_proxy: false` — never alters macOS routing, DNS, or host VPN.
/// 2. No `bind_interface` — follows macOS routing naturally across Wi-Fi / Ethernet / Hotspot.
/// 3. Client inbound `watch-in` unconditionally routes to `proxy-out`, with `final: "block"`.
///    No client traffic can ever fall back to `direct`.
pub fn compile_singbox_config(node: &NormalizedOutboundNode, listen_port: u16) -> Result<Value> {
    node.validate()?;
    if listen_port == 0 {
        return Err(invalid("本地监听端口无效"));
    }

    let outbound = build_singbox_outbound(node)?;
    let server_is_ip = node.server.parse::<IpAddr>().is_ok();

    let mut outbounds = vec![outbound, json!({ "type": "block", "tag": "block" })];
    let dns = if server_is_ip {
        json!({
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "https://1.1.1.1/dns-query",
                    "detour": "proxy-out"
                }
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4"
        })
    } else {
        // Only used to resolve the remote proxy server's own hostname before tunneling.
        // Client traffic from `watch-in` can never reach `direct-dns-bootstrap`.
        outbounds.push(json!({ "type": "direct", "tag": "direct-dns-bootstrap" }));
        json!({
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "https://1.1.1.1/dns-query",
                    "detour": "proxy-out"
                },
                {
                    "tag": "dns-bootstrap",
                    "address": "local",
                    "detour": "direct-dns-bootstrap"
                }
            ],
            "rules": [
                {
                    "domain": [node.server],
                    "server": "dns-bootstrap"
                }
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4"
        })
    };

    Ok(json!({
        "log": {
            "level": "warn",
            "timestamp": false
        },
        "dns": dns,
        "inbounds": [
            {
                "type": "mixed",
                "tag": "watch-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
                "set_system_proxy": false
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {
                    "inbound": ["watch-in"],
                    "outbound": "proxy-out"
                }
            ],
            "final": "block"
        }
    }))
}

fn build_singbox_outbound(node: &NormalizedOutboundNode) -> Result<Value> {
    let mut obj = Map::new();
    obj.insert("tag".into(), json!("proxy-out"));
    obj.insert("server".into(), json!(node.server));
    obj.insert("server_port".into(), json!(node.port));

    match node.protocol {
        OutboundProtocol::Vless => {
            obj.insert("type".into(), json!("vless"));
            obj.insert("uuid".into(), json!(node.uuid.clone().unwrap_or_default()));
            if let Some(ref flow) = node.flow {
                if !flow.is_empty() {
                    obj.insert("flow".into(), json!(flow));
                }
            }
            if node.udp {
                obj.insert("packet_encoding".into(), json!("xudp"));
            }
        }
        OutboundProtocol::Vmess => {
            obj.insert("type".into(), json!("vmess"));
            obj.insert("uuid".into(), json!(node.uuid.clone().unwrap_or_default()));
            obj.insert(
                "security".into(),
                json!(node.method.clone().unwrap_or_else(|| "auto".into())),
            );
            obj.insert("alter_id".into(), json!(node.alter_id));
        }
        OutboundProtocol::Trojan => {
            obj.insert("type".into(), json!("trojan"));
            obj.insert(
                "password".into(),
                json!(node.password.clone().unwrap_or_default()),
            );
        }
        OutboundProtocol::Shadowsocks => {
            obj.insert("type".into(), json!("shadowsocks"));
            obj.insert(
                "method".into(),
                json!(node.method.clone().unwrap_or_default()),
            );
            obj.insert(
                "password".into(),
                json!(node.password.clone().unwrap_or_default()),
            );
        }
        OutboundProtocol::Hysteria2 => {
            obj.insert("type".into(), json!("hysteria2"));
            obj.insert(
                "password".into(),
                json!(node.password.clone().unwrap_or_default()),
            );
        }
        OutboundProtocol::Tuic => {
            obj.insert("type".into(), json!("tuic"));
            obj.insert("uuid".into(), json!(node.uuid.clone().unwrap_or_default()));
            obj.insert(
                "password".into(),
                json!(node.password.clone().unwrap_or_default()),
            );
            obj.insert("congestion_control".into(), json!("bbr"));
        }
        OutboundProtocol::Socks5 => {
            obj.insert("type".into(), json!("socks"));
            obj.insert("version".into(), json!("5"));
            if let Some(ref u) = node.username {
                if !u.is_empty() {
                    obj.insert("username".into(), json!(u));
                }
            }
            if let Some(ref p) = node.password {
                if !p.is_empty() {
                    obj.insert("password".into(), json!(p));
                }
            }
        }
        OutboundProtocol::Http => {
            obj.insert("type".into(), json!("http"));
            if let Some(ref u) = node.username {
                if !u.is_empty() {
                    obj.insert("username".into(), json!(u));
                }
            }
            if let Some(ref p) = node.password {
                if !p.is_empty() {
                    obj.insert("password".into(), json!(p));
                }
            }
        }
    }

    if let Some(ref tls) = node.tls {
        if tls.enabled || tls.reality.is_some() {
            let mut tls_obj = Map::new();
            tls_obj.insert("enabled".into(), json!(true));
            if !tls.server_name.is_empty() {
                tls_obj.insert("server_name".into(), json!(tls.server_name));
            }
            if tls.insecure {
                tls_obj.insert("insecure".into(), json!(true));
            }
            if !tls.alpn.is_empty() {
                tls_obj.insert("alpn".into(), json!(tls.alpn));
            }
            if let Some(ref fp) = tls.fingerprint {
                tls_obj.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
            } else if tls.reality.is_some() {
                tls_obj.insert(
                    "utls".into(),
                    json!({ "enabled": true, "fingerprint": "chrome" }),
                );
            }
            if let Some(ref reality) = tls.reality {
                let mut r = Map::new();
                r.insert("enabled".into(), json!(true));
                r.insert("public_key".into(), json!(reality.public_key));
                if !reality.short_id.is_empty() {
                    r.insert("short_id".into(), json!(reality.short_id));
                }
                tls_obj.insert("reality".into(), Value::Object(r));
            }
            obj.insert("tls".into(), Value::Object(tls_obj));
        }
    }

    if let Some(ref tr) = node.transport {
        match tr.kind.as_str() {
            "ws" => {
                let mut ws = Map::new();
                ws.insert("type".into(), json!("ws"));
                if !tr.path.is_empty() {
                    ws.insert("path".into(), json!(tr.path));
                }
                if !tr.host.is_empty() {
                    ws.insert("headers".into(), json!({ "Host": tr.host }));
                }
                obj.insert("transport".into(), Value::Object(ws));
            }
            "grpc" => {
                let mut g = Map::new();
                g.insert("type".into(), json!("grpc"));
                if !tr.service_name.is_empty() {
                    g.insert("service_name".into(), json!(tr.service_name));
                }
                obj.insert("transport".into(), Value::Object(g));
            }
            "httpupgrade" => {
                let mut u = Map::new();
                u.insert("type".into(), json!("httpupgrade"));
                if !tr.path.is_empty() {
                    u.insert("path".into(), json!(tr.path));
                }
                if !tr.host.is_empty() {
                    u.insert("host".into(), json!(tr.host));
                }
                obj.insert("transport".into(), Value::Object(u));
            }
            "h2" | "http" => {
                let mut h = Map::new();
                h.insert("type".into(), json!("http"));
                if !tr.path.is_empty() {
                    h.insert("path".into(), json!(tr.path));
                }
                if !tr.host.is_empty() {
                    h.insert("host".into(), json!([tr.host]));
                }
                obj.insert("transport".into(), Value::Object(h));
            }
            _ => {}
        }
    }

    Ok(Value::Object(obj))
}

/// Parse one or more nodes from pasted text or subscription response body.
/// Automatically detects JSON, URI share links, Base64 subscriptions, and Clash YAML.
pub fn parse_nodes_from_text(
    raw: &str,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Result<Vec<NormalizedOutboundNode>> {
    if raw.len() > MAX_IMPORT_BYTES {
        return Err(invalid("导入内容过大（上限 2 MB）"));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid("导入内容为空"));
    }

    // 1. JSON manifest (built-in service API or structured export)
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            let nodes = parse_json_nodes(&value, provider_kind, source_id)?;
            if !nodes.is_empty() {
                return finalize_nodes(nodes);
            }
        }
    }

    // 2. Direct URI lines
    let uri_nodes = parse_uri_lines(trimmed, provider_kind, source_id);
    if !uri_nodes.is_empty() {
        return finalize_nodes(uri_nodes);
    }

    // 3. Base64-encoded subscription body (commonly returned by remote subscription URLs)
    if !trimmed.contains(':') && !trimmed.contains("server:") && trimmed.len() >= 16 {
        if let Some(decoded) = decode_base64_utf8(trimmed) {
            let decoded_uris = parse_uri_lines(&decoded, provider_kind, source_id);
            if !decoded_uris.is_empty() {
                return finalize_nodes(decoded_uris);
            }
            let decoded_yaml = parse_clash_yaml(&decoded, provider_kind, source_id);
            if !decoded_yaml.is_empty() {
                return finalize_nodes(decoded_yaml);
            }
        }
    }

    // 4. Clash / Mihomo YAML (single node block or `proxies:` list)
    let yaml_nodes = parse_clash_yaml(trimmed, provider_kind, source_id);
    if !yaml_nodes.is_empty() {
        return finalize_nodes(yaml_nodes);
    }

    Err(invalid(
        "未能识别有效的节点配置；支持 Clash YAML 节点片段、vless/vmess/trojan/ss/hy2 链接、Base64 订阅或 JSON 节点清单",
    ))
}

fn finalize_nodes(mut nodes: Vec<NormalizedOutboundNode>) -> Result<Vec<NormalizedOutboundNode>> {
    if nodes.is_empty() {
        return Err(invalid("未解析到任何有效节点"));
    }
    if nodes.len() > MAX_IMPORT_NODES {
        nodes.truncate(MAX_IMPORT_NODES);
    }
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut valid = Vec::with_capacity(nodes.len());
    for node in nodes {
        node.validate()?;
        if seen_ids.insert(node.id.clone()) {
            valid.push(node);
        }
    }
    Ok(valid)
}

fn parse_json_nodes(
    value: &Value,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Result<Vec<NormalizedOutboundNode>> {
    if let Some(list) = value.as_array() {
        let mut out = Vec::new();
        for item in list {
            if let Some(node) = parse_json_node_item(item, provider_kind, source_id)? {
                out.push(node);
            }
        }
        return Ok(out);
    }
    if let Some(obj) = value.as_object() {
        for key in ["nodes", "proxies", "outbounds"] {
            if let Some(arr) = obj.get(key).and_then(Value::as_array) {
                let mut out = Vec::new();
                for item in arr {
                    if let Some(node) = parse_json_node_item(item, provider_kind, source_id)? {
                        out.push(node);
                    }
                }
                if !out.is_empty() {
                    return Ok(out);
                }
            }
        }
        if let Some(node) = parse_json_node_item(value, provider_kind, source_id)? {
            return Ok(vec![node]);
        }
    }
    Ok(Vec::new())
}

fn parse_json_node_item(
    item: &Value,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Result<Option<NormalizedOutboundNode>> {
    if let Some(uri) = item.as_str() {
        let parsed = parse_uri_lines(uri, provider_kind, source_id);
        return Ok(parsed.into_iter().next());
    }
    // Already NormalizedOutboundNode JSON
    if let Ok(mut node) = serde_json::from_value::<NormalizedOutboundNode>(item.clone()) {
        node.provider_kind = provider_kind;
        if source_id.is_some() {
            node.source_id = source_id.map(str::to_owned);
        }
        return Ok(Some(node));
    }
    // Clash-style or sing-box outbound JSON object
    if let Some(obj) = item.as_object() {
        let mut flat = BTreeMap::new();
        let mut nested = BTreeMap::new();
        for (k, v) in obj {
            match v {
                Value::String(s) => {
                    flat.insert(k.to_ascii_lowercase(), s.clone());
                }
                Value::Number(n) => {
                    flat.insert(k.to_ascii_lowercase(), n.to_string());
                }
                Value::Bool(b) => {
                    flat.insert(k.to_ascii_lowercase(), b.to_string());
                }
                Value::Object(sub) => {
                    let mut sub_map = BTreeMap::new();
                    for (sk, sv) in sub {
                        match sv {
                            Value::String(s) => {
                                sub_map.insert(sk.to_ascii_lowercase(), s.clone());
                            }
                            Value::Number(n) => {
                                sub_map.insert(sk.to_ascii_lowercase(), n.to_string());
                            }
                            Value::Bool(b) => {
                                sub_map.insert(sk.to_ascii_lowercase(), b.to_string());
                            }
                            Value::Object(deep) => {
                                for (dk, dv) in deep {
                                    if let Some(ds) = dv.as_str() {
                                        sub_map.insert(format!("{}.{}", sk.to_ascii_lowercase(), dk.to_ascii_lowercase()), ds.to_string());
                                    } else if let Some(db) = dv.as_bool() {
                                        sub_map.insert(format!("{}.{}", sk.to_ascii_lowercase(), dk.to_ascii_lowercase()), db.to_string());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    nested.insert(k.to_ascii_lowercase(), sub_map);
                }
                _ => {}
            }
        }
        return Ok(build_node_from_clash_maps(&flat, &nested, provider_kind, source_id));
    }
    Ok(None)
}

fn parse_uri_lines(
    text: &str,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Vec<NormalizedOutboundNode> {
    let mut nodes = Vec::new();
    for line in text.lines() {
        let token = line.trim();
        if token.is_empty() || token.starts_with('#') {
            continue;
        }
        if let Some(node) = parse_single_uri(token, provider_kind, source_id) {
            nodes.push(node);
        }
    }
    nodes
}

fn parse_single_uri(
    uri: &str,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Option<NormalizedOutboundNode> {
    if let Some(rest) = uri.strip_prefix("vmess://") {
        return parse_vmess_uri(rest, provider_kind, source_id);
    }
    if let Some(rest) = uri.strip_prefix("ss://") {
        return parse_ss_uri(rest, provider_kind, source_id);
    }
    let parsed = Url::parse(uri).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed.host_str()?.trim_matches(['[', ']']).to_string();
    let port = parsed.port().or_else(|| match scheme.as_str() {
        "https" | "vless" | "trojan" | "hysteria2" | "hy2" | "tuic" => Some(443),
        "http" => Some(80),
        "socks5" | "socks" => Some(1080),
        _ => None,
    })?;
    let query: BTreeMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect();
    let name = parsed
        .fragment()
        .map(percent_decode)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("{}:{}", scheme.to_ascii_uppercase(), mask_server(&host, port)));

    match scheme.as_str() {
        "vless" => {
            let uuid = percent_decode(parsed.username());
            if uuid.is_empty() {
                return None;
            }
            let flow = query
                .get("flow")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let security = query.get("security").map(|s| s.to_ascii_lowercase());
            let sni = query
                .get("sni")
                .or_else(|| query.get("servername"))
                .cloned()
                .unwrap_or_default();
            let fp = query
                .get("fp")
                .or_else(|| query.get("client-fingerprint"))
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty());
            let pbk = query.get("pbk").or_else(|| query.get("public-key")).cloned();
            let sid = query
                .get("sid")
                .or_else(|| query.get("short-id"))
                .cloned()
                .unwrap_or_default();
            let insecure = matches!(
                query.get("allowinsecure").or_else(|| query.get("insecure")).map(String::as_str),
                Some("1" | "true")
            );
            let reality = pbk.filter(|v| !v.is_empty()).map(|public_key| RealityConfig {
                public_key,
                short_id: sid,
            });
            let tls_enabled = matches!(security.as_deref(), Some("tls" | "reality")) || reality.is_some();
            let tls = tls_enabled.then(|| TlsConfig {
                enabled: true,
                server_name: sni,
                insecure,
                alpn: split_csv(query.get("alpn")),
                fingerprint: fp,
                reality,
            });
            let transport = parse_uri_transport(&query);
            let id = make_node_id(OutboundProtocol::Vless, &host, port, &name, &uuid);
            Some(NormalizedOutboundNode {
                id,
                name,
                provider_kind,
                source_id: source_id.map(str::to_owned),
                protocol: OutboundProtocol::Vless,
                server: host,
                port,
                uuid: Some(uuid),
                password: None,
                username: None,
                method: None,
                alter_id: 0,
                flow,
                udp: true,
                tls,
                transport,
                protocol_note: None,
            })
        }
        "trojan" => {
            let password = percent_decode(parsed.username());
            if password.is_empty() {
                return None;
            }
            let sni = query
                .get("sni")
                .or_else(|| query.get("peer"))
                .cloned()
                .unwrap_or_else(|| host.clone());
            let fp = query
                .get("fp")
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty());
            let insecure = matches!(
                query.get("allowinsecure").or_else(|| query.get("insecure")).map(String::as_str),
                Some("1" | "true")
            );
            let id = make_node_id(OutboundProtocol::Trojan, &host, port, &name, &password);
            Some(NormalizedOutboundNode {
                id,
                name,
                provider_kind,
                source_id: source_id.map(str::to_owned),
                protocol: OutboundProtocol::Trojan,
                server: host,
                port,
                uuid: None,
                password: Some(password),
                username: None,
                method: None,
                alter_id: 0,
                flow: None,
                udp: true,
                tls: Some(TlsConfig {
                    enabled: true,
                    server_name: sni,
                    insecure,
                    alpn: split_csv(query.get("alpn")),
                    fingerprint: fp,
                    reality: None,
                }),
                transport: parse_uri_transport(&query),
                protocol_note: None,
            })
        }
        "hysteria2" | "hy2" => {
            let password = percent_decode(parsed.username());
            if password.is_empty() {
                return None;
            }
            let sni = query
                .get("sni")
                .cloned()
                .unwrap_or_else(|| host.clone());
            let insecure = matches!(
                query.get("insecure").map(String::as_str),
                Some("1" | "true")
            );
            let id = make_node_id(OutboundProtocol::Hysteria2, &host, port, &name, &password);
            Some(NormalizedOutboundNode {
                id,
                name,
                provider_kind,
                source_id: source_id.map(str::to_owned),
                protocol: OutboundProtocol::Hysteria2,
                server: host,
                port,
                uuid: None,
                password: Some(password),
                username: None,
                method: None,
                alter_id: 0,
                flow: None,
                udp: true,
                tls: Some(TlsConfig {
                    enabled: true,
                    server_name: sni,
                    insecure,
                    alpn: split_csv(query.get("alpn")),
                    fingerprint: None,
                    reality: None,
                }),
                transport: None,
                protocol_note: None,
            })
        }
        "tuic" => {
            let uuid = percent_decode(parsed.username());
            let password = parsed.password().map(percent_decode).unwrap_or_default();
            if uuid.is_empty() || password.is_empty() {
                return None;
            }
            let sni = query.get("sni").cloned().unwrap_or_else(|| host.clone());
            let insecure = matches!(
                query.get("allow_insecure").or_else(|| query.get("insecure")).map(String::as_str),
                Some("1" | "true")
            );
            let id = make_node_id(OutboundProtocol::Tuic, &host, port, &name, &uuid);
            Some(NormalizedOutboundNode {
                id,
                name,
                provider_kind,
                source_id: source_id.map(str::to_owned),
                protocol: OutboundProtocol::Tuic,
                server: host,
                port,
                uuid: Some(uuid),
                password: Some(password),
                username: None,
                method: None,
                alter_id: 0,
                flow: None,
                udp: true,
                tls: Some(TlsConfig {
                    enabled: true,
                    server_name: sni,
                    insecure,
                    alpn: {
                        let a = split_csv(query.get("alpn"));
                        if a.is_empty() { vec!["h3".into()] } else { a }
                    },
                    fingerprint: None,
                    reality: None,
                }),
                transport: None,
                protocol_note: None,
            })
        }
        "socks5" | "socks" | "http" | "https" => {
            let protocol = if scheme.starts_with("socks") {
                OutboundProtocol::Socks5
            } else {
                OutboundProtocol::Http
            };
            let username = (!parsed.username().is_empty()).then(|| percent_decode(parsed.username()));
            let password = parsed.password().map(percent_decode);
            let tls = (scheme == "https").then(|| TlsConfig {
                enabled: true,
                server_name: host.clone(),
                ..TlsConfig::default()
            });
            let id = make_node_id(
                protocol,
                &host,
                port,
                &name,
                username.as_deref().unwrap_or(""),
            );
            Some(NormalizedOutboundNode {
                id,
                name,
                provider_kind,
                source_id: source_id.map(str::to_owned),
                protocol,
                server: host,
                port,
                uuid: None,
                password,
                username,
                method: None,
                alter_id: 0,
                flow: None,
                udp: protocol == OutboundProtocol::Socks5,
                tls,
                transport: None,
                protocol_note: None,
            })
        }
        _ => None,
    }
}

fn parse_vmess_uri(
    payload: &str,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Option<NormalizedOutboundNode> {
    let decoded = decode_base64_utf8(payload.trim())?;
    let v: Value = serde_json::from_str(&decoded).ok()?;
    let obj = v.as_object()?;
    let server = obj.get("add")?.as_str()?.trim().to_string();
    let port: u16 = match obj.get("port")? {
        Value::Number(n) => n.as_u64()?.try_into().ok()?,
        Value::String(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    let uuid = obj.get("id")?.as_str()?.trim().to_string();
    let name = obj
        .get("ps")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("VMess {}", mask_server(&server, port)));
    let alter_id: u16 = match obj.get("aid") {
        Some(Value::Number(n)) => n.as_u64().and_then(|x| u16::try_from(x).ok()).unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    };
    let method = obj
        .get("scy")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("auto")
        .to_string();
    let tls_enabled = obj
        .get("tls")
        .and_then(Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("tls"));
    let sni = obj
        .get("sni")
        .or_else(|| obj.get("host"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let fp = obj
        .get("fp")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let net = obj
        .get("net")
        .and_then(Value::as_str)
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    let path = obj
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let transport = if net != "tcp" && !net.is_empty() {
        Some(TransportConfig {
            kind: net.clone(),
            path: if net == "grpc" { String::new() } else { path.clone() },
            host,
            service_name: if net == "grpc" { path } else { String::new() },
        })
    } else {
        None
    };
    let id = make_node_id(OutboundProtocol::Vmess, &server, port, &name, &uuid);
    Some(NormalizedOutboundNode {
        id,
        name,
        provider_kind,
        source_id: source_id.map(str::to_owned),
        protocol: OutboundProtocol::Vmess,
        server,
        port,
        uuid: Some(uuid),
        password: None,
        username: None,
        method: Some(method),
        alter_id,
        flow: None,
        udp: true,
        tls: tls_enabled.then(|| TlsConfig {
            enabled: true,
            server_name: sni,
            insecure: false,
            alpn: Vec::new(),
            fingerprint: fp,
            reality: None,
        }),
        transport,
        protocol_note: None,
    })
}

fn parse_ss_uri(
    rest: &str,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Option<NormalizedOutboundNode> {
    let (main, fragment) = match rest.split_once('#') {
        Some((l, r)) => (l, Some(percent_decode(r))),
        None => (rest, None),
    };
    let main = main.split_once('?').map(|(l, _)| l).unwrap_or(main);
    let (userinfo_raw, hostport) = if let Some((l, r)) = main.rsplit_once('@') {
        let userinfo = decode_base64_utf8(l).unwrap_or_else(|| percent_decode(l));
        (userinfo, r.to_string())
    } else {
        let decoded = decode_base64_utf8(main)?;
        let (l, r) = decoded.rsplit_once('@')?;
        (l.to_string(), r.to_string())
    };
    let (method, password) = userinfo_raw.split_once(':')?;
    let (server, port_str) = split_host_port(&hostport)?;
    let port: u16 = port_str.parse().ok()?;
    let name = fragment
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("SS {}", mask_server(&server, port)));
    let id = make_node_id(OutboundProtocol::Shadowsocks, &server, port, &name, password);
    Some(NormalizedOutboundNode {
        id,
        name,
        provider_kind,
        source_id: source_id.map(str::to_owned),
        protocol: OutboundProtocol::Shadowsocks,
        server,
        port,
        uuid: None,
        password: Some(password.to_string()),
        username: None,
        method: Some(method.to_string()),
        alter_id: 0,
        flow: None,
        udp: true,
        tls: None,
        transport: None,
        protocol_note: None,
    })
}

fn parse_uri_transport(query: &BTreeMap<String, String>) -> Option<TransportConfig> {
    let kind = query
        .get("type")
        .or_else(|| query.get("network"))
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if kind.is_empty() || kind == "tcp" || kind == "none" {
        return None;
    }
    Some(TransportConfig {
        kind,
        path: query.get("path").cloned().unwrap_or_default(),
        host: query.get("host").cloned().unwrap_or_default(),
        service_name: query
            .get("servicename")
            .or_else(|| query.get("service-name"))
            .cloned()
            .unwrap_or_default(),
    })
}

/// Parse Clash / Mihomo YAML either as a full subscription (`proxies:`) or as a
/// standalone pasted single-node block (even with an optional decorative header line).
fn parse_clash_yaml(
    text: &str,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Vec<NormalizedOutboundNode> {
    let mut blocks: Vec<(BTreeMap<String, String>, BTreeMap<String, BTreeMap<String, String>>)> =
        Vec::new();
    let lines: Vec<&str> = text.lines().collect();

    // Check if there is an explicit `proxies:` top-level section.
    let start_idx = lines
        .iter()
        .position(|line| {
            let stripped = strip_yaml_comment(line).trim();
            stripped == "proxies:"
        })
        .map(|idx| idx + 1);

    if let Some(start) = start_idx {
        let mut cur_flat: BTreeMap<String, String> = BTreeMap::new();
        let mut cur_nested: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut active_nested: Option<String> = None;
        let mut item_indent: Option<usize> = None;

        for raw_line in &lines[start..] {
            let cleaned = strip_yaml_comment(raw_line);
            let trimmed = cleaned.trim();
            if trimmed.is_empty() {
                continue;
            }
            let indent = raw_line.chars().take_while(|c| *c == ' ').count();
            // Next top-level section ends `proxies:`
            if indent == 0 && !trimmed.starts_with('-') && trimmed.ends_with(':') {
                break;
            }
            if let Some(after_dash) = trimmed.strip_prefix('-') {
                let after = after_dash.trim();
                if item_indent.is_none() || indent <= item_indent.unwrap_or(usize::MAX) {
                    if !cur_flat.is_empty() {
                        blocks.push((
                            std::mem::take(&mut cur_flat),
                            std::mem::take(&mut cur_nested),
                        ));
                    }
                    active_nested = None;
                    item_indent = Some(indent);
                    if after.starts_with('{') && after.ends_with('}') {
                        if let Some((f, n)) = parse_flow_yaml_map(after) {
                            blocks.push((f, n));
                        }
                        continue;
                    }
                    if let Some((k, v)) = split_yaml_kv(after) {
                        if v.is_empty() {
                            active_nested = Some(k);
                        } else {
                            cur_flat.insert(k, v);
                        }
                    }
                    continue;
                }
            }
            if let Some((k, v)) = split_yaml_kv(trimmed) {
                let base_indent = item_indent.unwrap_or(0) + 2;
                if indent > base_indent {
                    if let Some(ref parent) = active_nested {
                        cur_nested.entry(parent.clone()).or_default().insert(k, v);
                        continue;
                    }
                }
                if v.is_empty() {
                    active_nested = Some(k);
                } else {
                    active_nested = None;
                    cur_flat.insert(k, v);
                }
            }
        }
        if !cur_flat.is_empty() {
            blocks.push((cur_flat, cur_nested));
        }
    } else {
        // Standalone pasted single-node YAML snippet (with optional leading title line
        // or optional leading `- `).
        let mut cur_flat: BTreeMap<String, String> = BTreeMap::new();
        let mut cur_nested: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut active_nested: Option<String> = None;
        let mut base_indent: Option<usize> = None;

        for raw_line in &lines {
            let cleaned = strip_yaml_comment(raw_line);
            let trimmed = cleaned.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                if let Some((f, n)) = parse_flow_yaml_map(trimmed) {
                    blocks.push((f, n));
                }
                continue;
            }
            let indent = raw_line.chars().take_while(|c| *c == ' ').count();
            let effective = trimmed.strip_prefix("- ").unwrap_or(trimmed);
            let Some((k, v)) = split_yaml_kv(effective) else {
                // Ignore decorative title lines like `普通共享｜🇬🇧 ...` that contain no YAML key.
                continue;
            };
            if base_indent.is_none() {
                base_indent = Some(indent);
            }
            let root_indent = base_indent.unwrap_or(0);
            if indent > root_indent {
                if let Some(ref parent) = active_nested {
                    cur_nested.entry(parent.clone()).or_default().insert(k, v);
                    continue;
                }
            }
            if v.is_empty() {
                active_nested = Some(k);
            } else {
                active_nested = None;
                cur_flat.insert(k, v);
            }
        }
        if !cur_flat.is_empty() {
            blocks.push((cur_flat, cur_nested));
        }
    }

    blocks
        .into_iter()
        .filter_map(|(flat, nested)| {
            build_node_from_clash_maps(&flat, &nested, provider_kind, source_id)
        })
        .collect()
}

fn build_node_from_clash_maps(
    flat: &BTreeMap<String, String>,
    nested: &BTreeMap<String, BTreeMap<String, String>>,
    provider_kind: ManagedVpnProviderKind,
    source_id: Option<&str>,
) -> Option<NormalizedOutboundNode> {
    let server = flat.get("server")?.trim().to_string();
    let port: u16 = flat
        .get("port")
        .or_else(|| flat.get("server_port"))?
        .trim()
        .parse()
        .ok()?;
    let raw_type = flat
        .get("type")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    let flow = flat
        .get("flow")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let reality_opts = nested
        .get("reality-opts")
        .or_else(|| nested.get("reality_opts"))
        .or_else(|| nested.get("reality"));
    let reality_pbk = reality_opts
        .and_then(|m| m.get("public-key").or_else(|| m.get("public_key")))
        .or_else(|| {
            nested
                .get("tls")
                .and_then(|m| m.get("reality.public_key").or_else(|| m.get("reality.public-key")))
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let reality_sid = reality_opts
        .and_then(|m| m.get("short-id").or_else(|| m.get("short_id")))
        .or_else(|| {
            nested
                .get("tls")
                .and_then(|m| m.get("reality.short_id").or_else(|| m.get("reality.short-id")))
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let reality = reality_pbk.map(|public_key| RealityConfig {
        public_key,
        short_id: reality_sid,
    });

    let mut protocol_note = None;
    let protocol = match raw_type.as_str() {
        "vless" => OutboundProtocol::Vless,
        "vmess" => {
            // Clash / Mihomo provider exports frequently tag VLESS Reality nodes as
            // `type: vmess` while carrying `flow: xtls-rprx-*` and `reality-opts`.
            let looks_like_vless_reality = reality.is_some()
                || flow
                    .as_deref()
                    .is_some_and(|f| f.to_ascii_lowercase().starts_with("xtls-rprx-"));
            if looks_like_vless_reality {
                protocol_note = Some("已自动识别为 VLESS Reality（原配置标注 type: vmess）".into());
                OutboundProtocol::Vless
            } else {
                OutboundProtocol::Vmess
            }
        }
        "trojan" => OutboundProtocol::Trojan,
        "ss" | "shadowsocks" => OutboundProtocol::Shadowsocks,
        "hysteria2" | "hy2" => OutboundProtocol::Hysteria2,
        "tuic" => OutboundProtocol::Tuic,
        "socks5" | "socks" => OutboundProtocol::Socks5,
        "http" => OutboundProtocol::Http,
        "" if reality.is_some() => OutboundProtocol::Vless,
        _ => return None,
    };

    let name = flat
        .get("name")
        .or_else(|| flat.get("tag"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{} {}", protocol.label(), mask_server(&server, port)));

    let uuid = flat
        .get("uuid")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let password = flat
        .get("password")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let username = flat
        .get("username")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let method = flat
        .get("cipher")
        .or_else(|| flat.get("method"))
        .or_else(|| flat.get("security"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let alter_id = flat
        .get("alterid")
        .or_else(|| flat.get("alter_id"))
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(0);
    let udp = flat
        .get("udp")
        .map(|s| parse_yaml_bool(s))
        .unwrap_or(true);

    let tls_flag = flat
        .get("tls")
        .map(|s| parse_yaml_bool(s))
        .or_else(|| nested.get("tls").and_then(|m| m.get("enabled")).map(|s| parse_yaml_bool(s)))
        .unwrap_or(matches!(
            protocol,
            OutboundProtocol::Trojan | OutboundProtocol::Hysteria2 | OutboundProtocol::Tuic
        ));
    let server_name = flat
        .get("servername")
        .or_else(|| flat.get("sni"))
        .or_else(|| nested.get("tls").and_then(|m| m.get("server_name")))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let insecure = flat
        .get("skip-cert-verify")
        .or_else(|| flat.get("insecure"))
        .or_else(|| nested.get("tls").and_then(|m| m.get("insecure")))
        .map(|s| parse_yaml_bool(s))
        .unwrap_or(false);
    let fingerprint = flat
        .get("client-fingerprint")
        .or_else(|| flat.get("fingerprint"))
        .or_else(|| nested.get("tls").and_then(|m| m.get("utls.fingerprint")))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let tls = (tls_flag || reality.is_some()).then(|| TlsConfig {
        enabled: true,
        server_name,
        insecure,
        alpn: Vec::new(),
        fingerprint,
        reality,
    });

    let network = flat
        .get("network")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let transport = match network.as_str() {
        "ws" => {
            let ws = nested.get("ws-opts");
            Some(TransportConfig {
                kind: "ws".into(),
                path: ws.and_then(|m| m.get("path")).cloned().unwrap_or_default(),
                host: ws
                    .and_then(|m| m.get("headers.host").or_else(|| m.get("host")))
                    .cloned()
                    .unwrap_or_default(),
                service_name: String::new(),
            })
        }
        "grpc" => {
            let grpc = nested.get("grpc-opts");
            Some(TransportConfig {
                kind: "grpc".into(),
                path: String::new(),
                host: String::new(),
                service_name: grpc
                    .and_then(|m| m.get("grpc-service-name").or_else(|| m.get("service_name")))
                    .cloned()
                    .unwrap_or_default(),
            })
        }
        "httpupgrade" | "h2" | "http" => Some(TransportConfig {
            kind: network,
            path: flat.get("path").cloned().unwrap_or_default(),
            host: flat.get("host").cloned().unwrap_or_default(),
            service_name: String::new(),
        }),
        _ => None,
    };

    let secret_seed = uuid
        .as_deref()
        .or(password.as_deref())
        .or(username.as_deref())
        .unwrap_or("");
    let id = make_node_id(protocol, &server, port, &name, secret_seed);

    Some(NormalizedOutboundNode {
        id,
        name,
        provider_kind,
        source_id: source_id.map(str::to_owned),
        protocol,
        server,
        port,
        uuid,
        password,
        username,
        method,
        alter_id,
        flow,
        udp,
        tls,
        transport,
        protocol_note,
    })
}

fn parse_flow_yaml_map(
    raw: &str,
) -> Option<(BTreeMap<String, String>, BTreeMap<String, BTreeMap<String, String>>)> {
    let inner = raw.trim().strip_prefix('{')?.strip_suffix('}')?.trim();
    let mut flat = BTreeMap::new();
    let mut nested = BTreeMap::new();
    for part in split_top_level_commas(inner) {
        let Some((k, v)) = split_yaml_kv(part.trim()) else {
            continue;
        };
        if v.starts_with('{') && v.ends_with('}') {
            if let Some((sub, _)) = parse_flow_yaml_map(&v) {
                nested.insert(k, sub);
            }
        } else {
            flat.insert(k, v);
        }
    }
    (!flat.is_empty()).then_some((flat, nested))
}

fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    for (i, ch) in s.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '{' | '[' => depth += 1,
                '}' | ']' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    out.push(&s[start..i]);
                    start = i + 1;
                }
                _ => {}
            },
        }
    }
    if start <= s.len() {
        out.push(&s[start..]);
    }
    out
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for (i, ch) in line.char_indices() {
        match quote {
            Some(q) if ch == q => {
                quote = None;
                prev_space = false;
            }
            Some(_) => prev_space = false,
            None => {
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                    prev_space = false;
                } else if ch == '#' && prev_space {
                    return &line[..i];
                } else {
                    prev_space = ch.is_whitespace();
                }
            }
        }
    }
    line
}

fn split_yaml_kv(line: &str) -> Option<(String, String)> {
    let idx = line.find(':')?;
    let key = line[..idx].trim();
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return None;
    }
    let val_raw = line[idx + 1..].trim();
    let val = unquote_yaml(val_raw);
    Some((key.to_ascii_lowercase(), val))
}

fn unquote_yaml(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_yaml_bool(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

fn split_csv(raw: Option<&String>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

fn split_host_port(hp: &str) -> Option<(String, &str)> {
    if let Some(rest) = hp.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        Some((host.to_string(), port))
    } else {
        let (host, port) = hp.rsplit_once(':')?;
        Some((host.to_string(), port))
    }
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Self-contained RFC 4648 base64 / base64url decoder (tolerant of whitespace and omitted padding).
fn decode_base64_utf8(input: &str) -> Option<String> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() * 3 / 4 + 2);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in cleaned {
        if b == b'=' {
            break;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clash_yaml_vmess_with_reality_and_vision_auto_normalizes_to_vless_reality() {
        let yaml = r#"
示例共享｜🇬🇧 UK Test Reality

name: 示例共享｜🇬🇧 UK Test Reality
type: vmess  # Clash metadata; actually VLESS Reality
server: 203.0.113.10
port: 443
uuid: 00000000-0000-4000-8000-000000000001
alterId: 0
cipher: auto
udp: true
flow: xtls-rprx-vision
tls: true
servername: www.example.com        # SNI
reality-opts:
  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  short-id: 0123456789abcdef
client-fingerprint: chrome
skip-cert-verify: false
encryption: none
"#;
        let nodes =
            parse_nodes_from_text(yaml, ManagedVpnProviderKind::Custom, Some("manual")).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.protocol, OutboundProtocol::Vless);
        assert_eq!(node.server, "203.0.113.10");
        assert_eq!(node.port, 443);
        assert_eq!(node.flow.as_deref(), Some("xtls-rprx-vision"));
        assert!(node.protocol_note.as_deref().unwrap().contains("VLESS Reality"));
        let tls = node.tls.as_ref().unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.server_name, "www.example.com");
        assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
        let reality = tls.reality.as_ref().unwrap();
        assert_eq!(reality.public_key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(reality.short_id, "0123456789abcdef");

        let compiled = compile_singbox_config(node, 18999).unwrap();
        assert_eq!(compiled["inbounds"][0]["type"], "mixed");
        assert_eq!(compiled["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(compiled["inbounds"][0]["listen_port"], 18999);
        assert_eq!(compiled["inbounds"][0]["set_system_proxy"], false);
        assert_eq!(compiled["outbounds"][0]["type"], "vless");
        assert_eq!(compiled["outbounds"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(compiled["outbounds"][0]["tls"]["reality"]["enabled"], true);
        assert_eq!(compiled["outbounds"][0]["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(compiled["route"]["final"], "block");
        // IP literal server requires zero direct outbound and zero bind_interface.
        let text = compiled.to_string();
        assert!(!text.contains("\"tun\""));
        assert!(!text.contains("bind_interface"));
        assert!(!text.contains("\"direct\""));

        let summary = node.redacted_summary(None);
        let summary_json = serde_json::to_string(&summary).unwrap();
        assert_eq!(summary.server_masked, "203.0.*.*:443");
        assert!(!summary_json.contains("00000000-0000-4000-8000-000000000001"));
        assert!(!summary_json.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!summary_json.contains("0123456789abcdef"));
    }

    #[test]
    fn parses_vless_trojan_hy2_and_clash_proxies_list() {
        let uris = "\
vless://00000000-0000-4000-8000-000000000002@198.51.100.20:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.org&fp=chrome&pbk=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&sid=abcdef01#US%20Reality
trojan://test-secret-pw@edge.example.com:443?sni=edge.example.com#JP%20Trojan
hysteria2://hy2-secret-pw@198.51.100.21:8443?sni=hy2.example.com#SG%20HY2
";
        let nodes =
            parse_nodes_from_text(uris, ManagedVpnProviderKind::BuiltinService, Some("svc-1"))
                .unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].protocol, OutboundProtocol::Vless);
        assert_eq!(nodes[0].name, "US Reality");
        assert_eq!(nodes[1].protocol, OutboundProtocol::Trojan);
        assert_eq!(nodes[2].protocol, OutboundProtocol::Hysteria2);

        // Domain server gets a dedicated DNS-only bootstrap outbound, while all
        // watch-in client traffic routes strictly to proxy-out with final=block.
        let compiled_domain = compile_singbox_config(&nodes[1], 19001).unwrap();
        assert_eq!(compiled_domain["route"]["rules"][0]["inbound"][0], "watch-in");
        assert_eq!(compiled_domain["route"]["rules"][0]["outbound"], "proxy-out");
        assert_eq!(compiled_domain["route"]["final"], "block");
    }

    #[test]
    fn rejects_loopback_and_localhost_nodes() {
        let bad = "vless://00000000-0000-4000-8000-000000000002@127.0.0.1:443?security=tls&sni=example.com#Loop";
        assert!(parse_nodes_from_text(bad, ManagedVpnProviderKind::Custom, None).is_err());
        let bad_host = "trojan://pw@localhost:443#Local";
        assert!(parse_nodes_from_text(bad_host, ManagedVpnProviderKind::Custom, None).is_err());
    }
}
