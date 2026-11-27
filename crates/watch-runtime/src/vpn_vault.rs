//! Private `0600` vault for managed VPN node credentials, built-in VPN service
//! configuration, and remote subscription sync.
//!
//! Secrets (UUIDs, passwords, Reality keys, service tokens, subscription URLs)
//! never leave this file into `config.json`, logs, or UI snapshots.

use crate::storage::StateStore;
use claude_watch_core::{
    error::{CoreError, Result},
    vpn_profile::{
        parse_nodes_from_text, ManagedVpnProviderKind, NodeProbeStats, NormalizedOutboundNode,
        RedactedNodeSummary,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, io::Read, path::PathBuf, time::Duration};
use url::Url;

const MAX_REMOTE_SUBSCRIPTION_BYTES: u64 = 2 * 1024 * 1024;
const REMOTE_FETCH_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct BuiltinServiceConfig {
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnVault {
    pub schema: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builtin_service: Option<BuiltinServiceConfig>,
    #[serde(default)]
    pub nodes: Vec<NormalizedOutboundNode>,
    #[serde(default)]
    pub probe_stats: BTreeMap<String, NodeProbeStats>,
}

impl Default for VpnVault {
    fn default() -> Self {
        Self {
            schema: 1,
            builtin_service: None,
            nodes: Vec::new(),
            probe_stats: BTreeMap::new(),
        }
    }
}

pub struct VpnVaultStore {
    pub storage: StateStore,
}

impl VpnVaultStore {
    pub fn new(storage: StateStore) -> Self {
        Self { storage }
    }

    pub fn path(&self) -> PathBuf {
        self.storage.paths.watch().join("vpn-vault.json")
    }

    pub fn load(&self) -> Result<VpnVault> {
        let p = self.path();
        if !p.exists() {
            return Ok(VpnVault::default());
        }
        let val = self.storage.read_json(&p, json!({}))?;
        let vault: VpnVault = serde_json::from_value(val)
            .map_err(|_| CoreError::new("vpn_vault_corrupted", "内置 VPN 私密凭据库格式无效"))?;
        Ok(vault)
    }

    fn save_locked(&self, vault: &VpnVault) -> Result<()> {
        let dir = self.storage.paths.watch();
        self.storage.private_dir(&dir)?;
        let val = serde_json::to_value(vault)
            .map_err(|_| CoreError::new("vpn_vault_encode_failed", "内置 VPN 凭据序列化失败"))?;
        self.storage.atomic_json(&self.path(), &val)
    }

    pub fn node_by_id(&self, id: &str) -> Result<Option<NormalizedOutboundNode>> {
        let vault = self.load()?;
        Ok(vault.nodes.into_iter().find(|n| n.id == id))
    }

    pub fn list_redacted_nodes(&self) -> Result<Vec<RedactedNodeSummary>> {
        let vault = self.load()?;
        Ok(vault
            .nodes
            .iter()
            .map(|n| n.redacted_summary(vault.probe_stats.get(&n.id).cloned()))
            .collect())
    }

    pub fn redacted_service_summary(&self) -> Result<Value> {
        let vault = self.load()?;
        Ok(redact_service(vault.builtin_service.as_ref()))
    }

    pub fn import_text(
        &self,
        raw: &str,
        provider_kind: ManagedVpnProviderKind,
        source_id: Option<&str>,
        replace_provider: bool,
    ) -> Result<Vec<RedactedNodeSummary>> {
        let parsed = parse_nodes_from_text(raw, provider_kind, source_id)?;
        self.upsert_nodes(parsed, provider_kind, replace_provider)
    }

    pub fn upsert_nodes(
        &self,
        incoming: Vec<NormalizedOutboundNode>,
        provider_kind: ManagedVpnProviderKind,
        replace_provider: bool,
    ) -> Result<Vec<RedactedNodeSummary>> {
        let _lock = self.storage.lock("vpn-vault", None)?;
        let mut vault = self.load()?;
        if replace_provider {
            vault.nodes.retain(|n| n.provider_kind != provider_kind);
        }
        let mut imported_summaries = Vec::with_capacity(incoming.len());
        for node in incoming {
            node.validate()?;
            let summary = node.redacted_summary(vault.probe_stats.get(&node.id).cloned());
            if let Some(existing) = vault.nodes.iter_mut().find(|n| n.id == node.id) {
                *existing = node;
            } else {
                vault.nodes.push(node);
            }
            imported_summaries.push(summary);
        }
        let valid_ids: std::collections::BTreeSet<String> =
            vault.nodes.iter().map(|n| n.id.clone()).collect();
        vault.probe_stats.retain(|id, _| valid_ids.contains(id));
        self.save_locked(&vault)?;
        Ok(imported_summaries)
    }

    pub fn delete_node(&self, id: &str) -> Result<bool> {
        let _lock = self.storage.lock("vpn-vault", None)?;
        let mut vault = self.load()?;
        let before = vault.nodes.len();
        vault.nodes.retain(|n| n.id != id);
        vault.probe_stats.remove(id);
        let removed = vault.nodes.len() != before;
        if removed {
            self.save_locked(&vault)?;
        }
        Ok(removed)
    }

    pub fn record_probe_stats(&self, node_id: &str, stats: NodeProbeStats) -> Result<()> {
        let _lock = self.storage.lock("vpn-vault", None)?;
        let mut vault = self.load()?;
        if vault.nodes.iter().any(|n| n.id == node_id) {
            vault.probe_stats.insert(node_id.to_string(), stats);
            self.save_locked(&vault)?;
        }
        Ok(())
    }

    pub fn set_builtin_service(
        &self,
        url: &str,
        token: Option<&str>,
        label: Option<&str>,
    ) -> Result<Value> {
        validate_service_url(url, false)?;
        let _lock = self.storage.lock("vpn-vault", None)?;
        let mut vault = self.load()?;
        let prev = vault.builtin_service.clone().unwrap_or_default();
        let next_token = match token {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            Some(_) => String::new(),
            None => prev.token,
        };
        if next_token.len() > 2048 || next_token.chars().any(char::is_control) {
            return Err(CoreError::new("invalid_vpn_service", "服务授权码格式无效"));
        }
        let next_label = label
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if !prev.label.is_empty() {
                    prev.label
                } else {
                    "自带 VPN 服务".into()
                }
            });
        let cfg = BuiltinServiceConfig {
            url: url.trim().to_string(),
            token: next_token,
            label: next_label,
            last_synced_at: prev.last_synced_at,
            last_error: None,
            notice: prev.notice,
        };
        let summary = redact_service(Some(&cfg));
        vault.builtin_service = Some(cfg);
        self.save_locked(&vault)?;
        Ok(summary)
    }

    pub fn clear_builtin_service(&self) -> Result<()> {
        let _lock = self.storage.lock("vpn-vault", None)?;
        let mut vault = self.load()?;
        vault.builtin_service = None;
        vault
            .nodes
            .retain(|n| n.provider_kind != ManagedVpnProviderKind::BuiltinService);
        let valid_ids: std::collections::BTreeSet<String> =
            vault.nodes.iter().map(|n| n.id.clone()).collect();
        vault.probe_stats.retain(|id, _| valid_ids.contains(id));
        self.save_locked(&vault)
    }

    /// Synchronize nodes from the configured built-in VPN service endpoint.
    /// Fetches directly via system network (never blocked by an unstarted tunnel).
    pub fn sync_builtin_service(&self, now_secs: u64) -> Result<Value> {
        let vault = self.load()?;
        let service = vault.builtin_service.ok_or_else(|| {
            CoreError::new("vpn_service_unconfigured", "尚未配置自带 VPN 服务接入地址")
        })?;
        self.sync_from_url_with_fetcher(&service, now_secs, fetch_remote_text)
    }

    pub fn import_remote_subscription(
        &self,
        url: &str,
        provider_kind: ManagedVpnProviderKind,
    ) -> Result<Vec<RedactedNodeSummary>> {
        validate_service_url(url, false)?;
        let body = fetch_remote_text(url.trim(), "")?;
        self.import_text(&body, provider_kind, Some("subscription"), false)
    }

    pub fn sync_from_url_with_fetcher<F>(
        &self,
        service: &BuiltinServiceConfig,
        now_secs: u64,
        fetcher: F,
    ) -> Result<Value>
    where
        F: FnOnce(&str, &str) -> Result<String>,
    {
        let body = match fetcher(&service.url, &service.token) {
            Ok(b) => b,
            Err(err) => {
                let _lock = self.storage.lock("vpn-vault", None)?;
                let mut vault = self.load()?;
                if let Some(ref mut cfg) = vault.builtin_service {
                    cfg.last_error = Some(err.message.clone());
                    let _ = self.save_locked(&vault);
                }
                return Err(err);
            }
        };

        let notice = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v.get("notice").and_then(Value::as_str).map(str::to_owned))
            .filter(|s| !s.trim().is_empty() && s.chars().count() <= 300);

        let nodes = parse_nodes_from_text(
            &body,
            ManagedVpnProviderKind::BuiltinService,
            Some("builtin_service"),
        )?;
        let summaries = self.upsert_nodes(nodes, ManagedVpnProviderKind::BuiltinService, true)?;

        let service_summary = {
            let _lock = self.storage.lock("vpn-vault", None)?;
            let mut vault = self.load()?;
            if let Some(ref mut cfg) = vault.builtin_service {
                cfg.last_synced_at = Some(now_secs);
                cfg.last_error = None;
                cfg.notice = notice;
                self.save_locked(&vault)?;
            }
            redact_service(vault.builtin_service.as_ref())
        };

        Ok(json!({
            "status": "ok",
            "count": summaries.len(),
            "nodes": summaries,
            "service": service_summary,
        }))
    }
}

pub fn validate_service_url(raw: &str, allow_http_loopback: bool) -> Result<Url> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 || trimmed.chars().any(char::is_control) {
        return Err(CoreError::new("invalid_vpn_service", "服务地址为空或格式无效"));
    }
    let parsed = Url::parse(trimmed)
        .map_err(|_| CoreError::new("invalid_vpn_service", "服务地址不是有效的 URL"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| CoreError::new("invalid_vpn_service", "服务地址缺少主机名"))?;
    let scheme_ok = parsed.scheme() == "https"
        || (allow_http_loopback
            && parsed.scheme() == "http"
            && (host == "127.0.0.1" || host == "localhost" || host == "::1"));
    if !scheme_ok {
        return Err(CoreError::new(
            "invalid_vpn_service",
            "远程 VPN 服务与订阅地址必须使用 HTTPS",
        ));
    }
    Ok(parsed)
}

fn fetch_remote_text(url: &str, token: &str) -> Result<String> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(REMOTE_FETCH_TIMEOUT))
        .build()
        .new_agent();
    let mut req = agent.get(url).header("User-Agent", "AgentWatch/4.3 (clash-meta)");
    if !token.trim().is_empty() {
        req = req
            .header("Authorization", &format!("Bearer {}", token.trim()))
            .header("X-Watch-Token", token.trim());
    }
    let response = req.call().map_err(|err| {
        CoreError::new(
            "vpn_service_fetch_failed",
            &format!("拉取远程节点失败：{}", sanitize_fetch_error(&err.to_string())),
        )
    })?;
    let mut buf = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(MAX_REMOTE_SUBSCRIPTION_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|_| CoreError::new("vpn_service_fetch_failed", "读取远程节点响应失败"))?;
    if buf.len() as u64 > MAX_REMOTE_SUBSCRIPTION_BYTES {
        return Err(CoreError::new(
            "vpn_service_oversize",
            "远程节点响应超过 2 MB 安全上限",
        ));
    }
    String::from_utf8(buf)
        .map_err(|_| CoreError::new("vpn_service_invalid", "远程节点响应不是有效 UTF-8 文本"))
}

fn sanitize_fetch_error(raw: &str) -> String {
    raw.split('?')
        .next()
        .unwrap_or("网络请求失败")
        .chars()
        .take(160)
        .collect()
}

fn redact_service(cfg: Option<&BuiltinServiceConfig>) -> Value {
    let Some(cfg) = cfg else {
        return json!({
            "configured": false,
            "label": "",
            "host": "",
            "has_token": false,
        });
    };
    let host = Url::parse(&cfg.url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    json!({
        "configured": !cfg.url.is_empty(),
        "label": cfg.label,
        "host": host,
        "has_token": !cfg.token.is_empty(),
        "last_synced_at": cfg.last_synced_at,
        "last_error": cfg.last_error,
        "notice": cfg.notice,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn vault_stores_secrets_0600_and_never_leaks_them_in_redacted_views() {
        let root = std::env::temp_dir().join(format!("cw-vpn-vault-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let vault = VpnVaultStore::new(store);

        let yaml = r#"
name: UK Test Reality
type: vmess
server: 203.0.113.42
port: 443
uuid: 00000000-0000-4000-8000-000000000099
flow: xtls-rprx-vision
tls: true
servername: www.example.com
reality-opts:
  public-key: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
  short-id: 0011223344556677
client-fingerprint: chrome
"#;
        let imported = vault
            .import_text(yaml, ManagedVpnProviderKind::Custom, Some("paste"), false)
            .unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].server_masked, "203.0.*.*:443");

        let mode = std::fs::metadata(vault.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vpn-vault.json must be strictly 0600");

        let svc = vault
            .set_builtin_service(
                "https://vpn.example.com/sub?key=super-secret-query",
                Some("tok-super-secret"),
                Some("主公自带节点"),
            )
            .unwrap();
        let svc_text = svc.to_string();
        assert_eq!(svc["configured"], true);
        assert_eq!(svc["host"], "vpn.example.com");
        assert_eq!(svc["has_token"], true);
        assert!(!svc_text.contains("super-secret-query"));
        assert!(!svc_text.contains("tok-super-secret"));

        // Sync builtin service preserves custom nodes while replacing builtin nodes.
        let cfg = vault.load().unwrap().builtin_service.unwrap();
        let sync_res = vault
            .sync_from_url_with_fetcher(&cfg, 1_800_000_000, |_url, tok| {
                assert_eq!(tok, "tok-super-secret");
                Ok(json!({
                    "notice": "官方专线正常",
                    "nodes": [
                        "trojan://svc-secret@198.51.100.50:443?sni=edge.example.com#Official%20US"
                    ]
                })
                .to_string())
            })
            .unwrap();
        assert_eq!(sync_res["count"], 1);
        assert_eq!(sync_res["service"]["notice"], "官方专线正常");

        let all = vault.list_redacted_nodes().unwrap();
        assert_eq!(all.len(), 2);
        let serialized = serde_json::to_string(&all).unwrap();
        assert!(!serialized.contains("00000000-0000-4000-8000-000000000099"));
        assert!(!serialized.contains("svc-secret"));
        assert!(!serialized.contains("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"));

        std::fs::remove_dir_all(root).unwrap();
    }
}
