//! Read-only dispatch for pure-Rust multi-source IP risk & routing intelligence (`ip-intel`).
//!
//! Enforces strict controlled-proxy isolation: when Managed Built-in VPN mode is active,
//! requests strictly route through the private `watch-vpn-core` tunnel and fail closed
//! if the tunnel is down (never leaking over direct host routing or external proxy).

use claude_watch_core::{
    cli::Request,
    config::valid_loopback_proxy,
    error::{CoreError, Result},
    vpn_profile::VpnSourceMode,
};
use claude_watch_runtime::{
    config_store::ConfigStore,
    ip_intel_collector::collect_ip_intel,
    managed_vpn,
    network_client::{default_proxy_url, NetworkClient, UreqTransport},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn resolve_controlled_proxy(storage: &StateStore) -> std::result::Result<String, String> {
    let cfg = ConfigStore {
        storage: storage.clone(),
    }
    .load()
    .ok();
    let is_managed = cfg
        .as_ref()
        .is_some_and(|c| c.effective_vpn_source_mode() == VpnSourceMode::Managed);
    if is_managed {
        return managed_vpn::active_upstream_endpoint(storage).ok_or_else(|| {
            "当前处于「独立内置 VPN」模式但独立隧道尚未启动；为保护隐私已拒绝回退本机网络探测".into()
        });
    }
    if let Some(ep) = managed_vpn::active_upstream_endpoint(storage) {
        return Ok(ep);
    }
    if let Some(configured) = cfg
        .as_ref()
        .map(|c| c.proxy_url.trim())
        .filter(|s| !s.is_empty() && valid_loopback_proxy(s))
    {
        return Ok(configured.to_owned());
    }
    Ok(default_proxy_url().into())
}

pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if request.command != "ip-intel" {
        return Ok(None);
    }
    let storage = StateStore::new(paths);
    let active_proxy = match resolve_controlled_proxy(&storage) {
        Ok(proxy) => proxy,
        Err(reason) => {
            return Ok(Some(json!({
                "schema": 1,
                "status": "error",
                "query": request.value("ip").unwrap_or(""),
                "error": reason,
            })));
        }
    };
    let client = NetworkClient::new(Arc::new(UreqTransport), Some(active_proxy))
        .map_err(|error| CoreError::new(&error.code, &error.detail))?
        .with_state_store(storage);
    Ok(Some(collect_ip_intel(&client, request.value("ip"), None)))
}
