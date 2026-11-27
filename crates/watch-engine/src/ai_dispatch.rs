//! Read-only dispatch for the monitor's Rust-candidate AI probe.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    ai_probe,
    managed_vpn,
    network_client::{NetworkClient, UreqTransport},
    storage::{Paths, StateStore},
};
use serde_json::Value;
use std::{sync::Arc, time::Duration};

/// The parser owns the public `ai-probe --service <claude|gpt>` grammar.  This
/// dispatch layer only accepts that already-bounded value and never consumes a
/// user URL, credentials, proxy setting, or mutation flag.
pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if request.command != "ai-probe" {
        return Ok(None);
    }
    let service = request
        .value("service")
        .ok_or_else(|| CoreError::new("invalid_arguments", "AI 诊断需要 --service"))?;
    if !matches!(service, "claude" | "gpt") {
        return Err(CoreError::new("invalid_arguments", "AI 诊断服务无效"));
    }
    let storage = StateStore::new(paths);
    let active_proxy = managed_vpn::active_upstream_endpoint(&storage)
        .unwrap_or_else(|| claude_watch_runtime::network_client::default_proxy_url().into());
    let client = NetworkClient::new(
        Arc::new(UreqTransport),
        Some(active_proxy),
    )
        .map_err(|error| CoreError::new(&error.code, &error.detail))?
        .with_timeout(Duration::from_secs(6));
    Ok(Some(ai_probe::production(client, service)))
}
