//! Read-only dispatch for the monitor's pure-Rust AI & edge-protocol probe (`ai-probe`).
use crate::ip_intel_dispatch::resolve_controlled_proxy;
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    ai_probe,
    network_client::{NetworkClient, UreqTransport},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if request.command != "ai-probe" {
        return Ok(None);
    }
    let service = request
        .value("service")
        .ok_or_else(|| CoreError::new("invalid_arguments", "AI 诊断需要 --service"))?;
    if !matches!(service, "claude" | "gpt" | "all") {
        return Err(CoreError::new("invalid_arguments", "AI 诊断服务无效"));
    }
    let storage = StateStore::new(paths);
    let active_proxy = match resolve_controlled_proxy(&storage) {
        Ok(proxy) => proxy,
        Err(reason) => {
            let now = claude_watch_runtime::native::now();
            return Ok(Some(json!({
                "service": service,
                "status": "error",
                "startedAt": now,
                "finishedAt": now,
                "exitIP": "",
                "claudeExitIP": "",
                "gptExitIP": "",
                "referenceIP": "",
                "exitSource": "",
                "countryCode": "",
                "country": "",
                "region": "",
                "city": "",
                "organization": "",
                "ipTimezone": "",
                "endpoints": [],
                "errors": [{"stage": "proxy", "code": "managed_vpn_inactive", "message": reason}],
                "details": []
            })));
        }
    };
    let client = NetworkClient::new(Arc::new(UreqTransport), Some(active_proxy))
        .map_err(|error| CoreError::new(&error.code, &error.detail))?
        .with_timeout(Duration::from_secs(6));
    Ok(Some(ai_probe::production(client, service)))
}
