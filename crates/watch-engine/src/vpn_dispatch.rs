//! CLI & GUI command dispatch for Managed Built-in VPN (`watch-vpn-core`).
//!
//! All secret material (node UUIDs, passwords, Reality keys, service tokens)
//! remains confined inside `vpn-vault.json` (`0600`). Every returned JSON payload
//! is strictly redacted.

use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
    vpn_profile::{parse_nodes_from_text, ManagedVpnProviderKind, VpnSourceMode},
};
use claude_watch_runtime::{
    config_store::ConfigStore,
    managed_vpn,
    native,
    storage::{Paths, StateStore},
    vpn_vault::VpnVaultStore,
};
use serde_json::{json, Value};
use std::io::Read;

const MAX_VPN_INPUT_BYTES: usize = 2 * 1024 * 1024;

fn read_stdin_text(limit: usize) -> Result<String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .take(limit as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| CoreError::new("input_unavailable", "输入不可读取"))?;
    if buf.len() > limit {
        return Err(CoreError::new("oversize_input", "输入超过资源上限"));
    }
    String::from_utf8(buf).map_err(|_| CoreError::new("invalid_input", "输入不是有效的 UTF-8 文本"))
}

pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if request.command != "vpn" {
        return Ok(None);
    }
    let storage = StateStore::new(paths);
    let config_store = ConfigStore {
        storage: storage.clone(),
    };
    let vault = VpnVaultStore::new(storage.clone());

    match request.action.as_deref().unwrap_or("status") {
        "status" => {
            let cfg = config_store.load().unwrap_or_default();
            let mode = cfg.effective_vpn_source_mode();
            let managed = cfg.managed_vpn.clone().unwrap_or_default();
            let runtime_state = managed_vpn::read_runtime_state(&storage);
            let core_info = managed_vpn::core_availability_summary(&storage);
            let nodes = vault.list_redacted_nodes()?;
            let service = vault.redacted_service_summary()?;
            let selected_node = managed
                .selected_node_id
                .as_deref()
                .and_then(|id| nodes.iter().find(|n| n.id == id).cloned());
            Ok(Some(json!({
                "status": "ok",
                "mode": mode.as_str(),
                "managed_config": managed,
                "runtime": runtime_state,
                "core": core_info,
                "service": service,
                "selected_node": selected_node,
                "node_count": nodes.len(),
                "nodes": nodes,
            })))
        }
        "nodes" => {
            let cfg = config_store.load().unwrap_or_default();
            let managed = cfg.managed_vpn.clone().unwrap_or_default();
            let nodes = vault.list_redacted_nodes()?;
            let service = vault.redacted_service_summary()?;
            Ok(Some(json!({
                "status": "ok",
                "selected_node_id": managed.selected_node_id,
                "node_count": nodes.len(),
                "nodes": nodes,
                "service": service,
            })))
        }
        "mode" => {
            request.require_apply()?;
            let raw_mode = request
                .value("mode")
                .ok_or_else(|| CoreError::new("invalid_arguments", "切换模式需要 --mode external|managed"))?;
            let mode = VpnSourceMode::parse(raw_mode)?;
            let saved = config_store.set_vpn_source_mode(mode)?;
            native::notify_channel_update();
            Ok(Some(json!({
                "status": "ok",
                "mode": saved.effective_vpn_source_mode().as_str(),
                "managed_config": saved.managed_vpn,
                "message": if mode == VpnSourceMode::Managed {
                    "已切换为独立内置 VPN 模式（不影响本机 VPN 与系统代理）"
                } else {
                    "已切换为复用本机外部 VPN 模式"
                }
            })))
        }
        "import" => {
            let preview_only = request.flag("preview");
            if !preview_only {
                request.require_apply()?;
            }
            let provider = match request.value("provider") {
                Some(raw) => ManagedVpnProviderKind::parse(raw)?,
                None => ManagedVpnProviderKind::Custom,
            };
            let raw_input = read_stdin_text(MAX_VPN_INPUT_BYTES)?;
            let trimmed = raw_input.trim();
            if trimmed.is_empty() {
                return Err(CoreError::new("invalid_vpn_profile", "导入内容不能为空"));
            }

            // Accept either raw pasted YAML/URI text OR structured JSON `{"text": "...", "url": "..."}`.
            let (text_payload, remote_url) = if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                if let Some(obj) = v.as_object() {
                    if obj.contains_key("text") || obj.contains_key("url") {
                        let t = obj.get("text").and_then(Value::as_str).map(str::to_owned);
                        let u = obj.get("url").and_then(Value::as_str).map(str::to_owned);
                        (t, u)
                    } else {
                        (Some(trimmed.to_string()), None)
                    }
                } else {
                    (Some(trimmed.to_string()), None)
                }
            } else if trimmed.starts_with("https://") && !trimmed.contains('\n') && !trimmed.contains(' ') {
                (None, Some(trimmed.to_string()))
            } else {
                (Some(trimmed.to_string()), None)
            };

            if preview_only {
                let text = text_payload.ok_or_else(|| {
                    CoreError::new("invalid_vpn_profile", "预览模式仅支持本地文本片段，远程订阅请直接导入")
                })?;
                let parsed = parse_nodes_from_text(&text, provider, Some("preview"))?;
                let summaries: Vec<_> = parsed.iter().map(|n| n.redacted_summary(None)).collect();
                return Ok(Some(json!({
                    "status": "ok",
                    "preview": true,
                    "count": summaries.len(),
                    "nodes": summaries,
                })));
            }

            let imported = if let Some(url) = remote_url.filter(|u| !u.trim().is_empty()) {
                vault.import_remote_subscription(&url, provider)?
            } else {
                let text = text_payload.unwrap_or_default();
                vault.import_text(&text, provider, Some("manual"), false)?
            };

            // If no node was selected yet, auto-select the first newly imported node
            // (without forcing mode switch unless already in Managed mode).
            let mut cfg = config_store.load().unwrap_or_default();
            if cfg
                .managed_vpn
                .as_ref()
                .and_then(|m| m.selected_node_id.as_ref())
                .is_none()
            {
                if let Some(first) = imported.first() {
                    if let Ok(Some(node)) = vault.node_by_id(&first.id) {
                        let activate = cfg.effective_vpn_source_mode() == VpnSourceMode::Managed;
                        cfg = config_store.select_managed_vpn_node(&node, activate)?;
                    }
                }
            }
            native::notify_channel_update();
            Ok(Some(json!({
                "status": "ok",
                "count": imported.len(),
                "nodes": imported,
                "selected_node_id": cfg.managed_vpn.and_then(|m| m.selected_node_id),
                "message": format!("已安全导入 {} 个节点（凭据已存入 0600 私密库）", imported.len()),
            })))
        }
        "select" => {
            request.require_apply()?;
            let id = request
                .value("id")
                .ok_or_else(|| CoreError::new("invalid_arguments", "切换节点需要 --id"))?;
            let node = vault
                .node_by_id(id)?
                .ok_or_else(|| CoreError::new("vpn_node_not_found", "未找到指定的内置 VPN 节点"))?;
            let activate = request.value("mode").is_none_or(|m| m != "keep");
            let saved = config_store.select_managed_vpn_node(&node, activate)?;
            native::notify_channel_update();
            Ok(Some(json!({
                "status": "ok",
                "mode": saved.effective_vpn_source_mode().as_str(),
                "selected_node": node.redacted_summary(None),
                "message": format!("已选定独立节点「{}」，后台正在切换并核验通道", node.name),
            })))
        }
        "delete" => {
            request.require_apply()?;
            let id = request
                .value("id")
                .ok_or_else(|| CoreError::new("invalid_arguments", "删除节点需要 --id"))?;
            let removed = vault.delete_node(id)?;
            let _ = config_store.clear_selected_managed_node_if_matches(id)?;
            native::notify_channel_update();
            Ok(Some(json!({
                "status": "ok",
                "removed": removed,
                "id": id,
                "message": if removed { "已删除节点并清除凭据" } else { "节点不存在" }
            })))
        }
        "probe" => {
            let id = request
                .value("id")
                .ok_or_else(|| CoreError::new("invalid_arguments", "节点测速需要 --id"))?;
            let node = vault
                .node_by_id(id)?
                .ok_or_else(|| CoreError::new("vpn_node_not_found", "未找到指定的内置 VPN 节点"))?;
            let stats = managed_vpn::probe_managed_node(&storage, &node)?;
            Ok(Some(json!({
                "status": "ok",
                "id": node.id,
                "name": node.name,
                "probe": stats,
            })))
        }
        "service-set" => {
            request.require_apply()?;
            let raw = read_stdin_text(32 * 1024)?;
            let payload: Value = claude_watch_runtime::storage::strict_json(raw.as_bytes())?;
            let url = payload["url"]
                .as_str()
                .ok_or_else(|| CoreError::new("invalid_vpn_service", "缺少自带 VPN 服务接入地址"))?;
            let token = payload.get("token").and_then(Value::as_str);
            let label = payload.get("label").and_then(Value::as_str);
            let service = vault.set_builtin_service(url, token, label)?;
            Ok(Some(json!({
                "status": "ok",
                "service": service,
                "message": "已保存自带 VPN 服务接入配置（授权码仅存于本机 0600 私密库）",
            })))
        }
        "service-sync" => {
            request.require_apply()?;
            let now_secs = native::now().max(0.0) as u64;
            let result = vault.sync_builtin_service(now_secs)?;
            native::notify_channel_update();
            Ok(Some(result))
        }
        "service-clear" => {
            request.require_apply()?;
            vault.clear_builtin_service()?;
            let cfg = config_store.load().unwrap_or_default();
            if let Some(selected_id) = cfg
                .managed_vpn
                .as_ref()
                .and_then(|m| m.selected_node_id.as_deref())
            {
                if vault.node_by_id(selected_id)?.is_none() {
                    let _ = config_store.clear_selected_managed_node_if_matches(selected_id);
                }
            }
            native::notify_channel_update();
            Ok(Some(json!({
                "status": "ok",
                "message": "已清除自带 VPN 服务配置与同步节点",
            })))
        }
        _ => Err(CoreError::new("invalid_arguments", "未知的 vpn 子命令")),
    }
}
