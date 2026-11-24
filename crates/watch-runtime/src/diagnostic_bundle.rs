//! Offline, bounded, allowlisted diagnostic export. Never runs probes or reads accounts/config.
use crate::{build_identity, storage::StateStore};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

const FILE_LIMIT: usize = 512 * 1024;
const SNAPSHOT_FILE_LIMIT: usize = 1024 * 1024;
const OUTPUT_LIMIT: usize = 4_000_000;
const COMPACT_BUDGET_LIMIT: usize = 3_000_000;
const MAX_RECORDS: usize = 600;

// Deliberately no generic "message", "detail", "path", "value", URL, endpoint,
// IP, host, peer, local, node, proxy_chain, chains, executable, argv, account,
// token, expectation, observation, baseline, egress, country, timezone, or
// arbitrary object-map key.
fn allowed(key: &str) -> bool {
    matches!(key, "schema" | "time" | "ts_unix_ms" | "at" | "timestamp" | "observed_at" | "updated_at"
        | "captured_at" | "completed_at" | "issued_at" | "valid_until" | "executed_at" | "received_at"
        | "expires_at" | "started_at" | "finished_at" | "elapsed_seconds" | "duration_ms"
        | "created_at" | "locked_at" | "revoked_at" | "sample_started_at" | "capturedAt" | "observedAt"
        | "id" | "category" | "component" | "operation" | "event" | "stage" | "step" | "step_id"
        | "status" | "state" | "result" | "reason" | "reason_code" | "code" | "error_code"
        | "last_error_code" | "last_error" | "unavailable_reason" | "action" | "phase" | "previous_state"
        | "version" | "build" | "app_version" | "app_build" | "source_revision" | "source_dirty"
        | "source_tree_digest" | "build_identity" | "run_id" | "attempt_id" | "transaction_id"
        | "session_id" | "round_id" | "roundID" | "correlation_id" | "flow_id" | "producer_boot_id"
        | "executor_boot_id" | "boot_id" | "observer_boot_id" | "family" | "pid" | "count" | "seq" | "event_seq"
        | "sample_seq" | "epoch" | "change_generation" | "vpn_epoch"
        | "policy_version" | "policy_digest" | "guard_policy_digest" | "configured_policy_version"
        | "saved_policy_version" | "permit_generation" | "command_seq" | "applied_command_seq"
        | "applied_policy_version" | "permit_state" | "enforcement_state" | "backend" | "network_backend"
        | "components_ready" | "sandbox_ready" | "identity_report" | "blocking_gates" | "ready"
        | "gateway_endpoint_protected" | "i01_passed" | "i02_passed" | "i03_passed"
        | "i04_passed" | "i05_passed" | "i06_passed" | "health" | "channel_diagnostic" | "failure"
        | "last_failure" | "dropped" | "write_failed" | "state_write_failed" | "health_write_failed"
        | "written" | "scope" | "shutdown_flush_guaranteed" | "log_health" | "eventError"
        | "active_flows" | "active_flows_count" | "new_connections_blocked" | "terminated_flows_count"
        | "blocked_new_connections" | "direct_fallback_blocked" | "channels" | "families"
        | "authoritative_permits" | "enforcement_receipts" | "claude" | "codex" | "chatgpt" | "openai"
        | "process_complete" | "process_confirmed_exited_count" | "processConfirmedExitedCount"
        | "process_sampled_at" | "process_reason_counts" | "processReasonCounts"
        | "network_quality" | "network_round_id" | "network_sampled_at" | "network_reused"
        | "activity_state" | "bytes_state" | "activity_sampled_at" | "publisher_error_code"
        | "sampling_diagnostics" | "samplingDiagnostics" | "requires_migration" | "vpn_match" | "verdict" | "reasons"
        | "exit_code" | "build_exit_code" | "install_exit_code" | "signal" | "truncated"
        | "file_count" | "url_count" | "target_pid" | "reply_code" | "reply_error" | "ae_error"
        | "source" | "cause_code" | "passed_count" | "producer_pid" | "verified_pid" | "return_id"
        | "os_status" | "unmanaged_process_count" | "apple_event_reply_confirmed" | "appkit_activated"
        | "instance_id" | "target" | "trigger" | "outcome" | "error" | "family_state" | "snapshot_seq"
        | "coverage_scope" | "protection_state" | "protection" | "phases" | "elapsed_ms" | "log_available" | "log_rotated"
        | "omitted_lines" | "heartbeat_present" | "heartbeat_pid" | "heartbeat_status" | "heartbeat_age_seconds"
        | "heartbeatAge" | "backend_alive" | "protection_ready" | "sampling_state" | "backend_sampling_state"
        | "service_heartbeat_present" | "service_heartbeat_age_seconds" | "evidence_observed_at"
        | "process_found" | "start_identity_matches" | "native_path_matches" | "launchd_registered"
        | "launchd_state" | "launchd_pid" | "worker_verified" | "worker_error_code" | "source_error_code"
        | "source_error" | "backend_read_error" | "backend_healthy" | "native_backend_healthy"
        | "backend_receipt_age_seconds" | "snapshot_read_failed" | "snapshot_present" | "snapshot_age_seconds"
        | "installed" | "auto_start" | "autoStart" | "keep_alive" | "keepAlive" | "hasBaseline" | "stderrBytes"
        | "proxy_present" | "proxy_read_failed" | "proxy_age_seconds" | "proxy_entry_verified"
        | "proxy_api_available" | "proxy_port_covered" | "context_available" | "same_candidate_context"
        | "source_sample_advanced" | "deadline_remaining_seconds" | "differences" | "field"
        | "source_observed_at" | "recorded_at" | "writer_boot_id" | "component_version" | "os_error"
        | "target_version" | "target_build" | "binary_sha256"
        | "dropped_queue_records" | "failed_write_records" | "counts_saturated"
        | "truncation" | "file_or_records" | "object_fields" | "array_items" | "depth_limit"
        | "complete" | "verification_pending" | "issues" | "revision"
        | "collector_state" | "collectorState" | "target_count" | "targetCount"
        | "parsed_count" | "parsedCount" | "accepted_count" | "acceptedCount"
        | "correlated_count" | "correlatedCount" | "unconfirmed_count" | "unconfirmedCount"
        | "confirmed_exited_count" | "confirmedExitedCount" | "uiFilteredCount" | "uiDropped"
        | "entryState" | "entryReason" | "entrySource" | "apiState" | "mode" | "coversProxy"
        | "connectionObservation" | "targetDiscovery" | "channelSupervision" | "vpnSupervision"
        | "association" | "policy" | "flow_kind" | "flow_path" | "protocol" | "kind" | "runtimeRole" | "matchReason"
        | "sandbox_evidence" | "applied" | "direct_network_blocked" | "unix_relay_blocked"
        | "verified_helper_origin" | "unprotected_pids" | "protected_pids" | "unmanaged_member_pids"
        | "uncovered_boundaries" | "server_identity_verified" | "gateway_endpoint_protection_verified"
        | "gateway_endpoint_protection_method" | "configured_entries" | "unknown_count"
        | "consistency" | "level" | "running_mode" | "tun_enabled" | "system_proxy_enabled"
        | "upstream_protocol" | "degraded" | "retry_count" | "healthy" | "desired"
        | "supported" | "protocols" | "tcp" | "udp" | "http" | "https" | "quic" | "dns"
        | "blocked_evidence_valid_until" | "event_history" | "process_execution_state" | "process_preserved")
        || claude_watch_core::policy::PolicyCatalog::families().iter().any(|f| f.id == key)
}

fn safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 192
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        && !value.contains("http:")
        && !value.contains("https:")
        && value.parse::<std::net::IpAddr>().is_err()
}

fn safe_string(value: Option<&Value>) -> Value {
    match value.and_then(Value::as_str) {
        Some(s) if safe_label(s) => Value::String(s.to_string()),
        _ => Value::Null,
    }
}

fn safe_flow_path(value: Option<&Value>) -> Value {
    match value.and_then(Value::as_str) {
        Some(s @ ("direct" | "proxy_gateway" | "controlled_gateway" | "tun" | "unconfirmed")) => {
            Value::String(s.to_string())
        }
        _ => Value::Null,
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct TruncationTracker {
    object_fields: bool,
    array_items: bool,
    depth_limit: bool,
}

impl TruncationTracker {
    fn any(&self) -> bool {
        self.object_fields || self.array_items || self.depth_limit
    }
}

fn project(value: &Value, depth: usize, tracker: &mut TruncationTracker) -> Option<Value> {
    if depth > 10 {
        tracker.depth_limit = true;
        return None;
    }
    match value {
        Value::Object(object) => {
            let mut result = Map::new();
            let filtered: Vec<(&String, &Value)> =
                object.iter().filter(|(key, _)| allowed(key)).collect();
            if filtered.len() > 96 {
                tracker.object_fields = true;
            }
            for (key, child) in filtered.into_iter().take(96) {
                if let Some(child) = project(child, depth + 1, tracker) {
                    result.insert(key.clone(), child);
                }
            }
            Some(Value::Object(result))
        }
        Value::Array(array) => {
            if array.len() > 64 {
                tracker.array_items = true;
            }
            Some(Value::Array(
                array
                    .iter()
                    .take(64)
                    .filter_map(|v| project(v, depth + 1, tracker))
                    .collect(),
            ))
        }
        Value::String(s) if safe_label(s) => Some(value.clone()),
        Value::Bool(_) | Value::Number(_) | Value::Null => Some(value.clone()),
        _ => None,
    }
}

fn read_bounded_with_limit(
    path: &Path,
    tail: bool,
    limit: usize,
) -> Result<(Vec<u8>, bool, u64, Option<f64>), &'static str> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => return Err("unsafe_path"),
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err("missing"),
            Err(_) => return Err("unreadable"),
        }
    }
    #[cfg(target_os = "macos")]
    const NOFOLLOW: i32 = 0x0100 | 0x0004; // O_NOFOLLOW | O_NONBLOCK: a replaced FIFO cannot stall export.
    #[cfg(target_os = "linux")]
    const NOFOLLOW: i32 = 0x20000 | 0x0800;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW)
        .open(path)
        .map_err(|_| "unreadable")?;
    let metadata = file.metadata().map_err(|_| "unreadable")?;
    if !metadata.is_file() {
        return Err("not_regular_file");
    }
    let file_size = metadata.len();
    let modified_at = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64());
    let mut truncated = file_size > limit as u64;
    if truncated && !tail {
        return Err("oversize");
    }
    if truncated {
        file.seek(SeekFrom::End(-(limit as i64)))
            .map_err(|_| "unreadable")?;
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "unreadable")?;
    if bytes.len() > limit {
        bytes.truncate(limit);
        truncated = true;
    }
    if truncated {
        // A partial first line is not a malformed record and must not be parsed.
        let start = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |n| n + 1);
        bytes.drain(..start);
    }
    Ok((bytes, truncated, file_size, modified_at))
}

fn read_bounded(path: &Path, tail: bool) -> Result<(Vec<u8>, bool), &'static str> {
    let (bytes, truncated, _, _) = read_bounded_with_limit(path, tail, FILE_LIMIT)?;
    Ok((bytes, truncated))
}

fn source(path: &Path, label: &str, json_lines: bool) -> Value {
    let (bytes, mut file_truncated) = match read_bounded(path, json_lines) {
        Ok(result) => result,
        Err(reason) => return json!({"source": label, "status": reason}),
    };
    let mut invalid = 0;
    let mut records = Vec::new();
    let lines: Vec<&[u8]> = if json_lines {
        bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        vec![&bytes]
    };
    if lines.len() > MAX_RECORDS {
        file_truncated = true;
    }
    let mut tracker = TruncationTracker::default();
    for line in lines.iter().rev().take(MAX_RECORDS).rev() {
        if json_lines && line.len() > 64 * 1024 {
            invalid += 1;
            continue;
        }
        match serde_json::from_slice::<Value>(line) {
            Ok(value) => {
                if let Some(safe) = project(&value, 0, &mut tracker) {
                    records.push(safe);
                }
            }
            Err(_) => invalid += 1,
        }
    }
    let overall_truncated = file_truncated || tracker.any();
    let mut result = json!({
        "source": label,
        "status": "read",
        "truncated": overall_truncated,
        "invalid_records": invalid,
        "records": records
    });
    if overall_truncated {
        result["truncation"] = json!({
            "file_or_records": file_truncated,
            "object_fields": tracker.object_fields,
            "array_items": tracker.array_items,
            "depth_limit": tracker.depth_limit
        });
    }
    result
}

/// Projects `state/runtime-snapshot.json` into a compact, strictly redacted
/// operational summary (omitting duplicated `events`, hosts, IPs, endpoints,
/// proxy chains, executable paths, and arbitrary messages).
fn project_runtime_snapshot_source(path: &Path) -> Value {
    let label = "runtime-snapshot.json";
    let (bytes, _, _, _) = match read_bounded_with_limit(path, false, SNAPSHOT_FILE_LIMIT) {
        Ok(result) => result,
        Err(reason) => return json!({"source": label, "status": reason}),
    };
    let raw: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return json!({"source": label, "status": "read", "truncated": false, "invalid_records": 1, "records": []});
        }
    };
    let snap = raw.get("snapshot").unwrap_or(&raw);
    let mut tracker = TruncationTracker::default();
    let mut projected = Map::new();
    if let Some(v) = snap.get("capturedAt").filter(|v| v.is_number()) {
        projected.insert("capturedAt".into(), v.clone());
    }
    if let Some(health) = snap.get("health").and_then(|v| project(v, 0, &mut tracker)) {
        projected.insert("health".into(), health);
    }
    for key in ["installed", "autoStart", "keepAlive", "hasBaseline", "stderrBytes"] {
        if let Some(v) = snap.get(key).filter(|v| v.is_boolean() || v.is_number()) {
            projected.insert(key.into(), v.clone());
        }
    }
    projected.insert(
        "event_error_present".into(),
        Value::Bool(snap.get("eventError").is_some_and(|v| !v.is_null())),
    );
    projected.insert(
        "proxy_error_present".into(),
        Value::Bool(snap.get("proxyError").is_some_and(|v| !v.is_null())),
    );
    for key in [
        "targetDiscovery",
        "samplingDiagnostics",
        "channelSupervision",
        "vpnSupervision",
    ] {
        if let Some(v) = snap.get(key).and_then(|v| project(v, 0, &mut tracker)) {
            projected.insert(key.into(), v);
        }
    }
    if let Some(proxy) = snap.get("proxy").and_then(Value::as_object) {
        let mut pmap = Map::new();
        for key in [
            "observedAt",
            "entryState",
            "entryReason",
            "entrySource",
            "apiState",
            "mode",
            "coversProxy",
        ] {
            if let Some(v) = proxy.get(key).and_then(|v| project(v, 1, &mut tracker)) {
                pmap.insert(key.into(), v);
            }
        }
        if let Some(co) = proxy
            .get("connectionObservation")
            .and_then(|v| project(v, 1, &mut tracker))
        {
            pmap.insert("connectionObservation".into(), co);
        }
        if let Some(flows) = proxy.get("flows").and_then(Value::as_array) {
            if flows.len() > 64 {
                tracker.array_items = true;
            }
            let flow_rows: Vec<Value> = flows
                .iter()
                .take(64)
                .map(|flow| {
                    let mut row = Map::new();
                    if let Some(pid) = flow.get("pid").filter(|v| v.is_u64()) {
                        row.insert("pid".into(), pid.clone());
                    }
                    for (src, dst) in [
                        ("protocol", "protocol"),
                        ("flow_kind", "flow_kind"),
                        ("association", "association"),
                        ("policy", "policy"),
                        ("reason", "reason"),
                    ] {
                        let v = safe_string(flow.get(src));
                        if !v.is_null() {
                            row.insert(dst.into(), v);
                        }
                    }
                    let fp = safe_flow_path(flow.get("path"));
                    if !fp.is_null() {
                        row.insert("flow_path".into(), fp);
                    }
                    Value::Object(row)
                })
                .collect();
            pmap.insert("flows_total".into(), json!(flows.len()));
            pmap.insert("flows".into(), Value::Array(flow_rows));
        }
        projected.insert("proxy".into(), Value::Object(pmap));
    }
    if let Some(processes) = snap.get("processes").and_then(Value::as_array) {
        if processes.len() > 64 {
            tracker.array_items = true;
        }
        let proc_rows: Vec<Value> = processes
            .iter()
            .take(64)
            .map(|proc_row| {
                let mut row = Map::new();
                if let Some(pid) = proc_row.get("pid").filter(|v| v.is_u64()) {
                    row.insert("pid".into(), pid.clone());
                }
                for key in ["kind", "runtimeRole", "matchReason"] {
                    let v = safe_string(proc_row.get(key));
                    if !v.is_null() {
                        row.insert(key.into(), v);
                    }
                }
                if let Some(prot) = proc_row
                    .get("protection")
                    .and_then(|v| project(v, 2, &mut tracker))
                {
                    row.insert("protection".into(), prot);
                }
                Value::Object(row)
            })
            .collect();
        projected.insert("processes_total".into(), json!(processes.len()));
        projected.insert("processes".into(), Value::Array(proc_rows));
    }
    let overall_truncated = tracker.any();
    let mut result = json!({
        "source": label,
        "status": "read",
        "truncated": overall_truncated,
        "invalid_records": 0,
        "records": [Value::Object(projected)]
    });
    if overall_truncated {
        result["truncation"] = json!({
            "file_or_records": false,
            "object_fields": tracker.object_fields,
            "array_items": tracker.array_items,
            "depth_limit": tracker.depth_limit
        });
    }
    result
}

/// Projects `state/managed-launch-instances.json` without executable paths or
/// audit-token digests.
fn project_managed_instances_source(path: &Path) -> Value {
    let label = "managed-launch-instances.json";
    let (bytes, _) = match read_bounded(path, false) {
        Ok(result) => result,
        Err(reason) => return json!({"source": label, "status": reason}),
    };
    let raw: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return json!({"source": label, "status": "read", "truncated": false, "invalid_records": 1, "records": []});
        }
    };
    let mut tracker = TruncationTracker::default();
    let list = raw.as_array().cloned().unwrap_or_default();
    if list.len() > 64 {
        tracker.array_items = true;
    }
    let mut records = Vec::new();
    for item in list.iter().take(64) {
        let mut row = Map::new();
        for key in [
            "instance_id",
            "family",
            "target",
            "state",
            "error_code",
            "created_at",
            "updated_at",
        ] {
            if let Some(v) = item.get(key).and_then(|v| project(v, 1, &mut tracker)) {
                row.insert(key.into(), v);
            }
        }
        if let Some(ev) = item
            .get("sandbox_evidence")
            .and_then(|v| project(v, 1, &mut tracker))
        {
            row.insert("sandbox_evidence".into(), ev);
        }
        if let Some(pids) = item.get("controlled_subtree_pids").and_then(Value::as_array) {
            row.insert("subtree_pid_count".into(), json!(pids.len()));
        }
        if let Some(members) = item
            .pointer("/process_visibility/members")
            .and_then(Value::as_array)
        {
            let verified = members
                .iter()
                .filter(|m| m.get("currently_verified") == Some(&Value::Bool(true)))
                .count();
            row.insert("member_count".into(), json!(members.len()));
            row.insert("verified_member_count".into(), json!(verified));
        }
        records.push(Value::Object(row));
    }
    let overall_truncated = tracker.any();
    let mut result = json!({
        "source": label,
        "status": "read",
        "truncated": overall_truncated,
        "invalid_records": 0,
        "records": records
    });
    if overall_truncated {
        result["truncation"] = json!({
            "file_or_records": false,
            "object_fields": tracker.object_fields,
            "array_items": tracker.array_items,
            "depth_limit": tracker.depth_limit
        });
    }
    result
}

/// Projects `switcher/vpn-observation.json` while strictly excluding node names,
/// proxy group names, proxy chains, and endpoints.
fn project_vpn_observation_source(path: &Path) -> Value {
    let label = "vpn-observation.json";
    let (bytes, _) = match read_bounded(path, false) {
        Ok(result) => result,
        Err(reason) => return json!({"source": label, "status": reason}),
    };
    let raw: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return json!({"source": label, "status": "read", "truncated": false, "invalid_records": 1, "records": []});
        }
    };
    let mut tracker = TruncationTracker::default();
    let mut out = Map::new();
    for key in [
        "source",
        "sample_started_at",
        "observed_at",
        "valid_until",
        "source_error",
        "sample_seq",
        "epoch",
    ] {
        if let Some(v) = raw.get(key).and_then(|v| project(v, 1, &mut tracker)) {
            out.insert(key.into(), v);
        }
    }
    if let Some(cons) = raw.get("consistency") {
        let projected_cons = match cons {
            Value::String(s) if safe_label(s) => Value::String(s.clone()),
            Value::Object(m) => {
                let mut cm = Map::new();
                for (k, v) in m {
                    if matches!(k.as_str(), "consistent" | "inconsistent" | "unavailable" | "state" | "reason" | "code") {
                        let safe = match v {
                            Value::String(s) if safe_label(s) => Some(Value::String(s.clone())),
                            Value::Bool(_) | Value::Number(_) => Some(v.clone()),
                            _ => None,
                        };
                        if let Some(s) = safe {
                            cm.insert(k.clone(), s);
                        }
                    }
                }
                Value::Object(cm)
            }
            _ => Value::Null,
        };
        if !projected_cons.is_null() {
            out.insert("consistency".into(), projected_cons);
        }
    }
    let project_observed = |field: Option<&Value>| -> Option<Value> {
        let obj = field?.as_object()?;
        let state = safe_string(obj.get("state"));
        if state.is_null() {
            return None;
        }
        let mut fm = Map::new();
        fm.insert("state".into(), state);
        if let Some(v) = obj.get("value") {
            match v {
                Value::Bool(b) => {
                    fm.insert("code".into(), Value::Bool(*b));
                }
                Value::String(s) if safe_label(s) => {
                    fm.insert("code".into(), Value::String(s.clone()));
                }
                _ => {}
            }
        }
        Some(Value::Object(fm))
    };
    for key in [
        "upstream_protocol",
        "running_mode",
        "tun_enabled",
        "system_proxy_enabled",
    ] {
        if let Some(v) = project_observed(raw.get(key)) {
            out.insert(key.into(), v);
        }
    }
    json!({
        "source": label,
        "status": "read",
        "truncated": tracker.any(),
        "invalid_records": 0,
        "records": [Value::Object(out)]
    })
}

/// Extracts only known ASCII diagnostic error-code counts from plain-text native
/// daemon logs (`logs/native-agent.{out,err}.log`). Raw lines are never exported.
fn project_text_log_summary(path: &Path, label: &str) -> Value {
    const ALLOWED_PREFIXES: [&str; 14] = [
        "native_",
        "gateway_",
        "vpn_",
        "seatbelt_",
        "process_",
        "guard_",
        "channel_",
        "collector_",
        "launchd_",
        "sandbox_",
        "audit_",
        "session_",
        "proxy_",
        "target_",
    ];
    let (bytes, truncated, file_size, modified_at) =
        match read_bounded_with_limit(path, true, FILE_LIMIT) {
            Ok(result) => result,
            Err(reason) => return json!({"source": label, "status": reason}),
        };
    let text = String::from_utf8_lossy(&bytes);
    let total_lines = text.lines().count();
    let mut code_counts: BTreeMap<String, u64> = BTreeMap::new();
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if token.len() >= 6
            && token.len() <= 64
            && token.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && ALLOWED_PREFIXES.iter().any(|prefix| token.starts_with(prefix))
        {
            *code_counts.entry(token.to_string()).or_insert(0) += 1;
        }
    }
    let mut top_codes: Vec<(String, u64)> = code_counts.into_iter().collect();
    top_codes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top_codes.truncate(32);
    let counts_obj: Map<String, Value> = top_codes
        .into_iter()
        .map(|(k, v)| (k, Value::from(v)))
        .collect();
    json!({
        "source": label,
        "status": "read",
        "truncated": truncated,
        "invalid_records": 0,
        "records": [{
            "file_size_bytes": file_size,
            "modified_at": modified_at,
            "sampled_lines": total_lines,
            "code_counts": counts_obj
        }]
    })
}

fn recent(dir: &Path, prefix: &str, suffix: &str, limit: usize) -> (Vec<PathBuf>, &'static str) {
    if dir
        .ancestors()
        .any(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
    {
        return (vec![], "unsafe_path");
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (vec![], "missing"),
        Err(_) => return (vec![], "unreadable"),
    };
    let mut paths = Vec::new();
    let mut visited = 0;
    for entry in entries.take(513) {
        visited += 1;
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(prefix)
            && name.ends_with(suffix)
            && !(prefix == "initialization-" && name.starts_with("initialization-flow-"))
        {
            paths.push(entry.path());
        }
    }
    paths.sort_by_cached_key(|path| {
        (
            fs::symlink_metadata(path)
                .ok()
                .and_then(|m| m.modified().ok()),
            path.clone(),
        )
    });
    paths.reverse();
    let limited = paths.len() > limit || visited > 512;
    paths.truncate(limit);
    let status = if limited {
        "bounded_recent_subset"
    } else if paths.is_empty() {
        "missing"
    } else {
        "read"
    };
    (paths, status)
}

fn build_summary(sources: &[Value]) -> Value {
    let mut read_count = 0u64;
    let mut missing_count = 0u64;
    let mut truncated_count = 0u64;
    let mut error_count = 0u64;
    for src in sources {
        match src["status"].as_str() {
            Some("read" | "bounded_recent_subset") => read_count += 1,
            Some("missing") => missing_count += 1,
            _ => error_count += 1,
        }
        if src["truncated"] == Value::Bool(true) {
            truncated_count += 1;
        }
    }
    let find_first_record = |name: &str| -> Option<&Value> {
        sources
            .iter()
            .find(|s| s["source"] == name && s["status"] == "read")
            .and_then(|s| s["records"].as_array())
            .and_then(|arr| arr.first())
    };

    let runtime_snap = find_first_record("runtime-snapshot.json");
    let channel_sup = find_first_record("channel-supervision.json");
    let target_disc = find_first_record("target-discovery.json");
    let vpn_obs = find_first_record("vpn-observation.json");

    let mut family_states = Map::new();
    if let Some(sup) = channel_sup {
        if let Some(families) = sup.get("families").and_then(Value::as_object) {
            for (family, fstate) in families {
                let mut item = Map::new();
                for key in [
                    "permit_state",
                    "reason_code",
                    "permit_generation",
                    "command_seq",
                    "enforcement_state",
                    "active_flows_count",
                    "verdict",
                ] {
                    if let Some(v) = fstate.get(key) {
                        item.insert(key.into(), v.clone());
                    }
                }
                if let Some(receipt) = sup.pointer(&format!("/enforcement_receipts/{family}")) {
                    for key in ["state", "active_flows_count", "blocked_new_connections"] {
                        if let Some(v) = receipt.get(key) {
                            item.entry(key.to_string()).or_insert_with(|| v.clone());
                        }
                    }
                }
                family_states.insert(family.clone(), Value::Object(item));
            }
        }
    }

    let mut diag_reason_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut diag_stage_counts: BTreeMap<String, u64> = BTreeMap::new();
    if let Some(diag_src) = sources
        .iter()
        .find(|s| s["source"] == "diagnostic-events.jsonl" && s["status"] == "read")
    {
        if let Some(records) = diag_src["records"].as_array() {
            for rec in records {
                let cd = rec.get("channel_diagnostic").unwrap_or(rec);
                if let Some(reason) = cd.get("reason_code").and_then(Value::as_str) {
                    if safe_label(reason) {
                        *diag_reason_counts.entry(reason.to_string()).or_insert(0) += 1;
                    }
                }
                if let Some(code) = cd.pointer("/failure/code").and_then(Value::as_str) {
                    if safe_label(code) {
                        *diag_reason_counts.entry(code.to_string()).or_insert(0) += 1;
                    }
                }
                if let Some(stage) = cd.get("stage").and_then(Value::as_str) {
                    if safe_label(stage) {
                        *diag_stage_counts.entry(stage.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    let top_map = |map: BTreeMap<String, u64>| -> Map<String, Value> {
        let mut items: Vec<(String, u64)> = map.into_iter().collect();
        items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        items.truncate(20);
        items.into_iter().map(|(k, v)| (k, Value::from(v))).collect()
    };

    json!({
        "source_counts": {
            "read": read_count,
            "missing": missing_count,
            "truncated": truncated_count,
            "error": error_count
        },
        "daemon_health": runtime_snap.and_then(|s| s.pointer("/health/state")).cloned().unwrap_or(Value::Null),
        "target_discovery_complete": target_disc
            .and_then(|s| s.get("complete"))
            .or_else(|| runtime_snap.and_then(|s| s.pointer("/targetDiscovery/complete")))
            .cloned()
            .unwrap_or(Value::Null),
        "process_complete": runtime_snap
            .and_then(|s| s.pointer("/samplingDiagnostics/process_complete"))
            .cloned()
            .unwrap_or(Value::Null),
        "vpn_consistency": vpn_obs.and_then(|s| s.get("consistency")).cloned().unwrap_or(Value::Null),
        "vpn_source_error": vpn_obs.and_then(|s| s.get("source_error")).cloned().unwrap_or(Value::Null),
        "family_states": family_states,
        "recent_diagnostic_reason_counts": top_map(diag_reason_counts),
        "recent_diagnostic_stage_counts": top_map(diag_stage_counts)
    })
}

/// This is historical diagnostic evidence; it does not establish current protection.
pub fn collect(storage: &StateStore) -> Value {
    collect_with_broker(storage, Path::new("/Library/Logs/ClaudeWatchGateway"))
}

fn collect_with_broker(storage: &StateStore, broker: &Path) -> Value {
    let mut sources = Vec::new();
    let base = storage.paths.base();
    let state = storage.paths.watch().join("state");
    let logs = storage.paths.watch().join("logs");

    for name in [
        "events.jsonl",
        "events.previous.jsonl",
        "traffic-events.jsonl",
        "traffic-events.previous.jsonl",
        "diagnostic-events.jsonl",
        "diagnostic-events.previous.jsonl",
    ] {
        sources.push(source(&base.join(name), name, true));
    }

    // Core supervision & runtime state files
    for name in [
        "channel-supervision.json",
        "seatbelt-runtime.json",
        "channel-log-health.json",
        "target-discovery.json",
        "channel-protocol-coverage.json",
        "guard-service-heartbeat.json",
        "native-listener.json",
    ] {
        sources.push(source(&state.join(name), name, false));
    }
    sources.push(project_runtime_snapshot_source(
        &state.join("runtime-snapshot.json"),
    ));
    sources.push(project_managed_instances_source(
        &state.join("managed-launch-instances.json"),
    ));
    sources.push(project_vpn_observation_source(
        &base.join("vpn-observation.json"),
    ));
    sources.push(source(
        &base.join("guard-heartbeat.json"),
        "guard-heartbeat.json",
        false,
    ));
    for family in claude_watch_core::policy::PolicyCatalog::families() {
        let session_path = storage.paths.session_for(family.id);
        let label = format!("session-guard-{}.json", family.id);
        sources.push(source(&session_path, &label, false));
    }

    let (channel_event_paths, channel_event_status) =
        recent(&state.join("channel-events"), "", ".json", 2);
    sources.push(json!({"source": "channel-events", "status": channel_event_status, "selection_limit": 2}));
    for (index, path) in channel_event_paths.iter().enumerate() {
        sources.push(source(
            path,
            &format!("channel-events-recent-{index}"),
            false,
        ));
    }

    for prefix in [
        "initialization-flow-",
        "initialization-",
        "controlled-entry-",
        "leak-diagnostics-",
    ] {
        let (paths, status) = recent(&logs, prefix, ".jsonl", 3);
        sources.push(json!({"source": prefix, "status": status, "selection_limit": 3}));
        for (index, path) in paths.iter().enumerate() {
            sources.push(source(path, &format!("{prefix}recent-{index}"), true));
        }
    }

    for name in ["native-agent.err.log", "native-agent.out.log"] {
        sources.push(project_text_log_summary(&logs.join(name), name));
    }

    for name in ["events.jsonl", "events.jsonl.1", "events.jsonl.2"] {
        sources.push(source(&broker.join(name), &format!("gateway-{name}"), true));
    }

    let installer = storage.paths.home.join("Library/Logs/ClaudeWatchInstaller");
    let (runs, status) = recent(&installer, "reinstall-", "", 3);
    sources.push(json!({"source": "installer", "status": status, "selection_limit": 3}));
    for (index, path) in runs.iter().enumerate() {
        sources.push(source(
            &path.join("run.json"),
            &format!("installer-recent-{index}"),
            false,
        ));
    }

    let summary = build_summary(&sources);

    // Keep a report for each source even when the total budget omits its payload.
    let mut used = serde_json::to_vec(&summary).map_or(8192, |v| v.len()) + 4096;
    for source in &mut sources {
        let bytes = serde_json::to_vec(source).map_or(COMPACT_BUDGET_LIMIT, |v| v.len());
        if used + bytes > COMPACT_BUDGET_LIMIT - 16384 {
            *source = json!({"source": source["source"], "status": "export_budget_exceeded"});
        }
        used += serde_json::to_vec(source).map_or(0, |v| v.len());
    }
    json!({
        "schema": 1,
        "kind": "claude_watch_diagnostics",
        "generated_at": std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
        "exporter_build": build_identity::current(),
        "summary": summary,
        "sources": sources,
        "bounded": true,
        "scope": "historical_evidence_not_current_protection",
        "sensitive_fields": "omitted_by_allowlist",
        "projection_limits": {
            "file_tail_bytes": FILE_LIMIT,
            "snapshot_file_bytes": SNAPSHOT_FILE_LIMIT,
            "records_per_file": MAX_RECORDS,
            "array_items_per_record": 64,
            "nesting_depth": 10,
            "output_bytes": OUTPUT_LIMIT
        },
        "omitted": "raw output, URLs, IPs, paths, node names, proxy chains, account data, credentials, arbitrary messages",
        "code_locations": {
            "channel_enforcer": "crates/watch-runtime/src/channel_enforcer.rs",
            "channel_supervisor": "crates/watch-runtime/src/channel_supervisor.rs",
            "channel_diagnostics": "crates/watch-runtime/src/channel_diagnostics.rs",
            "diagnostic_bundle": "crates/watch-runtime/src/diagnostic_bundle.rs",
            "initialization": "monitor/Sources/FirstRunInitialization.swift",
            "controlled_entry": "monitor/ControlledEntry/ControlledEntryApp.swift",
            "gateway_broker": "crates/watch-gateway-broker/src/main.rs",
            "reinstall": "monitor/reinstall.sh"
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;

    #[test]
    fn service_liveness_export_keeps_layers_without_private_identity_or_network_data() {
        let value = json!({"backend_alive":true,"protection_ready":false,"sampling_state":"stale",
            "backend_sampling_state":"stale","service_heartbeat_present":true,
            "service_heartbeat_age_seconds":1.0,"evidence_observed_at":20.0,
            "start_stamp":"private process identity","endpoint":"http://secret@proxy","detail":"private details"});
        let projected = project(&value, 0, &mut TruncationTracker::default()).unwrap();
        assert_eq!(projected["backend_alive"], true);
        assert_eq!(projected["protection_ready"], false);
        assert_eq!(projected["sampling_state"], "stale");
        assert_eq!(projected["service_heartbeat_age_seconds"], 1.0);
        assert!(!projected.to_string().contains("private"));
        assert!(!projected.to_string().contains("secret"));
    }

    #[test]
    fn complete_snapshot_uses_file_budget_and_recent_logs_use_modification_time() {
        let root = std::env::temp_dir().join(format!("cw-large-snapshot-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let path = root.join("snapshot.json");
        let data = serde_json::to_vec(&json!({
            "families": {
                "claude": {"reason_code": "vpn_expectation_mismatched", "command_seq": 71},
                "openai": {"reason_code": "vpn_expectation_mismatched", "command_seq": 99}
            },
            "authoritative_permits": {
                "claude": {"permit_generation": 1},
                "openai": {"permit_generation": 2}
            },
            "enforcement_receipts": {
                "claude": {"action": "disconnect-and-force-quit"},
                "openai": {"action": "disconnect-channel"}
            },
            "private_padding": "private-network-address".repeat(4000)
        }))
        .unwrap();
        assert!(data.len() > 64 * 1024 && data.len() < FILE_LIMIT);
        fs::write(&path, &data).unwrap();
        let snapshot = source(&path, "snapshot", false);
        assert_eq!(snapshot["invalid_records"], 0, "{snapshot}");
        assert_eq!(snapshot["records"][0]["families"]["claude"]["command_seq"], 71);
        assert_eq!(snapshot["records"][0]["families"]["openai"]["command_seq"], 99);
        assert_eq!(snapshot["records"][0]["authoritative_permits"]["openai"]["permit_generation"], 2);
        assert_eq!(snapshot["records"][0]["enforcement_receipts"]["openai"]["action"], "disconnect-channel");
        assert!(!snapshot.to_string().contains("private-network-address"));
        let old = root.join("initialization-flow-zzz.jsonl");
        let new = root.join("initialization-flow-aaa.jsonl");
        fs::write(&old, b"{}\n").unwrap();
        fs::write(&new, b"{}\n").unwrap();
        fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1)))
            .unwrap();
        assert_eq!(recent(&root, "initialization-flow-", ".jsonl", 1).0, vec![new]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn truncation_metadata_is_reported_when_arrays_objects_or_depth_exceed_limits() {
        let root = std::env::temp_dir().join(format!("cw-truncation-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();

        // 1. Array with 65 items (exceeding 64 limit)
        let array_path = root.join("oversize_array.json");
        let array_data = json!({
            "stage": "sampling",
            "reasons": (0..65).map(|i| format!("code_{i}")).collect::<Vec<_>>()
        });
        fs::write(&array_path, serde_json::to_vec(&array_data).unwrap()).unwrap();
        let array_source = source(&array_path, "oversize_array", false);
        assert_eq!(array_source["truncated"], true);
        assert_eq!(array_source["truncation"]["array_items"], true);
        assert_eq!(array_source["truncation"]["file_or_records"], false);
        assert_eq!(array_source["records"][0]["reasons"].as_array().unwrap().len(), 64);

        // 2. Normal small record without any truncation
        let normal_path = root.join("normal.json");
        let normal_data = json!({"status": "ok", "component": "enforcer"});
        fs::write(&normal_path, serde_json::to_vec(&normal_data).unwrap()).unwrap();
        let normal_source = source(&normal_path, "normal", false);
        assert_eq!(normal_source["truncated"], false);
        assert!(normal_source.get("truncation").is_none());

        // 3. Deeply nested structure exceeding depth 10
        let mut deep = json!({"status": "ok"});
        for _ in 0..12 {
            deep = json!({"state": deep});
        }
        let deep_path = root.join("deep.json");
        fs::write(&deep_path, serde_json::to_vec(&deep).unwrap()).unwrap();
        let deep_source = source(&deep_path, "deep", false);
        assert_eq!(deep_source["truncated"], true);
        assert_eq!(deep_source["truncation"]["depth_limit"], true);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn diagnostic_export_is_bounded_redacted_and_reports_evidence_gaps() {
        let root = std::env::temp_dir().join(format!("cw-export-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        fs::create_dir_all(storage.paths.base()).unwrap();
        let record = json!({"category":"channel-diagnostic","time":12,"channel_diagnostic":{
            "component":"channel_enforcer","stage":"termination_confirmed","executor_boot_id":"boot-123",
            "flow_id":"flow-456","command_seq":3,"failure":{"code":"fixture_failure","reason":"https://private.invalid"}},
            "url":"https://secret.invalid/key", "account":"private-account", "token":"private-token",
            "message":"PRIVATE-PAYLOAD", "args":["PRIVATE-ARGV"], "state":{"pid":123,"endpoint":"private-endpoint"}});
        let line = format!("{}\n", record);
        fs::write(storage.paths.base().join("events.jsonl"), line.repeat(4000)).unwrap();
        fs::write(storage.paths.base().join("diagnostic-events.jsonl"), b"invalid\n").unwrap();
        fs::create_dir_all(storage.paths.watch().join("state")).unwrap();
        std::os::unix::fs::symlink(
            storage.paths.base().join("events.jsonl"),
            storage.paths.watch().join("state/seatbelt-runtime.json"),
        )
        .unwrap();
        let broker = root.join("broker");
        fs::create_dir(&broker).unwrap();
        fs::write(
            broker.join("events.jsonl"),
            b"{\"operation\":\"logging_recovery\",\"dropped_queue_records\":1,\"failed_write_records\":2,\"counts_saturated\":false}\n",
        )
        .unwrap();
        let bundle = collect_with_broker(&storage, &broker);
        let encoded = serde_json::to_string(&bundle).unwrap();
        assert!(encoded.len() < OUTPUT_LIMIT);
        for secret in [
            "secret.invalid",
            "private-account",
            "private-token",
            "PRIVATE-PAYLOAD",
            "PRIVATE-ARGV",
            "private-endpoint",
            "private.invalid",
        ] {
            assert!(!encoded.contains(secret), "leaked {secret}");
        }
        assert!(encoded.contains("flow-456") && encoded.contains("fixture_failure"));
        let sources = bundle["sources"].as_array().unwrap();
        assert_eq!(sources[0]["truncated"], true);
        assert!(sources.iter().any(|s| s["status"] == "missing"));
        assert!(sources.iter().any(|s| s["status"] == "unsafe_path"));
        assert!(sources.iter().any(|s| s["invalid_records"] == 1));
        let recovery = sources
            .iter()
            .find(|s| s["source"] == "gateway-events.jsonl")
            .unwrap();
        assert_eq!(recovery["records"][0]["dropped_queue_records"], 1);
        assert_eq!(recovery["records"][0]["failed_write_records"], 2);
        assert_eq!(recovery["records"][0]["counts_saturated"], false);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expanded_sources_and_summary_keep_operational_facts_and_strip_all_sensitive_fields() {
        let root = std::env::temp_dir().join(format!("cw-export-expanded-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        let state = storage.paths.watch().join("state");
        let logs = storage.paths.watch().join("logs");
        fs::create_dir_all(storage.paths.base()).unwrap();
        fs::create_dir_all(state.join("channel-events")).unwrap();
        fs::create_dir_all(&logs).unwrap();

        fs::write(
            state.join("runtime-snapshot.json"),
            serde_json::to_vec(&json!({
                "schema": 1,
                "snapshot": {
                    "capturedAt": 1700000100.0,
                    "health": {"state": "running", "mode": "ACTIVE", "pid": 4242, "heartbeatAge": 0.5, "detail": "secret-health-detail"},
                    "installed": true,
                    "targetDiscovery": {"complete": true, "revision": "rev-1", "issues": []},
                    "samplingDiagnostics": {"process_complete": true, "process_reason_counts": {}},
                    "proxy": {
                        "observedAt": 1700000100.0,
                        "entryState": "verified",
                        "apiState": "verified",
                        "mode": "rule",
                        "coversProxy": true,
                        "endpoint": "http://127.0.0.1:7890",
                        "connectionObservation": {
                            "collectorState": "ok",
                            "targetCount": 2,
                            "parsedCount": 4,
                            "acceptedCount": 4,
                            "correlatedCount": 4,
                            "unconfirmedCount": 0
                        },
                        "flows": [{
                            "pid": 82449,
                            "host": "secret-host.example.com",
                            "peer": "203.0.113.42:443",
                            "local": "127.0.0.1:51234",
                            "destinationIP": "203.0.113.42",
                            "protocol": "TCP",
                            "path": "controlled_gateway",
                            "flow_kind": "ai_platform",
                            "association": "correlated",
                            "policy": "proxy",
                            "reason": "seatbelt_gateway_correlated",
                            "chains": ["JP-Secret-Node-01", "ProxyGroup-Secret"]
                        }]
                    },
                    "processes": [{
                        "pid": 82449,
                        "kind": "chatgpt",
                        "runtimeRole": "desktop_main",
                        "executable": "/Users/alice/secret/ChatGPT",
                        "protection": {"state": "protected"}
                    }],
                    "events": [{"title": "DUPLICATED_EVENT_SHOULD_BE_OMITTED"}]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        fs::write(
            state.join("managed-launch-instances.json"),
            serde_json::to_vec(&json!([{
                "instance_id": "inst-001",
                "family": "openai",
                "target": "chatgpt-desktop",
                "state": "exec_verified",
                "sandbox_evidence": {
                    "applied": true,
                    "direct_network_blocked": true,
                    "unix_relay_blocked": true,
                    "verified_helper_origin": true
                },
                "controlled_subtree_pids": [82449, 83333],
                "verified_executable": "/Users/alice/secret/ChatGPT",
                "process_visibility": {
                    "members": [
                        {"pid": 82449, "currently_verified": true, "verified_executable": "/Users/alice/secret/ChatGPT"},
                        {"pid": 83333, "currently_verified": true, "verified_executable": "/Users/alice/secret/codex"}
                    ]
                }
            }]))
            .unwrap(),
        )
        .unwrap();

        fs::write(
            storage.paths.base().join("vpn-observation.json"),
            serde_json::to_vec(&json!({
                "source": "tag",
                "upstream_endpoint": "http://127.0.0.1:7890",
                "upstream_protocol": {"state": "known", "value": "http_connect"},
                "running_mode": {"state": "known", "value": "rule"},
                "tun_enabled": {"state": "known", "value": true},
                "system_proxy_enabled": {"state": "known", "value": true},
                "selected_group": "ProxyGroup-Secret",
                "selected_node": "JP-Secret-Node-01",
                "proxy_chain": ["JP-Secret-Node-01"],
                "sample_started_at": 1700000090.0,
                "observed_at": 1700000091.0,
                "valid_until": 1700000151.0,
                "consistency": "consistent",
                "source_error": null,
                "sample_seq": 42,
                "epoch": {"observer_boot_id": "vpn-obs-1", "change_generation": 2}
            }))
            .unwrap(),
        )
        .unwrap();

        fs::write(
            state.join("channel-supervision.json"),
            serde_json::to_vec(&json!({
                "families": {
                    "openai": {
                        "permit_state": "permitted",
                        "reason_code": "session_adopted",
                        "permit_generation": 15,
                        "command_seq": 21
                    }
                },
                "enforcement_receipts": {
                    "openai": {
                        "state": "forwarding",
                        "active_flows_count": 12
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        fs::write(
            storage.paths.session_for("openai"),
            serde_json::to_vec(&json!({
                "session_id": "sess-openai-1",
                "state": "active",
                "created_at": 1700000080.0,
                "unknown_count": 0,
                "baseline": {"ip": "203.0.113.42", "country": "JP"},
                "account": "alice@secret.example"
            }))
            .unwrap(),
        )
        .unwrap();

        fs::write(
            storage.paths.base().join("diagnostic-events.jsonl"),
            format!(
                "{}\n{}\n",
                json!({"category":"channel-diagnostic","time":100,"channel_diagnostic":{"stage":"command_applied","reason_code":"permit_lease_expired"}}),
                json!({"category":"channel-diagnostic","time":101,"channel_diagnostic":{"stage":"connection_rejected","reason_code":"permit_lease_expired","failure":{"code":"203.0.113.42"}}})
            ),
        )
        .unwrap();

        fs::write(
            logs.join("native-agent.err.log"),
            "2026-11-24 /Users/alice/secret/file error=native_listener_response_timeout ip=203.0.113.42 token=sk-secret-999\nerror=native_listener_response_timeout gateway_capacity_exhausted\n",
        )
        .unwrap();

        let broker = root.join("broker");
        fs::create_dir(&broker).unwrap();
        let bundle = collect_with_broker(&storage, &broker);
        let encoded = serde_json::to_string_pretty(&bundle).unwrap();
        assert!(encoded.len() < OUTPUT_LIMIT);

        for secret in [
            "secret-host.example.com",
            "203.0.113.42",
            "127.0.0.1",
            "JP-Secret-Node-01",
            "ProxyGroup-Secret",
            "/Users/alice/secret",
            "alice@secret.example",
            "sk-secret-999",
            "DUPLICATED_EVENT_SHOULD_BE_OMITTED",
            "secret-health-detail",
        ] {
            assert!(!encoded.contains(secret), "leaked secret: {secret}");
        }

        // Verify summary & projected operational fields exist
        assert_eq!(bundle["summary"]["daemon_health"], "running");
        assert_eq!(bundle["summary"]["target_discovery_complete"], true);
        assert_eq!(bundle["summary"]["process_complete"], true);
        assert_eq!(bundle["summary"]["vpn_consistency"], "consistent");
        assert_eq!(bundle["summary"]["family_states"]["openai"]["permit_state"], "permitted");
        assert_eq!(bundle["summary"]["family_states"]["openai"]["active_flows_count"], 12);
        assert_eq!(bundle["summary"]["recent_diagnostic_reason_counts"]["permit_lease_expired"], 2);

        let sources = bundle["sources"].as_array().unwrap();
        let snap = sources.iter().find(|s| s["source"] == "runtime-snapshot.json").unwrap();
        assert_eq!(snap["records"][0]["proxy"]["flows"][0]["flow_path"], "controlled_gateway");
        assert_eq!(snap["records"][0]["proxy"]["flows"][0]["association"], "correlated");
        assert_eq!(snap["records"][0]["proxy"]["connectionObservation"]["correlatedCount"], 4);

        let inst = sources.iter().find(|s| s["source"] == "managed-launch-instances.json").unwrap();
        assert_eq!(inst["records"][0]["instance_id"], "inst-001");
        assert_eq!(inst["records"][0]["verified_member_count"], 2);
        assert_eq!(inst["records"][0]["sandbox_evidence"]["direct_network_blocked"], true);

        let vpn = sources.iter().find(|s| s["source"] == "vpn-observation.json").unwrap();
        assert_eq!(vpn["records"][0]["sample_seq"], 42);
        assert_eq!(vpn["records"][0]["running_mode"]["code"], "rule");
        assert_eq!(vpn["records"][0]["tun_enabled"]["code"], true);

        let err_log = sources.iter().find(|s| s["source"] == "native-agent.err.log").unwrap();
        assert_eq!(err_log["records"][0]["code_counts"]["native_listener_response_timeout"], 2);
        assert_eq!(err_log["records"][0]["code_counts"]["gateway_capacity_exhausted"], 1);

        fs::remove_dir_all(root).unwrap();
    }
}
