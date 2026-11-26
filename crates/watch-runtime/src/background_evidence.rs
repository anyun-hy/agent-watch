//! Window-independent native DNS/WebRTC evidence coordination. It never grants
//! launch permission or controls an application: validated receipts are consumed
//! by the existing guard.
use crate::{
    config_store::{guard_policy_digest, ConfigStore},
    receipt_store::ReceiptStore,
    session_store::SessionStore,
    storage::StateStore,
};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    processes::Provider,
    session::{Desktop, Phase, Session},
};
use crate::session_store::desktop_groups::{desktop_members, group_rechecking, has_desktop_group};
use serde_json::{json, Value};

pub use claude_watch_core::evidence::ProbeKind;
use claude_watch_core::evidence::{EvidenceAction, EvidenceRequest};
pub trait EvidenceSystem {
    fn now(&self) -> f64;
    fn local(&mut self, config: &Config) -> Result<Value>;
    fn desktop_matches(&mut self, desktop: &Desktop) -> Result<bool>;
    fn desktop_unique_stamp(&mut self, desktop: &Desktop) -> Result<Option<String>>;
    fn channel_process_matches(&mut self, _process: &claude_watch_core::channel::BoundProcessToken) -> Result<bool> {
        Ok(false)
    }
    /// Complete native membership, not just the representative PID. Adapters
    /// which cannot enumerate a group must explicitly decline it.
    fn desktop_group_stamps(&mut self, members: &[Desktop]) -> Result<Option<Vec<(Desktop, String)>>> {
        if members.len() != 1 {
            return Err(err("evidence_identity_unknown", "证据适配器不能核对完整桌面集合"));
        }
        Ok(self.desktop_unique_stamp(&members[0])?.map(|stamp| vec![(members[0].clone(), stamp)]))
    }
    fn collect(&mut self, kind: ProbeKind) -> Result<Value>;
    /// The full launch-grade audit runs here, never on the fast guard thread.
    fn revalidate(&mut self) -> Result<(Value, Value)> {
        Err(err("revalidation_unavailable", "新进程的完整校验不可用"))
    }
    fn cancelled(&self) -> bool {
        false
    }
    /// The service whose session is revalidated; its policy family decides
    /// what the lease records. Defaults to the supervised Claude desktop and
    /// is overridden by adapters that supervise other families.
    fn supervised_provider(&self) -> Provider {
        Provider::Claude
    }
    /// Fixed-target test/CLI adapters cannot silently collect another family.
    fn set_family(&mut self, family: &str) -> Result<()> {
        if PolicyCatalog::family_for(self.supervised_provider()).map(|f| f.id) == Some(family) {
            Ok(())
        } else {
            Err(err("evidence_family_unavailable", "证据适配器不能切换到该服务"))
        }
    }
}
fn err(code: &str, detail: &str) -> CoreError {
    CoreError::new(code, detail)
}
fn context(local: &Value) -> Option<&str> {
    if local["proxy"] != "ok"
        || local["tun"] != "ok"
        || local["observation_unavailable"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    {
        return None;
    }
    local
        .get("context_id")
        .or_else(|| local.get("context"))?
        .as_str()
        .filter(|s| !s.is_empty())
}
fn fresh(store: &StateStore, kind: ProbeKind, ctx: &str, current_ip: Option<&str>, now: f64, since: Option<f64>) -> bool {
    ReceiptStore { storage: store.clone() }.probe_is_fresh(kind, ctx, current_ip, now, since)
}

/// Use the stored source timestamps. Same-network receipts remain reusable
/// until the route or verified egress changes; that egress has its own lifetime.
fn next_review(store: &StateStore, ctx: &str, local: &Value) -> Option<f64> {
    let ip = local["evidence_egress_ip"].as_str();
    let (dns, rtc) = ReceiptStore { storage: store.clone() }.probe_receipts();
    let mut deadline = local["evidence_egress_observed_at"].as_f64()
        .map(|at| at + claude_watch_core::session::GUARD_EGRESS_TTL);
    for (kind, value, sampled_at) in [(ProbeKind::Dns, dns, "finished_at"), (ProbeKind::WebRtc, rtc, "sampled_at")] {
        if !claude_watch_core::receipts::network_reusable(&value, ctx, ip) {
            if let Some(due) = value[sampled_at].as_f64().map(|at| at + kind.refresh_age()) {
                deadline = Some(deadline.map_or(due, |previous| previous.min(due)));
            }
        }
    }
    deadline
}

/// A notice does not stop supervision. Only warn-only locks may refresh;
/// mandatory close/force locks stay latched and are never resumed here.
fn refreshable(session: &Session, config: &Config, provider: Provider) -> bool {
    match session.state {
        Phase::Active | Phase::Rechecking => true,
        Phase::Locked => session.reason.as_ref()
            .is_some_and(|reason| config.close_action(&reason.code, provider) == "warn"),
        Phase::Pending | Phase::Ended => false,
    }
}

fn matching_desktops<S: EvidenceSystem>(system: &mut S, session: &Session) -> Result<bool> {
    if let Some(processes) = SessionStore::channel_processes(session)? {
        for process in &processes {
            if system.channel_process_matches(process)? { return Ok(true); }
        }
        return Ok(false);
    }
    if has_desktop_group(session) {
        let members = desktop_members(session)?;
        let Some(bindings) = system.desktop_group_stamps(&members)? else { return Ok(false) };
        let actual = crate::session_store::desktop_groups::canonical_desktops(
            bindings.iter().map(|(d, _)| d.clone()).collect(),
        )?;
        Ok(actual == members)
    } else {
        match session.desktop.as_ref() {
            Some(desktop) => system.desktop_matches(desktop),
            None => Ok(false),
        }
    }
}

/// One worker services all declared families. Receipts may be reused only
/// when their verified context and freshness match; sessions and locks never
/// cross families. A failure in one family must not starve the next one.
pub fn refresh_supervised_sessions<S: EvidenceSystem>(store: &StateStore, system: &mut S) -> Result<Value> {
    let mut reports = Vec::new();
    for family in PolicyCatalog::families() {
        if system.cancelled() { break; }
        if PolicyCatalog::guard_target(family).is_none() { continue; }
        let result = system.set_family(family.id).and_then(|()| {
            if PolicyCatalog::family_for(system.supervised_provider()).map(|f| f.id) != Some(family.id) {
                return Err(err("evidence_family_mismatch", "证据适配器与会话服务不一致"));
            }
            refresh_active_session(store, system)
        });
        let mut report = match result {
            Ok(value) => value,
            Err(error) => json!({"status":"incomplete","count":0,"code":error.code}),
        };
        report["family"] = json!(family.id);
        reports.push(report);
    }
    let has = |status: &str| reports.iter().any(|v| v["status"] == status);
    let status = if has("risk") { "risk" } else if has("incomplete") { "incomplete" }
        else if has("ok") { "ok" } else { "idle" };
    let count: u64 = reports.iter().filter_map(|v| v["count"].as_u64()).sum();
    let probes = |key: &str| -> Vec<&str> {
        ["dns", "webrtc"].into_iter().filter(|kind| reports.iter().any(|v| {
            v[key].as_array().is_some_and(|names| names.iter().any(|name| name.as_str() == Some(*kind)))
        })).collect()
    };
    let next_review = reports.iter().filter_map(|v| v["next_review_at"].as_f64()).min_by(f64::total_cmp);
    Ok(json!({"status":status,"count":count,"next_review_at":next_review,"failed_probes":probes("failed_probes"),
        "risk_probes":probes("risk_probes"),"families":reports}))
}

/// Called by the independent worker on an invalidation or evidence deadline. GUI-produced fresh
/// receipts are reused, so opening the window does not double probe frequency.
pub fn refresh_active_session<S: EvidenceSystem>(
    store: &StateStore,
    system: &mut S,
) -> Result<Value> {
    let config = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    if !config.enabled || !config.guard_enabled || system.cancelled() {
        return Ok(json!({"status":"idle","count":0}));
    }
    let provider = system.supervised_provider();
    let family = PolicyCatalog::family_for(provider)
        .ok_or_else(|| err("evidence_family_unavailable", "证据服务未声明会话策略"))?;
    let sessions = SessionStore::for_family(store.clone(), family.id);
    let Some(session) = sessions
        .load(system.now())?
        .filter(|s| refreshable(s, &config, provider))
    else {
        return Ok(json!({"status":"idle","count":0}));
    };
    let channel_bound = SessionStore::channel_processes(&session)?.is_some();
    let desktop = session.desktop.as_ref();
    if !channel_bound && desktop.is_none() {
        return Err(err("evidence_identity_unknown", "受控会话缺少主进程身份"));
    }
    let binding_matches = |s: &Session| if channel_bound {
        SessionStore::channel_processes(s).ok().flatten().is_some()
    } else {
        s.desktop.as_ref() == desktop && s.extra.get("desktop_group_v1") == session.extra.get("desktop_group_v1")
    };
    let grouped = has_desktop_group(&session);
    let rechecking = session.state == Phase::Rechecking || group_rechecking(&session);
    if grouped && !matching_desktops(system, &session)? {
        return Ok(json!({"status":"idle","count":0}));
    }
    let current_local = system.local(&config)?;
    if context(&current_local).is_none() {
        return Err(err("evidence_context_unconfirmed", "网络采样未确认；已通过检测记录保留"));
    }
    if !rechecking && context(&current_local) == Some(session.context_id.as_str())
        && [ProbeKind::Dns, ProbeKind::WebRtc]
            .iter()
            .all(|kind| fresh(store, *kind, &session.context_id, current_local["evidence_egress_ip"].as_str(), system.now(), None))
    {
        return Ok(json!({"status":"ok","count":0,"failed_probes":[],
            "next_review_at":next_review(store, &session.context_id, &current_local)}));
    }
    if !matching_desktops(system, &session)? {
        return Ok(json!({"status":"idle","count":0}));
    }
    let policy = guard_policy_digest(&config)?;
    let evidence_context = if rechecking {
        let local = system.local(&config)?;
        let current_context = context(&local)
            .ok_or_else(|| err("evidence_context_unconfirmed", "新进程网络上下文未确认"))?
            .to_owned();
        if !sessions.recheck_context(
            &session.session_id,
            desktop.ok_or_else(|| err("evidence_identity_unknown", "复核会话缺少主进程身份"))?,
            &current_context,
            system.now(),
        )? {
            return Err(err("evidence_session_changed", "新进程会话已变化"));
        }
        current_context
    } else {
        session.context_id.clone()
    };
    let mut count = 0u32;
    let mut errors = Vec::new();
    let mut risks = Vec::new();
    for kind in [ProbeKind::Dns, ProbeKind::WebRtc] {
        if system.cancelled() {
            break;
        }
        let since = rechecking.then_some(session.created_at);
        if fresh(store, kind, &evidence_context, current_local["evidence_egress_ip"].as_str(), system.now(), since) {
            continue;
        }
        let before = system.local(&config)?;
        if context(&before) != Some(evidence_context.as_str()) {
            return Err(err(
                "evidence_context_unconfirmed",
                "当前网络未能与受控会话核对，未更新保护证据",
            ));
        }
        let collected = system.collect(kind);
        let current = ConfigStore {
            storage: store.clone(),
        }
        .load()?;
        if system.cancelled()
            || !current.enabled
            || !current.guard_enabled
            || guard_policy_digest(&current)? != policy
        {
            return Err(err(
                "evidence_policy_changed",
                "采集期间保护设置已变更，未覆盖回执",
            ));
        }
        let active = sessions.load(system.now())?;
        if !active.as_ref().is_some_and(|s| {
            refreshable(s, &current, provider)
                && s.context_id == evidence_context
                && s.session_id == session.session_id
                && binding_matches(s)
        }) || !matching_desktops(system, active.as_ref().unwrap_or(&session))?
        {
            return Err(err(
                "evidence_session_changed",
                "采集期间受控会话已变化，未覆盖回执",
            ));
        }
        let after = system.local(&current)?;
        if context(&after).is_none() {
            return Err(err("evidence_context_unconfirmed", "采样暂不可用；已通过检测记录保留"));
        }
        if context(&after) != context(&before) || after["evidence_egress_ip"] != before["evidence_egress_ip"] {
            return Err(err(
                "evidence_context_changed",
                "采集前后网络身份未持续确认，未覆盖回执",
            ));
        }
        let result = collected.and_then(|probe| {
            // Use exactly the selected family's session lock. No network work
            // is performed inside it, and a newer lock/replacement wins.
            sessions.close_if_current(Some(&session.session_id), system.now(), || {
                let latest = ConfigStore { storage: store.clone() }.load()?;
                if !latest.enabled || !latest.guard_enabled || guard_policy_digest(&latest)? != policy {
                    return Err(err("evidence_policy_changed", "采集期间保护策略已变化"));
                }
                let current_session = sessions.load(system.now())?;
                if !current_session.as_ref().is_some_and(|s| {
                    refreshable(s, &latest, provider)
                        && s.context_id == evidence_context
                        && binding_matches(s)
                }) || (channel_bound && !matching_desktops(system, current_session.as_ref().unwrap_or(&session))?) {
                    return Err(err("evidence_session_changed", "采集期间受控会话已变化"));
                }
                let receipts = ReceiptStore { storage: store.clone() };
                match kind {
                    ProbeKind::Dns => receipts.record_dns(&probe, &after, None, system.now()),
                    ProbeKind::WebRtc => receipts.record_webrtc(&probe, &after, Some(&evidence_context), system.now()),
                }
            })?.ok_or_else(|| err("evidence_session_changed", "采集期间受控会话已变化"))
        });
        match result {
            Ok(receipt) => {
                count += 1;
                let state = match kind {
                    ProbeKind::Dns => receipt.pointer("/comparison/state"),
                    ProbeKind::WebRtc => receipt.pointer("/risk/state"),
                }
                .and_then(Value::as_str);
                match state {
                    Some("fail") => risks.push(kind.label()),
                    Some("ok") => {}
                    _ => errors.push(kind.label()),
                }
            }
            Err(e) if e.code == "superseded_receipt" => {}
            Err(e)
                if matches!(
                    e.code.as_str(),
                    "evidence_session_changed" | "evidence_policy_changed"
                ) =>
            {
                return Err(e)
            }
            Err(_) => errors.push(kind.label()),
        }
    }
    if rechecking
        && errors.is_empty()
        && risks.is_empty()
        && !system.cancelled()
    {
        let (audit, egress) = system.revalidate()?;
        let completed = if grouped {
            let Some(bindings) = system.desktop_group_stamps(&desktop_members(&session)?)? else {
                return Err(err("evidence_session_changed", "重新校验期间桌面集合已变化"));
            };
            if system.cancelled() { return Err(err("evidence_session_changed", "重新校验已取消")); }
            sessions.complete_group_recheck(&session, &bindings, &audit, &egress,
                system.now(), system.supervised_provider())?
        } else {
            let desktop = desktop.ok_or_else(|| err("evidence_identity_unknown", "复核会话缺少主进程身份"))?;
            let Some(stamp) = system.desktop_unique_stamp(desktop)? else {
                return Err(err("evidence_session_changed", "重新校验期间进程已变化"));
            };
            if system.cancelled() { return Err(err("evidence_session_changed", "重新校验已取消")); }
            sessions.complete_recheck(&session.session_id, desktop, &stamp, &audit, &egress,
                system.now(), system.supervised_provider())?
        };
        if completed.is_none() {
            return Err(err("evidence_session_changed", "重新校验结果已过期"));
        }
    }
    Ok(
        json!({"status":if !risks.is_empty(){"risk"}else if errors.is_empty(){"ok"}else{"incomplete"},"count":count,"next_review_at":next_review(store, &evidence_context, &current_local),
            "failed_probes":errors,"risk_probes":risks}),
    )
}

/// On-demand and read-only requests share the resident probe executor and
/// ReceiptStore used by supervision. No operation/session lock is acquired.
pub fn serve_evidence_request<S: EvidenceSystem>(
    store: &StateStore, system: &mut S, request: &EvidenceRequest,
) -> Result<Value> {
    request.validate()?;
    let config = ConfigStore { storage: store.clone() }.load()?;
    if system.cancelled() { return Err(err("evidence_cancelled", "检测已取消")); }
    let before = system.local(&config)?;
    let ctx = context(&before).ok_or_else(|| err("evidence_context_unconfirmed", "当前网络上下文未确认"))?.to_owned();
    if request.expected_context.as_deref().is_some_and(|v|
        v != ctx && v != claude_watch_core::receipts::tag_signature(&before)) {
        return Err(err("evidence_context_changed", "请求所属网络与当前网络不一致"));
    }
    let policy = guard_policy_digest(&config)?;
    let receipts = ReceiptStore { storage: store.clone() };
    let mut items = serde_json::Map::new();
    let mut count = 0;
    // DNS has the shorter launch window. Collect it last so a slow WebRTC
    // probe cannot age a just-collected DNS receipt out of the launch gate.
    let mut kinds = request.kinds.clone();
    if request.purpose == claude_watch_core::evidence::EvidencePurpose::Launch {
        kinds.sort_by_key(|kind| *kind == ProbeKind::Dns);
    }
    for &kind in &kinds {
        let mut item = receipts.evidence_item(kind, &ctx, request.purpose, request.expected_ip.as_deref(), before["evidence_egress_ip"].as_str(), system.now())?;
        let fresh = matches!(item["state"].as_str(), Some("ok" | "fail"))
            && item["probe"]["status"] == "complete";
        if request.action == EvidenceAction::Refresh && (request.force || !fresh) {
            let round_before = system.local(&config)?;
            if context(&round_before).is_none() {
                return Err(err("evidence_context_unconfirmed", "采样暂不可用；已通过检测记录保留"));
            }
            if context(&round_before) != Some(ctx.as_str()) || round_before["evidence_egress_ip"] != before["evidence_egress_ip"] {
                return Err(err("evidence_context_changed", "检测开始前网络上下文已变化"));
            }
            let started = system.now();
            let collected = system.collect(kind);
            let current = ConfigStore { storage: store.clone() }.load()?;
            if system.cancelled() { return Err(err("evidence_cancelled", "检测已取消")); }
            if guard_policy_digest(&current)? != policy {
                return Err(err("evidence_policy_changed", "检测期间策略已变化，未覆盖回执"));
            }
            let after = system.local(&current)?;
            if context(&after).is_none() {
                return Err(err("evidence_context_unconfirmed", "采样暂不可用；已通过检测记录保留"));
            }
            if context(&after) != Some(ctx.as_str()) || after["evidence_egress_ip"] != before["evidence_egress_ip"] {
                return Err(err("evidence_context_changed", "检测期间网络上下文已变化，未覆盖回执"));
            }
            // A failed current attempt is evidence of incompleteness. Persist it
            // without renewing any old success; last-valid remains display-only.
            let probe = collected.unwrap_or_else(|e| json!({
                "kind":kind.label(),"status":if e.code.contains("timeout") {"timeout"} else {"error"},
                "startedAt":started,"finishedAt":system.now(),"scope":"原生后台检测",
                "observations":[],"errors":[{"stage":"collector","code":e.code,"message":e.message}],
                "contextChanged":false,"details":[]
            }));
            let result = match kind {
                ProbeKind::Dns => receipts.record_dns(&probe, &after, Some(&ctx), system.now()),
                ProbeKind::WebRtc => receipts.record_webrtc(&probe, &after, Some(&ctx), system.now()),
            };
            match result {
                Ok(recorded) => {
                    count += 1;
                    item = receipts.evidence_item(kind, &ctx, request.purpose, request.expected_ip.as_deref(), after["evidence_egress_ip"].as_str(), system.now())?;
                    if recorded["comparison"]["state"] == "unknown" || recorded["risk"]["state"] == "unknown" {
                        item["sampling_error"] = json!("本次采样未完成；沿用同一网络已通过的结果，原采样时间不变");
                    }
                }
                Err(e) => {
                    // A rejected attempt cannot present a previous receipt as its result.
                    item = json!({"state":"unknown","code":e.code,"detail":e.message,
                        "stored":false,"receipt":null,"probe":null,"display_probe":null,"valid_until":null,"diagnostic":null});
                }
            }
        }
        items.insert(kind.label().into(), item);
    }
    let state = if items.values().any(|v| v["state"] == "fail") { "risk" }
        else if items.values().all(|v| v["state"] == "ok") { "ok" } else { "incomplete" };
    Ok(json!({"schema":1,"id":request.id,"status":state,"count":count,
        "context_id":ctx,"context_key":claude_watch_core::receipts::tag_signature(&before),
        "evaluated_at":system.now(),"items":items}))
}
