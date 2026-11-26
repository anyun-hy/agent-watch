//! Background WebKit refresh has an independent worker so slow external
//! diagnostics cannot pause process/session protection or heartbeat publication.
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    processes::Provider,
    session::Desktop,
};
use claude_watch_runtime::{
    audit_store::AuditSystem,
    background_evidence::{self, EvidenceSystem, ProbeKind},
    controlled::DesktopSystem,
    desktop_native::{DesktopRuntime, NativeDesktop},
    events::{EventFields, EventStore},
    macos::Authority,
    native,
    storage::{Paths, StateStore},
};
use serde_json::Value;
use std::{
    os::{fd::AsFd, unix::net::UnixStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

struct NativeEvidence {
    host: super::runtime::Host,
    desktop: NativeDesktop<Arc<claude_watch_runtime::commands::SystemRunner>>,
    stop: Arc<AtomicBool>,
}
fn next_review_delay(failures: &mut u32, incomplete: bool, due: Option<f64>, now: f64) -> Option<Duration> {
    let remaining = due.map(|at| {
        // A corrupt future stamp must not overflow a Duration or postpone
        // verification beyond the longest supported receipt lifetime.
        Duration::from_secs_f64((at - now).clamp(0.0, ProbeKind::WebRtc.refresh_age()))
    });
    if incomplete {
        *failures = failures.saturating_add(1).min(3);
        let retry = Duration::from_secs((5u64 << *failures).min(30));
        // Another family's fresh evidence may expire before this retry.
        Some(remaining.filter(|delay| !delay.is_zero()).map_or(retry, |delay| retry.min(delay)))
    } else {
        *failures = 0;
        remaining
    }
}
fn evidence_error_code(code: &str) -> &str {
    match code {
        "evidence_worker_missing"
        | "evidence_runtime_invalid"
        | "evidence_context_changed"
        | "evidence_context_unconfirmed"
        | "evidence_session_changed"
        | "evidence_policy_changed"
        | "revalidation_timeout"
        | "revalidation_context_changed"
        | "revalidation_lease_rollback_failed"
        | "revalidation_unavailable"
        | "preflight_blocked"
        | "egress_changed"
        | "risk_evidence_unavailable"
        | "desktop_inventory_incomplete" => code,
        _ => "evidence_refresh_failed",
    }
}
impl EvidenceSystem for NativeEvidence {
    fn now(&self) -> f64 {
        native::now()
    }
    fn local(&mut self, config: &Config) -> Result<Value> {
        let mut local = AuditSystem::local(&self.host, config)?;
        if local["evidence_network_bound"] == true {
            let egress = self.host.network.fast_egress();
            let ip = egress.data.as_ref().and_then(|v| v["ip"].as_str())
                .ok_or_else(|| CoreError::new("evidence_egress_unavailable", "出口采样未完成；已通过检测记录保留"))?;
            local["evidence_egress_ip"] = Value::String(ip.into());
            local["evidence_egress_observed_at"] = serde_json::json!(egress.finished_at);
        }
        Ok(local)
    }
    fn desktop_matches(&mut self, expected: &Desktop) -> Result<bool> {
        Ok(self
            .desktop
            .desktops()?
            .iter()
            .any(|(actual, main, _)| *main && actual == expected))
    }
    fn channel_process_matches(&mut self, process: &claude_watch_core::channel::BoundProcessToken) -> Result<bool> {
        Ok(process.audit_token.as_ref().is_some_and(|token|
            claude_watch_system::process_audit_token_matches(process.pid, process.uid,
                process.start_seconds, process.start_microseconds, token)))
    }
    fn desktop_unique_stamp(&mut self, expected: &Desktop) -> Result<Option<String>> {
        let processes = self.desktop.desktops()?;
        let mut mains = processes.iter().filter(|(_, main, _)| *main);
        let first = mains.next();
        Ok(first
            .filter(|(actual, _, _)| actual == expected && mains.next().is_none())
            .map(|(_, _, stamp)| stamp.clone()))
    }
    fn desktop_group_stamps(&mut self, expected: &[Desktop]) -> Result<Option<Vec<(Desktop, String)>>> {
        claude_watch_runtime::session_store::desktop_groups::group_stamps(
            expected, &self.desktop.desktops()?,
        )
    }
    fn collect(&mut self, kind: ProbeKind) -> Result<Value> {
        Ok(match kind {
            ProbeKind::Dns => claude_watch_runtime::native_leak_probes::collect_dns(
                self.host.runner.as_ref(),
                &self.host.network,
            ),
            ProbeKind::WebRtc => {
                claude_watch_runtime::native_leak_probes::collect_webrtc(&self.host.network)
            }
        })
    }
    fn revalidate(&mut self) -> Result<(Value, Value)> {
        let network = self.host.network.clone();
        let storage = self.host.storage.clone();
        let mut runtime = DesktopRuntime {
            desktop: &mut self.desktop,
            system: &mut self.host,
            network,
            storage,
            started: Instant::now(),
            cli: None,
        };
        let audit = runtime.full_audit()?;
        let egress = runtime.egress();
        Ok((audit, egress))
    }
    fn cancelled(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
    fn supervised_provider(&self) -> Provider {
        self.desktop.provider()
    }
    fn set_family(&mut self, family: &str) -> Result<()> {
        let target = PolicyCatalog::family(family).and_then(PolicyCatalog::guard_target)
            .ok_or_else(|| CoreError::new("evidence_family_unavailable", "策略未声明该证据服务"))?;
        self.desktop.set_guard_target(target);
        Ok(())
    }
}
/// Session heartbeats can replace the file without changing which probes
/// it needs. Keep only the inputs consumed by refresh_active_session.
fn session_inputs(store: &StateStore, path: &std::path::Path) -> Value {
    match store.read_json(path, Value::Null) {
        Ok(value) if value.is_object() => serde_json::json!([
            value["schema"], value["session_id"], value["state"], value["context_id"],
            value["created_at"], value["reason"]["code"], value["desktop"],
            value["baseline"]["ip"], value["last_check"]["ip"],
            value[claude_watch_core::session::GROUP_KEY], value[claude_watch_core::session::GROUP_RECHECK_KEY],
            value["channel_processes_v1"],
        ]),
        Ok(value) => value,
        Err(error) => serde_json::json!({"error":error.code}),
    }
}

pub struct EvidenceWorker {
    cancel: UnixStream,
    worker: thread::JoinHandle<()>,
}
impl EvidenceWorker {
    pub fn is_finished(&self) -> bool { self.worker.is_finished() }
    pub fn join(self) -> thread::Result<()> {
        drop(self.cancel);
        self.worker.join()
    }
}

pub fn spawn(paths: Paths, stop: Arc<AtomicBool>) -> Result<EvidenceWorker> {
    let store = StateStore::new(paths.clone());
    let mut host = super::runtime::host(paths, Authority::ReadOnly)?;
    host.request_evidence = false;
    let desktop = NativeDesktop::new(
        host.runner.clone(),
        super::runtime::process_component()?,
        Authority::ReadOnly,
    )?;
    let (cancel, cancellation) = UnixStream::pair().map_err(|_| CoreError::new("evidence_worker_failed", "保护证据停止通道无法启动"))?;
    let worker = thread::Builder::new()
        .name("claude-background-evidence".into())
        .spawn(move || {
            let mut system = NativeEvidence {
                host,
                desktop,
                stop: stop.clone(),
            };
            let events = EventStore::new(store.clone());
            let server = match claude_watch_runtime::evidence_client::EvidenceServer::bind(&store) {
                Ok(server) => server,
                Err(error) => {
                    let _ = events.append("background-evidence", EventFields {
                        status: Some("error".into()), code: Some(error.code), ..Default::default()
                    }, native::now());
                    return;
                }
            };

            let mut changes = claude_watch_system::network_events::NetworkEventWatcher::default();
            changes.watch_file(store.paths.config());
            let mut sessions = std::collections::BTreeMap::new();
            for family in PolicyCatalog::families() {
                let path = store.paths.session_for(family.id);
                changes.watch_file(&path);
                sessions.insert(path.clone(), session_inputs(&store, &path));
            }
            let mut last_report = String::new();
            let mut last_report_at = Instant::now();
            let mut failures = 0;
            while !stop.load(Ordering::Acquire) {
                let _ = server.poll(&store, &mut system);
                let started = Instant::now();
                let outcome = background_evidence::refresh_supervised_sessions(&store, &mut system);
                let (status, code, count) = match &outcome {
                    Ok(v) => (
                        v["status"].as_str().unwrap_or("incomplete"),
                        v["families"].as_array().and_then(|rows| rows.iter()
                            .find_map(|row| row["code"].as_str())).map(evidence_error_code),
                        v["count"].as_u64().unwrap_or(0) as u32,
                    ),
                    Err(e) => (
                        "incomplete",
                        Some(evidence_error_code(&e.code)),
                        0,
                    ),
                };
                let signature = format!("{status}:{code:?}");
                if status != "idle"
                    && (count > 0
                        || signature != last_report
                        || last_report_at.elapsed() >= Duration::from_secs(1800))
                {
                    let _ = events.append(
                        "background-evidence",
                        EventFields {
                            operation: Some("session-evidence".into()),
                            status: Some(status.into()),
                            code: code.map(str::to_owned),
                            stage: outcome.as_ref().ok().and_then(|v| {
                                let probes = if status == "risk" {
                                    &v["risk_probes"]
                                } else {
                                    &v["failed_probes"]
                                };
                                let names = probes
                                    .as_array()?
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>();
                                (!names.is_empty()).then(|| names.join("-"))
                            }),
                            count: Some(count),
                            elapsed_seconds: Some(started.elapsed().as_secs_f64()),
                            ..Default::default()
                        },
                        native::now(),
                    );
                    last_report_at = Instant::now();
                }
                last_report = signature;
                let due = outcome.as_ref().ok().and_then(|report| report["next_review_at"].as_f64());
                let delay = next_review_delay(&mut failures, status == "incomplete", due, native::now());
                let deadline = delay.map(|delay| Instant::now() + delay);
                loop {
                    if stop.load(Ordering::Acquire) { return; }
                    let remaining = deadline.map(|end| end.saturating_duration_since(Instant::now()));
                    let (events, ready) = changes.wait_with_readers(remaining, &[cancellation.as_fd(), server.as_fd()]);
                    if ready == Some(0) { return; }
                    let mut invalidated = ready == Some(1)
                        && server.poll_with_update(&store, &mut system).ok().flatten() == Some(true);
                    for event in events {
                        use claude_watch_system::network_events::NetworkEventKind;
                        match event {
                            NetworkEventKind::Timeout => {}
                            NetworkEventKind::WatchedFileChanged(path) if sessions.contains_key(&path) => {
                                let next = session_inputs(&store, &path);
                                let previous = sessions.get_mut(&path).unwrap();
                                invalidated |= next != *previous;
                                *previous = next;
                            }
                            _ => invalidated = true,
                        }
                    }
                    if invalidated || deadline.is_some_and(|end| Instant::now() >= end) { break; }
                }
            }

        })
        .map_err(|_| CoreError::new("evidence_worker_failed", "保护证据更新线程无法启动"))?;
    Ok(EvidenceWorker { cancel, worker })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_probes_back_off_without_delaying_guard_or_renewing_evidence() {
        let mut failures = 0;
        for seconds in [10, 20, 30, 30, 30] {
            assert_eq!(
                next_review_delay(&mut failures, true, None, 100.0).unwrap(),
                Duration::from_secs(seconds)
            );
        }
        assert_eq!(next_review_delay(&mut failures, false, None, 100.0), None, "idle waits for a state change");
        assert_eq!(next_review_delay(&mut failures, false, Some(108.0), 100.0), Some(Duration::from_secs(8)));
        assert_eq!(next_review_delay(&mut failures, true, None, 100.0).unwrap(), Duration::from_secs(10));
    }
}
