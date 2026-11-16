//! Injected network/clock facts only; all IPC, collection coordination,
//! validation, storage and projection remain production implementations.
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    session::Desktop,
};
use claude_watch_runtime::background_evidence::{EvidenceSystem, ProbeKind};
use serde_json::{json, Value};
use std::path::PathBuf;
#[allow(dead_code)] // Some consumers bind the full context ID instead.
pub const SIGNATURE: &str = "127.0.0.1:7890|rule|fixture|fixture";
pub struct EvidenceFacts {
    pub control: PathBuf,
    pub calls: usize,
    collected_change: bool,
}
impl EvidenceFacts {
    pub fn new(control: PathBuf) -> Self {
        Self {
            control,
            calls: 0,
            collected_change: false,
        }
    }
    fn input(&self) -> Value {
        std::fs::read(&self.control)
            .ok()
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or(json!({}))
    }
}
impl EvidenceSystem for EvidenceFacts {
    fn now(&self) -> f64 {
        claude_watch_runtime::native::now() + self.input()["clock_offset_seconds"].as_f64().unwrap_or(0.0)
    }
    fn local(&mut self, _: &Config) -> Result<Value> {
        let input = self.input();
        if input["sampling_unavailable"] == true { return Err(CoreError::new("evidence_egress_unavailable", "fixture sampling gap")); }
        let changed = input["change"] == true && self.collected_change;
        Ok(
            json!({"context":if changed {"changed-context"}else{input["context"].as_str().unwrap_or("fixture-context")},"context_id":if changed {"changed-context"}else{input["context"].as_str().unwrap_or("fixture-context")},
            "evidence_network_bound":input["network_bound"] == true,
            "evidence_egress_ip":input["egress_ip"].as_str().unwrap_or("1.1.1.1"),
            "proxy":"ok","tun":"ok","observation_unavailable":if input["unavailable_after_calls"].as_u64().is_some_and(|n| self.calls as u64 >= n) {json!(["sampler_gap"])} else {json!([])},
            "tag":{"entry":{"endpoint":"127.0.0.1:7890"},"api":{"mode":"rule","selected_node":"fixture","global_node":"fixture"}}}),
        )
    }
    fn desktop_matches(&mut self, _: &Desktop) -> Result<bool> {
        Ok(false)
    }
    fn desktop_unique_stamp(&mut self, _: &Desktop) -> Result<Option<String>> {
        Ok(None)
    }
    fn collect(&mut self, kind: ProbeKind) -> Result<Value> {
        self.calls += 1;
        let input = self.input();
        self.collected_change = input["change"] == true;
        if let Some(delay) = input["delay_ms"].as_u64() {
            std::thread::sleep(std::time::Duration::from_millis(delay.min(200)));
        }
        if input["timeout"] == true {
            return Err(CoreError::new("evidence_probe_timeout", "本轮采集超时"));
        }
        let at = self.now() - input["age_seconds"].as_f64().unwrap_or(0.0);
        let mut value = json!({"kind":kind.label(),"status":"complete","startedAt":at-1.,"finishedAt":at,
            "scope":"isolated network fixture","contextChanged":false,"errors":[],"details":[],
            "observations":[{"address":"1.1.1.1","kind":"http","source":"fixture","country":"JP"}]});
        value["observations"]
            .as_array_mut()
            .unwrap()
            .push(match kind {
                ProbeKind::Dns => {
                    json!({"address":"8.8.8.8","kind":"resolver","source":"fixture","country":"JP"})
                }
                ProbeKind::WebRtc => {
                    json!({"address":if input["leak"] == true {"8.8.8.8"} else {"1.1.1.1"},"kind":"srflx","source":"fixture","country":"JP"})
                }
            });
        if kind == ProbeKind::Dns {
            value["externalJSON"]=json!(serde_json::to_string(&json!({
            "session":"a".repeat(40),"dns_servers":{"8.8.8.8":5},"http":{"address":"1.1.1.1","country":"JP"},
            "geoip":[{"ip":"8.8.8.8","country_code":"JP"}]})).unwrap());
        }
        Ok(value)
    }
}
