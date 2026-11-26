//! The single request contract used by UI, CLI and the daemon evidence worker.
use crate::{
    error::{CoreError, Result},
    receipts,
};
use serde::{Deserialize, Serialize};

// Native Rust DNS and ICE probes finish in sub-second time on healthy networks
// with bounded 5-second fallbacks; keep a tight ceiling for two probes + IPC.
pub const REQUEST_TIMEOUT_SECONDS: u64 = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeKind {
    Dns,
    WebRtc,
}
impl ProbeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::WebRtc => "webrtc",
        }
    }
    pub fn refresh_age(self) -> f64 {
        match self {
            Self::Dns => 10.0,
            Self::WebRtc => 60.0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceAction {
    Refresh,
    Inspect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidencePurpose {
    Display,
    Launch,
}
impl EvidencePurpose {
    pub fn max_age(self, kind: ProbeKind) -> f64 {
        match (self, kind) {
            (Self::Launch, ProbeKind::Dns) => receipts::DNS_LAUNCH_TTL,
            _ => receipts::DNS_DISPLAY_TTL,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequest {
    pub schema: u32,
    pub id: String,
    pub action: EvidenceAction,
    pub purpose: EvidencePurpose,
    pub kinds: Vec<ProbeKind>,
    pub expected_context: Option<String>,
    pub expected_ip: Option<String>,
    #[serde(default)]
    pub force: bool,
}
impl EvidenceRequest {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || v == b'-')
            || self.kinds.is_empty()
            || self.kinds.len() > 2
            || (self.kinds.len() == 2 && self.kinds[0] == self.kinds[1])
            || self
                .expected_context
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 2048)
            || (self.action == EvidenceAction::Inspect && self.force)
        {
            return Err(CoreError::new(
                "invalid_evidence_request",
                "检测请求格式无效",
            ));
        }
        receipts::expected_addresses(self.expected_ip.as_deref().unwrap_or(""))?;
        Ok(())
    }
}
