#[path = "support/evidence_fixture.rs"]
mod fixture;
use claude_watch_core::evidence::{EvidenceAction, EvidencePurpose, EvidenceRequest, ProbeKind};
use claude_watch_runtime::{background_evidence::serve_evidence_request, local_http::diagnostic_network_config,
    receipt_store::ReceiptStore, storage::{Paths, StateStore}};
use serde_json::{json, Value};

#[test]
fn unchanged_network_reuses_original_success_changes_reprobe_and_sampling_failure_is_separate() {
    let root = std::env::temp_dir().join(format!("cw-network-evidence-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap()); store.initialize().unwrap();
    let control = root.join("control.json");
    let write = |v: Value| std::fs::write(&control, serde_json::to_vec(&v).unwrap()).unwrap();
    write(json!({"network_bound":true}));
    let mut facts = fixture::EvidenceFacts::new(control.clone());
    let mut request = EvidenceRequest { schema:1, id:"network-reuse".into(), action:EvidenceAction::Refresh,
        purpose:EvidencePurpose::Display, kinds:vec![ProbeKind::Dns, ProbeKind::WebRtc],
        expected_context:Some(fixture::SIGNATURE.into()), expected_ip:None, force:false };
    let first = serve_evidence_request(&store, &mut facts, &request).unwrap();
    assert_eq!(first["status"], "ok"); assert_eq!(facts.calls, 2);
    write(json!({"network_bound":true,"clock_offset_seconds":86400}));
    for purpose in [EvidencePurpose::Display, EvidencePurpose::Launch] {
        request.purpose = purpose;
        let reused = serve_evidence_request(&store, &mut facts, &request).unwrap();
        assert_eq!(reused["status"], "ok"); assert_eq!(reused["count"], 0);
        for kind in ["dns", "webrtc"] {
            assert_eq!(reused["items"][kind]["receipt"], first["items"][kind]["receipt"]);
            assert_eq!(reused["items"][kind]["validity"], "network");
            assert!(reused["items"][kind]["valid_until"].is_null());
        }
    }
    assert_eq!(facts.calls, 2);
    let risk_time = claude_watch_runtime::native::now() + 86400.;
    let risk = ReceiptStore { storage:store.clone() }.session_risk("fixture-context", Some("1.1.1.1"), risk_time);
    assert_eq!(risk["state"], "safe"); assert_eq!(risk["validated_at"], risk_time);
    assert_eq!(risk["sources"]["dns"]["observed_at"], first["items"]["dns"]["probe"]["finishedAt"]);
    let audit = json!({"ready":true,"observed_at":risk_time,"expires_at":risk_time+30.,
        "context_id":"fixture-context","observation_id":"reuse-round","context_transition":{"state":"stable"},
        "egress_reference":{"ip":"1.1.1.1","country":"JP","checked_at":risk_time,"context":"fixture-context","source":"fixture"}});
    let egress = json!({"ip":"1.1.1.1","country":"JP","observed_at":risk_time,"source":"fixture"});
    let sessions = claude_watch_runtime::session_store::SessionStore::new(store.clone());
    sessions.begin_verified(&ReceiptStore { storage:store.clone() }, &audit, &egress, risk_time).unwrap();
    let mut stale = egress.clone(); stale["observed_at"] = json!(risk_time - 31.);
    assert!(sessions.begin_verified(&ReceiptStore { storage:store.clone() }, &audit, &stale, risk_time).is_err(),
        "diagnostic reuse cannot bypass the live egress deadline");
    write(json!({"network_bound":true,"clock_offset_seconds":86401,"timeout":true}));
    request.force = true;
    let failed_sample = serve_evidence_request(&store, &mut facts, &request).unwrap();
    for kind in ["dns", "webrtc"] {
        assert_eq!(failed_sample["items"][kind]["state"], "ok");
        assert_eq!(failed_sample["items"][kind]["receipt"], first["items"][kind]["receipt"]);
        assert!(failed_sample["items"][kind]["sampling_error"].is_string());
    }
    write(json!({"network_bound":true,"clock_offset_seconds":86402,"unavailable_after_calls":facts.calls + 1}));
    assert_eq!(serve_evidence_request(&store, &mut facts, &request).unwrap_err().code, "evidence_context_unconfirmed");
    request.force = false;
    write(json!({"network_bound":true,"clock_offset_seconds":86402}));
    let recovered = serve_evidence_request(&store, &mut facts, &request).unwrap();
    assert_eq!(recovered["count"], 0);
    assert_eq!(recovered["items"]["dns"]["receipt"], first["items"]["dns"]["receipt"]);
    write(json!({"network_bound":true,"sampling_unavailable":true}));
    assert_eq!(serve_evidence_request(&store, &mut facts, &request).unwrap_err().code, "evidence_egress_unavailable");
    for (index, change) in [json!({"egress_ip":"8.8.8.8"}),json!({"egress_ip":"8.8.8.8","context":"new-rules-same-ip"})].into_iter().enumerate() {
        let mut input = change; input["network_bound"] = json!(true); input["clock_offset_seconds"] = json!(86402 + index);
        write(input);
        let changed = serve_evidence_request(&store, &mut facts, &request).unwrap();
        assert_eq!(changed["count"], 2); assert_eq!(changed["status"], "ok");
    }
    // A real negative result replaces success; sampler errors do not hide it.
    request.force = true;
    write(json!({"network_bound":true,"egress_ip":"8.8.8.8","context":"new-rules-same-ip","clock_offset_seconds":86405,"leak":true}));
    let leaked = serve_evidence_request(&store, &mut facts, &request).unwrap();
    assert_eq!(leaked["items"]["webrtc"]["state"], "fail");
    let receipts = ReceiptStore { storage:store.clone() };
    let now = claude_watch_runtime::native::now() + 86406.;
    assert_eq!(receipts.dns_status_for_network("new-rules-same-ip", Some("8.8.8.8"), true, now, |t| t.to_string())["state"], "ok");
    assert_eq!(receipts.dns_status_for_network("new-rules-same-ip", None, true, now, |t| t.to_string())["network_state"], "unavailable");
    assert_eq!(receipts.dns_status_for_network("new-rules-same-ip", Some("9.9.9.9"), true, now, |t| t.to_string())["network_state"], "changed");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn runtime_network_binding_tracks_modes_rules_and_tun_without_sampling_metadata() {
    let config = json!({"mode":"global","tun":{"enable":true},"dns":{"enable":true},"mixed-port":7890});
    let proxies = json!({"proxies":{"GLOBAL":{"now":"node"}}});
    let rules = json!({"state":"available","entries":["MATCH,GLOBAL"]});
    let baseline = diagnostic_network_config(&config, &proxies, &rules);
    assert!(baseline.is_string());
    let mut unchanged = config.clone(); unchanged["log-level"] = json!("debug"); unchanged["observed_at"] = json!(12345);
    assert_eq!(diagnostic_network_config(&unchanged, &proxies, &rules), baseline);
    for (key, value) in [("mode",json!("rule")),("tun",json!({"enable":false})),("dns",json!({"enable":false}))] {
        let mut changed = config.clone(); changed[key] = value;
        assert_ne!(diagnostic_network_config(&changed, &proxies, &rules), baseline);
    }
    assert_ne!(diagnostic_network_config(&config, &proxies, &json!({"state":"available","entries":["MATCH,DIRECT"]})), baseline);
    assert!(diagnostic_network_config(&config, &proxies, &json!({"state":"unavailable"})).is_null());
}
