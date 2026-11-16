use claude_watch_core::error::Result;
use claude_watch_runtime::commands::{Output, ReadCommand, ReadRunner};
use claude_watch_runtime::macos::*;
use claude_watch_runtime::network_client::{
    NetworkClient, Request, Response, Transport, TransportError,
};
use claude_watch_runtime::repair::RepairSystem;
use claude_watch_runtime::storage::{Paths, StateStore};
use std::{collections::HashMap, fs, sync::Arc, time::Duration};
struct R;
impl ReadRunner for R {
    fn run(&self, c: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
        match c{ReadCommand::Observer(_)=>Ok(Output{status:0,stderr:vec![],stdout:br#"{"schema":1,"status":"ok","uid":1,"started_at":1,"finished_at":1,"network":{"service":"Wi-Fi","interface":"en0"}}"#.to_vec()}),_=>unreachable!()}
    }
}
struct T;
impl Transport for T {
    fn get(&self, _: &Request) -> std::result::Result<Response, TransportError> {
        Ok(Response {
            status: 200,
            headers: HashMap::new(),
            body: b"ip=1.1.1.1\nloc=JP\n".to_vec(),
        })
    }
}
struct M;
impl Mutator for M {
    fn apply(&mut self, _: &serde_json::Value) -> Result<()> {
        Ok(())
    }
    fn restore(&mut self, _: &serde_json::Value) -> Result<bool> {
        Ok(true)
    }
}
#[test]
fn readonly_adapter_never_delegates_mutation() {
    let root = std::env::temp_dir().join(format!("macos-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let mut m = Macos {
        request_evidence: true,
        runner: R,
        network: NetworkClient::new(Arc::new(T), None).unwrap(),
        storage: StateStore::new(Paths::new(&root).unwrap()),
        authority: Authority::ReadOnly,
        mutator: M,
        probes: Arc::new(|| panic!("offline must not probe")),
    };
    assert_eq!(
        RepairSystem::apply(&mut m, &serde_json::json!({"id":"timezone"}))
            .unwrap_err()
            .code,
        "write_not_authorized"
    );
    fs::remove_dir_all(root).unwrap();
}

#[path = "support/evidence_fixture.rs"]
mod evidence_fixture;

#[test]
fn preflight_adapter_uses_supplied_context_and_daemon_without_gui_or_operation_reentry() {
    use claude_watch_runtime::{
        audit_store::AuditSystem, evidence_client::EvidenceServer, receipt_store::ReceiptStore,
    };
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        thread,
    };
    let root = std::path::PathBuf::from("/tmp").join(format!(
        "cwm-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    storage.initialize().unwrap();
    let server = EvidenceServer::bind(&storage).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let owned = storage.clone();
    let worker = thread::spawn(move || {
        let mut facts = evidence_fixture::EvidenceFacts::new(owned.paths.home.join("control.json"));
        while !stopped.load(Ordering::Acquire) {
            server.poll(&owned, &mut facts).unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        facts.calls
    });
    // R's Observer response has no context. Refresh must use the verified audit
    // sample passed below instead of reading that unrelated environment again.
    let mut host = Macos {
        request_evidence: true,
        runner: R,
        network: NetworkClient::new(Arc::new(T), None).unwrap(),
        storage: storage.clone(),
        authority: Authority::ReadOnly,
        mutator: M,
        probes: Arc::new(|| panic!("no other probes")),
    };
    let lock = storage.lock("operation", None).unwrap();
    let local = serde_json::json!({"context_id":"fixture-context"});
    assert_eq!(
        AuditSystem::refresh_leaks(&mut host, &local, true).unwrap(),
        (None, None)
    );
    let receipts = ReceiptStore {
        storage: storage.clone(),
    };
    assert_eq!(
        receipts.dns_status(
            "fixture-context",
            true,
            claude_watch_runtime::native::now(),
            |v| v.to_string()
        )["state"],
        "ok"
    );
    assert_eq!(
        receipts.webrtc_status("fixture-context", claude_watch_runtime::native::now())["state"],
        "ok"
    );
    assert!(!storage.paths.session().exists());
    drop(lock);
    stop.store(true, Ordering::Release);
    assert_eq!(worker.join().unwrap(), 2);
    host.request_evidence = false;
    // The evidence worker's revalidation consumes the same receipts; it does
    // not issue a request to its own, now stopped socket.
    assert!(AuditSystem::refresh_leaks(&mut host, &local, true).is_ok());
    fs::remove_dir_all(root).unwrap();
}
