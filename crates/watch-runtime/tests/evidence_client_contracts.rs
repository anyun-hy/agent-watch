#[path = "support/evidence_fixture.rs"]
mod fixture;
use claude_watch_core::evidence::*;
use claude_watch_runtime::{
    evidence_client::{request_daemon_evidence, EvidenceServer},
    storage::{Paths, StateStore},
};
use std::{
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
fn request() -> EvidenceRequest {
    EvidenceRequest {
        schema: 1,
        id: "ipc-contract".into(),
        action: EvidenceAction::Refresh,
        purpose: EvidencePurpose::Display,
        kinds: vec![ProbeKind::Dns, ProbeKind::WebRtc],
        expected_context: Some(fixture::SIGNATURE.into()),
        expected_ip: None,
        force: false,
    }
}
#[test]
fn actual_server_cold_start_receipts_operation_lock_and_unavailable() {
    let root = std::path::PathBuf::from("/tmp").join(format!(
        "cwe-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir(&root).unwrap();
    let paths = Paths::new(&root).unwrap();
    let store = StateStore::new(paths.clone());
    store.initialize().unwrap();
    assert_eq!(
        request_daemon_evidence(&paths, &request(), Duration::from_secs(2))
            .unwrap_err()
            .code,
        "daemon_unavailable"
    );
    let server = EvidenceServer::bind(&store).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let threaded = store.clone();
    let worker = thread::spawn(move || {
        let mut facts = fixture::EvidenceFacts::new(threaded.paths.home.join("control.json"));
        while !stopped.load(Ordering::Acquire) {
            server.poll(&threaded, &mut facts).unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        facts.calls
    });
    let lock = store.lock("operation", None).unwrap();
    let mut missing = request();
    missing.action = EvidenceAction::Inspect;
    let absent = request_daemon_evidence(&paths, &missing, Duration::from_secs(3)).unwrap();
    assert_eq!(absent["status"], "incomplete");
    assert_eq!(absent["items"]["dns"]["stored"], false);
    assert!(absent["items"]["dns"]["receipt"].is_null());
    let first = request_daemon_evidence(&paths, &request(), Duration::from_secs(3)).unwrap();
    assert_eq!(first["status"], "ok");
    assert_eq!(first["count"], 2);
    assert_eq!(first["items"]["dns"]["stored"], true);
    let reused = request_daemon_evidence(&paths, &request(), Duration::from_secs(3)).unwrap();
    assert_eq!(reused["count"], 0);
    assert_eq!(
        first["items"]["dns"]["probe"]["finishedAt"],
        reused["items"]["dns"]["probe"]["finishedAt"]
    );
    // Waiting does expire evidence, even on an unchanged VPN. Refresh must
    // collect both probes again through this same service and return them.
    fs::write(root.join("control.json"), br#"{"clock_offset_seconds":301}"#).unwrap();
    let expired = request_daemon_evidence(&paths, &missing, Duration::from_secs(3)).unwrap();
    assert_eq!(expired["status"], "incomplete");
    let refreshed = request_daemon_evidence(&paths, &request(), Duration::from_secs(3)).unwrap();
    assert_eq!(refreshed["context_id"], first["context_id"]);
    assert_eq!(refreshed["count"], 2);
    for kind in ["dns", "webrtc"] {
        assert_eq!(refreshed["items"][kind]["state"], "ok");
        assert!(refreshed["items"][kind]["probe"]["finishedAt"].as_f64().unwrap()
            > first["items"][kind]["probe"]["finishedAt"].as_f64().unwrap());
    }
    drop(lock);
    stop.store(true, Ordering::Release);
    assert_eq!(worker.join().unwrap(), 4);
    assert_eq!(
        request_daemon_evidence(&paths, &request(), Duration::from_secs(2))
            .unwrap_err()
            .code,
        "daemon_unavailable"
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn response_timeout_is_distinct_from_daemon_absence() {
    let root = std::path::PathBuf::from("/tmp").join(format!(
        "cwt-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir(&root).unwrap();
    let paths = Paths::new(&root).unwrap();
    let store = StateStore::new(paths.clone());
    store.initialize().unwrap();
    let _server = EvidenceServer::bind(&store).unwrap(); // real endpoint, deliberately unserviced
    assert_eq!(
        request_daemon_evidence(&paths, &request(), Duration::from_millis(30))
            .unwrap_err()
            .code,
        "evidence_timeout"
    );
    drop(_server);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn response_generation_and_endpoint_permissions_still_reject() {
    use std::{io::{BufRead, BufReader, Write}, os::unix::{net::UnixListener, fs::PermissionsExt}};
    let root = std::path::PathBuf::from("/tmp").join(format!("cwg-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
    fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    store.initialize().unwrap();
    let path = claude_watch_runtime::evidence_client::evidence_socket_path(&store.paths);
    store.private_dir(path.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(request_daemon_evidence(&store.paths, &request(), Duration::from_secs(1)).unwrap_err().code, "daemon_unavailable");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let worker = thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&mut peer).read_line(&mut line).unwrap();
        let response = serde_json::json!({"schema":1,"id":"previous-request","status":"ok",
            "result":{"schema":1,"id":"previous-request","items":{},"detail":"x".repeat(6000)}});
        writeln!(peer, "{response}").unwrap();
    });
    let result = request_daemon_evidence(&store.paths, &request(), Duration::from_secs(2));
    worker.join().unwrap();
    assert_eq!(result.unwrap_err().code, "evidence_response_invalid");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn request_frame_can_arrive_in_separate_socket_reads() {
    use std::{io::{Read, Write}, os::unix::net::UnixStream, sync::mpsc};
    let root = std::path::PathBuf::from("/tmp").join(format!("cwf-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
    fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    store.initialize().unwrap();
    let server = EvidenceServer::bind(&store).unwrap();
    let (sent, received) = mpsc::channel();
    let threaded = store.clone();
    let worker = thread::spawn(move || {
        received.recv().unwrap();
        let mut facts = fixture::EvidenceFacts::new(threaded.paths.home.join("control.json"));
        server.poll(&threaded, &mut facts)
    });
    let mut stream = UnixStream::connect(claude_watch_runtime::evidence_client::evidence_socket_path(&store.paths)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut input = request(); input.action = EvidenceAction::Inspect;
    let bytes = serde_json::to_vec(&input).unwrap();
    stream.write_all(&bytes[..8]).unwrap();
    sent.send(()).unwrap();
    thread::sleep(Duration::from_millis(100));
    let remaining = stream.write_all(&bytes[8..]).and_then(|_| stream.write_all(b"\n"));
    let handled = worker.join().unwrap();
    assert!(handled.is_ok(), "split request failed: {handled:?}");
    remaining.unwrap();
    let mut response = String::new(); stream.read_to_string(&mut response).unwrap();
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["id"], input.id);
    assert_eq!(response["status"], "ok");
    fs::remove_dir_all(root).unwrap();
}
