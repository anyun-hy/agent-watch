#[path = "../../watch-runtime/tests/support/evidence_fixture.rs"]
mod fixture;
use claude_watch_runtime::{
    evidence_client::EvidenceServer,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
struct Service {
    root: PathBuf,
    store: StateStore,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Service {
    fn new(root: PathBuf) -> Self {
        fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        store.initialize().unwrap();
        let server = EvidenceServer::bind(&store).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let owned = store.clone();
        let worker = thread::spawn(move || {
            let mut facts = fixture::EvidenceFacts::new(owned.paths.home.join("control.json"));
            while !stopping.load(Ordering::Acquire) {
                let _ = server.poll(&owned, &mut facts);
                thread::sleep(Duration::from_millis(2));
            }
        });
        Self {
            root,
            store,
            stop,
            worker: Some(worker),
        }
    }
    fn call(&self, action: &str, purpose: &str, force: bool) -> (i32, Value) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"));
        command.args(["evidence", action, "--home", self.root.to_str().unwrap()]);
        if action == "refresh" {
            command.arg("--apply");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = json!({"schema":1,"id":"cli-contract","action":action,"purpose":purpose,"kinds":["dns","webrtc"],"expected_context":fixture::SIGNATURE,"expected_ip":null,"force":force});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap(),
            serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
                panic!(
                    "{} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            }),
        )
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn root() -> PathBuf {
    let p = PathBuf::from("/tmp").join(format!(
        "cwp-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir(&p).unwrap();
    p
}
#[test]
fn cli_refresh_and_inspect_use_actual_daemon_handler_and_precise_rejections() {
    let root = root();
    let service = Service::new(root.join("home"));
    assert!(!service.store.paths.session().exists());
    let (exit, cold) = service.call("refresh", "launch", false);
    assert_eq!(exit, 0, "{cold}");
    assert_eq!(cold["status"], "ok");
    assert_eq!(cold["items"]["dns"]["state"], "ok");
    fs::write(service.root.join("control.json"), br#"{"change":true}"#).unwrap();
    let (exit, changed) = service.call("refresh", "launch", true);
    assert_eq!(exit, 4);
    assert_eq!(changed["code"], "evidence_context_changed");
    fs::write(service.root.join("control.json"), br#"{"timeout":true}"#).unwrap();
    let (exit, timeout) = service.call("refresh", "display", true);
    assert_eq!(exit, 0);
    assert_eq!(timeout["status"], "incomplete");
    assert_eq!(timeout["items"]["dns"]["code"], "timeout");
    assert_eq!(
        timeout["items"]["dns"]["display_probe"]["status"],
        "complete"
    );
    drop(service);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn cli_inspection_of_same_45_second_receipt_separates_display_from_launch() {
    let root = root();
    let service = Service::new(root.join("home"));
    fs::write(service.root.join("control.json"), br#"{"age_seconds":45}"#).unwrap();
    let (exit, display) = service.call("refresh", "display", true);
    assert_eq!(exit, 0);
    assert_eq!(display["items"]["dns"]["state"], "ok");
    let (exit, launch) = service.call("inspect", "launch", false);
    assert_eq!(exit, 0);
    assert_eq!(launch["items"]["dns"]["state"], "unknown");
    assert_eq!(launch["items"]["dns"]["code"], "evidence_expired");
    assert_eq!(
        display["items"]["dns"]["probe"]["finishedAt"],
        launch["items"]["dns"]["probe"]["finishedAt"]
    );
    drop(service);
    fs::remove_dir_all(root).unwrap();
}
#[test]
#[ignore = "requires separately compiled Swift test binary; never builds an application"]
fn swift_production_receiver_roundtrip() {
    let binary =
        std::env::var("CW_PHASE1_SWIFT_TEST").expect("explicit compiled test binary required");
    let root = root();
    let primary = Service::new(root.join("home"));
    let ttl = Service::new(root.join("ttl-home"));
    fs::write(root.join("isolated-evidence-test"), b"phase1\n").unwrap();
    let real_home = std::env::var_os("HOME").expect("user home");
    let alias = root.join("home-alias");
    std::os::unix::fs::symlink(&real_home, &alias).unwrap();
    for forbidden in [PathBuf::from(real_home), alias] {
        let rejected = Command::new(&binary)
            .args([
                env!("CARGO_BIN_EXE_claude-watch-engine"),
                forbidden.to_str().unwrap(),
                "--isolated-home",
            ])
            .output()
            .unwrap();
        assert_eq!(rejected.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("SECURITY VIOLATION"));
    }
    println!("Real HOME and its symlink alias: both rejected before invoking the engine");
    let result = Command::new(binary)
        .args([
            env!("CARGO_BIN_EXE_claude-watch-engine"),
            root.to_str().unwrap(),
            "--isolated-home",
        ])
        .output()
        .unwrap();
    println!("{}", String::from_utf8_lossy(&result.stdout));
    eprintln!("{}", String::from_utf8_lossy(&result.stderr));
    assert!(result.status.success());
    drop(ttl);
    drop(primary);
    fs::remove_dir_all(root).unwrap();
}
