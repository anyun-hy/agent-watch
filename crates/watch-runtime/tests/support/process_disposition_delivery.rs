#[path = "published_events.rs"]
mod published_events;

#[path = "hardened_helper.rs"]
mod hardened_helper;

use super::*;
use crate::{
    channel_enforcer::LocalTunnelEnforcer,
    managed_cli_supervisor_fixture as fixture,
    managed_entry::DesktopManagedEntrySpec,
    receipt_store::ReceiptStore,
    sandbox_launch::build_helper_verifier_for_path,
    storage::Paths,
};
use claude_watch_core::{
    channel::{ChannelPermitState, PolicyVersion},
    config::Config,
    controlled_launch::{ControlledLaunchRequest, ProxyAdaptationKind},
    processes::LaunchTarget,
};
use claude_watch_system::{inspect_process_identity, sha256_file_hex};
use serde_json::{json, Value};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

#[path = "managed_entry_live_members.rs"]
mod live_members;

const BOOT: &str = "owned-entry-and-disposition-executor";

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    root: PathBuf,
    storage: StateStore,
    config: Config,
    policy: PolicyVersion,
    helper: PathBuf,
    registry: Arc<SandboxLaunchRegistry>,
    enforcer: Arc<LocalTunnelEnforcer>,
    gateway: SocketAddr,
    _upstream: TcpListener,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    listeners: Vec<claude_watch_system::ListenerWorker>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for listener in self.listeners.drain(..) { let _ = listener.join(); }
        for worker in self.workers.drain(..) { let _ = worker.join(); }
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    fn start() -> Self { Self::with_actions("force", None) }

    fn with_actions(ip: &str, dns: Option<&str>) -> Self {
        Self::with_family_actions("claude", ip, dns)
    }

    fn with_family_actions(family: &str, ip: &str, dns: Option<&str>) -> Self {
        let root = PathBuf::from("/private/tmp").join(format!("cw-x-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]));
        fs::create_dir(&root).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = fixture::config(&storage, &upstream.local_addr().unwrap().to_string());
        let prefix = if family == "claude" { "claude" } else { "gpt" };
        config.policy_actions.insert(format!("{prefix}_close_ip"), ip.into());
        if let Some(dns)=dns { config.policy_actions.insert(format!("{prefix}_close_dns"),dns.into()); }
        let confirmation = (family == "openai" && ip == "force").then_some("gpt_close_ip");
        let config = (ConfigStore { storage: storage.clone() })
            .save_with_force_confirmation(config.value().unwrap(), confirmation).unwrap();
        let policy = ChannelSupervisor::compute_policy_version(&config).unwrap();
        let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/watch-sandbox-launcher").canonicalize().unwrap();
        let helper = hardened_helper::copy_signed(&helper, &root.join("watch-sandbox-launcher"));
        let verifier = build_helper_verifier_for_path(&helper).unwrap();
        let registry = Arc::new(SandboxLaunchRegistry::new(BOOT, policy.clone(), verifier, Some(storage.clone())));
        let enforcer = Arc::new(LocalTunnelEnforcer::new(BOOT));
        let stop = Arc::new(AtomicBool::new(false));
        let now = native::now();
        // Isolated component readiness. No production I03 or launchd override.
        enforcer.configure_seatbelt_backend(true, now).unwrap();
        enforcer.set_clock(native::now).unwrap();
        let registry_for_gateway = registry.clone();
        enforcer.set_accepted_connection_attributor(move |context|
            registry_for_gateway.attribute_accepted_connection(context, native::now())).unwrap();
        let (gateway, tunnel) = enforcer.start_local_proxy_listener("127.0.0.1:0", stop.clone(), now).unwrap();
        let registrations = registry.start_registration_listener(&root.join("reg.sock"), stop.clone()).unwrap();
        Self { root, storage, config, policy, helper, registry, enforcer, gateway, _upstream: upstream, stop, workers: Vec::new(), listeners: vec![tunnel, registrations] }
    }

    fn launch(&self, target: LaunchTarget, image: &Path, args: Vec<String>) -> Owned {
        let executable = image.canonicalize().unwrap().to_string_lossy().into_owned();
        let fingerprint = sha256_file_hex(image).unwrap();
        self.registry.approve_target_executable(&executable, &fingerprint);
        self.registry.refresh_executable_verifications();
        let request = ControlledLaunchRequest {
            entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).into(),
            target,
            target_executable: executable.clone(),
            target_fingerprint: fingerprint,
            args,
            cwd: Some(self.root.to_string_lossy().into_owned()),
            proxy_adaptation: ProxyAdaptationKind::EnvOnly,
            gateway_endpoint: self.gateway.to_string(),
            policy_version: self.policy.clone(),
            vpn_epoch: Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)),
            launch_nonce: uuid::Uuid::new_v4().to_string(),
            executor_boot_id: BOOT.into(),
            script_entry: None, script_fingerprint: None, interpreter: None, interpreter_fingerprint: None, script_source: None,
            desktop_sandbox_compat_no_sandbox: false, extra_deny_read_write_paths: vec![],
        };
        let mut owned = Owned(Command::new(&self.helper).arg("--launch-json").arg(serde_json::to_string(&request).unwrap())
            .arg("--registration-socket").arg(self.root.join("reg.sock")).stdin(Stdio::null()).spawn().unwrap());
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            self.registry.reconcile_process_trees(native::now());
            if self.registry.instances().iter().any(|i| i.pid == owned.0.id()
                && i.has_verified_main_protection(BOOT, &self.policy)) { break; }
            assert!(owned.0.try_wait().unwrap().is_none(), "owned helper exited before verification");
            assert!(Instant::now() < until, "owned helper not verified: {:?}", self.registry.instances());
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(inspect_process_identity(owned.0.id()).unwrap().executable_path, executable);
        owned
    }

    fn compile(&self, source: &str, executable: &Path) {
        let source_path = self.root.join(format!("{}.c", uuid::Uuid::new_v4()));
        fs::write(&source_path, source).unwrap();
        let output = Command::new("xcrun").args(["clang", "-O0", "-Wall", "-Werror"])
            .arg(&source_path).arg("-o").arg(executable).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }

    fn sleeper(&self) -> PathBuf {
        let image = self.root.join("owned-sleeper");
        self.compile("#include <unistd.h>\nint main(void){for(;;)pause();}\n", &image);
        image
    }

    fn observation(&self, supervisor: &mut ChannelSupervisor, seq: u64, now: f64) {
        let mut observation = fixture::sample_vpn_observation(now, 1);
        observation.sample_seq = seq;
        observation.upstream_endpoint = Some(self.config.proxy_url.clone());
        supervisor.handle_event(SupervisionEvent::VpnObservationUpdated { observation, observed_at: now }).unwrap();
    }

    fn environment(&self, supervisor: &mut ChannelSupervisor, family: &str, ip: &str, now: f64) {
        let mut egress = fixture::controlled_egress(&self.config, now, ip, "US",
            Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)));
        egress["family"] = json!(family);
        supervisor.handle_event(SupervisionEvent::EnvironmentUpdated {
            egress, local_guard: json!({"proxy":"ok","tun":"disabled","context_id":"ctx-vpn"}), observed_at: now,
        }).unwrap();
    }

    fn inventory(&self, supervisor: &mut ChannelSupervisor, family: &str, now: f64) {
        let tokens = self.registry.verified_family_tokens(family, now);
        supervisor.handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: family.into(), desktops: vec![], processes: tokens, observed_at: now,
        }).unwrap();
    }

    fn bind(&self, supervisor: &mut ChannelSupervisor, family: &'static str, now: f64) {
        let mut audit = fixture::fixture_audit_val(&self.storage, now, "1.1.1.1", "US");
        audit["launch_target"] = json!(if family == "claude" { "claude-cli" } else { "codex-cli" });
        audit["authorization_scope"] = json!("observation");
        let current = fixture::controlled_egress(&self.config, now, "1.1.1.1", "US",
            Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)));
        let tokens = self.registry.verified_family_tokens(family, now);
        SessionStore::for_family(self.storage.clone(), family).begin_channel_verified(
            &ReceiptStore { storage: self.storage.clone() }, &audit, &current, &tokens, now,
        ).unwrap();
        self.inventory(supervisor, family, now);
        let state = &supervisor.snapshot(now).families[family];
        assert_eq!(state.permit_state, ChannelPermitState::Permitted, "{state:?}");
    }

    fn supervisor(&self, families: &[&'static str]) -> ChannelSupervisor {
        let mut supervisor = ChannelSupervisor::new(self.storage.clone(), Some(self.enforcer.clone()), None).unwrap();
        let now = native::now();
        fixture::seed_probe_receipts(&self.storage, now, "US");
        self.observation(&mut supervisor, 1, now);
        self.environment(&mut supervisor, "*", "1.1.1.1", now);
        for family in families { self.bind(&mut supervisor, family, now); }
        supervisor
    }
}

fn export(name: &str, value: &Value) {
    println!("{value}");
    if let Some(directory) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::write(Path::new(&directory).join(name), serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
}

fn wait_until_exited(identity: &ProcessKernelIdentity) {
    let until = Instant::now() + Duration::from_millis(500);
    while !claude_watch_system::bound_lifetime_exited(identity) {
        assert!(Instant::now() < until, "signal must really end the owned fixture");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn phase2_live_gateway_distinguishes_vpn_gate_and_warn_close_force() {
    use std::{io::{Read, Write}, net::TcpStream, os::unix::process::ExitStatusExt};
    use crate::channel_enforcer::ChannelEnforcer;
    use claude_watch_core::channel::ChannelEnforcementState;

    fn header(stream: &mut TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).expect("complete HTTP header, not EOF or timeout");
            bytes.push(byte[0]);
            assert!(bytes.len() < 4096);
        }
        bytes
    }
    fn accept(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "fixture connection was not established");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
    }
    fn ordinary_pair(listener: &TcpListener) -> (TcpStream, TcpStream) {
        (TcpStream::connect(listener.local_addr().unwrap()).unwrap(), accept(listener))
    }
    fn exchange(pair: &mut (TcpStream, TcpStream)) {
        pair.0.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        pair.0.write_all(b"o").unwrap();
        let mut byte = [0];
        pair.1.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"o");
        pair.1.write_all(b"k").unwrap();
        pair.0.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"k");
    }

    for family in ["claude", "openai"] {
        for (vpn_mismatch, action) in [(true, "warn"), (true, "force"), (false, "warn"), (false, "close"), (false, "force")] {
            let mut fixture = Fixture::with_family_actions(family, action, None);
            fixture._upstream.set_nonblocking(true).unwrap();
            let image = fixture.root.join("owned-network-client");
            // The actual Seatbelt child owns the gateway socket. Marker files
            // report facts; all decisions and effects run in production Rust.
            fixture.compile(r#"
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static void mark(const char *name) {
    FILE *out = fopen(name, "w");
    if (!out || fclose(out)) exit(91);
}
static int tunnel(int port, int expected) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval timeout = { .tv_sec = 3 };
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr))) exit(92);
    const char *request = "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n";
    if (write(fd, request, strlen(request)) != (ssize_t)strlen(request)) exit(93);
    char header[1024] = {0}; size_t n = 0;
    while (n < sizeof(header)-1 && !strstr(header, "\r\n\r\n")) {
        if (read(fd, &header[n], 1) != 1) exit(94);
        n++;
    }
    int status = 0;
    if (sscanf(header, "HTTP/1.1 %d", &status) != 1 || status != expected) exit(95);
    return fd;
}
int main(int argc, char **argv) {
    if (argc != 2) return 90;
    signal(SIGPIPE, SIG_IGN);
    for (int i = 0; access("permit-ready", F_OK); i++) {
        if (i == 500) return 96;
        usleep(10000);
    }
    int fd = tunnel(atoi(argv[1]), 200);
    char byte; ssize_t n;
    while ((n = read(fd, &byte, 1)) == 1) {
        if (write(fd, &byte, 1) != 1) return 97;
    }
    if (n != 0) return 98;
    mark("client-eof"); close(fd);
    close(tunnel(atoi(argv[1]), 502));
    mark("reconnect-rejected");
    for (;;) pause();
}
"#, &image);
            let target_kind = if family == "claude" { LaunchTarget::ClaudeCli } else { LaunchTarget::CodexCli };
            let mut target = fixture.launch(target_kind, &image, vec![fixture.gateway.port().to_string()]);
            let identity = inspect_process_identity(target.0.id()).unwrap();
            let mut supervisor = fixture.supervisor(&[family]);
            let (events, receipts) = mpsc::channel();
            let (dispatcher, worker) = ProcessDispositionDispatcher::start(
                fixture.storage.clone(), fixture.stop.clone(), events).unwrap();
            fixture.workers.push(worker);
            supervisor.install_process_disposition_dispatcher(dispatcher);
            supervisor.set_process_disposition_registry(fixture.registry.clone());
            fs::write(fixture.root.join("permit-ready"), b"ready").unwrap();
            let mut upstream = accept(&fixture._upstream);
            assert!(header(&mut upstream).starts_with(b"CONNECT fixture.invalid:443 "));
            upstream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
            let mut byte = [0];
            upstream.write_all(b"a").unwrap(); upstream.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"a");
            let mut ordinary = ordinary_pair(&fixture._upstream);
            exchange(&mut ordinary);

            let now = native::now();
            if vpn_mismatch {
                let mut observation = fixture::sample_vpn_observation(now, 2);
                observation.upstream_endpoint = Some(fixture.config.proxy_url.clone());
                observation.selected_node = claude_watch_core::vpn::ObservedField::Known("unexpected".into());
                supervisor.handle_event(SupervisionEvent::VpnObservationUpdated { observation, observed_at: now }).unwrap();
            } else {
                fixture.environment(&mut supervisor, family, "9.9.9.9", now);
            }
            let cutoff = vpn_mismatch || action != "warn";
            assert_eq!(supervisor.snapshot(now).families[family].permit_state,
                if cutoff { ChannelPermitState::Revoked } else { ChannelPermitState::Permitted });
            if cutoff {
                assert_eq!(upstream.read(&mut byte).expect("upstream must receive EOF, not timeout/reset"), 0);
                if !vpn_mismatch && matches!(action, "close" | "force") {
                    let event = receipts.recv_timeout(Duration::from_secs(3)).expect("actual exit result");
                    let SupervisionEvent::ProcessReceiptArrived { receipt, .. } = &event else { panic!("{event:?}"); };
                    assert!(receipt.target_results.iter().any(|r| r.pid == identity.pid && r.terminated && r.signal_sent_at.is_some()));
                    supervisor.handle_event(event).unwrap();
                    wait_until_exited(&identity);
                    assert_eq!(target.0.wait().unwrap().signal(), Some(if action == "force" { 9 } else { 15 }));
                } else {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !fixture.root.join("reconnect-rejected").exists() {
                        assert!(target.0.try_wait().unwrap().is_none(), "client must stay alive after cutoff");
                        assert!(Instant::now() < deadline, "client EOF and actual reconnect rejection missing");
                        thread::sleep(Duration::from_millis(5));
                    }
                    assert!(fixture.root.join("client-eof").exists());
                }
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let receipt = fixture.enforcer.receipt_for(family, native::now()).unwrap().unwrap();
                    if receipt.enforcement_state == ChannelEnforcementState::Blocked && receipt.active_flows_count == 0 { break; }
                    assert!(Instant::now() < deadline, "relay must publish actual completion");
                    thread::sleep(Duration::from_millis(5));
                }
            } else {
                upstream.write_all(b"b").unwrap(); upstream.read_exact(&mut byte).unwrap();
                assert_eq!(&byte, b"b", "warn keeps the established flow working");
                assert!(published_events::after(&fixture.storage, 0).iter().any(|event|
                    event.family_state.family == family && event.family_state.reason_code == "egress_ip_changed"));
            }
            if vpn_mismatch || action == "warn" {
                assert!(receipts.try_recv().is_err(), "network-only policy cannot dispatch process force");
                assert_eq!(inspect_process_identity(identity.pid), Some(identity));
            }
            exchange(&mut ordinary);
            exchange(&mut ordinary_pair(&fixture._upstream));
            export(&format!("phase2-{family}-{vpn_mismatch}-{action}.json"), &json!({
                "family":family, "vpn_mismatch":vpn_mismatch, "action":action,
                "physical_cutoff":cutoff, "process_forced":!vpn_mismatch && action=="force",
                "ordinary_existing_and_new_connections":"passed", "result":"passed"
            }));
        }
    }
}

#[test]
fn v1_worker_delivery_preserves_partial_result_in_both_policy_orders() {
    let mut cases = Vec::new();
    for policy_first in [true, false] {
        let mut fixture = Fixture::start();
        let image = fixture.sleeper();
        let a = fixture.launch(LaunchTarget::ClaudeCli, &image, vec![]);
        let b = fixture.launch(LaunchTarget::ClaudeCli, &image, vec![]);
        let other = fixture.launch(LaunchTarget::CodexCli, &image, vec![]);
        let ordinary = Owned(Command::new(&image).spawn().unwrap());
        let mut identities = [inspect_process_identity(a.0.id()).unwrap(), inspect_process_identity(b.0.id()).unwrap()];
        identities.sort_by_key(|p| p.pid);
        let [first, second] = identities;
        let other_identity = inspect_process_identity(other.0.id()).unwrap();
        let ordinary_identity = inspect_process_identity(ordinary.0.id()).unwrap();
        // Match production's receipt receiver clock before the first command.
        // This fixture executes real work; event time is not receipt arrival time.
        let mut supervisor = ChannelSupervisor::new(fixture.storage.clone(), Some(fixture.enforcer.clone()), None).unwrap();
        supervisor.set_inline_receipt_clock(native::now);
        let now = native::now();
        fixture::seed_probe_receipts(&fixture.storage, now, "US");
        fixture.observation(&mut supervisor, 1, now);
        fixture.environment(&mut supervisor, "*", "1.1.1.1", now);
        for family in ["claude", "openai"] { fixture.bind(&mut supervisor, family, now); }
        let before = supervisor.snapshot(native::now());
        assert_eq!(before.families["openai"].policy_sync_state, claude_watch_core::channel::PolicySyncState::Applied);
        let (events, receipts) = mpsc::channel();
        let (entered, waiting) = mpsc::sync_channel(1);
        let (resume, barrier) = mpsc::sync_channel(1);
        let barrier = Mutex::new(barrier);
        let (dispatcher, worker) = ProcessDispositionDispatcher::start_with(
            fixture.storage.clone(), fixture.stop.clone(), events, move |storage, job, stop| {
                execute_batch(storage, job, stop, |index| {
                    if index == 1 {
                        entered.send(Instant::now()).unwrap();
                        barrier.lock().unwrap().recv_timeout(Duration::from_millis(1500)).unwrap();
                    }
                }, |token, actual, now| job.registry.current_disposition_member(&job.intent, token, actual, now),
                claude_watch_system::bound_lifetime_exited)
            },
        ).unwrap();
        fixture.workers.push(worker);
        supervisor.install_process_disposition_dispatcher(dispatcher);
        supervisor.set_process_disposition_registry(fixture.registry.clone());
        // The service intentionally keeps a stable command in the first half
        // of a lease. Reach its renewal window before pausing the force worker.
        let renewal_at = (before.captured_at + before.families["openai"].valid_until.unwrap()) / 2.0;
        thread::sleep(Duration::from_secs_f64((renewal_at - native::now()).max(0.0)));
        fixture.environment(&mut supervisor, "claude", "9.9.9.9", native::now());
        let requested = supervisor.snapshot(native::now());
        assert_eq!(requested.families["claude"].process_execution_state.as_deref(), Some("executing"), "{:?}", requested.families["claude"]);
        let waiting_since = waiting.recv_timeout(Duration::from_secs(2)).expect("actual worker after signal #1");
        wait_until_exited(&first);
        assert_eq!(inspect_process_identity(second.pid), Some(second.clone()));
        assert!(receipts.try_recv().is_err(), "worker is paused before target 2");

        // Advance an actual OpenAI inventory event and apply a fresh same-epoch
        // lease before the original force batch can finish.
        let renewal_start = Instant::now();
        fixture.inventory(&mut supervisor, "openai", native::now());
        fixture.observation(&mut supervisor, 2, native::now());
        let renewed = supervisor.snapshot(native::now());
        let renewal_finished = Instant::now();
        assert!(receipts.try_recv().is_err());
        let old = &before.families["openai"];
        let new = &renewed.families["openai"];
        assert_eq!(new.permit_state, ChannelPermitState::Permitted);
        assert_eq!(new.policy_sync_state, claude_watch_core::channel::PolicySyncState::Applied);
        assert_eq!(old.session_id, new.session_id);
        assert!(new.command_seq > old.command_seq && new.valid_until.unwrap() > old.valid_until.unwrap());
        let disk = fixture.storage.read_json(&fixture.storage.paths.watch().join("state/channel-supervision.json"), Value::Null).unwrap();
        assert_eq!(disk["enforcement_receipts"]["openai"]["command_seq"], new.command_seq);
        assert!(published_events::after(&fixture.storage, before.snapshot_seq).iter().any(|e| e.family_state.family == "openai" && e.family_state.command_seq == new.command_seq));

        let mut warn = fixture.config.clone();
        warn.policy_actions.insert("claude_close_ip".into(), "warn".into());
        let warn = (ConfigStore { storage: fixture.storage.clone() }).save(warn.value().unwrap()).unwrap();
        let policy_update = |supervisor: &mut ChannelSupervisor| {
            supervisor.handle_event(SupervisionEvent::PolicyUpdated { config: warn.clone(), observed_at: native::now() }).unwrap();
        };
        if policy_first { policy_update(&mut supervisor); }
        let paused_before_resume = waiting_since.elapsed();
        resume.send(()).unwrap();
        let event = receipts.recv_timeout(Duration::from_secs(3)).unwrap();
        let SupervisionEvent::ProcessReceiptArrived { receipt, received_at } = &event else { panic!("{event:?}"); };
        assert_eq!(receipt.process_execution_state, "partially_terminated", "{receipt:?}");
        assert_eq!(receipt.target_results[0].pid, first.pid);
        assert!(receipt.target_results[0].terminated && receipt.target_results[0].signal_sent_at.is_some());
        assert_eq!(receipt.target_results[1].pid, second.pid);
        assert_eq!(receipt.target_results[1].process_state, "cancelled");
        assert!(receipt.target_results[1].signal_sent_at.is_none());

        let mut forged = receipt.clone();
        forged.authority.as_mut().unwrap().command_seq += 1;
        supervisor.ingest_process_receipt(forged, *received_at).unwrap();
        assert!(supervisor.snapshot(native::now()).families["claude"].previous_process_disposition_receipts.is_empty());
        let policy_before_receipt = supervisor.authoritative_state_for_family("claude").unwrap();
        let observed = supervisor.handle_event(event.clone()).unwrap();
        assert_eq!(supervisor.authoritative_state_for_family("claude").unwrap(), policy_before_receipt);
        if !policy_first {
            assert_eq!(observed.families["claude"].process_disposition_receipt.as_ref(), Some(receipt));
            policy_update(&mut supervisor);
        }
        let snapshot = supervisor.snapshot(native::now());
        let final_state = &snapshot.families["claude"];
        assert_eq!(final_state.permit_state, ChannelPermitState::Revoked);
        assert!(final_state.process_disposition_action.is_none() && final_state.process_disposition_receipt.is_none());
        assert_eq!(final_state.previous_process_disposition_receipts.as_slice(), std::slice::from_ref(receipt));
        let history = published_events::after(&fixture.storage, renewed.snapshot_seq);
        assert!(history.iter().any(|e| e.family_state.previous_process_disposition_receipts.as_slice() == std::slice::from_ref(receipt)));
        let replay = supervisor.handle_event(event.clone()).unwrap();
        assert_eq!(replay.snapshot_seq, snapshot.snapshot_seq, "replay must not publish a second result");
        assert_eq!(inspect_process_identity(second.pid), Some(second.clone()));
        assert_eq!(inspect_process_identity(other_identity.pid), Some(other_identity));
        assert_eq!(inspect_process_identity(ordinary_identity.pid), Some(ordinary_identity));
        cases.push(json!({
            "policy_first":policy_first, "snapshot":snapshot, "events":history, "now":native::now(),
            "first":first.pid,"second":second.pid,"worker_blocked_before_second_ms":paused_before_resume.as_secs_f64()*1000.0,
            "renewal_ms":(renewal_finished - renewal_start).as_secs_f64()*1000.0,
            "openai_old_until":old.valid_until,"openai_new_until":new.valid_until,
            "openai_old_seq":old.command_seq,"openai_new_seq":new.command_seq,
        }));
    }
    export("process-disposition-delivery.json", &json!(cases));
}

#[test]
fn v1_worker_deadline_retains_unconfirmed_exit_when_observation_is_withheld() {
    let mut fixture = Fixture::start();
    let image = fixture.sleeper();
    let child = fixture.launch(LaunchTarget::ClaudeCli, &image, vec![]);
    let actual = inspect_process_identity(child.0.id()).unwrap();
    let mut supervisor = fixture.supervisor(&["claude"]);
    let (events, receipts) = mpsc::channel();
    let (dispatcher, worker) = ProcessDispositionDispatcher::start_with(
        fixture.storage.clone(), fixture.stop.clone(), events, |storage, job, stop| {
            // Model a missing exit observation with a real signal and the real
            // wait limit. No unkillable process or fabricated kernel exit.
            execute_batch(storage, job, stop, |_| {},
                |token, actual, now| job.registry.current_disposition_member(&job.intent, token, actual, now),
                |_| false)
        },
    ).unwrap();
    fixture.workers.push(worker);
    supervisor.install_process_disposition_dispatcher(dispatcher);
    supervisor.set_process_disposition_registry(fixture.registry.clone());
    let started = Instant::now();
    fixture.environment(&mut supervisor, "claude", "9.9.9.9", native::now());
    let requested = supervisor.snapshot(native::now());
    assert_eq!(requested.families["claude"].process_execution_state.as_deref(), Some("executing"), "{:?}", requested.families["claude"]);
    let event = receipts.recv_timeout(Duration::from_secs(4)).unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= WAIT_FOR_EXIT && elapsed < Duration::from_secs(4), "{elapsed:?}");
    let snapshot = supervisor.handle_event(event).unwrap();
    let state = &snapshot.families["claude"];
    let receipt = state.process_disposition_receipt.as_ref().unwrap();
    assert_eq!(receipt.process_execution_state, "unknown");
    assert_eq!(receipt.target_results[0].process_state, "exit_unconfirmed");
    assert!(!receipt.target_results[0].terminated && receipt.target_results[0].signal_sent_at.is_some());
    wait_until_exited(&actual);
    export("process-disposition-deadline.json", &json!({"snapshot":snapshot,"elapsed_ms":elapsed.as_secs_f64()*1000.0}));
}

#[test]
fn independent_risks_submit_only_the_configured_exit_intent_for_verified_members() {
    for (ip,dns,expected,dns_age) in [("warn","force",Some("dns_egress_changed"),0.),
        ("force","warn",Some("egress_ip_changed"),0.),("close","force",Some("dns_egress_changed"),0.),
        ("close","warn",Some("egress_ip_changed"),0.),("warn","warn",None,0.),
        ("warn","force",Some("dns_egress_changed"),299.5),("warn","force",None,301.)] {
        let mut fixture=Fixture::with_actions(ip,Some(dns));
        let image=fixture.sleeper(); let target=fixture.launch(LaunchTarget::ClaudeCli,&image,vec![]);
        let identity=inspect_process_identity(target.0.id()).unwrap();
        let mut supervisor=fixture.supervisor(&["claude"]);
        let original=SessionStore::new(fixture.storage.clone()).load(native::now()).unwrap().unwrap();
        let (events,_receipts)=mpsc::channel(); let (requests,received)=mpsc::channel();
        let (dispatcher,worker)=ProcessDispositionDispatcher::start_with(
            fixture.storage.clone(),fixture.stop.clone(),events,move |_,job,_| {
                requests.send(job.intent.clone()).unwrap(); None
            }).unwrap();
        fixture.workers.push(worker);
        supervisor.install_process_disposition_dispatcher(dispatcher);
        supervisor.set_process_disposition_registry(fixture.registry.clone());
        if ip=="close" && dns=="force" {
            fixture.environment(&mut supervisor,"claude","9.9.9.9",native::now());
            assert_eq!(SessionStore::new(fixture.storage.clone()).load(native::now()).unwrap().unwrap().state,Phase::Locked);
            assert_eq!(received.recv_timeout(Duration::from_secs(2)).unwrap().action,"close",
                "a close risk requests normal exit, never force");
        }
        let sampled_at=native::now();
        fixture::seed_probe_receipts(&fixture.storage,sampled_at,"JP");
        // Advance the injected receiver clock; retain the real cached probe's
        // original timestamp and current kernel-verified process identity.
        let now=sampled_at+dns_age;
        if dns_age>0. {
            fixture.enforcer.set_clock(move || now).unwrap();
            fixture.observation(&mut supervisor,2,now);
        }
        fixture.environment(&mut supervisor,"claude","9.9.9.9",now);
        if let Some(reason)=expected {
            let intent=received.recv_timeout(Duration::from_secs(2)).expect("Supervisor must submit the configured exit job");
            assert_eq!(intent.action,if reason=="dns_egress_changed" { dns } else { ip }); assert_eq!(intent.risk_code,reason);
            assert_eq!(intent.session_id,original.session_id); assert_eq!(intent.family,"claude");
            assert_eq!(intent.target_identities.len(),1);
            let token=&intent.target_identities[0];
            assert!(token.matches_process(identity.pid,identity.uid,identity.start_seconds,identity.start_microseconds,Some(&identity.audit_token)));
            assert_eq!(intent.target_executables[&identity.pid],identity.executable_path);
            assert_eq!(intent.policy_version,fixture.policy);
            if reason=="dns_egress_changed" { assert!(intent.valid_until <= sampled_at + claude_watch_core::session::RISK_EVIDENCE_TTL,
                "rereading a cached probe cannot extend its process authority"); }
            assert_eq!(supervisor.snapshot(now).families["claude"].process_execution_state.as_deref(),Some("executing"));
        } else {
            assert!(received.recv_timeout(Duration::from_millis(150)).is_err(),"warn or expired evidence cannot queue process effects");
            assert!(supervisor.snapshot(now).families["claude"].process_disposition_action.is_none());
        }
        assert_eq!(inspect_process_identity(identity.pid),Some(identity),"the capture executor never signals the owned process");
    }
}

#[test]
fn external_process_actions_use_real_worker_and_preserve_warn_and_later_launches() {
    use std::{io::Read, os::unix::process::ExitStatusExt};
    use claude_watch_core::{channel::{BackendCoverageScope, BoundProcessToken, NetworkBackendKind}, processes::ProcessRole};
    let bound = |p: &claude_watch_system::ProcessKernelIdentity|
        BoundProcessToken::with_system_identity(p.pid, p.uid, p.start_seconds, p.start_microseconds, ProcessRole::Cli)
            .with_audit_token(p.audit_token);
    for (family, action) in [("openai", "warn"), ("openai", "close"), ("openai", "force"), ("claude", "close"), ("claude", "force")] {
        let mut fixture = Fixture::with_family_actions(family, action, None);
        let image = fixture.root.join("external-exit-fixture");
        fixture.compile("#include <signal.h>\n#include <unistd.h>\nint main(int argc,char **argv){if(argc>1){signal(SIGTERM,SIG_IGN);write(1,\"R\",1);}for(;;)pause();}\n", &image);
        fixture.registry.approve_target_executable(image.to_string_lossy().into_owned(), sha256_file_hex(&image).unwrap());
        let anchor_image = fixture.root.join("unapproved-anchor");
        fs::copy(&image, &anchor_image).unwrap();
        let anchor = Owned(Command::new(&anchor_image).spawn().unwrap());
        let anchor_id = inspect_process_identity(anchor.0.id()).unwrap();
        let mut first = Owned(Command::new(&image).spawn().unwrap());
        let identity = inspect_process_identity(first.0.id()).unwrap();
        assert!(fixture.registry.instances().is_empty(), "fixture must be launched outside Watch");
        assert!(fixture.registry.external_disposition_target_current(&bound(&identity), &identity));
        let mut wrong = bound(&identity); wrong.start_seconds += 1;
        assert!(!fixture.registry.external_disposition_target_current(&wrong, &identity));
        wrong = bound(&identity); wrong.uid += 1;
        assert!(!fixture.registry.external_disposition_target_current(&wrong, &identity));
        wrong = bound(&identity); wrong.audit_token.as_mut().unwrap()[7] += 1;
        assert!(!fixture.registry.external_disposition_target_current(&wrong, &identity));
        wrong = bound(&identity); wrong.audit_token = None;
        assert!(!fixture.registry.external_disposition_target_current(&wrong, &identity));
        let mut supervisor = ChannelSupervisor::new(fixture.storage.clone(), Some(fixture.enforcer.clone()), None).unwrap();
        supervisor.set_process_disposition_registry(fixture.registry.clone());
        let (events, receipts) = mpsc::channel();
        let (dispatcher, worker) = ProcessDispositionDispatcher::start(fixture.storage.clone(), fixture.stop.clone(), events).unwrap();
        fixture.workers.push(worker);
        supervisor.install_process_disposition_dispatcher(dispatcher);
        let now = native::now();
        fixture::seed_probe_receipts(&fixture.storage, now, "US");
        fixture.observation(&mut supervisor, 1, now);
        fixture.environment(&mut supervisor, "*", "1.1.1.1", now);
        let mut audit = fixture::fixture_audit_val(&fixture.storage, now, "1.1.1.1", "US");
        audit["launch_target"] = json!(if family == "claude" { "claude-cli" } else { "codex-cli" });
        audit["authorization_scope"] = json!("observation");
        let egress = fixture::controlled_egress(&fixture.config, now, "1.1.1.1", "US",
            Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)));
        SessionStore::for_family(fixture.storage.clone(), family).begin_channel_verified(
            &ReceiptStore { storage: fixture.storage.clone() }, &audit, &egress, &[bound(&anchor_id), bound(&identity)], now,
        ).unwrap();
        let inventory = |supervisor: &mut ChannelSupervisor, identity: &claude_watch_system::ProcessKernelIdentity| {
            let at = native::now();
            supervisor.set_family_coverage_scope(family, Some(BackendCoverageScope {
                backend: NetworkBackendKind::Seatbelt, unprotected_pids: vec![anchor_id.pid, identity.pid], ..Default::default()
            }), at);
            supervisor.handle_event(SupervisionEvent::ProcessInventoryUpdated {
                family: family.into(), desktops: vec![], processes: vec![bound(&anchor_id), bound(identity)], observed_at: at,
            }).unwrap();
        };
        inventory(&mut supervisor, &identity);
        fixture.environment(&mut supervisor, family, "9.9.9.9", native::now());
        if action == "warn" {
            assert!(receipts.recv_timeout(Duration::from_millis(150)).is_err(), "warn must never send process signals");
            assert_eq!(inspect_process_identity(identity.pid), Some(identity));
            continue;
        }
        let accept = |supervisor: &mut ChannelSupervisor, identity: &claude_watch_system::ProcessKernelIdentity| {
            let event = receipts.recv_timeout(Duration::from_secs(3)).unwrap_or_else(|error|
                panic!("real worker must return the exit receipt: {error:?}; family={family}; state={:?}", supervisor.snapshot(native::now()).families[family]));
            let SupervisionEvent::ProcessReceiptArrived { receipt, .. } = &event else { panic!("wrong event") };
            assert_eq!(receipt.process_execution_state, "confirmed", "{receipt:?}");
            assert_eq!(receipt.target_results[0].pid, identity.pid);
            assert_eq!(receipt.action, action);
            assert_eq!(receipt.target_results[0].requested_action, if action == "force" { "force_quit" } else { "quit" });
            assert_eq!(receipt.target_results[0].process_state, "confirmed_exit_after_request");
            assert!(receipt.authority.as_ref().unwrap().target_instances.is_empty());
            let authority = receipt.authority.as_ref().unwrap();
            let mut replaced = bound(identity); replaced.start_microseconds += 1;
            assert!(!current_policy_and_session(&fixture.storage, authority, &replaced, native::now()),
                "a replaced lifetime is not authorized by the old session");
            let mut wrong = authority.clone(); wrong.executor_boot_id = "old-executor".into();
            assert!(!fixture.registry.current_disposition_member(&wrong, &bound(identity), identity, native::now()));
            wrong = authority.clone(); wrong.session_id = "other-session".into();
            assert!(!current_policy_and_session(&fixture.storage, &wrong, &bound(identity), native::now()));
            wait_until_exited(identity);
            supervisor.handle_event(event).unwrap();
            let state = &supervisor.snapshot(native::now()).families[family];
            assert_eq!(state.process_execution_state.as_deref(), Some("confirmed"));
            assert!(state.coverage_scope.protected_pids.is_empty(), "force does not invent gateway coverage");
        };
        accept(&mut supervisor, &identity);
        assert_eq!(first.0.wait().unwrap().signal(), Some(if action == "force" { 9 } else { 15 }));
        // Same risk, same session: an external process started later must not
        // be skipped by the previous process episode's deduplication.
        let mut later = Owned(Command::new(&image).spawn().unwrap());
        let later_id = inspect_process_identity(later.0.id()).unwrap();
        inventory(&mut supervisor, &later_id);
        accept(&mut supervisor, &later_id);
        assert_eq!(later.0.wait().unwrap().signal(), Some(if action == "force" { 9 } else { 15 }));
        assert!(fixture.registry.instances().is_empty());
        assert_eq!(inspect_process_identity(anchor_id.pid), Some(anchor_id.clone()), "unapproved images remain untouched");
        if action == "close" {
            let mut ignoring = Owned(Command::new(&image).arg("ignore-term").stdout(Stdio::piped()).spawn().unwrap());
            ignoring.0.stdout.as_mut().unwrap().read_exact(&mut [0]).unwrap();
            let ignoring_id = inspect_process_identity(ignoring.0.id()).unwrap();
            inventory(&mut supervisor, &ignoring_id);
            let event = receipts.recv_timeout(Duration::from_secs(3)).unwrap();
            let SupervisionEvent::ProcessReceiptArrived { receipt, .. } = &event else { panic!("wrong event") };
            assert_eq!(receipt.action, "close");
            assert_eq!(receipt.target_results[0].process_state, "timeout");
            assert!(!receipt.target_results[0].terminated);
            assert!(ignoring.0.try_wait().unwrap().is_none(), "normal close must not escalate to SIGKILL");
            supervisor.handle_event(event).unwrap();
        }
        let unapproved = Owned(Command::new(&image).spawn().unwrap());
        let unapproved_id = inspect_process_identity(unapproved.0.id()).unwrap();
        fixture.registry.replace_approved_targets(Default::default(), Default::default());
        assert!(!fixture.registry.external_disposition_target_current(&bound(&unapproved_id), &unapproved_id));
        inventory(&mut supervisor, &unapproved_id);
        assert!(receipts.recv_timeout(Duration::from_millis(150)).is_err(), "revoked executable approval cannot fall back to PID-only authority");
        assert_eq!(inspect_process_identity(unapproved_id.pid), Some(unapproved_id));
    }
}
