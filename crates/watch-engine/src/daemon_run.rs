use claude_watch_core::{
    channel::{
        BackendCoverageScope, NetworkBackendKind, PolicyVersion,
    },
    cli::Request,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    vpn::VpnExpectation,
};
#[cfg(test)]
use claude_watch_core::channel::ChannelMonitorSnapshot;
use claude_watch_runtime::{
    alert_gate::AlertGate,
    channel_enforcer::{
        register_production_enforcer, unregister_production_enforcer, ChannelEnforcer,
        LocalTunnelEnforcer,
    },
    channel_supervisor::{AsyncAuditRequest, ChannelSupervisor, SupervisionEvent},
    channel_diagnostics::ChannelDiagnostics,
    config_store::ConfigStore,
    controlled::Controller,
    daemon::{DaemonLease, PROCESS_INTERVAL},
    desktop_native::{DesktopRuntime, NativeDesktop},
    events::{Alert, EventFields, EventStore, Severity},
    macos::Authority,
    native::{self, Observer},
    native_notifications::{AlertDispatcher, NativeNotifier},
    sampler::{pinned_node, Sampler},
    sandbox_launch::{
        build_helper_verifier_from_manifest, default_registration_socket_path,
        lookup_packaged_network_backend, SandboxLaunchRegistry,
    },
    snapshot_publication::SnapshotPublisher,
    storage::{Paths, StateStore},
    vpn_observer::{
        resolve_vpn_controller_credentials, HttpControllerVpnReader, VpnObserver, VpnSourceReader,
    },
};
use claude_watch_system::network_events::{NetworkEventKind, NetworkEventWatcher};
use serde_json::{json, Value};
use std::{
    os::{fd::AsFd, unix::net::UnixStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

/// A single ownership-transfer slot: newer producer rounds replace pending
/// ones. Consumed rounds are never retained here or timestamped again.
#[derive(Default)]
struct ActiveGuardState {
    active_families: std::sync::Mutex<std::collections::BTreeSet<String>>,
    needs_immediate_probe: AtomicBool,
    has_active_managed: AtomicBool,
}

impl ActiveGuardState {
    fn update_families(&self, families: Vec<String>) -> bool {
        let next: std::collections::BTreeSet<String> = families.into_iter().collect();
        self.has_active_managed.store(!next.is_empty(), Ordering::Release);
        let mut guard = self.active_families.lock().unwrap_or_else(|e| e.into_inner());
        let added = next.iter().any(|family| !guard.contains(family));
        *guard = next;
        if added {
            self.needs_immediate_probe.store(true, Ordering::Release);
        }
        added
    }

    fn request_immediate_probe(&self) {
        self.needs_immediate_probe.store(true, Ordering::Release);
    }

    fn take_immediate_probe(&self) -> bool {
        self.needs_immediate_probe.swap(false, Ordering::AcqRel)
    }

    fn active_families(&self) -> std::collections::BTreeSet<String> {
        self.active_families.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn has_active_managed(&self) -> bool {
        self.has_active_managed.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct GuardRoundHandoff {
    state: std::sync::Mutex<GuardRoundState>,
    ready: std::sync::Condvar,
}
#[derive(Default)]
struct GuardRoundState {
    pending: Option<(f64, Result<claude_watch_runtime::sampler::ProcessRound>)>,
    closed: bool,
}
impl GuardRoundHandoff {
    fn publish(&self, round: Result<claude_watch_runtime::sampler::ProcessRound>) {
        let observed_at = round.as_ref().map_or_else(|_| native::now(), |round| round.observed_at);
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.closed {
            state.pending = Some((observed_at, round));
            self.ready.notify_one();
        }
    }
    fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        state.pending = None;
        self.ready.notify_all();
    }
    fn take(&self) -> Option<(f64, Result<claude_watch_runtime::sampler::ProcessRound>)> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        self.ready.wait_while(state, |s| s.pending.is_none() && !s.closed)
            .unwrap_or_else(|error| error.into_inner()).pending.take()
    }
    fn unchanged(
        &self,
        current: &claude_watch_runtime::sampler::ProcessRound,
        backend: &std::path::Path,
        owner_pid: Option<u32>,
    ) -> bool {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match state.pending.as_ref() {
            Some((_, Ok(newer))) => claude_watch_runtime::macos::guard_round_matches_for_owner(
                current, newer, backend, owner_pid,
            ),
            Some((_, Err(_))) => false,
            None => claude_watch_runtime::macos::guard_round_matches_for_owner(
                current, current, backend, owner_pid,
            ),
        }
    }
}

#[cfg(test)]
#[path = "../../watch-runtime/tests/support/hardened_helper.rs"]
mod hardened_helper;

#[cfg(all(test, target_os = "macos"))]
#[path = "../tests/support/queued_channel_fixture.rs"]
mod queued_channel_contracts;

pub struct ProductionChannelStack {
    stop: Arc<AtomicBool>,
    pub packaged_backend: Option<NetworkBackendKind>,
    pub enforcer: Arc<LocalTunnelEnforcer>,
    pub sandbox_registry: Option<Arc<SandboxLaunchRegistry>>,
    pub supervisor: ChannelSupervisor,
    #[allow(dead_code)]
    pub event_tx: Sender<SupervisionEvent>,
    pub event_rx: Receiver<SupervisionEvent>,
    pub vpn_wake_handle: Option<UnixStream>,
    last_vpn_refresh_signal: Option<Instant>,
    pub lease_watchdog: thread::JoinHandle<()>,
    pub async_audit_worker: claude_watch_runtime::channel_supervisor::AuditWorker,
    process_disposition_worker: Option<thread::JoinHandle<()>>,
    pub sandbox_registration_worker: Option<claude_watch_system::ListenerWorker>,
    pub vpn_observer_worker: Option<thread::JoinHandle<()>>,
    pub last_policy_version: Option<PolicyVersion>,
    activate_local_interception: bool,
    local_proxy_worker: Option<claude_watch_system::ListenerWorker>,
    target_refresh_worker: Option<thread::JoinHandle<()>>,
    target_refresh_cancel: Option<UnixStream>,
    sampling_wake: Option<UnixStream>,
    backend_refresh_requested: bool,
    active_guard: Arc<ActiveGuardState>,
    #[cfg(all(test, target_os = "macos"))]
    private_loopback_backend: bool,
}

fn refresh_and_stage_production_targets(
    storage: &StateStore,
    resources_dir: Option<&std::path::Path>,
    registry: &SandboxLaunchRegistry,
    event_tx: &Sender<SupervisionEvent>,
) -> Result<()> {
    use claude_watch_runtime::target_discovery::DiscoveryHandle;
    let discovery = DiscoveryHandle::for_home(&storage.paths.home);
    let runner = super::runtime::runner()?;
    let snapshot = discovery.observation_snapshot(runner.as_ref(), native::now());
    stage_discovery_snapshot(storage, resources_dir, registry, event_tx, &discovery, &snapshot)
}

fn stage_discovery_snapshot(
    storage: &StateStore, resources_dir: Option<&std::path::Path>, registry: &SandboxLaunchRegistry,
    event_tx: &Sender<SupervisionEvent>, discovery: &claude_watch_runtime::target_discovery::DiscoveryHandle,
    snapshot: &claude_watch_runtime::target_discovery::DiscoverySnapshot,
) -> Result<()> {
    use claude_watch_runtime::managed_entry::stage_deliverable_entries;
    let manifest = discovery.approved_manifest(snapshot)?;
    for family in registry.replace_discovery_approvals(manifest.targets, manifest.children, manifest.cli_sources, manifest.script_combos) {
        // Only Supervisor emits network commands. Identity loss precedes disk staging.
        let _ = event_tx.send(SupervisionEvent::ProcessInventoryUnavailable { family, observed_at: native::now() });
    }
    let entries_root = storage.paths.watch().join("entries");
    let discovered_specs = manifest.desktop_specs;
    let watch_engine_bin = resources_dir
        .map(|d| d.join("watch-engine"))
        .filter(|p| p.is_file())
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_else(|| PathBuf::from("/usr/bin/true"));
    let launcher_bin = resources_dir
        .map(|d| d.join("watch-sandbox-launcher"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| watch_engine_bin.with_file_name("watch-sandbox-launcher"));
    let controlled_entry_macho = resources_dir
        .map(|d| d.join("ControlledEntry"))
        .filter(|p| p.is_file());
    let (approval_boot, script_approvals) = registry.script_launch_approval_view();
    claude_watch_runtime::target_discovery::publish_runtime_snapshot(storage, snapshot,
        &manifest.selection_issues, manifest.needs_verification_retry, &approval_boot, &script_approvals)?;
    stage_deliverable_entries(
        &entries_root,
        &discovered_specs,
        &watch_engine_bin,
        &launcher_bin,
        controlled_entry_macho.as_deref(),
    )?;
    if manifest.needs_verification_retry {
        // Valid scopes and revocations above are already applied. Do not let
        // the refresh worker cache this revision as fully staged: a temporary
        // read failure can recover without any further metadata change.
        return Err(CoreError::new("target_approval_pending", "部分安装文件待重新验证，其他目标已分别更新"));
    }
    Ok(())
}

/// Shared discovery revision plus exact runtime components; no private second
/// scanner and no content hashing on an unchanged refresh round.
fn target_metadata_signature(storage: &StateStore, resources_dir: Option<&std::path::Path>) -> Vec<(PathBuf, Vec<i128>, Option<PathBuf>)> {
    use std::os::unix::fs::MetadataExt;
    let discovery=claude_watch_runtime::target_discovery::DiscoveryHandle::for_home(&storage.paths.home);
    let revision=super::runtime::runner().map(|runner|discovery.observation_snapshot(runner.as_ref(),native::now()).revision.clone()).unwrap_or_default();
    let mut out=vec![(storage.paths.watch().join("state/target-discovery-revision"),revision.bytes().map(i128::from).collect(),None)];
    if let Some(resources)=resources_dir {
        for name in ["watch-engine","watch-sandbox-launcher","ControlledEntry"] {
            let path=resources.join(name);
            let values=std::fs::metadata(&path).map(|m|vec![m.dev() as i128,m.ino() as i128,m.len() as i128,m.mtime() as i128,
                m.mtime_nsec() as i128,m.ctime() as i128,m.ctime_nsec() as i128,m.mode() as i128]).unwrap_or_else(|_|vec![-1]);
            out.push((path.clone(),values,std::fs::canonicalize(path).ok()));
        }
    }
    out
}

fn notify_sampling_wake(wake: &Option<UnixStream>) {
    if let Some(stream) = wake {
        use std::io::Write;
        let _ = (&*stream).write(&[1]);
    }
}

fn spawn_target_refresh_worker(
    storage: StateStore,
    resources_dir: Option<PathBuf>,
    registry: Arc<SandboxLaunchRegistry>,
    stop: Arc<AtomicBool>,
    event_tx: Sender<SupervisionEvent>,
    sampling_wake: Option<UnixStream>,
) -> Result<(thread::JoinHandle<()>, UnixStream)> {
    let error = |_| CoreError::new("target_refresh_worker_failed", "受控目标通知通道无法启动");
    let (cancel, cancellation) = UnixStream::pair().map_err(error)?;
    let discovery = claude_watch_runtime::target_discovery::DiscoveryHandle::for_home(&storage.paths.home);
    let mut publications = discovery.subscribe_publications().map_err(error)?;
    let mut registrations = registry.subscribe_changes().map_err(error)?;
    let worker = thread::Builder::new().name("channel-target-refresh".into()).spawn(move || {
        let mut watcher = NetworkEventWatcher::new(&[]);
        let mut previous = None;
        while !stop.load(Ordering::Acquire) {
            // Publish already-known identity/metadata loss before any slow content read.
            registry.reconcile_process_trees(native::now());
            for family in registry.take_invalidated_families() {
                let _ = event_tx.send(SupervisionEvent::ProcessInventoryUnavailable { family, observed_at: native::now() });
            }
            let current = target_metadata_signature(&storage, resources_dir.as_deref());
            let mut retry = false;
            if previous.as_ref() != Some(&current) {
                if refresh_and_stage_production_targets(&storage, resources_dir.as_deref(), &registry, &event_tx).is_ok() {
                    let mut paths = discovery.installed_target_paths();
                    paths.extend(current.iter().skip(1).map(|(path, _, _)| path.clone()));
                    watcher.set_watched_files(paths);
                    previous = Some(current);
                } else { retry = true; }
            }
            for family in registry.refresh_executable_verifications() {
                let _ = event_tx.send(SupervisionEvent::ProcessInventoryUnavailable {
                    family, observed_at: native::now(),
                });
            }
            // A partially staged image needs an explicit retry. Live process
            // identities have the same evidence budget as protection verdicts.
            let interval = if retry {
                Some(PROCESS_INTERVAL)
            } else if registry.has_live_instances() {
                Some(Duration::from_secs_f64(claude_watch_core::channel::MAX_ENFORCEMENT_RECEIPT_AGE / 2.0))
            } else { None };
            let (_, ready) = watcher.wait_with_readers(interval,
                &[cancellation.as_fd(), publications.as_fd(), registrations.as_fd()]);
            if ready == Some(0) { break; }
            let mut buffer = [0; 256];
            use std::io::Read;
            if ready == Some(1) { let _ = publications.read(&mut buffer); }
            if ready == Some(2) {
                let _ = registrations.read(&mut buffer);
                notify_sampling_wake(&sampling_wake);
            }
        }
    }).map_err(|_| CoreError::new("target_refresh_worker_failed", "受控目标刷新线程启动失败"))?;
    Ok((worker, cancel))
}

fn locate_runtime_resources_dir(storage: &StateStore) -> Option<PathBuf> {
    for candidate in [
        storage.paths.watch().join("runtime"),
        storage.paths.base().join("bin"),
    ] {
        if candidate.join("BuildInfo.plist").is_file()
            || candidate.join("components.json").is_file()
            || candidate.join("watch-sandbox-launcher").is_file()
        {
            return Some(candidate);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if parent.join("BuildInfo.plist").is_file()
                || parent.join("components.json").is_file()
                || parent.join("watch-sandbox-launcher").is_file()
            {
                return Some(parent.to_path_buf());
            }
        }
    }
    None
}

#[cfg(test)]
mod m5_tests {
    use super::*;
    use claude_watch_core::processes::{Identity,LaunchTarget};
    use claude_watch_runtime::{commands::{ReadCommand,ReadRunner,ObserverAction,Output,SystemRunner},
        managed_entry::{prepare_desktop_managed_launch,DesktopEntryPreparation},target_discovery::*};
    use std::{fs,os::unix::fs::PermissionsExt,time::Duration};
    struct Registry(PathBuf);
    impl ApplicationRegistry for Registry {
        fn locations(&self,id:&str)->Result<claude_watch_system::application_locations::ApplicationLocations> {
            Ok(claude_watch_system::application_locations::ApplicationLocations { paths:if id==DESKTOP_IDS[0].0{vec![self.0.clone()]}else{vec![]},complete:true })
        }
    }
    struct Reader { metadata:SystemRunner, identity:Identity,bundle:PathBuf }
    impl ReadRunner for Reader {
        fn run(&self,command:ReadCommand,input:&[u8],timeout:Duration,limit:usize)->Result<Output> {
            let now=native::now();let mut value=json!({"schema":1,"status":"ok","uid":self.identity.uid,"started_at":now,"finished_at":now});
            match command {
                ReadCommand::Plist(path)=>return self.metadata.run(ReadCommand::Plist(path),input,timeout,limit),
                ReadCommand::PlistXml(path)=>return self.metadata.run(ReadCommand::PlistXml(path),input,timeout,limit),
                ReadCommand::Observer(ObserverAction::Inventory)=>{
                    let mut row=json!(self.identity);row["bundle_path"]=json!(self.bundle);row["bundle_id"]=Value::Null;
                    value["state"]=json!("ok");value["truncated"]=json!(false);value["requested_count"]=json!(1);
                    value["processes"]=json!([row]);value["unavailable"]=json!([]);value["exited"]=json!([]);
                }
                ReadCommand::Observer(ObserverAction::Arguments)=>{
                    let request:Value=serde_json::from_slice(input).unwrap();value["round_id"]=request["round_id"].clone();
                    value["argument_prefixes"]=json!([{"pid":self.identity.pid,"state":"ok","identity":self.identity,
                        "arguments":[self.identity.executable],"cwd":"/fixture","truncated":false}]);
                }
                _=>panic!("M5 staging fixture must not run AI, user shell, VPN or process control"),
            }
            Ok(Output {status:0,stdout:serde_json::to_vec(&value).unwrap(),stderr:vec![]})
        }
    }

    #[test]
    fn idle_discovery_worker_observes_cli_installation_and_replacement() {
        use std::{io::Read, os::unix::fs::symlink};
        let root = PathBuf::from("/private/tmp").join(format!("cw-discovery-event-{}", uuid::Uuid::new_v4()));
        let bin = root.join(".local/bin");
        let versions = root.join(".local/share/claude/versions");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&versions).unwrap();
        let image = versions.join("current");
        symlink(&image, bin.join("claude")).unwrap();
        let mut inputs = DiscoveryInputs::for_home(&root);
        inputs.caller_path = vec![bin.clone()];
        inputs.overrides.clear();
        let discovery = DiscoveryHandle::with_registry(inputs, Arc::new(Registry(root.join("absent"))));
        let runner = Arc::new(SystemRunner::new(native::built_observer_path().unwrap()).unwrap());
        let mut changes = discovery.subscribe_publications().unwrap();
        let mut events = NetworkEventWatcher::new(&[]);
        let mut next = || {
            let (_, ready) = events.wait_with_readers(Duration::from_millis(1500), &[changes.as_fd()]);
            assert_eq!(ready, Some(0), "the directory event must beat both the retry and registry deadlines");
            assert!(changes.read(&mut [0; 64]).unwrap() > 0);
            discovery.observation_snapshot(runner.as_ref(), native::now())
        };
        let worker = DiscoveryWorker::start(discovery.clone(), runner.clone(), Arc::new(AtomicBool::new(false))).unwrap();
        let initial = next();
        assert!(initial.complete && initial.targets.is_empty(), "{initial:?}");
        let mut revision = initial.revision.clone();
        for version in [1, 2] {
            let staged_image = root.join("private-image");
            fs::write(&staged_image, [0xcf, 0xfa, 0xed, 0xfe, version]).unwrap();
            fs::set_permissions(&staged_image, fs::Permissions::from_mode(0o755)).unwrap();
            fs::rename(staged_image, &image).unwrap();
            let snapshot = next();
            assert_ne!(revision, snapshot.revision);
            assert!(snapshot.complete && snapshot.targets.iter().any(|item| item.valid() && item.executable.as_ref() == Some(&image)), "{snapshot:?}");
            revision = snapshot.revision.clone();
        }
        drop(worker);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_discovery_stages_custom_claude_and_binds_the_controlled_request() {
        let root=PathBuf::from("/private/tmp").join(format!("cw-m5-stage-{}",uuid::Uuid::new_v4()));
        let home=root.join("home");fs::create_dir_all(&home).unwrap();
        let bundle=root.join("Custom & Sources/Claude 'Renamed'.app");fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        let executable=bundle.join("Contents/MacOS/Agent & Main");fs::write(&executable,b"private native discovery fixture").unwrap();
        fs::set_permissions(&executable,fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(bundle.join("Contents/Info.plist"),r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>Agent &amp; Main</string></dict></plist>"#).unwrap();
        let store=StateStore::new(Paths::new(&home).unwrap());
        let reader=Reader {metadata:SystemRunner::new(native::built_observer_path().unwrap()).unwrap(),bundle:bundle.clone(),
            identity:Identity {pid:4100,parent:1,uid:claude_watch_system::effective_uid(),executable:executable.to_string_lossy().into_owned(),
                start_seconds:100,start_microseconds:1,start_stamp:"private-stage".into()} };
        let mut inputs=DiscoveryInputs::for_home(&home);inputs.application_roots.clear();inputs.query_registry=true;
        let discovery=DiscoveryHandle::with_registry(inputs,Arc::new(Registry(bundle.clone())));
        discovery.observed_process_bundles([(bundle.clone(),None)]);
        let snapshot=discovery.refresh(&reader,native::now());
        let policy=PolicyVersion {policy_digest:"m5-policy".into(),guard_policy_digest:"m5-guard".into()};
        let registry=SandboxLaunchRegistry::new("m5-boot",policy.clone(),claude_watch_system::SandboxPeerVerifier {
            expected_uid:claude_watch_system::effective_uid(),expected_helper_executable:"/fixture/helper".into(),
            expected_helper_sha256:"fixture".into(),expected_helper_cdhash:"0".repeat(40) },None);
        let (tx,rx)=std::sync::mpsc::channel();
        stage_discovery_snapshot(&store,None,&registry,&tx,&discovery,&snapshot).unwrap();
        assert!(rx.try_recv().is_err());registry.refresh_executable_verifications();assert_eq!(registry.executable_verification_counts().1,1);
        let mut desktop=NativeDesktop::new(&reader,native::built_process_control_path().unwrap().into(),Authority::ReadOnly).unwrap();
        desktop.set_discovery(discovery.clone());desktop.select_target(LaunchTarget::ClaudeDesktop).unwrap();
        let spec=desktop.build_managed_entry_spec().unwrap();assert_eq!(spec.target_executable,executable);
        let request=match prepare_desktop_managed_launch(&spec,&[],&registry,"m5-boot",&policy,None,"127.0.0.1:1021".parse().unwrap(),vec![]).unwrap() {
            DesktopEntryPreparation::ReadyToLaunch {request}=>request,other=>panic!("unexpected preparation: {other:?}"),
        };
        assert_eq!(request.target_executable,executable.to_string_lossy());assert_eq!(request.target_fingerprint,claude_watch_system::sha256_file_hex(&executable).unwrap());
        let mut sampler=Sampler::new(&reader,store.paths.clone());sampler.set_discovery(discovery.clone());let round=sampler.processes().unwrap();
        assert_eq!(round.targets.len(),1);assert_eq!(round.targets[0].identity.executable,request.target_executable);
        assert_eq!(round.discovery.as_ref().unwrap()["revision"],snapshot.revision);
        assert_eq!(desktop.desktops().unwrap().len(),1,"actual validated path works without NSRunningApplication bundle-id presentation");
        let staged=store.paths.watch().join("entries/apps/Claude (Controlled).app");
        let info=reader.run(ReadCommand::Plist(staged.join("Contents/Info.plist")),&[],Duration::from_secs(3),128*1024).unwrap();
        let info:Value=serde_json::from_slice(&info.stdout).unwrap();
        assert_eq!(info["CWTargetBundlePath"],json!(bundle));assert_eq!(info["CWTargetExecutable"],request.target_executable);
        let script=fs::read_to_string(staged.join("Contents/MacOS/ControlledEntry")).unwrap();
        assert!(script.contains("--target-bundle") && script.contains("'\\''Renamed'\\''"));
        let parsed=claude_watch_core::cli::Request::parse(&["launch".into(),"--target".into(),"claude-desktop".into(),"--target-bundle".into(),bundle.to_string_lossy().into_owned(),"--apply".into()]).unwrap();
        assert_eq!(parsed.value("target-bundle"),bundle.to_str());
        for (target,path) in [("claude-cli",bundle.to_string_lossy().into_owned()),("claude-desktop","relative.app".into()),("claude-desktop","/tmp/control\n.app".into())] {
            assert!(claude_watch_core::cli::Request::parse(&["launch".into(),"--target".into(),target.into(),"--target-bundle".into(),path,"--apply".into()]).is_err(),"bundle binding requires a desktop target and an absolute, non-control path");
        }
        let enforcer=LocalTunnelEnforcer::new("m5-boot");enforcer.configure_seatbelt_backend(false,native::now()).unwrap();
        assert!(!enforcer.sandbox_ready().unwrap());assert!(registry.instances().is_empty(),"discovery/staging/preparation creates no sandbox or protected instance");
        if let Some(dir)=std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
            fs::create_dir_all(&dir).unwrap();fs::write(std::path::Path::new(&dir).join("target-discovery-staging.json"),
                serde_json::to_vec_pretty(&json!({"snapshot":snapshot.as_ref(),"entry_info":info,"request":request,"i03_ready":false})).unwrap()).unwrap();
        }
        println!("M5 production vertical: registered custom renamed Claude -> production staging and content approval -> same NativeDesktop/Sampler revision -> bound controlled request; I03 remains closed");
        fs::remove_dir_all(root).unwrap();
    }
}

fn spawn_vpn_observation_worker(
    storage: StateStore,
    packaged_backend: Option<NetworkBackendKind>,
    stop: Arc<AtomicBool>,
    event_tx: Sender<SupervisionEvent>,
    lease_watchdog: thread::Thread,
    active_guard: Arc<ActiveGuardState>,
    custom_reader: Option<Arc<dyn VpnSourceReader>>,
) -> Result<(thread::JoinHandle<()>, UnixStream)> {
    const STEADY_STATE_VPN_CHECK_INTERVAL: Duration = Duration::from_secs(15);
    const TRANSIENT_VPN_RETRY_DELAY: Duration = Duration::from_secs(1);
    const MAX_TRANSIENT_VPN_FAILURES: u32 = 2;

    let obs_boot_id = format!(
        "vpn-obs-{}-{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let watcher = NetworkEventWatcher::default();
    let (wake_handle, mut cancellation) = UnixStream::pair()
        .map_err(|_| CoreError::new("vpn_observer_worker_failed", "VPN 观察停止通道无法启动"))?;
    let _ = wake_handle.set_nonblocking(true);
    let _ = cancellation.set_nonblocking(true);
    let listener_stream = custom_reader.is_none().then(super::runtime::listener_stream).flatten();
    let mut frames = listener_stream.as_ref().map(|stream| stream.subscribe_frames()).transpose()?;
    let handle = thread::Builder::new()
        .name("channel-vpn-observer".into())
        .spawn(move || {
            let mut observer = VpnObserver::new(obs_boot_id, Some(storage.clone()));
            let mut watcher = watcher;
            let mut first = true;
            let mut awaiting_revision = None;
            let mut retry_after: Option<Instant> = None;
            let mut last_steady_check: Option<Instant> = None;
            let mut consecutive_transient_failures: u32 = 0;
            let seen_failure = std::cell::Cell::new(0);
            let failure_tx = event_tx.clone();
            let notice: Arc<claude_watch_runtime::native_listener::ListenerFailureNotice> = Arc::new(move |error| {
                let _ = failure_tx.send(SupervisionEvent::VpnObservationUnavailable {
                    reason: error.code.clone(), observed_at: native::now(),
                });
            });
            if let Some(stream) = &listener_stream { stream.subscribe_failures(&notice); }
            let mut live_reader = None;
            let config_store = ConfigStore { storage: storage.clone() };
            watcher.watch_file(storage.paths.config());
            let mut expectation = config_store.resolve_runtime_config_state(packaged_backend)
                .config.vpn_expectation.unwrap_or_else(VpnExpectation::unconfigured);
            let watch_configs = |watcher: &mut NetworkEventWatcher, expectation: &VpnExpectation| {
                let mut files = claude_watch_runtime::vpn_observer::vpn_controller_config_paths(
                    &storage.paths.home, &expectation.proxy_mode);
                files.push(storage.paths.config());
                files.push(storage.paths.home.join("Library/Application Support/com.tag.lab.v2/dns_config.yaml"));
                watcher.set_watched_files(files);
            };
            let sync_watched_pid = |watcher: &mut NetworkEventWatcher, observer: &VpnObserver| {
                if let Some(pid) = observer.observed_listener_pid() {
                    watcher.set_watched_pids(&[pid]);
                } else {
                    watcher.set_watched_pids(&[]);
                }
            };
            watch_configs(&mut watcher, &expectation);
            while !stop.load(Ordering::Acquire) {
                use claude_watch_runtime::vpn_observer::{DEFAULT_VPN_OBSERVATION_TTL_SECONDS, VPN_OBSERVATION_RENEWAL_LEAD_SECONDS};
                let now = native::now();
                let current_obs = observer.state.current_observation();
                let expiry = current_obs.map(|obs| obs.valid_until);
                let renewal_at = current_obs.map(|obs| {
                    let ttl = (obs.valid_until - obs.observed_at).max(0.0);
                    let lead = VPN_OBSERVATION_RENEWAL_LEAD_SECONDS.min(ttl / 2.0);
                    (obs.valid_until - lead).max(obs.observed_at + 0.1)
                });
                let mut timeout = if first {
                    Some(Duration::ZERO)
                } else if awaiting_revision.is_some() {
                    // Actively waiting on the listener stream socket for the requested frame;
                    // keep a bounded wakeup against the safety-net deadline so we never stall.
                    expiry.map(|at| Duration::from_secs_f64((at - now).clamp(0.1, DEFAULT_VPN_OBSERVATION_TTL_SECONDS)))
                } else if let Some(at) = renewal_at {
                    Some(Duration::from_secs_f64((at - now).clamp(0.0, DEFAULT_VPN_OBSERVATION_TTL_SECONDS)))
                } else if frames.is_some() {
                    None
                } else {
                    Some(Duration::from_secs_f64(DEFAULT_VPN_OBSERVATION_TTL_SECONDS))
                };
                if !first && awaiting_revision.is_none() && custom_reader.is_none()
                    && expectation.configured
                    && active_guard.has_active_managed()
                    && observer.observed_listener_pid().is_some()
                {
                    let steady_wait = last_steady_check.map_or(STEADY_STATE_VPN_CHECK_INTERVAL, |at| {
                        STEADY_STATE_VPN_CHECK_INTERVAL.saturating_sub(at.elapsed())
                    });
                    timeout = Some(timeout.map_or(steady_wait, |budget| budget.min(steady_wait)));
                }
                if let Some(at) = retry_after {
                    let retry = at.saturating_duration_since(Instant::now());
                    timeout = Some(timeout.map_or(retry, |budget| budget.min(retry)));
                }
                let mut readers = vec![cancellation.as_fd()];
                if let Some(frames) = &frames { readers.push(frames.as_fd()); }
                let (events, ready) = watcher.wait_with_readers(timeout, &readers);
                let mut requested_refresh = false;
                if ready == Some(0) {
                    use std::io::Read;
                    let mut buffer = [0u8; 64];
                    let mut peer_closed = false;
                    loop {
                        match cancellation.read(&mut buffer) {
                            Ok(0) => {
                                peer_closed = true;
                                break;
                            }
                            Ok(_) => {
                                requested_refresh = true;
                            }
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => {
                                peer_closed = true;
                                break;
                            }
                        }
                    }
                    if peer_closed || stop.load(Ordering::Acquire) {
                        break;
                    }
                } else if stop.load(Ordering::Acquire) {
                    break;
                }
                if ready == Some(1) {
                    use std::io::Read;
                    let mut buffer = [0; 256];
                    if let Some(stream) = &mut frames { let _ = stream.read(&mut buffer); }
                }
                let now = native::now();
                let send = |observation: claude_watch_core::vpn::VpnObservation| {
                    let _ = event_tx.send(SupervisionEvent::VpnObservationUpdated {
                        observation, observed_at: native::now(),
                    });
                };
                let collector_loss = || {
                    let (revision, error) = listener_stream.as_ref()?.failure_since(seen_failure.get())?;
                    seen_failure.set(revision);
                    Some(error)
                };
                let starting = first;
                let retry = retry_after.is_some_and(|at| Instant::now() >= at);
                if retry { retry_after = None; }
                let mut refresh = starting;
                first = false;
                if let Some(error) = collector_loss() {
                    // The stream already withdrew the supervisor's evidence at receipt.
                    if expectation.configured {
                        observer.invalidate_if_changed(&error.code, &expectation, now);
                        sync_watched_pid(&mut watcher, &observer);
                    }
                }
                let mut invalidation = None;
                let mut wake = false;
                for event in events {
                    match event {
                        NetworkEventKind::WatchedFileChanged(path) if path == storage.paths.config() => {
                            let resolved_cfg = config_store.resolve_runtime_config_state(packaged_backend);
                            let updated = resolved_cfg.config.vpn_expectation.clone().unwrap_or_else(VpnExpectation::unconfigured);
                            if updated != expectation {
                                expectation = updated;
                                watch_configs(&mut watcher, &expectation);
                                invalidation = Some("vpn_expectation_changed".into());
                            }
                            if resolved_cfg.blocking_reason().is_none() {
                                let _ = event_tx.send(SupervisionEvent::PolicyUpdated {
                                    config: resolved_cfg.config.clone(), observed_at: now,
                                });
                            }
                        }
                        NetworkEventKind::WatchedFileChanged(path) => {
                            let file = path.file_name().and_then(|s| s.to_str()).unwrap_or("watched_file");
                            invalidation = Some(format!("watched_file_changed:{file}"));
                        }
                        NetworkEventKind::WatchedProcessExited(pid) => {
                            invalidation = Some(format!("vpn_listener_exited:{pid}"));
                        }
                        NetworkEventKind::DarwinNotification(name) => {
                            if name == "com.apple.system.clock_set" { lease_watchdog.unpark(); }
                            invalidation = Some(format!("darwin_notification:{name}"));
                        }
                        NetworkEventKind::ClockDiscontinuity => {
                            lease_watchdog.unpark();
                            invalidation = Some("clock_discontinuity".into());
                        }
                        NetworkEventKind::WakeSignal => { lease_watchdog.unpark(); wake = true; }
                        NetworkEventKind::Timeout => {}
                    }
                }
                if wake { invalidation = Some("system_wake".into()); }
                let source_changed = invalidation.is_some();
                if let Some(reason) = invalidation {
                    consecutive_transient_failures = 0;
                    last_steady_check = None;
                    watcher.set_watched_pids(&[]);
                    if expectation.configured {
                        if let Some(obs) = observer.invalidate_network_event(&reason, &expectation, now) { send(obs); }
                    }
                    refresh = true;
                }
                if wake {
                    let _ = event_tx.send(SupervisionEvent::LeaseExpired { observed_at: now, woke_from_sleep: true });
                }
                let due = renewal_at.is_some_and(|at| now >= at);
                let steady_due = !source_changed
                    && awaiting_revision.is_none()
                    && custom_reader.is_none()
                    && active_guard.has_active_managed()
                    && observer.observed_listener_pid().is_some()
                    && last_steady_check.is_none_or(|at| at.elapsed() >= STEADY_STATE_VPN_CHECK_INTERVAL);
                if !refresh && !due && !steady_due && !retry && !requested_refresh && ready != Some(1) { continue; }

                if let Some(reader) = &custom_reader {
                    if let Ok(transition) = observer.observe_from_reader(reader.as_ref(), &expectation, false, now) {
                        send(transition.observation);
                    }
                } else if expectation.configured {
                    // Event-driven steady-state check: when no local invalidation occurred
                    // and we already have a kernel-verified listener PID, verify PID birth
                    // time + read TAG controller directly without contending on the shared
                    // `watch-native-collector` stream.
                    let can_try_steady = !source_changed
                        && !starting
                        && awaiting_revision.is_none()
                        && (due || steady_due || retry || requested_refresh)
                        && observer.observed_listener_pid().is_some();
                    if can_try_steady {
                        if live_reader.is_none() {
                            match resolve_vpn_controller_credentials(&storage, &expectation.proxy_mode) {
                                Ok(credentials) => {
                                    live_reader = Some(HttpControllerVpnReader::new_live(expectation.proxy_mode.clone(), credentials)
                                        .with_listener_snapshot_result(Box::new(|timeout| {
                                            let runner = super::runtime::runner()?;
                                            claude_watch_runtime::vpn_observer::read_vpn_kernel_snapshot_checked(runner.as_ref(), timeout)
                                        })));
                                }
                                Err(error) => {
                                    live_reader = None;
                                    consecutive_transient_failures = consecutive_transient_failures.saturating_add(1);
                                    if consecutive_transient_failures < MAX_TRANSIENT_VPN_FAILURES
                                        && observer.state.current_observation().is_some_and(|obs| obs.is_fresh(native::now()) && obs.source_error.is_none())
                                    {
                                        retry_after = Some(Instant::now() + TRANSIENT_VPN_RETRY_DELAY);
                                        continue;
                                    }
                                    watcher.set_watched_pids(&[]);
                                    if let Some(obs) = observer.invalidate_if_changed(&error.code, &expectation, native::now()) { send(obs); }
                                    retry_after = Some(Instant::now() + PROCESS_INTERVAL);
                                    continue;
                                }
                            }
                        }
                        if let Some(reader) = &live_reader {
                            let steady_result = observer.observe_steady_state_controller(
                                reader,
                                &expectation,
                                native::now(),
                                collector_loss,
                                |obs| {
                                    let publish = || send(obs.clone());
                                    if let Some(stream) = &listener_stream {
                                        stream.send_if_no_new_failure(seen_failure.get(), publish)
                                    } else {
                                        publish();
                                        Ok(())
                                    }
                                },
                            );
                            match steady_result {
                                Ok(true) => {
                                    consecutive_transient_failures = 0;
                                    retry_after = None;
                                    last_steady_check = Some(Instant::now());
                                    sync_watched_pid(&mut watcher, &observer);
                                    continue;
                                }
                                Ok(false) => {
                                    // No kernel-verified listener frame yet; fall through to full observation.
                                }
                                Err(error) if error.code == "vpn_listener_owner_changed_during_sample" => {
                                    // Confirmed listener PID exit/restart: fail closed immediately and re-sample.
                                    consecutive_transient_failures = 0;
                                    last_steady_check = None;
                                    watcher.set_watched_pids(&[]);
                                    if let Some(obs) = observer.invalidate_network_event(&error.code, &expectation, native::now()) { send(obs); }
                                    if let Some(stream) = &listener_stream {
                                        if let Ok(revision) = stream.request_sample() {
                                            awaiting_revision = Some(revision);
                                        } else {
                                            retry_after = Some(Instant::now() + PROCESS_INTERVAL);
                                        }
                                    } else {
                                        retry_after = Some(Instant::now() + PROCESS_INTERVAL);
                                    }
                                    continue;
                                }
                                Err(error) => {
                                    consecutive_transient_failures = consecutive_transient_failures.saturating_add(1);
                                    if consecutive_transient_failures < MAX_TRANSIENT_VPN_FAILURES
                                        && observer.state.current_observation().is_some_and(|obs| obs.is_fresh(native::now()) && obs.source_error.is_none())
                                    {
                                        retry_after = Some(Instant::now() + TRANSIENT_VPN_RETRY_DELAY);
                                        continue;
                                    }
                                    watcher.set_watched_pids(&[]);
                                    if let Some(obs) = observer.invalidate_if_changed(&error.code, &expectation, native::now()) { send(obs); }
                                    retry_after = Some(Instant::now() + PROCESS_INTERVAL);
                                    continue;
                                }
                            }
                        }
                    }

                    if let Some(stream) = &listener_stream {
                        // Authentication requests the startup frame. A route/config change
                        // requires a strictly post-change frame (`request_sample`); routine
                        // recovery/renewal can join an already in-flight frame (`request_or_join_sample`).
                        if source_changed {
                            match stream.request_sample() {
                                Ok(revision) => { awaiting_revision = Some(revision); }
                                Err(error) => {
                                    watcher.set_watched_pids(&[]);
                                    if let Some(obs) = observer.invalidate_if_changed(&error.code, &expectation, now) { send(obs); }
                                    retry_after = Some(Instant::now() + PROCESS_INTERVAL);
                                    continue;
                                }
                            }
                        } else if awaiting_revision.is_none() && (due || retry || requested_refresh) {
                            match stream.request_or_join_sample() {
                                Ok(revision) => { awaiting_revision = Some(revision); }
                                Err(error) => {
                                    consecutive_transient_failures = consecutive_transient_failures.saturating_add(1);
                                    if consecutive_transient_failures < MAX_TRANSIENT_VPN_FAILURES
                                        && observer.state.current_observation().is_some_and(|obs| obs.is_fresh(native::now()) && obs.source_error.is_none())
                                    {
                                        retry_after = Some(Instant::now() + TRANSIENT_VPN_RETRY_DELAY);
                                        continue;
                                    }
                                    watcher.set_watched_pids(&[]);
                                    if let Some(obs) = observer.invalidate_if_changed(&error.code, &expectation, now) { send(obs); }
                                    retry_after = Some(Instant::now() + PROCESS_INTERVAL);
                                    continue;
                                }
                            }
                        }
                        if let Some(required) = awaiting_revision {
                            if !stream.wait_for_revision(0, Duration::ZERO).is_ok_and(|revision| revision >= required) {
                                continue;
                            }
                            awaiting_revision = None;
                            refresh = true;
                        }
                    }
                    if live_reader.is_none() || refresh || due || requested_refresh {
                        match resolve_vpn_controller_credentials(&storage, &expectation.proxy_mode) {
                            Ok(credentials) => {
                                live_reader = Some(HttpControllerVpnReader::new_live(expectation.proxy_mode.clone(), credentials)
                                    .with_listener_snapshot_result(Box::new(|timeout| {
                                        let runner = super::runtime::runner()?;
                                        claude_watch_runtime::vpn_observer::read_vpn_kernel_snapshot_checked(runner.as_ref(), timeout)
                                    })));
                            }
                            Err(error) => {
                                live_reader = None;
                                watcher.set_watched_pids(&[]);
                                if let Some(obs) = observer.invalidate_if_changed(&error.code, &expectation, native::now()) { send(obs); }
                                retry_after = Some(Instant::now() + PROCESS_INTERVAL);
                                continue;
                            }
                        }
                    }
                    let Some(reader) = &live_reader else { continue };
                    let result = observer.observe_listener_event(reader, &expectation, refresh || due || requested_refresh,
                        native::now(), collector_loss, |obs| {
                            let publish = || send(obs.clone());
                            if let Some(stream) = &listener_stream { stream.send_if_no_new_failure(seen_failure.get(), publish) }
                            else { publish(); Ok(()) }
                        });
                    if let Err(error) = result {
                        consecutive_transient_failures = consecutive_transient_failures.saturating_add(1);
                        if !source_changed
                            && consecutive_transient_failures < MAX_TRANSIENT_VPN_FAILURES
                            && observer.state.current_observation().is_some_and(|obs| obs.is_fresh(native::now()) && obs.source_error.is_none())
                        {
                            retry_after = Some(Instant::now() + TRANSIENT_VPN_RETRY_DELAY);
                        } else {
                            watcher.set_watched_pids(&[]);
                            if let Some(obs) = observer.invalidate_if_changed(&error.code, &expectation, native::now()) { send(obs); }
                            retry_after = Some(Instant::now() + PROCESS_INTERVAL);
                        }
                    } else {
                        consecutive_transient_failures = 0;
                        retry_after = None;
                        last_steady_check = Some(Instant::now());
                        sync_watched_pid(&mut watcher, &observer);
                    }
                } else {
                    retry_after = None;
                    awaiting_revision = None;
                    last_steady_check = None;
                    consecutive_transient_failures = 0;
                    watcher.set_watched_pids(&[]);
                    if observer.state.current_observation().is_some() {
                        if let Some(obs) = observer.invalidate_if_changed("vpn_expectation_unconfigured", &expectation, now) { send(obs); }
                    }
                }
            }
        })
        .map_err(|_| CoreError::new("vpn_observer_worker_failed", "VPN 状态只读观察线程启动失败"))?;
    Ok((handle, wake_handle))
}

#[cfg(test)]
pub fn assemble_production_channel_stack<F>(
    storage: StateStore,
    stop: Arc<AtomicBool>,
    activate_local_interception: bool,
    run_audit: F,
) -> Result<ProductionChannelStack>
where
    F: Fn(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + Sync + 'static,
{
    assemble_production_channel_stack_with_vpn_reader(
        storage,
        stop,
        activate_local_interception,
        None,
        run_audit,
    )
}

#[cfg(test)]
pub fn assemble_production_channel_stack_with_vpn_reader<F>(
    storage: StateStore,
    stop: Arc<AtomicBool>,
    activate_local_interception: bool,
    custom_vpn_reader: Option<Arc<dyn VpnSourceReader>>,
    run_audit: F,
) -> Result<ProductionChannelStack>
where
    F: Fn(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + Sync + 'static,
{
    let diagnostics = ChannelDiagnostics::new(storage.clone());
    assemble_channel_stack_with_diagnostics(
        storage,
        stop,
        activate_local_interception,
        custom_vpn_reader,
        diagnostics,
        std::sync::mpsc::channel(),
        Arc::new(ActiveGuardState::default()),
        None,
        run_audit,
    )
}

fn assemble_channel_stack_with_diagnostics<F>(
    storage: StateStore, stop: Arc<AtomicBool>, activate_local_interception: bool,
    custom_vpn_reader: Option<Arc<dyn VpnSourceReader>>, diagnostics: ChannelDiagnostics,
    (event_tx, event_rx): (Sender<SupervisionEvent>, Receiver<SupervisionEvent>),
    active_guard: Arc<ActiveGuardState>,
    sampling_wake: Option<UnixStream>,
    run_audit: F,
) -> Result<ProductionChannelStack>
where F: Fn(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + Sync + 'static,
{
    let resources_dir = locate_runtime_resources_dir(&storage);
    let packaged_backend = resources_dir
        .as_deref()
        .and_then(lookup_packaged_network_backend);
    let resolved_cfg = ConfigStore {
        storage: storage.clone(),
    }
    .resolve_runtime_config_state(packaged_backend);
    let config = resolved_cfg.config.clone();
    let config_blocking_reason = resolved_cfg.blocking_reason();
    let initial_policy_version = ChannelSupervisor::compute_policy_version(&config)?;
    let boot_id = format!(
        "daemon-{}-{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let enforcer = Arc::new(LocalTunnelEnforcer::new(boot_id.clone()));
    enforcer.set_clock(native::now)?;
    enforcer.set_diagnostics(diagnostics.clone())?;
    enforcer.set_strict_peer_verification(activate_local_interception);

    let sandbox_registry: Option<Arc<SandboxLaunchRegistry>> = None;
    let sandbox_registration_worker: Option<claude_watch_system::ListenerWorker> = None;

    let now_ts = native::now();
    enforcer.configure_seatbelt_backend(false, now_ts)?;
    if let Some(ref reason) = config_blocking_reason {
        enforcer.record_activation_failure(reason, now_ts)?;
    }

    let _ = enforcer.publish_protocol_coverage(&storage);
    register_production_enforcer(&storage.paths.watch(), enforcer.clone());


    // Wire receipt sink: Active and closed flows immediately emit events to supervisor
    let sink_tx = event_tx.clone();
    let _ = enforcer.set_receipt_event_sink(move |receipt| {
        let received_at = native::now();
        let _ = sink_tx.send(SupervisionEvent::EnforcementReceiptArrived {
            receipt,
            received_at,
        });
    });

    let lease_watchdog = enforcer.spawn_lease_watchdog(stop.clone(), native::now)?;

    let (vpn_observer_worker, vpn_wake_handle) =
        if activate_local_interception || custom_vpn_reader.is_some() {
            let (worker, wake) = spawn_vpn_observation_worker(
                storage.clone(),
                packaged_backend,
                stop.clone(),
                event_tx.clone(),
                lease_watchdog.thread().clone(),
                active_guard.clone(),
                custom_vpn_reader,
            )?;
            (Some(worker), Some(wake))
        } else {
            (None, None)
        };

    let (audit_req_tx, async_audit_worker) =
        ChannelSupervisor::spawn_async_audit_worker(stop.clone(), event_tx.clone(), run_audit)?;

    let mut supervisor = ChannelSupervisor::new_with_config(
        storage.clone(),
        config,
        config_blocking_reason,
        Some(enforcer.clone()),
        Some(audit_req_tx),
    )?;

    supervisor.set_diagnostics(diagnostics);
    supervisor.set_inline_receipt_clock(native::now);
    let process_disposition_worker = if activate_local_interception {
        let (dispatcher, worker) = claude_watch_runtime::process_disposition::ProcessDispositionDispatcher::start(
            storage, stop.clone(), event_tx.clone())?;
        supervisor.install_process_disposition_dispatcher(dispatcher);
        Some(worker)
    } else { None };

    let mut stack = ProductionChannelStack {
        stop,
        packaged_backend,
        enforcer,
        sandbox_registry,
        supervisor,
        event_tx,
        event_rx,
        vpn_wake_handle,
        last_vpn_refresh_signal: None,
        lease_watchdog,
        async_audit_worker,
        process_disposition_worker,
        sandbox_registration_worker,
        vpn_observer_worker,
        last_policy_version: Some(initial_policy_version),
        activate_local_interception,
        local_proxy_worker: None,
        target_refresh_worker: None,
        target_refresh_cancel: None,
        sampling_wake,
        backend_refresh_requested: false,
        active_guard,
        #[cfg(all(test, target_os = "macos"))]
        private_loopback_backend: false,
    };
    stack.reconcile_controlled_backend(now_ts)?;
    Ok(stack)
}

impl ProductionChannelStack {
    fn backend_workers_ready(&self) -> bool {
        self.supervisor.config_blocking_reason().is_none()
            && self.target_refresh_worker.as_ref().is_some_and(|worker| !worker.is_finished())
            && (!self.activate_local_interception
                || (self.sandbox_registration_worker.as_ref().is_some_and(|worker| !worker.is_finished())
                    && self.local_proxy_worker.as_ref().is_some_and(|worker| !worker.is_finished())))
    }

    fn listener_exit_notice(&self) -> impl FnOnce() + Send + 'static {
        let stop = self.stop.clone();
        let events = self.event_tx.clone();
        move || {
            if !stop.load(Ordering::Acquire) {
                // Wake the authority to check the terminated component and review live leases.
                let _ = events.send(SupervisionEvent::LeaseExpired { observed_at: native::now(), woke_from_sleep: false });
            }
        }
    }

    fn deliver_background_event(&mut self, event: SupervisionEvent) -> Result<()> {
        self.deliver_event_at(event, native::now())
    }

    #[cfg(test)]
    pub fn drain_background_events(&mut self) -> Result<()> {
        while let Ok(ev) = self.event_rx.try_recv() {
            self.deliver_background_event(ev)?;
        }
        Ok(())
    }

    /// Initial assembly and later recovery share one registry and independent component state.
    pub fn reconcile_controlled_backend(&mut self, now: f64) -> Result<()> {
        #[cfg(all(test, target_os = "macos"))]
        if self.private_loopback_backend {
            return self.reconcile_controlled_backend_with_listeners(now,
                |reg, path, stop| reg.start_registration_listener(path, stop),
                |enforcer, stop, now| enforcer.start_local_proxy_listener("127.0.0.1:0", stop, now));
        }
        self.reconcile_controlled_backend_with_listeners(now,
            |reg, path, stop| reg.start_registration_listener(path, stop),
            |enforcer, stop, now| {
                let verified = claude_watch_system::launchd_gateway::acquire_gateway_listener()
                    .map_err(|error| CoreError::new("gateway_endpoint_unverified_i03", &format!("系统托管网关不可用：{error}")))?;
                enforcer.start_verified_proxy_listener(verified, stop, now)
            })
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn start_private_loopback_backend(&mut self) -> Result<()> {
        if !super::entry_ready_fixture::is_private_fixture_home(&self.supervisor.storage.paths.home) {
            return Err(CoreError::new("fixture_home_required", "只允许为本轮自有临时目录绑定回环端口"));
        }
        self.private_loopback_backend = true;
        self.activate_local_interception = true;
        self.enforcer.set_strict_peer_verification(true);
        self.reconcile_controlled_backend(native::now())
    }

    fn synchronize_runtime_policy(&mut self, config: claude_watch_core::config::Config, now: f64) -> Result<()> {
        let version = ChannelSupervisor::compute_policy_version(&config)?;
        if self.supervisor.saved_policy_version() != &version {
            self.supervisor.handle_event(SupervisionEvent::PolicyUpdated { config, observed_at: now })?;
        }
        if let Some(reg) = &self.sandbox_registry { reg.update_policy_version(version.clone()); }
        self.last_policy_version = Some(version);
        Ok(())
    }

    fn reconcile_controlled_backend_with_listeners<R, P>(&mut self, now: f64, start_registration: R, start_proxy: P) -> Result<()>
    where R: FnOnce(&Arc<SandboxLaunchRegistry>, &std::path::Path, Arc<AtomicBool>) -> Result<claude_watch_system::ListenerWorker>,
          P: FnOnce(&Arc<LocalTunnelEnforcer>, Arc<AtomicBool>, f64) -> Result<(std::net::SocketAddr, claude_watch_system::ListenerWorker)>,
    {
        let resolved = (ConfigStore { storage: self.supervisor.storage.clone() })
            .resolve_runtime_config_state(self.packaged_backend);
        if let Some(reason) = resolved.blocking_reason() {
            self.supervisor.set_config_blocking_reason(Some(reason), now)?;
            return Ok(());
        }
        self.synchronize_runtime_policy(resolved.config, now)?;
        self.supervisor.set_config_blocking_reason(None, now)?;
        let resources = locate_runtime_resources_dir(&self.supervisor.storage);
        if self.sandbox_registry.is_none() {
            let verifier = resources.as_deref().ok_or_else(|| CoreError::new("helper_manifest_missing", "缺少受控运行组件目录"))
                .and_then(|dir| build_helper_verifier_from_manifest(dir, &dir.join("watch-sandbox-launcher")));
            let verifier = match verifier {
                Ok(v) => v,
                Err(err) => {
                    self.enforcer.configure_seatbelt_backend(false, now)?;
                    self.enforcer.record_activation_failure(&err.code, now)?;
                    return Ok(());
                }
            };
            let reg = Arc::new(SandboxLaunchRegistry::new(self.enforcer.boot_id()?,
                self.supervisor.saved_policy_version().clone(), verifier, Some(self.supervisor.storage.clone())));
            let attribution_registry = Arc::clone(&reg);
            self.enforcer.set_accepted_connection_attributor(move |ctx| attribution_registry.attribute_accepted_connection(ctx, native::now()))?;
            // Retain this exact Arc even when only one listener starts successfully.
            self.sandbox_registry = Some(reg);
        }
        let reg = self.sandbox_registry.as_ref().unwrap().clone();
        self.supervisor.set_process_disposition_registry(reg.clone());
        if self.target_refresh_worker.as_ref().is_some_and(|h| h.is_finished()) {
            let _ = self.target_refresh_worker.take().unwrap().join();
        }
        if self.target_refresh_worker.is_none() {
            let (worker, cancel) = spawn_target_refresh_worker(
                self.supervisor.storage.clone(),
                resources,
                reg.clone(),
                self.stop.clone(),
                self.event_tx.clone(),
                self.sampling_wake.as_ref().and_then(|s| s.try_clone().ok()),
            )?;
            self.target_refresh_worker = Some(worker);
            self.target_refresh_cancel = Some(cancel);
        }
        let mut component_error = None;
        if self.activate_local_interception {
            if self.sandbox_registration_worker.as_ref().is_some_and(|h| h.is_finished()) {
                let _ = self.sandbox_registration_worker.take().unwrap().join();
            }
            if self.local_proxy_worker.as_ref().is_some_and(|h| h.is_finished()) {
                let _ = self.local_proxy_worker.take().unwrap().join();
            }
            if self.sandbox_registration_worker.is_none() {
                match start_registration(&reg, &default_registration_socket_path(&self.supervisor.storage.paths.watch()), self.stop.clone()) {
                    Ok(worker) => {
                        worker.on_exit(self.listener_exit_notice());
                        self.sandbox_registration_worker = Some(worker);
                    }
                    Err(err) => component_error = Some(err.code),
                }
            }
            if self.local_proxy_worker.is_none() {
                match start_proxy(&self.enforcer, self.stop.clone(), now) {
                    Ok((_, worker)) => {
                        worker.on_exit(self.listener_exit_notice());
                        self.local_proxy_worker = Some(worker);
                    }
                    Err(err) => component_error = Some(err.code),
                }
            }
        }
        let components_ready = self.sandbox_registration_worker.as_ref().is_some_and(|worker| !worker.is_finished())
            && self.local_proxy_worker.as_ref().is_some_and(|worker| !worker.is_finished());
        reg.set_gateway_endpoint_protection(self.enforcer.gateway_endpoint_protection()?);
        // The kernel attribution callback was installed on this same registry
        // above. Individual connections still require their own live evidence.
        let report = reg.identity_report(true, components_ready, true);
        let sandbox_ready = self.apply_backend_identity_gate(&report, components_ready, now)?;
        if let Some(code) = component_error { self.enforcer.record_activation_failure(&code, now)?; }
        // Configuration/registration metadata is not an execution receipt or an applied policy.
        reg.publish_runtime_state(self.supervisor.saved_policy_version(), self.enforcer.local_proxy_port(),
            components_ready, components_ready && sandbox_ready && self.enforcer.sandbox_ready()?, &report, now)?;
        Ok(())
    }

    fn apply_backend_identity_gate(
        &self, report: &claude_watch_runtime::sandbox_launch::SandboxGatewayIdentityReport,
        _components_ready: bool, now: f64,
    ) -> Result<bool> {
        #[cfg(all(test, target_os = "macos"))]
        if self.private_loopback_backend {
            // The loopback fixture substitutes only for the broker boundary.
            // Keep the actual identity report; it still lacks I03 proof.
            self.enforcer.configure_seatbelt_backend(_components_ready, now)?;
            return self.enforcer.sandbox_ready();
        }
        self.enforcer.configure_seatbelt_backend_with_identity_gate(report, now)
    }

    fn deliver_event_at(&mut self, event: SupervisionEvent, delivered_at: f64) -> Result<()> {
        if matches!(&event, SupervisionEvent::PolicyUpdated { .. } | SupervisionEvent::ExecutorRestarted { .. }) {
            self.backend_refresh_requested = true;
        }
        if let SupervisionEvent::ProcessInventoryUpdated { family, processes, .. } = &event {
            if let Some(reg) = &self.sandbox_registry {
                let verified_tokens = reg.verified_family_tokens(family, delivered_at);
                let mut protected_pids: Vec<u32> = processes
                    .iter()
                    .filter(|token| {
                        verified_tokens
                            .iter()
                            .any(|verified| verified.same_verified_kernel_identity(token))
                    })
                    .map(|t| t.pid)
                    .collect();
                protected_pids.sort_unstable();
                protected_pids.dedup();
                let mut unprotected_pids: Vec<u32> = processes.iter()
                    .filter(|t| !protected_pids.contains(&t.pid)).map(|t| t.pid).collect();
                unprotected_pids.sort_unstable();
                unprotected_pids.dedup();
                // All identities from the verified inventory enter supervision.
                // Sandbox registration determines gateway coverage only.
                let id_report = reg.identity_report(true, true, true);
                self.supervisor.set_family_unmanaged_pids(family, unprotected_pids.clone(), delivered_at);
                self.supervisor.set_family_coverage_scope(family, Some(BackendCoverageScope {
                    backend: NetworkBackendKind::Seatbelt, configured_entries: vec![family.to_owned()],
                    protected_pids, unprotected_pids,
                    uncovered_boundaries: vec!["unmanaged_existing_processes".into(),
                        "direct_launch_outside_controlled_entry".into()],
                    server_identity_verified: id_report.gateway_server_identity_verified,
                    gateway_endpoint_protection_verified: id_report.gateway_endpoint_protection_verified,
                    gateway_endpoint_protection_method: id_report.gateway_endpoint_protection_method,
                }), delivered_at);
            }
        }
        let prev_vpn_epoch = self.supervisor.latest_vpn_observation().map(|o| o.epoch.clone());
        let prev_vpn_healthy = self.supervisor.latest_vpn_observation().is_some_and(|o| o.source_error.is_none());
        let trigger_hint = matches!(
            &event,
            SupervisionEvent::PolicyUpdated { .. }
                | SupervisionEvent::NetworkContextChanged { .. }
                | SupervisionEvent::ExecutorRestarted { .. }
                | SupervisionEvent::LeaseExpired { woke_from_sleep: true, .. }
        );
        self.supervisor.handle_queued_event(event, delivered_at)?;
        let next_vpn_epoch = self.supervisor.latest_vpn_observation().map(|o| o.epoch.clone());
        let next_vpn_healthy = self.supervisor.latest_vpn_observation().is_some_and(|o| o.source_error.is_none());
        let vpn_changed = next_vpn_epoch != prev_vpn_epoch || next_vpn_healthy != prev_vpn_healthy;
        let families_added = self.active_guard.update_families(self.supervisor.active_managed_families());
        if trigger_hint || vpn_changed || families_added {
            self.active_guard.request_immediate_probe();
        }
        if self.supervisor.needs_proactive_vpn_refresh(delivered_at) {
            self.request_vpn_refresh_now();
        }
        Ok(())
    }

    fn request_vpn_refresh_now(&mut self) {
        const MIN_ON_DEMAND_VPN_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
        if self
            .last_vpn_refresh_signal
            .is_some_and(|at| at.elapsed() < MIN_ON_DEMAND_VPN_REFRESH_INTERVAL)
        {
            return;
        }
        if let Some(stream) = self.vpn_wake_handle.as_mut() {
            use std::io::Write;
            if stream.write(b"R").is_ok() {
                self.last_vpn_refresh_signal = Some(Instant::now());
            }
        }
    }

    /// Production authority loop: slow network/process reads and guard_ticks
    /// live on a separate collector thread. Deadlines and VPN updates never wait
    /// for that thread to finish a round.
    fn run_authority_loop(
        &mut self, stop: &AtomicBool,
        worker_finished: impl Fn() -> bool,
        producer: Option<&claude_watch_core::processes::Identity>,
    ) -> Result<()> {
        let mut next_reconcile = (!self.backend_workers_ready()).then(|| Instant::now() + PROCESS_INTERVAL);
        let mut backend_retry = PROCESS_INTERVAL;
        let mut reviewed_at = None;
        let mut retry_review = None;
        let mut next_heartbeat = producer.map(|_| Instant::now());
        let pulse_event = |event: &SupervisionEvent| matches!(event,
            SupervisionEvent::VpnObservationUpdated { .. } | SupervisionEvent::VpnObservationUnavailable { .. }
            | SupervisionEvent::PolicyUpdated { .. } | SupervisionEvent::ExecutorRestarted { .. });
        while !stop.load(Ordering::Acquire) {
            if worker_finished() {
                return Err(CoreError::new("guard_collector_failed", "保护采集线程已退出"));
            }
            // Bound each drain so an event burst cannot starve lease checks.
            // Preserve the former loop's fail-closed/retry behavior on a bad
            // state read instead of terminating every background worker.
            for _ in 0..64 {
                let Ok(event) = self.event_rx.try_recv() else { break; };
                if producer.is_some() && pulse_event(&event) { next_heartbeat = Some(Instant::now()); }
                let result = self.deliver_background_event(event);
                self.retain_authority_after_error(result)?;
            }
            // Only authority progress renews the service pulse. Collector
            // receipts and permissions keep their independent observation times.
            if let Some(producer) = producer.filter(|_| next_heartbeat.is_some_and(|at| Instant::now() >= at)) {
                claude_watch_runtime::services::record_guard_heartbeat(&self.supervisor.storage, producer, native::now())?;
                next_heartbeat = Some(Instant::now() + claude_watch_runtime::macos::GUARD_SERVICE_PULSE_MAX_AGE * 2 / 3);
            }
            let now = native::now();
            let rollback = reviewed_at.is_some_and(|at| now < at);
            let due = reviewed_at.and_then(|at| self.supervisor.next_evidence_deadline(at));
            if reviewed_at.is_none() || rollback || due.is_some_and(|at| now >= at)
                || retry_review.is_some_and(|at| Instant::now() >= at) {
                let result = self.deliver_background_event(SupervisionEvent::LeaseExpired {
                    observed_at: now, woke_from_sleep: rollback,
                });
                retry_review = result.is_err().then(|| Instant::now() + PROCESS_INTERVAL);
                self.retain_authority_after_error(result)?;
                reviewed_at = Some(now);
            }
            let backend_due = next_reconcile.map_or_else(|| !self.backend_workers_ready(), |at| Instant::now() >= at);
            if !stop.load(Ordering::Acquire) && (self.backend_refresh_requested || backend_due) {
                if self.backend_refresh_requested { backend_retry = PROCESS_INTERVAL; }
                self.backend_refresh_requested = false;
                let result = self.reconcile_controlled_backend(native::now());
                let failed = result.is_err();
                self.retain_authority_after_error(result)?;
                let receipt_lifetime = Duration::from_secs_f64(claude_watch_core::channel::MAX_ENFORCEMENT_RECEIPT_AGE);
                next_reconcile = if !failed && self.backend_workers_ready() {
                    backend_retry = PROCESS_INTERVAL;
                    None
                } else {
                    let at = Instant::now() + backend_retry;
                    backend_retry = (backend_retry * 2).min(receipt_lifetime);
                    Some(at)
                };
            }
            let mut wait = [next_reconcile, next_heartbeat, retry_review].into_iter().flatten().min()
                .map(|at| at.saturating_duration_since(Instant::now()));
            if let Some(at) = reviewed_at.and_then(|last| self.supervisor.next_evidence_deadline(last)) {
                let due = Duration::from_secs_f64((at - native::now()).max(0.0));
                wait = Some(wait.map_or(due, |budget| budget.min(due)));
            }
            let received = match wait {
                Some(wait) => self.event_rx.recv_timeout(wait),
                None => self.event_rx.recv().map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(event) => {
                    if stop.load(Ordering::Acquire) { break; }
                    if producer.is_some() && pulse_event(&event) { next_heartbeat = Some(Instant::now()); }
                    let result = self.deliver_background_event(event);
                    self.retain_authority_after_error(result)?;
                },
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) =>
                    return Err(CoreError::new("supervision_channel_closed", "保护事件通道已关闭")),
            }
        }
        Ok(())
    }

    fn retain_authority_after_error(&self, result: Result<()>) -> Result<()> {
        if result.is_err() {
            let now = native::now();
            for family in PolicyCatalog::families() {
                self.enforcer.revoke_family(family.id, "authority_evidence_unavailable", now)?;
            }
        }
        Ok(())
    }

    /// Tests supply observation inputs to the actual authority ingestion path.
    #[cfg(test)]
    pub(crate) fn step_with_observations(&mut self, observations: Vec<SupervisionEvent>, now: f64) -> Result<ChannelMonitorSnapshot> {
        self.drain_background_events()?;
        self.reconcile_controlled_backend(now)?;
        for observation in observations { self.deliver_event_at(observation, now)?; }
        self.drain_background_events()?;
        Ok(self.supervisor.snapshot(now))
    }

    #[cfg(test)]
    pub fn wait_or_drain(&mut self, deadline: Instant, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let wait_for = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100));
            match self.event_rx.recv_timeout(wait_for) {
                Ok(ev) => {
                    let _ = self.deliver_background_event(ev);
                    let _ = self.drain_background_events();
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    thread::sleep(wait_for);
                }
            }
        }
    }

    pub fn shutdown(self) {
        // The guard loop can leave on error while the daemon is still alive.
        // Signal the owned workers before joining; callers need not do it first.
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = &self.sandbox_registration_worker { worker.cancel(); }
        if let Some(worker) = &self.local_proxy_worker { worker.cancel(); }
        self.lease_watchdog.thread().unpark();
        let now = native::now();
        for family in PolicyCatalog::families() {
            let _ = self.enforcer.revoke_family(family.id, "daemon_shutdown", now);
        }
        unregister_production_enforcer(&self.supervisor.storage.paths.watch());
        drop(self.supervisor);
        let _ = self.lease_watchdog.join();
        let _ = self.async_audit_worker.join();
        if let Some(worker) = self.process_disposition_worker { let _ = worker.join(); }
        if let Some(worker) = self.sandbox_registration_worker { let _ = worker.join(); }
        if let Some(worker) = self.local_proxy_worker { let _ = worker.join(); }
        drop(self.target_refresh_cancel);
        if let Some(worker) = self.target_refresh_worker { let _ = worker.join(); }
        drop(self.vpn_wake_handle);
        if let Some(worker) = self.vpn_observer_worker { let _ = worker.join(); }
    }
}

/// `PROCESS_INTERVAL` rounds of continuous degradation before the user is
/// interrupted (15 × 2 s ≈ 30 s).
const SUSTAINED_SAMPLING_ROUNDS: u32 = 15;
/// While an outage continues, remind at most once per half hour.
const SAMPLING_QUIET: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
struct ProtectionNoticeGate {
    incidents: std::collections::BTreeMap<String, (String, std::collections::BTreeSet<String>)>,
}
impl ProtectionNoticeGate {
    fn pending(&mut self, receipt: &Value) -> Vec<(String, String, String)> {
        let rows: Vec<&Value> = receipt["families"].as_array()
            .map(|v| v.iter().collect()).unwrap_or_else(|| vec![receipt]);
        let mut pending = Vec::new();
        for row in rows {
            let family = row["family"].as_str().unwrap_or("claude");
            if PolicyCatalog::family(family).is_none() { continue; }
            if row["status"] == "disabled" || row["channel_supervision"]["verdict"] == "forwarding_verified" {
                self.incidents.remove(family);
                continue;
            }
            if !matches!(row["action"].as_str(), Some("close-desktop" | "disconnect-channel"
                | "disconnect-and-force-quit" | "disconnect-and-partial-force-quit")) { continue; }
            let reason = row["channel_permit"]["reason_code"].as_str()
                .or_else(|| row["session_guard"]["reason"]["code"].as_str()).unwrap_or("unknown");
            let cause = if matches!(reason, "vpn_observation_stale" | "vpn_observation_unknown") {
                "VPN 观测证据暂不可确认"
            } else if reason == "permit_lease_expired" { "通道许可已到期" }
            else { "保护条件未满足" };
            let verdict = row["channel_supervision"]["verdict"].as_str().unwrap_or("unconfirmed");
            let (outcome, result) = if row["process_execution_state"] == "partially_terminated" {
                ("partially_terminated", "部分进程已退出，其余进程的处置尚未确认")
            } else if row["process_preserved"] == false
                && matches!(row["process_execution_state"].as_str(), Some("confirmed" | "already_exited")) {
                ("terminated", "已确认进程退出")
            } else if verdict == "isolated_keep_process" {
                ("blocked", "通道已确认阻断，进程保留")
            } else if verdict == "pending_isolation" {
                ("pending", "已请求阻断，等待执行结果")
            } else { ("unconfirmed", "当前执行结果待核验") };
            // Command numbers and observation times are not new incidents.
            let reason_key = if reason.starts_with("vpn_observation_") { "vpn_observation_unavailable" } else { reason };
            let incident = json!([row["channel_permit"]["session_id"], reason_key]).to_string();
            if self.incidents.get(family).is_some_and(|(prior, seen)| prior == &incident && seen.contains(outcome)) {
                continue;
            }
            let key = json!([incident, outcome]).to_string();
            let name = if family == "claude" { "Claude" } else { "ChatGPT / Codex" };
            pending.push((family.into(), key, format!("{name}：{cause}；{result}。")));
        }
        pending
    }
    fn accept(&mut self, pending: Vec<(String, String, String)>) {
        for (family, key, _) in pending {
            let (incident, outcome): (String, String) = serde_json::from_str(&key).expect("internal incident key");
            let entry = self.incidents.entry(family).or_default();
            if entry.0 != incident { entry.0 = incident; entry.1.clear(); }
            entry.1.insert(outcome);
        }
    }
}
/// Stable identity of a non-empty evidence set.
///
/// `None` means "nothing to report". Two equal signatures describe the same
/// standing fact, so the owner reports it once instead of once per sampling
/// round.
fn evidence_signature(rows: &Value) -> Option<String> {
    let rows = rows.as_array()?;
    if rows.is_empty() {
        return None;
    }
    Some(Value::Array(rows.clone()).to_string())
}

/// A process inventory has no reliable global launch notification for CLI
/// processes. Keep its existing evidence budget, wake early on route changes,
/// and wake immediately when a sandboxed process registers or gets attributed.
fn wait_for_sampling_event(watcher: &mut NetworkEventWatcher, mut frames: Option<&mut UnixStream>,
    mut sampling_wake: Option<&mut UnixStream>,
    source: Option<&claude_watch_runtime::native_listener::ListenerStream>, last_revision: &mut u64,
    requested: &mut Option<u64>, mut deadline: Instant, stop: &AtomicBool, shutdown: &UnixStream) -> Result<bool> {
    use std::io::Read;
    let mut network_changed = false;
    while !stop.load(Ordering::Acquire) {
        let pending = source.map(|s| s.wait_for_revision(0, Duration::ZERO)).transpose()?
            .is_some_and(|revision| revision > *last_revision);
        let source_deadline = source.map(|s| s.pending_sample_deadline()).transpose()?.flatten();
        let wake_at = source_deadline.map_or(deadline, |at| at.min(deadline));
        let timeout = if pending { Duration::ZERO } else { wake_at.saturating_duration_since(Instant::now()) };
        let mut readers = vec![shutdown.as_fd()];
        let frames_index = frames.as_ref().map(|fd| {
            readers.push(fd.as_fd());
            readers.len() - 1
        });
        let wake_index = sampling_wake.as_ref().map(|fd| {
            readers.push(fd.as_fd());
            readers.len() - 1
        });
        let (events, ready) = watcher.wait_with_readers(timeout, &readers);
        if ready == Some(0) || stop.load(Ordering::Acquire) { break; }
        if frames_index.is_some() && ready == frames_index {
            if let Some(stream) = &mut frames { let _ = stream.read(&mut [0; 256]); }
        }
        if wake_index.is_some() && ready == wake_index {
            if let Some(stream) = &mut sampling_wake { let _ = stream.read(&mut [0; 256]); }
            break;
        }
        let change = events.iter().any(|event| !matches!(event, NetworkEventKind::Timeout));
        network_changed |= change;
        let expired = Instant::now() >= deadline;
        let Some(source) = source else {
            if change || expired { break; }
            continue;
        };
        source.pending_sample_deadline()?;
        let revision = source.wait_for_revision(0, Duration::ZERO)?;
        let demand = change || (expired && requested.is_none() && revision == *last_revision);
        if demand {
            // A frame coalesced with a route change predates that change.
            // Even a disconnected source must reconnect and capture again.
            *requested = Some(revision + 1);
            *requested = Some(source.request_sample()?);
            deadline = Instant::now() + Duration::from_secs_f64(claude_watch_runtime::process_disposition::INTENT_TTL / 2.0);
        }
        if let Some((at, error)) = source.failure_since(*last_revision) {
            *last_revision = at;
            if at == revision && requested.is_none_or(|required| at >= required) {
                // This request produced an unavailable listener observation. The
                // listener reader exposes its error, while independent process and
                // network sources still need a normal, separately verified round.
                *requested = None;
                break;
            }
            return Err(error);
        }
        if revision > *last_revision {
            *last_revision = revision;
            if requested.is_none_or(|required| revision >= required) {
                *requested = None;
                break;
            }
        }
        if expired && !demand {
            return Err(CoreError::new("native_observation_unavailable", "等待新的原生监听采样超时"));
        }
    }
    Ok(network_changed)
}

// An online baseline can take much longer than a guard heartbeat interval.
// Collect it independently so login/reboot cannot stall the guard worker.
fn spawn_baseline<F>(stop: Arc<AtomicBool>, mut collect: F) -> Result<thread::JoinHandle<()>>
where
    F: FnMut() -> Result<bool> + Send + 'static,
{
    thread::Builder::new()
        .name("claude-environment-baseline".into())
        .spawn(move || {
            for _ in 0..3 {
                if stop.load(Ordering::Acquire) || collect().is_ok() {
                    break;
                }
            }
        })
        .map_err(|_| CoreError::new("baseline_start_failed", "后台环境采样线程无法启动"))
}
// Discovery reads application metadata and may hash executable contents. It
// must never hold the process/proxy publisher or the risk loop behind its lock.
// The owner also cancels/joins on early daemon errors, not just normal shutdown.
struct DiscoveryWorker {
    discovery: claude_watch_runtime::target_discovery::DiscoveryHandle,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl DiscoveryWorker {
    fn start<R: claude_watch_runtime::commands::ReadRunner + Send + Sync + 'static>(
        discovery: claude_watch_runtime::target_discovery::DiscoveryHandle,
        runner: R,
        stop: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut requests = discovery.subscribe_background_requests()
            .map_err(|_| CoreError::new("discovery_worker_failed", "应用发现变更通知通道无法启动"))?;
        discovery.cancel_pending_when(stop.clone());
        discovery.enable_background_observation();
        let cancelled = stop.clone();
        let worker_handle = discovery.clone();
        let worker = thread::Builder::new().name("watch-installation-discovery".into()).spawn(move || {
            use std::io::Read;
            let mut watcher = NetworkEventWatcher::new(&[]);
            let mut inputs = worker_handle.background_watch_paths();
            watcher.set_watched_files(inputs.clone());
            let mut last_incomplete_revision: Option<String> = None;
            let mut incomplete_streak: u32 = 0;
            while !cancelled.load(Ordering::Acquire) {
                let started = Instant::now();
                let snapshot = worker_handle.refresh(&runner, native::now());
                let updated = worker_handle.background_watch_paths();
                if inputs != updated {
                    watcher.set_watched_files(updated.clone());
                    inputs = updated;
                }
                let maximum_age = if snapshot.complete {
                    last_incomplete_revision = None;
                    incomplete_streak = 0;
                    claude_watch_runtime::target_discovery::APPLICATION_REGISTRY_MAX_AGE
                } else {
                    if last_incomplete_revision.as_deref() == Some(snapshot.revision.as_str()) {
                        incomplete_streak = incomplete_streak.saturating_add(1).min(4);
                    } else {
                        last_incomplete_revision = Some(snapshot.revision.clone());
                        incomplete_streak = 0;
                    }
                    PROCESS_INTERVAL
                        .saturating_mul(1u32 << incomplete_streak)
                        .min(claude_watch_runtime::target_discovery::APPLICATION_REGISTRY_MAX_AGE)
                };
                let (events, ready) = watcher.wait_with_readers(maximum_age.saturating_sub(started.elapsed()), &[requests.as_fd()]);
                if events.iter().any(|event| !matches!(event, NetworkEventKind::Timeout)) || ready.is_some() {
                    last_incomplete_revision = None;
                    incomplete_streak = 0;
                }
                if ready.is_some() {
                    let mut bytes = [0; 1024];
                    while let Ok(n) = requests.read(&mut bytes) {
                        if n == 0 { return; }
                    }
                }
            }
        }).map_err(|_| CoreError::new("discovery_worker_failed", "应用发现工作线程无法启动"))?;
        Ok(Self { discovery, stop, worker: Some(worker) })
    }
}
impl Drop for DiscoveryWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.discovery.request_background_refresh();
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

fn ensure_default_auto_update_enabled<R, T, M>(
    store: &StateStore,
    host: &mut claude_watch_runtime::macos::Macos<R, T, M>,
) where
    R: claude_watch_runtime::commands::ReadRunner,
    T: claude_watch_runtime::network_client::Transport,
    M: claude_watch_runtime::macos::Mutator,
{
    use claude_watch_runtime::services::ServiceSystem;
    let marker = store.paths.watch().join("state/auto-update-default-v1");
    if marker.exists() || !store.paths.watch().join("runtime/watch-engine").is_file() {
        return;
    }
    let config_store = ConfigStore {
        storage: store.clone(),
    };
    let Ok(mut cfg) = config_store.load() else {
        return;
    };
    if claude_watch_core::release_source::resolve_update_source(
        &cfg.update_url,
        &cfg.update_public_key,
    )
    .is_none()
    {
        return;
    }
    if !cfg.auto_update {
        cfg.auto_update = true;
        let Ok(val) = cfg.value() else { return };
        if config_store.save(val).is_err() {
            return;
        }
    }
    let _ = host.apply_service(&json!({"id": "updater", "after": true}));
    let _ = store.atomic_bytes(&marker, b"1\n", 0o600);
}

pub fn run(request: &Request, paths: Paths) -> Result<Value> {
    request.require_apply()?;
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown_signals = claude_watch_runtime::daemon::shutdown_signals(stop.clone())?;
    let runner = super::runtime::runner()?;
    let inventory = Observer {
        runner: runner.as_ref(),
    }
    .inventory()?;
    let producer = inventory
        .processes
        .get(&std::process::id())
        .ok_or_else(|| CoreError::new("daemon_identity_unavailable", "后台自身身份不可读取"))?
        .identity
        .clone();
    let identities = inventory
        .processes
        .into_iter()
        .map(|(pid, p)| (pid, p.identity))
        .collect();
    let storage = StateStore::new(paths.clone());
    if stop.load(Ordering::Acquire) {
        return Ok(json!({"status":"stopped","rounds":0}));
    }
    let owner = DaemonLease::acquire(storage.clone(), producer.clone(), &identities)?;
    // Authenticate/publish the native collector relationship first. Cold
    // discovery must not hide an otherwise live, unready publisher for tens
    // of seconds. The normal snapshot reader still verifies this producer.
    // The publisher retries a failed bootstrap cache write on the current
    // frame. Storage errors are visible in snapshot health independently of
    // the authenticated in-memory observations used by the protection loop.
    let _ = runner.publish_listeners(&storage);
    let mut listener_publisher = runner.start_listener_publisher(storage.clone())?;
    owner.publish_initial_inventory(&identities, native::now())?;
    let sampler = Sampler::new(runner.clone(), paths.clone());
    let discovery_worker = DiscoveryWorker::start(sampler.discovery(), runner.clone(), stop.clone())?;
    let mut publisher = SnapshotPublisher::new(
        storage.clone(),
        sampler,
        producer,
    )?;
    let alerts = if request.flag("observe-only") {
        None
    } else {
        Some(Arc::new(AlertDispatcher::new(
            storage.clone(),
            Arc::new(NativeNotifier::system()),
        )))
    };
    let diagnostic_queue = super::diagnostic_queue::DiagnosticQueue::new(storage.clone());
    let channel_diagnostics = ChannelDiagnostics::new(storage.clone());
    let events = EventStore::new(storage.clone());
    events.append(
        "daemon-start",
        EventFields {
            operation: Some("native-daemon".into()),
            pid: Some(std::process::id()),
            version: Some(claude_watch_runtime::monitor_snapshot::VERSION.into()),
            ..Default::default()
        },
        native::now(),
    )?;
    let baseline = if request.flag("observe-only") {
        None
    } else {
        let paths = paths.clone();
        let store = storage.clone();
        let auto_enable_updater = !request.flag("once");
        let mut runtime = None;
        Some(spawn_baseline(stop.clone(), move || {
            // Construct the adapter once inside this independent worker. A
            // failed observation must never terminate the guard worker.
            if runtime.is_none() {
                let mut host = super::runtime::host(paths.clone(), Authority::ExplicitPermit)?;
                if auto_enable_updater {
                    ensure_default_auto_update_enabled(&store, &mut host);
                }
                let desktop = NativeDesktop::new(
                    host.runner.clone(),
                    super::runtime::process_component()?,
                    Authority::ExplicitPermit,
                )?;
                runtime = Some((host, desktop));
            }
            let (host, desktop) = runtime.as_mut().unwrap();
            let network = host.network.clone();
            DesktopRuntime {
                desktop,
                system: host,
                network,
                storage: store.clone(),
                started: Instant::now(),
                cli: None,
            }
            .ensure_baseline_audit()
        })?)
    };
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    // One immutable handoff, not a second observation cache. A slow collector
    // cannot hold up the authority or accumulate unbounded stale rounds.
    let guard_rounds = Arc::new(GuardRoundHandoff::default());
    let active_guard = Arc::new(ActiveGuardState::default());
    let (mut sampling_wake_rx, sampling_wake_tx) = UnixStream::pair()
        .map_err(|_| CoreError::new("sampling_wake_failed", "进程采样唤醒通道无法启动"))?;
    let _ = sampling_wake_rx.set_nonblocking(true);
    let _ = sampling_wake_tx.set_nonblocking(true);
    let guard = if request.flag("observe-only") {
        drop(sampling_wake_tx);
        None
    } else {
        let guard_diagnostics = diagnostic_queue.clone();
        let mut host = super::runtime::host(paths.clone(), Authority::ExplicitPermit)?;
        let mut desktop = NativeDesktop::new(
            host.runner.clone(),
            super::runtime::process_component()?,
            Authority::ExplicitPermit,
        )?;
        let store = storage.clone();
        let stop = stop.clone();
        let guard_alerts = alerts.clone();
        let guard_channel_diagnostics = channel_diagnostics.clone();
        let audit_paths = paths.clone();
        let guard_producer = owner.producer.clone();
        let guard_events = event_tx.clone();
        let shutdown_rounds = guard_rounds.clone();
        let collector_rounds = guard_rounds.clone();
        let guard_active = active_guard.clone();
        let guard_sampling_wake = sampling_wake_tx;
        Some(
            thread::Builder::new()
                .name("claude-session-guard".into())
                .spawn(move || -> Result<()> {
                    let mut channel_stack = assemble_channel_stack_with_diagnostics(
                        store.clone(),
                        stop.clone(),
                        true,
                        None,
                        guard_channel_diagnostics,
                        (guard_events.clone(), event_rx),
                        guard_active.clone(),
                        Some(guard_sampling_wake),
                        move |req| {
                            let enforcer = claude_watch_runtime::channel_enforcer::registered_production_enforcer(&audit_paths.watch())
                                .ok_or_else(|| CoreError::new("controlled_channel_missing", "受控诊断执行器不可用，保持待验证"))?;
                            super::channel_audit::run(&audit_paths, &enforcer, req)
                        },
                    )?;
                    let collector_stop = stop.clone();
                    let collector_owner_pid = guard_producer.pid;
                    let collector_active = guard_active;
                    let enforcer = channel_stack.enforcer.clone();
                    let collector = thread::Builder::new().name("watch-guard-collector".into())
                        .spawn(move || -> Result<()> {
                            const ACTIVE_EGRESS_RECHECK_INTERVAL: Duration = Duration::from_secs(600);
                            let controller = Controller::new(store.clone());
                            let network = host.network.clone();
                            let mut runtime = DesktopRuntime {
                                desktop: &mut desktop, system: &mut host, network, storage: store,
                                started: Instant::now(), cli: None,
                            };
                            let mut guard_history = super::diagnostic_queue::GuardHistory::default();
                            let mut notices = ProtectionNoticeGate::default();
                            let mut unknown_gate = AlertGate::new(SUSTAINED_SAMPLING_ROUNDS, SAMPLING_QUIET);
                            let families: Vec<_> = PolicyCatalog::families().iter()
                                .filter(|family| PolicyCatalog::guard_target(family).is_some())
                                .map(|family| family.id).collect();
                            let mut last_probed_at: Option<Instant> = None;
                            let mut last_probed_families: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
                            let mut last_was_unknown = false;
                            while !collector_stop.load(Ordering::Acquire) {
                                let Some((observed_at, round)) = collector_rounds.take() else { break; };
                                let active_set = collector_active.active_families();
                                let immediate = collector_active.take_immediate_probe();
                                let recheck_due = !active_set.is_empty()
                                    && (active_set != last_probed_families
                                        || last_probed_at.is_none_or(|at| at.elapsed() >= ACTIVE_EGRESS_RECHECK_INTERVAL));
                                let should_probe = last_probed_at.is_none()
                                    || immediate
                                    || last_was_unknown
                                    || round.is_err()
                                    || recheck_due;
                                if should_probe {
                                    let probe_families: Vec<&str> = if active_set.is_empty() {
                                        families.clone()
                                    } else {
                                        families.iter().copied().filter(|f| active_set.contains(*f)).collect()
                                    };
                                    let (mut egress, mut local_guard) = match &round {
                                        Ok(round) => runtime.sample_guard_environment(&enforcer, &probe_families, round),
                                        Err(error) => (probe_families.iter().map(|family| ((*family).to_owned(), json!({"state":"unknown","code":error.code}))).collect(),
                                            json!({"proxy":"unknown","tun":"unknown","code":error.code})),
                                    };
                                    if round.as_ref().is_ok_and(|round| !collector_rounds.unchanged(round, &runtime.storage.paths.watch().join("runtime/watch-engine"), Some(collector_owner_pid))) {
                                        egress = probe_families.iter().map(|family| ((*family).to_owned(), json!({"state":"unknown","code":"process_observation_changed"}))).collect();
                                        local_guard = json!({"proxy":"unknown","tun":"unknown","code":"process_observation_changed","process_observed_at":observed_at});
                                    }
                                    let observed_at = observed_at.min(local_guard["environment_observed_at"].as_f64().unwrap_or(observed_at));
                                    let round_unknown = local_guard["proxy"] == "unknown" || local_guard["tun"] == "unknown";
                                    if round_unknown {
                                        last_was_unknown = true;
                                    } else {
                                        last_was_unknown = false;
                                        last_probed_at = Some(Instant::now());
                                        last_probed_families = active_set;
                                    }
                                    guard_events.send(SupervisionEvent::EnvironmentUpdated {
                                        egress: json!({"families":egress}), local_guard, observed_at,
                                    }).map_err(|_| CoreError::new("guard_authority_closed", "保护监督器已关闭"))?;
                                }
                                if collector_stop.load(Ordering::Acquire) { break; }
                                let receipt = controller.guard_tick(&mut runtime)?;
                                guard_history.observe(&guard_diagnostics, &receipt, native::now());
                                if let Some(alerts) = &guard_alerts {
                                    let pending = notices.pending(&receipt);
                                    if !pending.is_empty() {
                                        unknown_gate.observe(false);
                                        let message = pending.iter().map(|(_, _, text)| text.as_str())
                                            .collect::<Vec<_>>().join("；");
                                        if alerts.enqueue(Alert {
                                            title: "Agent Watch：保护状态变化".into(), message,
                                            severity: Severity::Warning,
                                        }) { notices.accept(pending); }
                                    } else if unknown_gate.observe(receipt["status"] == "unknown") {
                                        alerts.enqueue(Alert {
                                            title: "Agent Watch：保护采样异常".into(),
                                            message: "保护证据持续未能完整取得，后台正在重试。详情见环境状态。".into(),
                                            severity: Severity::Critical,
                                        });
                                    }
                                }
                            }
                            Ok(())
                        });
                    let collector = match collector {
                        Ok(worker) => worker,
                        Err(_) => {
                            channel_stack.shutdown();
                            return Err(CoreError::new("guard_collector_start_failed", "保护采集线程无法启动"));
                        }
                    };
                    let loop_result = channel_stack.run_authority_loop(
                        &stop, || collector.is_finished(), Some(&guard_producer));
                    stop.store(true, Ordering::Release);
                    // Keep the registry alive until the slow collector is no longer
                    // reading it. All workers share the same cancellation flag.
                    shutdown_rounds.close();
                    let collector_result = collector.join().unwrap_or_else(|_| Err(
                        CoreError::new("guard_collector_panicked", "保护采集线程异常退出")));
                    channel_stack.shutdown();
                    collector_result.and(loop_result)
                })
                .map_err(|_| CoreError::new("guard_start_failed", "后台保护工作线程无法启动"))?,
        )
    };
    let evidence = if request.flag("observe-only") {
        None
    } else {
        match super::evidence_run::spawn(paths, stop.clone()) {
            Ok(worker) => Some(worker),
            Err(error) => {
                stop.store(true, Ordering::Release);
                if let Some(guard) = guard {
                    let _ = guard.join();
                }
                return Err(error);
            }
        }
    };
    let mut sampling_history = super::diagnostic_queue::SamplingHistory::default();
    let mut sampling_gate = AlertGate::new(SUSTAINED_SAMPLING_ROUNDS, SAMPLING_QUIET);
    // Last reported sensitive-file evidence set.
    let mut reported_files: Option<String> = None;
    // Subscribe before collecting. A route/config change invalidates cached
    // network evidence even when the observed process identities are identical.
    let mut sampling_events = NetworkEventWatcher::default();
    sampling_events.watch_file(storage.paths.config());
    let mut network_changed = false;
    let outcome = (|| {
        let source = super::runtime::listener_stream();
        let mut frames = source.as_ref().map(|stream| stream.subscribe_frames()).transpose()?;
        let mut last_revision = source.as_ref().map(|stream| stream.wait_for_revision(0, Duration::ZERO)).transpose()?.unwrap_or(0);
        let mut requested_revision = None;
        let mut missing_frame = None;
        let mut rounds = 0u64;
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(json!({"status":"stopped","rounds":rounds}));
            }
            if source.as_ref().is_some_and(|stream| stream.is_finished()) {
                return Err(CoreError::new("native_listener_worker_failed", "原生监听采集线程已退出，等待后台重新启动"));
            }
            if discovery_worker.worker.as_ref().is_some_and(|worker| worker.is_finished()) {
                return Err(CoreError::new(
                    "discovery_worker_failed",
                    "应用发现线程异常退出，后台停止发布正常心跳",
                ));
            }
            if evidence.as_ref().is_some_and(|worker| worker.is_finished()) {
                return Err(CoreError::new(
                    "evidence_worker_failed",
                    "保护证据线程异常退出，等待后台重新启动",
                ));
            }
            if guard.as_ref().is_some_and(|g| g.is_finished()) {
                return Err(CoreError::new(
                    "guard_worker_failed",
                    "保护循环已退出，后台停止发布正常心跳",
                ));
            }
            let started = Instant::now();
            let config = ConfigStore {
                storage: storage.clone(),
            }
            .load()?;
            let pin = pinned_node(&storage.paths, &config.proxy_group);
            let publish_inventory = |result: std::result::Result<&claude_watch_runtime::sampler::ProcessRound, &CoreError>| {
                if guard.is_none() { return; }
                guard_rounds.publish(result.cloned().map_err(Clone::clone));
                let at = result.as_ref().map_or_else(|_| native::now(), |round| round.observed_at);
                for family in PolicyCatalog::families() {
                    let Some(target) = PolicyCatalog::guard_target(family) else { continue; };
                    let observation = match result.ok().and_then(|round|
                        claude_watch_runtime::desktop_native::supervision_inventory(round, target.provider()).ok()) {
                        Some((desktops, processes)) => SupervisionEvent::ProcessInventoryUpdated {
                            family: family.id.into(), desktops, processes, observed_at: at,
                        },
                        None => SupervisionEvent::ProcessInventoryUnavailable { family: family.id.into(), observed_at: at },
                    };
                    let _ = event_tx.send(observation);
                }
            };
            let sample = if let Some(error) = missing_frame.take() {
                publish_inventory(Err(&error));
                Err(error)
            } else {
                publisher.collect_with_inventory(&config.proxy_group, &pin, std::mem::take(&mut network_changed),
                    guard.is_some(), publish_inventory)
            };
            if stop.load(Ordering::Acquire) {
                return Ok(json!({"status":"stopped","rounds":rounds}));
            }
            let mut log_error = diagnostic_queue.health_message();
            if let Some(e) = listener_publisher.as_ref().and_then(|publisher| publisher.check().err()) {
                let note = format!("系统监听采样缓存发布异常（{}）", e.code);
                log_error = Some(log_error.map(|existing| format!("{existing}；{note}")).unwrap_or(note));
            }
            if let Some(note) = channel_diagnostics.health_message() {
                log_error = Some(log_error.map(|existing| format!("{existing}；{note}")).unwrap_or(note));
            }
            if let Some(count) = alerts.as_ref().map(|a| a.record_failures()).filter(|n| *n > 0) {
                let note = format!("本次后台运行的通知事件记录或冷却写入失败 {count} 次。");
                log_error = Some(log_error.map(|existing| format!("{existing}；{note}")).unwrap_or(note));
            }
            let snapshot = owner.publish_with_log_health(sample, native::now(), log_error.as_deref())?;
            sampling_history.observe(&diagnostic_queue, &snapshot, native::now());
            if let Some(alerts) = &alerts {
                // `quality` is a per-round verdict: one missing `lsof` sample
                // or an empty traffic counter flips it to "degraded" and the
                // next round usually restores it. Alerting on the first bad
                // round turned the watchdog into a recurring pop-up, because
                // the queue only suppresses an alert that is still pending or
                // on screen — dismissing one let the next round raise it
                // again. Require a sustained streak, then one reminder per
                // quiet period. The control panel keeps showing live state.
                if sampling_gate.observe(snapshot["health"]["state"] != "running") {
                    alerts.enqueue(Alert {
                        title: "Agent Watch：监控采样异常".into(),
                        message:
                            "本轮进程或连接观察未完成，采样仍会继续。请查看事件记录中的具体来源。"
                                .into(),
                        severity: Severity::Critical,
                    });
                }
                // Report each distinct sensitive-file evidence set once;
                // service-name candidates remain in the event log only.
                let files_signature = evidence_signature(&snapshot["activity"]["files"]["rows"]);
                if files_signature.is_some() && files_signature != reported_files {
                    alerts.enqueue(Alert{title:"Agent Watch：敏感目录文件描述符".into(),message:"未关联会话的进程持有敏感目录文件描述符；这不是完整的文件读取记录。详情见事件记录。".into(),severity:Severity::Warning});
                }
                reported_files = files_signature;
            }
            rounds = rounds.saturating_add(1);
            if request.flag("once") {
                return Ok(
                    json!({"status":"ok","rounds":rounds,"protection":if request.flag("observe-only"){"observation_only"}else{"enabled"},"snapshot":snapshot}),
                );
            }
            let inventory_budget = if snapshot["samplingDiagnostics"]["process_complete"] == true
                && snapshot["targetDiscovery"]["complete"] != false && snapshot["health"]["state"] == "running" {
                Duration::from_secs(5)
            } else { PROCESS_INTERVAL };
            let mut deadline = started + inventory_budget;
            if snapshot["samplingDiagnostics"]["network_reused"].is_boolean() {
                if let Some(review) = publisher.next_network_review() { deadline = deadline.min(review); }
            }
            match wait_for_sampling_event(&mut sampling_events, frames.as_mut(), Some(&mut sampling_wake_rx),
                source.as_deref(), &mut last_revision, &mut requested_revision, deadline, &stop, &shutdown_signals.wake) {
                Ok(changed) => {
                    if changed { active_guard.request_immediate_probe(); }
                    network_changed |= changed;
                }
                Err(error) => {
                    active_guard.request_immediate_probe();
                    missing_frame = Some(error);
                    network_changed = true;
                }
            }
        }
    })();
    stop.store(true, Ordering::Release);
    let _ = event_tx.send(SupervisionEvent::LeaseExpired { observed_at: native::now(), woke_from_sleep: false });
    let listener_result = listener_publisher.as_mut().map_or(Ok(()), |publisher| publisher.finish());
    let outcome = outcome.and_then(|result| listener_result.map(|()| result));
    let _ = events.append(
        "daemon-stop",
        EventFields {
            operation: Some("native-daemon".into()),
            status: Some(if outcome.is_err() { "error" } else { "stopped" }.into()),
            code: outcome.as_ref().err().map(|error| {
                match error.code.as_str() {
                    "native_listener_worker_failed" => "native_listener_worker_failed",
                    _ => "backend_error",
                }
                .into()
            }),
            ..Default::default()
        },
        native::now(),
    );
    let guard_result = if let Some(guard) = guard {
        match guard.join() {
            Ok(result) => result,
            Err(_) => Err(CoreError::new("guard_worker_failed", "保护循环异常退出")),
        }
    } else {
        Ok(())
    };
    // Always finish helper cancellation, even if the guard worker failed.
    if let Some(evidence) = evidence {
        let _ = evidence.join();
    }
    if let Some(baseline) = baseline {
        // A display-only HTTPS baseline has bounded requests but cannot be
        // interrupted mid-request. It must not delay launchd stop/replacement.
        if baseline.is_finished() {
            let _ = baseline.join();
        }
    }
    guard_result?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_round_handoff_keeps_latest_time_and_rejects_inflight_changes() {
        use claude_watch_runtime::sampler::{ProcessRound, ProcessTableObservation};
        let handoff = GuardRoundHandoff::default();
        let at = native::now();
        let row = json!({"uid":501,"executable":"/Applications/Surge.app/Contents/MacOS/Surge","stamp":"same-start"});
        let mut round = ProcessRound {
            id:"initial".into(), uid:501, targets:vec![], identities:Default::default(), roles:json!({}),
            match_evidence:Default::default(), unavailable:vec![], diagnostic_reasons:Default::default(),
            confirmed_exited_count:0, complete:true, observed_at:at, discovery:None,
            system_processes:Some(ProcessTableObservation { observed_at:at, processes:Ok([(42,row.clone())].into()), root_starts:Default::default() }),
        };
        for sequence in 0..100 {
            round.id = sequence.to_string();
            handoff.publish(Ok(round.clone()));
        }
        let (source_at, current) = handoff.take().unwrap();
        let current = current.unwrap();
        assert_eq!(current.id, "99");
        assert_eq!(source_at, at);
        assert_eq!(current.observed_at, at, "overwriting queued rounds must never renew their source time");
        let backend = std::path::Path::new("/fixture/runtime/watch-engine");
        handoff.publish(Ok(current.clone()));
        assert!(handoff.unchanged(&current, backend, Some(77)));
        let mut with_audit_child = current.clone();
        with_audit_child
            .system_processes
            .as_mut()
            .unwrap()
            .processes
            .as_mut()
            .unwrap()
            .insert(
                88,
                json!({"uid":501,"executable":"/fixture/runtime/watch-engine","stamp":"child-start"}),
            );
        handoff.publish(Ok(with_audit_child));
        assert!(
            handoff.unchanged(&current, backend, Some(77)),
            "transient same-binary audit/CLI workers must not invalidate daemon guard rounds"
        );
        round.system_processes.as_mut().unwrap().processes.as_mut().unwrap().insert(43, row);
        handoff.publish(Ok(round.clone()));
        assert!(!handoff.unchanged(&current, backend, Some(77)), "a newly observed candidate invalidates in-flight results");
        let mut stale = current.clone(); stale.observed_at -= 9.0;
        handoff.publish(Ok(stale));
        assert!(!handoff.unchanged(&current, backend, Some(77)));
        handoff.publish(Err(CoreError::new("sampling_failed", "fixture input")));
        assert!(!handoff.unchanged(&current, backend, Some(77)));
        let (failed_at, failed) = handoff.take().unwrap();
        assert!(failed.is_err());
        assert!(failed_at >= at && failed_at <= native::now());
        let started = Instant::now();
        handoff.close();
        assert!(handoff.take().is_none());
        assert!(started.elapsed() < Duration::from_millis(500), "empty handoff must leave stop checks bounded");
    }

    #[test]
    fn wait_for_sampling_event_wakes_immediately_on_sampling_wake_signal() {
        let mut watcher = NetworkEventWatcher::new(&[]);
        let (shutdown_rx, _shutdown_tx) = UnixStream::pair().unwrap();
        let (mut wake_rx, wake_tx) = UnixStream::pair().unwrap();
        let _ = shutdown_rx.set_nonblocking(true);
        let _ = wake_rx.set_nonblocking(true);
        let _ = wake_tx.set_nonblocking(true);
        let stop = AtomicBool::new(false);
        let mut last_revision = 0u64;
        let mut requested = None;
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            notify_sampling_wake(&Some(wake_tx));
        });
        let started = Instant::now();
        let changed = wait_for_sampling_event(
            &mut watcher,
            None,
            Some(&mut wake_rx),
            None,
            &mut last_revision,
            &mut requested,
            Instant::now() + Duration::from_secs(5),
            &stop,
            &shutdown_rx,
        )
        .unwrap();
        sender.join().unwrap();
        assert!(!changed, "sandbox registration wake must not trigger a slow network rescan");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "sampling loop must wake immediately on sandbox registration instead of waiting for 5s deadline (elapsed {:?})",
            started.elapsed()
        );
    }

    #[test]
    fn slow_collector_does_not_delay_vpn_events_or_expiry() {
        use claude_watch_core::vpn::{ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnObservation};
        let root = std::env::temp_dir().join(format!("cw-authority-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        let mut config = claude_watch_core::config::Config::default_for_new_install();
        config.proxy_mode = "clash-verge".into();
        config.proxy_url = "http://127.0.0.1:17890".into();
        config.proxy_group = "AI-Group".into();
        let mut expectation = VpnExpectation::unconfigured();
        expectation.configured = true;
        expectation.running_mode = Some("rule".into());
        expectation.expected_node = Some("US-West-01".into());
        expectation.expected_chain = vec!["AI-Group".into(), "US-West-01".into()];
        config.vpn_expectation = Some(expectation);
        ConfigStore { storage: storage.clone() }.save(config.value().unwrap()).unwrap();
        let resources = storage.paths.watch().join("runtime");
        std::fs::create_dir_all(&resources).unwrap();
        std::fs::write(resources.join("components.json"), json!({"network_backend":"seatbelt"}).to_string()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut stack = assemble_production_channel_stack(storage.clone(), stop.clone(), false,
            |_| panic!("no audit is needed without a protected process")).unwrap();
        let old_guard = json!({"status":"unknown","time":native::now()-77.0});
        storage.atomic_json(&storage.paths.base().join("guard-heartbeat.json"),&old_guard).unwrap();
        let sender = stack.event_tx.clone();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        // A collector stuck in an expensive system read remains blocked through
        // both checks. The production authority loop must keep making progress.
        let collector = thread::spawn(move || release_rx.recv_timeout(Duration::from_secs(5)));
        let loop_stop = stop.clone();
        let authority = thread::spawn(move || {
            let producer = claude_watch_core::processes::Identity {
                pid: 123, parent: 1, uid: 501, executable: "/fixture/watch-engine".into(),
                start_seconds: 100, start_microseconds: 0, start_stamp: "fixture-start".into(),
            };
            let result = stack.run_authority_loop(&loop_stop, || collector.is_finished(), Some(&producer));
            stack.shutdown();
            let _ = collector.join();
            result
        });
        let now = native::now();
        let observation = VpnObservation {
            source: "clash-verge".into(), source_instance: Some("fixture-instance".into()),
            source_revision: Some("fixture-revision".into()),
            upstream_endpoint: Some("http://127.0.0.1:17890".into()),
            upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
            running_mode: ObservedField::Known("rule".into()),
            tun_enabled: ObservedField::Known(false), system_proxy_enabled: ObservedField::Known(false),
            selected_group: ObservedField::Known("AI-Group".into()),
            selected_node: ObservedField::Known("US-West-01".into()),
            proxy_chain: ObservedField::Known(vec!["AI-Group".into(), "US-West-01".into()]),
            rules_digest: ObservedField::Unknown("not_required".into()),
            sample_started_at: now, observed_at: now, valid_until: now + 0.5,
            consistency: ObservationConsistency::RevisionVerified, source_error: None,
            sample_seq: 17, epoch: VpnEpoch::new("fixture-observer", 1),
        };
        sender.send(SupervisionEvent::VpnObservationUpdated { observation: observation.clone(), observed_at: now }).unwrap();
        let read = || claude_watch_runtime::channel_policy_status::read_frame(&storage)["vpn_supervision"].clone();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut matched = false;
        let mut expired = false;
        while Instant::now() < deadline {
            let state = read();
            if state["observation"]["sample_seq"] == 17 && state["vpn_match"]["verdict"] == "matched" {
                matched = true;
            }
            if matched && state["vpn_match"]["verdict"] == "stale" { expired = true; break; }
            thread::sleep(Duration::from_millis(10));
        }
        let final_state = read();
        let live_pulse = storage.read_json(
            &storage.paths.watch().join("state/guard-service-heartbeat.json"), Value::Null,
        ).unwrap();
        // An unreadable session must fail closed without killing the authority;
        // once repaired, a subsequent valid event must still be consumed.
        std::fs::write(storage.paths.session(), b"{invalid").unwrap();
        sender.send(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(), desktops: vec![], processes: vec![], observed_at: native::now(),
        }).unwrap();
        thread::sleep(Duration::from_millis(150));
        std::fs::remove_file(storage.paths.session()).unwrap();
        let refreshed_at = native::now();
        let mut recovered = observation;
        recovered.sample_seq = 18;
        recovered.sample_started_at = refreshed_at;
        recovered.observed_at = refreshed_at;
        recovered.valid_until = refreshed_at + 3.5;
        let sent = sender.send(SupervisionEvent::VpnObservationUpdated {
            observation: recovered, observed_at: refreshed_at,
        }).is_ok();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut resumed = false;
        while sent && Instant::now() < deadline {
            if read()["observation"]["sample_seq"] == 18 { resumed = true; break; }
            thread::sleep(Duration::from_millis(10));
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut pulse_advanced = false;
        while Instant::now() < deadline {
            let pulse = storage.read_json(&storage.paths.watch().join("state/guard-service-heartbeat.json"),Value::Null).unwrap();
            if pulse["time"].as_f64() > live_pulse["time"].as_f64() {
                pulse_advanced = true; break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let retained_guard = storage.read_json(&storage.paths.base().join("guard-heartbeat.json"),Value::Null).unwrap();
        // Always release/join before assertions, including the regression case.
        stop.store(true, Ordering::Release);
        let _ = release_tx.send(());
        let result = authority.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
        result.unwrap();
        assert!(matched, "fresh VPN event waited behind collector: {final_state}");
        assert!(expired, "deadline waited behind collector: {final_state}");
        assert!(resumed, "transient session error terminated authority");
        assert!(pulse_advanced,"slow collector prevented independent authority heartbeat renewal");
        assert_eq!(retained_guard,old_guard,"service liveness must not freshen protection evidence");
        assert_eq!(live_pulse["schema"], 1);
        assert_eq!(live_pulse["pid"], 123);
        assert_eq!(live_pulse["start_stamp"], "fixture-start");
        assert!(live_pulse["time"].as_f64().is_some_and(|at| at >= now - 1.0));
    }

    #[test]
    fn protection_notice_tracks_incidents_and_requires_confirmed_outcomes() {
        let mut gate = ProtectionNoticeGate::default();
        let sid = uuid::Uuid::new_v4().to_string();
        let row = |verdict: &str, seq: u64| json!({"family":"claude", "action":"disconnect-channel",
            "channel_permit":{"session_id":sid,"reason_code":"vpn_observation_stale","command_seq":seq},
            "channel_supervision":{"verdict":verdict}, "process_preserved":true});
        let first = gate.pending(&row("unconfirmed", 1));
        assert_eq!(first.len(), 1);
        assert!(first[0].2.contains("待核验"));
        assert!(!first[0].2.contains("已确认阻断"));
        // A queue rejection must remain retryable.
        assert_eq!(gate.pending(&row("unconfirmed", 1)).len(), 1);
        gate.accept(first);
        assert!(gate.pending(&row("unconfirmed", 2)).is_empty());
        gate.pending(&json!({"family":"claude","status":"unknown","action":"observe"}));
        assert!(gate.pending(&row("unconfirmed", 3)).is_empty());
        let confirmed = gate.pending(&row("isolated_keep_process", 3));
        assert_eq!(confirmed.len(), 1);
        assert!(confirmed[0].2.contains("已确认阻断"));
        gate.accept(confirmed);
        assert!(gate.pending(&row("isolated_keep_process", 4)).is_empty());
        // A transient read mismatch cannot replay previously reported outcomes.
        assert!(gate.pending(&row("unconfirmed", 4)).is_empty());
        assert!(gate.pending(&row("isolated_keep_process", 4)).is_empty());
        let mut partial = row("isolated_keep_process", 4);
        partial["action"] = json!("disconnect-and-partial-force-quit");
        partial["process_preserved"] = json!(false);
        partial["process_execution_state"] = json!("partially_terminated");
        let notices = gate.pending(&partial);
        assert_eq!(notices.len(), 1);
        assert!(notices[0].2.contains("部分进程已退出"));
        assert!(!notices[0].2.contains("进程保留"));
        // Only positive forwarding evidence clears the standing incident.
        gate.pending(&json!({"family":"claude","channel_supervision":{"verdict":"forwarding_verified"}}));
        assert_eq!(gate.pending(&row("isolated_keep_process", 5)).len(), 1);
        let mut other = row("isolated_keep_process", 5);
        other["family"] = json!("openai");
        assert_eq!(gate.pending(&json!({"families":[row("isolated_keep_process",5),other]})).len(), 2);
    }

    #[test]
    fn blocked_baseline_does_not_block_other_guard_work() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let worker = spawn_baseline(stop, move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(true)
        })
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let guard_work = thread::spawn(|| "guard tick");
        assert_eq!(guard_work.join().unwrap(), "guard tick");
        release_tx.send(()).unwrap();
        worker.join().unwrap();
    }

    /// No evidence means nothing to report — not an empty alert.
    #[test]
    fn an_empty_evidence_set_is_not_reported() {
        assert!(evidence_signature(&json!([])).is_none());
    }

    #[test]
    fn an_unreadable_evidence_set_is_not_reported() {
        assert!(evidence_signature(&Value::Null).is_none());
        assert!(evidence_signature(&json!({"state": "unavailable"})).is_none());
    }

    /// A standing fact must produce one alert, not one per sampling round:
    /// identical rows have to compare equal so the caller can skip repeats.
    #[test]
    fn the_same_rows_yield_the_same_signature() {
        let first = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        let again = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        assert_eq!(evidence_signature(&first), evidence_signature(&again));
    }

    /// A new process appearing is a new fact and must be reported again.
    #[test]
    fn a_changed_row_set_yields_a_new_signature() {
        let before = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        let after = json!([
            {"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"},
            {"pid": 9, "label": "com.example.other", "ownership": "unconfirmed"}
        ]);
        assert_ne!(evidence_signature(&before), evidence_signature(&after));
    }

    #[test]
    fn production_assembly_rejects_missing_retired_and_legacy_backend_inputs_without_fallback() {
        use claude_watch_core::{channel::ChannelPermitState, config::Config};
        for (backend, config, expected) in [
            (None, None, "packaged_network_backend_missing"),
            (Some("invalid"), Some(Config::default_for_new_install().value().unwrap()), "packaged_network_backend_missing"),
            (Some("network-extension"), Some(Config::default_for_new_install().value().unwrap()), "legacy_network_backend_removed"),
            (Some("seatbelt"), Some(json!({"schema":1})), "legacy_config_migration_required"),
            (Some("seatbelt"), Some(json!({"schema":2,"network_backend":"network_extension"})), "legacy_config_migration_required"),
        ] {
            let root = PathBuf::from("/private/tmp").join(format!("cw-no-ne-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&root).unwrap();
            let store = StateStore::new(Paths::new(&root).unwrap());
            if let Some(config) = config {
                store.atomic_json(&store.paths.config(), &config).unwrap();
            }
            // Even missing/invalid metadata gets a local candidate, so the
            // fixture can never discover unrelated metadata beside the test binary.
            let runtime = store.paths.watch().join("runtime");
            std::fs::create_dir_all(&runtime).unwrap();
            std::fs::write(runtime.join("components.json"), json!({"network_backend":backend}).to_string()).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let mut stack = assemble_production_channel_stack(store.clone(), stop.clone(), false,
                |_| panic!("blocked backend must not request a recovery audit")).unwrap();
            assert_eq!(stack.supervisor.config_blocking_reason(), Some(expected));
            assert_eq!(stack.enforcer.activation_error_code().unwrap().as_deref(), Some(expected));
            assert!(!stack.enforcer.is_ready().unwrap());
            assert!(stack.enforcer.local_proxy_port().is_none());
            assert!(stack.sandbox_registry.is_none());
            // Reconciliation must preserve the error, not silently reopen a backend.
            stack.reconcile_controlled_backend(native::now()).unwrap();
            assert_eq!(stack.supervisor.config_blocking_reason(), Some(expected));
            assert!(stack.supervisor.snapshot(native::now()).families.values()
                .all(|family| family.permit_state != ChannelPermitState::Permitted));
            stack.shutdown();
            assert!(stop.load(Ordering::Acquire));
            assert!(claude_watch_runtime::channel_enforcer::registered_production_enforcer(&store.paths.watch()).is_none());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn seatbelt_production_assembly_wires_registry_vpn_observer_and_enforces_i03_gate() {
        use claude_watch_core::{
            channel::{BoundProcessToken, NetworkBackendKind},
            config::Config,
            processes::ProcessRole,
            session::Desktop,
            vpn::{
                ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnExpectation,
                VpnObservation,
            },
        };

        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let root = std::path::PathBuf::from("/tmp").join(format!("cwdsb-{short_id}"));
        std::fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());

        // Save schema-2 seatbelt config first so `StateStore` initializes `watch/` with 0o700 permissions
        let mut cfg = Config::default_for_new_install();
        cfg.enabled = true;
        cfg.guard_enabled = true;
        cfg.proxy_mode = "tag".into();
        cfg.proxy_url = "http://127.0.0.1:17890".into();
        cfg.proxy_group = "TAG".into();
        let mut exp = VpnExpectation::unconfigured();
        exp.configured = true;
        exp.proxy_mode = "tag".into();
        exp.proxy_url = "http://127.0.0.1:17890".into();
        exp.proxy_group = "TAG".into();
        exp.running_mode = Some("rule".into());
        exp.expected_node = Some("JP-01".into());
        cfg.vpn_expectation = Some(exp);
        ConfigStore {
            storage: store.clone(),
        }
        .save(cfg.value().unwrap())
        .unwrap();

        let runtime_dir = store.paths.watch().join("runtime");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        // Stage a manifest-bound helper binary (`watch-sandbox-launcher`) and `components.json`
        let current_exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .unwrap();
        let helper_path = runtime_dir.join("watch-sandbox-launcher");
        hardened_helper::copy_signed(&current_exe, &helper_path);
        std::fs::write(
            runtime_dir.join("components.json"),
            hardened_helper::components(&helper_path).to_string(),
        )
        .unwrap();

        struct MockLiveVpnReader;
        impl VpnSourceReader for MockLiveVpnReader {
            fn read_observation(
                &self,
                _expectation: &VpnExpectation,
                _include_rules: bool,
                sample_seq: u64,
                epoch: VpnEpoch,
                now: f64,
            ) -> VpnObservation {
                let me = claude_watch_system::inspect_process_identity(std::process::id()).unwrap();
                VpnObservation {
                    source: "tag".into(),
                    source_instance: Some(format!(
                        "pid:{}:{}:{}",
                        me.pid, me.start_seconds, me.start_microseconds
                    )),
                    source_revision: Some("rev-prod-1".into()),
                    upstream_endpoint: Some("http://127.0.0.1:17890".into()),
                    upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
                    running_mode: ObservedField::Known("rule".into()),
                    tun_enabled: ObservedField::Known(false),
                    system_proxy_enabled: ObservedField::Unknown("system_proxy_not_sampled".into()),
                    selected_group: ObservedField::Known("TAG".into()),
                    selected_node: ObservedField::Known("JP-01".into()),
                    proxy_chain: ObservedField::Known(vec!["TAG".into(), "JP-01".into()]),
                    rules_digest: ObservedField::Unknown("controller_rules_not_sampled".into()),
                    sample_started_at: now,
                    observed_at: now,
                    valid_until: now + 5.0,
                    consistency: ObservationConsistency::RevisionVerified,
                    source_error: None,
                    sample_seq,
                    epoch,
                }
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let mut stack = assemble_production_channel_stack_with_vpn_reader(
            store.clone(),
            stop.clone(),
            false,
            Some(Arc::new(MockLiveVpnReader)),
            |_req| Err(CoreError::new("unused", "unused")),
        )
        .expect("assemble production seatbelt stack");

        // 1. Verify Seatbelt registration service, staged deliverable entries, and VPN observer were wired in production assembly
        assert!(
            stack.sandbox_registry.is_some(),
            "Seatbelt production assembly must initialize SandboxLaunchRegistry"
        );
        assert!(
            stack.vpn_wake_handle.is_some(),
            "Seatbelt production assembly must initialize VPN observer wake handle"
        );
        let entry_deadline = Instant::now() + Duration::from_secs(3);
        while !store.paths.watch().join("entries/entries-manifest.json").is_file() {
            assert!(Instant::now() < entry_deadline, "background entry staging did not finish");
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            store.paths.watch().join("entries/bin/claude").is_file()
                && store.paths.watch().join("entries/entries-manifest.json").is_file(),
            "Production Seatbelt assembly must stage deliverable CLI shims and entries-manifest.json"
        );
        // 2. Verify I03 identity gate blocked production enablement (`sandbox_ready == false`)
        assert!(
            !stack.enforcer.sandbox_ready().unwrap(),
            "Production Seatbelt assembly must keep sandbox_ready=false while I03 is unverified"
        );
        let rt_meta = store
            .read_json(
                &store.paths.watch().join("state/seatbelt-runtime.json"),
                Value::Null,
            )
            .unwrap();
        assert_eq!(rt_meta["backend"], "seatbelt");
        assert_eq!(rt_meta["sandbox_ready"], false);
        assert_eq!(
            rt_meta["identity_report"]["blocker_code"],
            "gateway_server_identity_unverified_i03"
        );

        // External identities enter supervision without gaining gateway coverage.
        let deadline = Instant::now() + Duration::from_secs(2);
        let snap = loop {
            let now = native::now();
            let observation = SupervisionEvent::ProcessInventoryUpdated { family:"claude".into(),
                desktops:vec![(Desktop { pid:4100,start_seconds:900,start_microseconds:1 },true,"fixture".into())],
                processes:vec![BoundProcessToken::with_system_identity(4100,501,900,1,ProcessRole::DesktopMain)
                    .with_audit_token([501,501,20,501,20,4100,0,9])], observed_at:now };
            let s=stack.step_with_observations(vec![observation],now).unwrap();
            if s.families["claude"].vpn_epoch.is_some() { break s; }
            assert!(Instant::now()<deadline,"VPN observation worker did not deliver sample");
            stack.wait_or_drain(deadline,&stop);
        };
        assert_eq!(snap.families["claude"].backend, NetworkBackendKind::Seatbelt);
        assert!(!snap.families["claude"].sandbox_ready);
        assert!(
            snap.families["claude"]
                .unmanaged_member_pids
                .contains(&4100),
            "unregistered process must appear in unmanaged_member_pids"
        );
        assert_eq!(snap.families["claude"].active_members.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![4100]);
        assert!(snap.families["claude"].coverage_scope.protected_pids.is_empty());

        // Codex already running at the first round, a later launch, then exit.
        let codex = |pid| BoundProcessToken::with_system_identity(pid, 501, 901, 1, ProcessRole::Cli)
            .with_audit_token([501, 501, 20, 501, 20, pid, 0, 9]);
        for pids in [vec![4200], vec![4200, 4201], vec![4201]] {
            let now = native::now();
            let s = stack.step_with_observations(vec![SupervisionEvent::ProcessInventoryUpdated {
                family: "openai".into(), desktops: vec![],
                processes: pids.iter().map(|pid| codex(*pid)).collect(), observed_at: now,
            }], now).unwrap();
            let family = &s.families["openai"];
            assert_eq!(family.active_members.iter().map(|p| p.pid).collect::<Vec<_>>(), pids);
            assert_eq!(family.unmanaged_member_pids, pids);
            assert!(family.coverage_scope.protected_pids.is_empty());
            assert!(!family.sandbox_ready, "monitoring cannot bypass the I03 identity gate");
            assert_eq!(s.families["claude"].active_members.len(), 1, "families remain independent");
        }

        stack.shutdown();
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod r1_tests {
    use super::*;
    use claude_watch_core::config::Config;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn cli_metadata_and_inventory_share_local_codex_retarget_and_removal() {
        use std::{collections::BTreeMap, os::unix::fs::symlink};
        let root = PathBuf::from("/private/tmp").join(format!("cwm-cli-meta-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        fs::create_dir_all(root.join(".local/bin")).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let registry = SandboxLaunchRegistry::new("metadata", PolicyVersion { policy_digest:"p".into(), guard_policy_digest:"g".into() },
            claude_watch_system::SandboxPeerVerifier { expected_uid:claude_watch_system::effective_uid(), expected_helper_executable:"/fixture/helper".into(),
                expected_helper_sha256:"fixture".into(), expected_helper_cdhash:"0".repeat(40) }, None);
        let (tx, _rx) = std::sync::mpsc::channel();
        let a = root.join("image-a"); let b = root.join("image-b");
        for (path, bytes) in [(&a, b"a"), (&b, b"b")] { fs::write(path, bytes).unwrap(); fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap(); }
        let alias = root.join(".local/bin/codex");
        let absent = target_metadata_signature(&store, None);
        symlink(&a, &alias).unwrap();
        let first = target_metadata_signature(&store, None); assert_ne!(first, absent);
        refresh_and_stage_production_targets(&store, None, &registry, &tx).unwrap(); registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts().1, 1);
        fs::remove_file(&alias).unwrap(); symlink(&b, &alias).unwrap();
        assert_ne!(first, target_metadata_signature(&store, None));
        refresh_and_stage_production_targets(&store, None, &registry, &tx).unwrap(); registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts().1, 1, "old canonical path must not accumulate");
        fs::remove_file(&alias).unwrap();
        refresh_and_stage_production_targets(&store, None, &registry, &tx).unwrap(); registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts(), (registry.executable_verification_counts().0, 0, 0));
        assert!(registry.replace_approved_targets(BTreeMap::new(), BTreeMap::new()).is_empty());
        let broken=root.join("Applications/Unreadable.app/Contents/MacOS/Main");
        fs::create_dir_all(broken.parent().unwrap()).unwrap();fs::write(&broken,b"private native fixture").unwrap();
        fs::set_permissions(&broken,fs::Permissions::from_mode(0o111)).unwrap();
        assert!(fs::File::open(&broken).is_err());
        fs::write(broken.parent().unwrap().parent().unwrap().join("Info.plist"),
            r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>Main</string></dict></plist>"#).unwrap();
        symlink(&b,&alias).unwrap();
        assert_eq!(refresh_and_stage_production_targets(&store,None,&registry,&tx).unwrap_err().code,"target_approval_pending");
        registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts().1,1,"normal Codex must stage despite unreadable Claude");
        let state=store.read_json(&store.paths.watch().join("state/target-discovery.json"),Value::Null).unwrap();
        assert_eq!(state["verification_pending"],true);
        assert!(state["selection_issues"].as_array().unwrap().contains(&json!("claude-desktop:target_fingerprint_failed")));
        fs::set_permissions(&broken,fs::Permissions::from_mode(0o755)).unwrap();
        refresh_and_stage_production_targets(&store,None,&registry,&tx).unwrap();registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts().1,2,"recovered image must become verifiable on retry");
        assert_eq!(store.read_json(&store.paths.watch().join("state/target-discovery.json"),Value::Null).unwrap()["verification_pending"],false);
        fs::remove_dir_all(root).unwrap();
    }

    struct Fixture { root: PathBuf, stack: Option<ProductionChannelStack>, store: StateStore }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(stack) = self.stack.take() { stack.shutdown(); }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn fixture(invalid_config: bool) -> Fixture {
        let root = PathBuf::from("/tmp").join(format!("cwr1-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        ConfigStore { storage: store.clone() }.save(Config::default_for_new_install().value().unwrap()).unwrap();
        let runtime = store.paths.watch().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let helper = runtime.join("watch-sandbox-launcher");
        hardened_helper::copy_signed(std::path::Path::new("/usr/bin/true"), &helper);
        fs::write(runtime.join("components.json"), hardened_helper::components(&helper).to_string()).unwrap();
        if invalid_config { fs::write(store.paths.config(), b"{").unwrap(); }
        let stack = assemble_production_channel_stack(store.clone(), Arc::new(AtomicBool::new(false)), false,
            |_| Err(CoreError::new("unused_fixture_audit", "unused"))).unwrap();
        Fixture { root, stack: Some(stack), store }
    }

    #[test]
    fn partial_listener_failures_retry_on_the_same_registry() {
        for registration_fails_first in [true, false] {
            let mut f = fixture(false);
            let stack = f.stack.as_mut().unwrap();
            stack.activate_local_interception = true;
            let original = stack.sandbox_registry.as_ref().unwrap().clone();
            stack.reconcile_controlled_backend_with_listeners(native::now(),
                |reg, path, stop| {
                    assert!(Arc::ptr_eq(reg, &original));
                    if registration_fails_first { Err(CoreError::new("fixture_registration_failure", "injected")) }
                    else { reg.start_registration_listener(path, stop) }
                },
                |enforcer, stop, now| {
                    if !registration_fails_first { Err(CoreError::new("fixture_proxy_failure", "injected")) }
                    else { enforcer.start_local_proxy_listener("127.0.0.1:0", stop, now) }
                }).unwrap();
            assert_eq!(stack.sandbox_registration_worker.is_none(), registration_fails_first);
            assert_eq!(stack.local_proxy_worker.is_some(), registration_fails_first);
            assert!(Arc::ptr_eq(stack.sandbox_registry.as_ref().unwrap(), &original));
            // Retry the same injected component listeners. The production
            // default now requires root launchd endpoint ownership and must
            // not silently fall back to a local bind when no service exists.
            stack.reconcile_controlled_backend_with_listeners(native::now(),
                |reg, path, stop| reg.start_registration_listener(path, stop),
                |enforcer, stop, now| enforcer.start_local_proxy_listener("127.0.0.1:0", stop, now)).unwrap();
            assert!(Arc::ptr_eq(stack.sandbox_registry.as_ref().unwrap(), &original));
            assert!(stack.sandbox_registration_worker.is_some());
            assert!(stack.local_proxy_worker.is_some());
            let port = stack.enforcer.local_proxy_port().unwrap();
            stack.reconcile_controlled_backend_with_listeners(native::now(),
                |_, _, _| panic!("must not duplicate a live registration listener"),
                |_, _, _| panic!("must not duplicate a live proxy listener")).unwrap();
            assert_eq!(stack.enforcer.local_proxy_port(), Some(port));
            assert!(!stack.enforcer.sandbox_ready().unwrap(), "I03 stays closed");
            assert!(stack.backend_workers_ready());
            let listener = if registration_fails_first { &stack.sandbox_registration_worker } else { &stack.local_proxy_worker };
            listener.as_ref().unwrap().cancel();
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                let notice = stack.event_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap();
                if matches!(notice, SupervisionEvent::LeaseExpired { woke_from_sleep: false, .. }) { break; }
            }
            assert!(!stack.backend_workers_ready(), "listener exit must wake the authority after the worker has stopped");
        }
    }

    #[test]
    fn corrected_startup_config_updates_supervisor_before_registry_version() {
        let mut f = fixture(true);
        assert!(f.stack.as_ref().unwrap().sandbox_registry.is_none());
        let mut cfg = Config::default_for_new_install();
        cfg.proxy_url = "http://127.0.0.1:18765".into();
        cfg.enabled = true;
        // Simulate an explicit external repair; ConfigStore::save correctly refuses to
        // merge into a corrupt file, and this test must not weaken that protection.
        f.store.atomic_json(&f.store.paths.config(), &cfg.value().unwrap()).unwrap();
        let saved = ConfigStore { storage: f.store.clone() }.load().unwrap();
        let expected = ChannelSupervisor::compute_policy_version(&saved).unwrap();
        let stack = f.stack.as_mut().unwrap();
        // No VPN observer/file-change event exists in this fixture: the recovery path must apply it itself.
        stack.reconcile_controlled_backend(native::now()).unwrap();
        assert!(stack.sandbox_registry.is_some());
        assert_eq!(stack.supervisor.saved_policy_version(), &expected);
        assert_eq!(stack.last_policy_version.as_ref(), Some(&expected));
        assert_eq!(stack.supervisor.config().proxy_url, saved.proxy_url);
        assert!(stack.supervisor.config_blocking_reason().is_none());
        assert!(!stack.enforcer.sandbox_ready().unwrap());
    }

    #[test]
    fn metadata_refresh_preserves_unchanged_entries_and_observes_target_changes() {
        let f = fixture(false);
        let target = f.root.join("Applications/Claude.app/Contents/MacOS/Claude");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(f.root.join("Applications/Claude.app/Contents/Info.plist"),
            r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>Claude</string></dict></plist>"#).unwrap();
        fs::write(&target, b"fixture-a").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let signature = target_metadata_signature(&f.store, Some(&f.store.paths.watch().join("runtime")));
        assert_eq!(signature, target_metadata_signature(&f.store, Some(&f.store.paths.watch().join("runtime"))));
        let entry = f.store.paths.watch().join("entries/apps/Claude (Controlled).app/Contents/Info.plist");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !entry.is_file() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        let modified = fs::metadata(&entry).unwrap().modified().unwrap();
        thread::sleep(Duration::from_millis(1200));
        assert_eq!(fs::metadata(&entry).unwrap().modified().unwrap(), modified,
            "unchanged metadata must not recopy/rewrite entries on every poll");
        fs::write(&target, b"fixture-b").unwrap();
        assert_ne!(signature, target_metadata_signature(&f.store, Some(&f.store.paths.watch().join("runtime"))));
        let sha = claude_watch_system::sha256_file_hex(&target).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !fs::read_to_string(&entry).unwrap().contains(&sha) {
            assert!(Instant::now() < deadline, "changed target was not refreshed");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn vpn_observer_worker_refreshes_immediately_on_wake_byte_without_exiting() {
        use claude_watch_core::vpn::{ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnObservation};
        use claude_watch_runtime::vpn_observer::VpnSourceReader;
        use std::io::Write;
        use std::sync::atomic::AtomicUsize;

        struct CountingReader(AtomicUsize);
        impl VpnSourceReader for CountingReader {
            fn read_observation(
                &self,
                _expectation: &VpnExpectation,
                _include_rules: bool,
                sample_seq: u64,
                epoch: VpnEpoch,
                now: f64,
            ) -> VpnObservation {
                self.0.fetch_add(1, Ordering::SeqCst);
                VpnObservation {
                    source: "clash-verge".into(),
                    source_instance: Some("inst-wake".into()),
                    source_revision: Some("rev-1".into()),
                    upstream_endpoint: Some("http://127.0.0.1:17890".into()),
                    upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
                    running_mode: ObservedField::Known("rule".into()),
                    tun_enabled: ObservedField::Known(false),
                    system_proxy_enabled: ObservedField::Known(false),
                    selected_group: ObservedField::Known("AI-Group".into()),
                    selected_node: ObservedField::Known("US-West-01".into()),
                    proxy_chain: ObservedField::Known(vec!["AI-Group".into(), "US-West-01".into()]),
                    rules_digest: ObservedField::Unknown("fixture".into()),
                    sample_started_at: now,
                    observed_at: now,
                    valid_until: now + 60.0,
                    consistency: ObservationConsistency::RevisionVerified,
                    source_error: None,
                    sample_seq,
                    epoch,
                }
            }
        }

        let root = std::env::temp_dir().join(format!("cw-vpn-wake-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let mut cfg = Config::default_for_new_install();
        cfg.proxy_mode = "clash-verge".into();
        cfg.proxy_url = "http://127.0.0.1:17890".into();
        let mut exp = VpnExpectation::unconfigured();
        exp.configured = true;
        exp.proxy_mode = "clash-verge".into();
        exp.proxy_url = "http://127.0.0.1:17890".into();
        cfg.vpn_expectation = Some(exp);
        ConfigStore { storage: store.clone() }.save(cfg.value().unwrap()).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = Arc::new(CountingReader(AtomicUsize::new(0)));
        let (handle, mut wake_handle) = spawn_vpn_observation_worker(
            store,
            None,
            stop.clone(),
            tx,
            thread::current(),
            Arc::new(ActiveGuardState::default()),
            Some(reader.clone()),
        )
        .unwrap();

        // 1. Initial sample arrives immediately on startup.
        let first = rx.recv_timeout(Duration::from_secs(2)).expect("initial VPN observation");
        let first_seq = match first {
            SupervisionEvent::VpnObservationUpdated { observation, .. } => observation.sample_seq,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(first_seq, 1);

        // 2. Writing a refresh byte wakes the worker immediately without exiting.
        wake_handle.write_all(b"R").unwrap();
        let second = rx.recv_timeout(Duration::from_secs(2)).expect("on-demand refreshed VPN observation");
        let second_seq = match second {
            SupervisionEvent::VpnObservationUpdated { observation, .. } => observation.sample_seq,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(second_seq, 2);
        assert!(!handle.is_finished(), "refresh wake byte must not terminate VPN observer thread");
        assert!(reader.0.load(Ordering::SeqCst) >= 2);

        // 3. Shutdown still stops cleanly when stop flag is set and wake handle drops.
        stop.store(true, Ordering::Release);
        drop(wake_handle);
        handle.join().expect("VPN observer worker must exit cleanly on shutdown");
        let _ = fs::remove_dir_all(&root);
    }
}
