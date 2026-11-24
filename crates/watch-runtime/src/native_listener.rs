//! Authenticated, bounded OS listener transport. The system shell only collects
//! raw observations; all interpretation and authority remain in Rust.
use crate::{
    commands::{Output, ReadCommand, ReadRunner},
    native::{self, Observer},
    sampler::parse_process_table,
    storage::{sha256, StateStore},
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::Identity,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::fd::AsFd,
    os::unix::net::{UnixListener, UnixStream},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

pub const SCRIPT: &str = "watch-native-collector.zsh";
const SCRIPT_BYTES: &[u8] = include_bytes!("../../../monitor/Resources/watch-native-collector.zsh");
const MAX_PART: usize = 4 * 1024 * 1024;
const MAX_TOTAL: usize = 8 * 1024 * 1024;
// Cached readers retain the collector's actual capture time. VPN and process
// consumers also apply their own shorter validity windows.
const MAX_AGE: f64 = 15.0;
/// Internal annotation ignored by netstat-row parsers. Consumers with tighter
/// evidence TTLs must preserve this capture time instead of stamping a reread.
pub(crate) const FRAME_META_PREFIX: &str = "# CW_LISTENER_FRAME ";
fn error(code: &str, detail: &str) -> CoreError {
    CoreError::new(code, detail)
}
fn invalid() -> CoreError {
    error("native_listener_protocol", "系统监听采样帧不完整或超出边界")
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub supervisor: Identity,
    pub worker: Identity,
    collector: Identity,
    root: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
struct Evidence {
    // Cached records already persist this lifetime in Captured::proof.
    #[serde(skip)]
    connection_source: Option<Identity>,
    supervisor: u32,
    collector: u32,
    sequence: u64,
    started: f64,
    finished: f64,
    table: String,
    owners: BTreeMap<u32, Value>,
    origins: BTreeMap<u32, Value>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Actor {
    supervisor: Identity,
    worker: Identity,
    root: PathBuf,
}
#[derive(Serialize, Deserialize)]
struct Captured {
    proof: Proof,
    evidence: Evidence,
}
#[derive(Serialize, Deserialize)]
struct Cached {
    schema: u32,
    published_at: f64,
    actor: Actor,
    listener: Option<Captured>,
    error: Option<CoreError>,
}
struct Raw {
    supervisor: u32,
    collector: u32,
    sequence: u64,
    started: f64,
    finished: f64,
    statuses: [i32; 3],
    before: Vec<u8>,
    table: Vec<u8>,
    errors: Vec<u8>,
    after: Vec<u8>,
}

fn frame<R: BufRead>(reader: &mut R) -> Result<Option<Raw>> {
    let mut header = Vec::new();
    if reader
        .take(513)
        .read_until(b'\n', &mut header)
        .map_err(|_| invalid())?
        == 0
    {
        return Ok(None);
    }
    if header.len() > 512 || header.last() != Some(&b'\n') {
        return Err(invalid());
    }
    let text = std::str::from_utf8(&header).map_err(|_| invalid())?;
    let fields = text.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 13 || fields[0] != "CWLISTENER1" {
        return Err(invalid());
    }
    let timestamp = |value: &str| -> Result<f64> {
        if value.len() > 32 || !value.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Err(invalid());
        }
        value.parse::<f64>().ok().filter(|t| t.is_finite() && *t > 0.0).ok_or_else(invalid)
    };
    let started = timestamp(fields[4])?;
    let finished = timestamp(fields[5])?;
    let n = fields[1..4]
        .iter()
        .chain(&fields[6..])
        .map(|v| v.parse::<u64>().map_err(|_| invalid()))
        .collect::<Result<Vec<_>>>()?;
    if n[0] < 2
        || n[1] < 2
        || n[0] > u32::MAX as u64
        || n[1] > u32::MAX as u64
        || n[2] == 0
        || n[3..6].iter().any(|v| *v > 255)
    {
        return Err(invalid());
    }
    let lengths = n[6..10]
        .iter()
        .map(|v| usize::try_from(*v).map_err(|_| invalid()))
        .collect::<Result<Vec<_>>>()?;
    if lengths.iter().any(|v| *v > MAX_PART) || lengths.iter().sum::<usize>() > MAX_TOTAL {
        return Err(invalid());
    }
    let mut parts = Vec::new();
    for length in lengths {
        let mut part = vec![0; length];
        reader.read_exact(&mut part).map_err(|_| invalid())?;
        parts.push(part);
    }
    let mut end = [0];
    reader.read_exact(&mut end).map_err(|_| invalid())?;
    if end != *b"\n" {
        return Err(invalid());
    }
    let mut parts = parts.into_iter();
    Ok(Some(Raw {
        supervisor: n[0] as u32,
        collector: n[1] as u32,
        sequence: n[2],
        started,
        finished,
        statuses: [n[3] as i32, n[4] as i32, n[5] as i32],
        before: parts.next().unwrap(),
        table: parts.next().unwrap(),
        errors: parts.next().unwrap(),
        after: parts.next().unwrap(),
    }))
}
fn same(a: &Value, b: &Value) -> bool {
    a["uid"] == b["uid"]
        && a["executable"] == b["executable"]
        && a["stamp"]
            .as_str()
            .zip(b["stamp"].as_str())
            .is_some_and(|(x, y)| x.split_whitespace().eq(y.split_whitespace()))
}
fn owner_ids(table: &str) -> Result<BTreeSet<u32>> {
    let mut ids = BTreeSet::new();
    for line in table.lines() {
        let f = line.split_whitespace().collect::<Vec<_>>();
        if f.len() < 6 || !matches!(f[0], "tcp4" | "tcp6" | "tcp46") || f[5] != "LISTEN" {
            return Err(invalid());
        }
        let owners = f[6..]
            .iter()
            .filter_map(|v| {
                let (name, pid) = v.split_once(':')?;
                if name.is_empty() || pid.starts_with('0') {
                    return None;
                }
                pid.parse::<u32>().ok().filter(|p| *p > 1)
            })
            .collect::<Vec<_>>();
        if owners.len() == 1 {
            ids.insert(owners[0]);
        }
    }
    if table.trim().is_empty() {
        return Err(error("native_listener_empty", "系统未提供 TCP 监听记录"));
    }
    Ok(ids)
}
fn normalize(raw: Raw) -> Result<Evidence> {
    if !(0.0..=5.0).contains(&(raw.finished - raw.started)) {
        return Err(error("native_listener_sample_span", "系统监听采样时间跨度无效，本轮证据不可用"));
    }
    if raw.statuses != [0, 0, 0] || !raw.errors.is_empty() {
        return Err(error(
            "native_listener_sample_failed",
            "系统监听或进程采样命令未完成；未视为网络切换",
        ));
    }
    let before = parse_process_table(std::str::from_utf8(&raw.before).map_err(|_| invalid())?)?;
    let after = parse_process_table(std::str::from_utf8(&raw.after).map_err(|_| invalid())?)?;
    let table = String::from_utf8(raw.table).map_err(|_| invalid())?;
    let ids = owner_ids(&table)?;
    let mut owners = BTreeMap::new();
    for pid in ids {
        if let Some((a, b)) = before.get(&pid).zip(after.get(&pid)) {
            if same(a, b) {
                owners.insert(pid, b.clone());
            }
        }
    }
    let mut origins = BTreeMap::new();
    for pid in [raw.supervisor, raw.collector] {
        let (a, b) = before.get(&pid).zip(after.get(&pid)).ok_or_else(invalid)?;
        if !same(a, b) {
            return Err(invalid());
        }
        origins.insert(pid, b.clone());
    }
    Ok(Evidence {
        connection_source: None,
        supervisor: raw.supervisor,
        collector: raw.collector,
        sequence: raw.sequence,
        started: raw.started,
        finished: raw.finished,
        table,
        owners,
        origins,
    })
}
fn resources(root: &Path, uid: u32) -> Result<()> {
    let engine = fs::symlink_metadata(root.join("watch-engine")).map_err(|_| invalid())?;
    if !engine.is_file()
        || engine.file_type().is_symlink()
        || engine.uid() != uid
        || engine.mode() & 0o022 != 0
        || engine.mode() & 0o111 == 0
    {
        return Err(error(
            "native_listener_component_changed",
            "原生运行组件身份不匹配",
        ));
    }
    let script = root.join(SCRIPT);
    let meta = fs::symlink_metadata(&script).map_err(|_| invalid())?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
        || meta.len() > 128 * 1024
        || sha256(&fs::read(&script).map_err(|_| invalid())?) != sha256(SCRIPT_BYTES)
    {
        return Err(error(
            "native_listener_component_changed",
            "系统采样组件身份或内容不匹配",
        ));
    }
    Ok(())
}
fn verify<R: ReadRunner>(p: &Proof, runner: &R, job: bool) -> Result<()> {
    verify_context(
        &p.supervisor,
        &p.worker,
        Some(&p.collector),
        &p.root,
        runner,
        job,
    )
}
fn verify_actor<R: ReadRunner>(p: &Actor, runner: &R, job: bool) -> Result<()> {
    verify_context(&p.supervisor, &p.worker, None, &p.root, runner, job)
}
fn verify_context<R: ReadRunner>(
    supervisor: &Identity,
    worker: &Identity,
    collector: Option<&Identity>,
    root: &Path,
    runner: &R,
    job: bool,
) -> Result<()> {
    let uid = worker.uid;
    if uid == 0
        || !worker.valid()
        || !supervisor.valid()
        || supervisor.uid != uid
        || worker.parent != supervisor.pid
        || supervisor.executable != "/bin/zsh"
        || Path::new(&worker.executable) != root.join("watch-engine")
        || collector.is_some_and(|c| {
            !c.valid()
                || c.uid != uid
                || c.parent != supervisor.pid
                || worker.pid == c.pid
                || c.executable != "/bin/zsh"
        })
    {
        return Err(error(
            "native_listener_origin_invalid",
            "系统采样进程关系未通过核对",
        ));
    }
    resources(root, uid)?;
    let mut expected = vec![supervisor.clone(), worker.clone()];
    if let Some(c) = collector {
        expected.push(c.clone());
    }
    let observer = Observer { runner };
    if expected
        .iter()
        .any(|i| !runner.process_identity(i.pid).is_some_and(|v| v.same_process(i)))
    {
        return Err(error(
            "native_listener_origin_changed",
            "系统采样进程退出或启动身份已变化",
        ));
    }
    let mut arg_targets = vec![supervisor.clone()];
    if let Some(c) = collector {
        arg_targets.push(c.clone());
    }
    let args = observer.arguments(&arg_targets, "native-listener-arguments")?;
    let prefix = vec![
        "/bin/zsh".to_string(),
        "-f".to_string(),
        root.join(SCRIPT).to_string_lossy().into_owned(),
    ];
    for id in &arg_targets {
        let a = args
            .get(&id.pid)
            .filter(|a| !a.truncated)
            .ok_or_else(invalid)?;
        if !a.tokens.starts_with(&prefix)
            || (id.pid != supervisor.pid
                && a.tokens.get(3..)
                    != Some(&["--collect".to_string(), supervisor.pid.to_string()][..]))
        {
            return Err(error(
                "native_listener_origin_invalid",
                "系统采样进程参数与固定组件不符",
            ));
        }
    }
    // Arguments are read between lifetime checks. PID reuse/exec or a replaced
    // collector must not borrow a former source's validated argument prefix.
    if expected.iter().any(|i| !runner.process_identity(i.pid).is_some_and(|v| v.same_process(i))) {
        return Err(error("native_listener_origin_changed", "系统采样来源在参数读取期间变化"));
    }
    if job {
        let mut expected = prefix;
        expected.extend(["daemon".to_string(), "--apply".to_string()]);
        if args
            .get(&supervisor.pid)
            .is_none_or(|v| v.tokens != expected)
        {
            return Err(error(
                "native_listener_origin_invalid",
                "正式采样监督进程的启动参数不匹配",
            ));
        }
        let o = runner.run(
            ReadCommand::LaunchctlGuiAgent { uid },
            &[],
            Duration::from_secs(3),
            256 * 1024,
        )?;
        if o.status != 0
            || crate::commands::loaded_agent_identity(o.text()?)
                != Some(("running", supervisor.pid))
        {
            return Err(error(
                "native_listener_unregistered",
                "系统采样监督进程不是当前固定后台任务",
            ));
        }
    }
    Ok(())
}
fn output<R: ReadRunner>(e: &Evidence, p: &Proof, runner: &R, job: bool) -> Result<Output> {
    let now = native::now();
    if !e.started.is_finite()
        || !e.finished.is_finite()
        || e.started <= 0.0
        || e.sequence == 0
        || e.finished < e.started
        || e.finished - e.started > 5.0
        || !(0.0..=MAX_AGE).contains(&(now - e.finished))
        || e.supervisor != p.supervisor.pid
        || e.collector != p.collector.pid
    {
        return Err(error(
            "native_listener_stale",
            "系统监听采样已过期或来源不匹配",
        ));
    }
    verify(p, runner, job)?;
    for origin in [&p.supervisor, &p.collector] {
        let actual =
            json!({"uid":origin.uid,"executable":origin.executable,"stamp":origin.start_stamp});
        if !e
            .origins
            .get(&origin.pid)
            .is_some_and(|captured| same(captured, &actual))
        {
            return Err(error(
                "native_listener_origin_changed",
                "系统采样来源在采样后重启",
            ));
        }
    }
    let current = runner.run(
        ReadCommand::ProcessTablePids { pids: e.owners.keys().copied().collect() },
        &[],
        Duration::from_secs(3),
        MAX_PART,
    )?;
    if current.status != 0 || !current.stderr.is_empty() {
        return Err(error(
            "native_listener_identity_unavailable",
            "无法复核当前监听进程",
        ));
    }
    let current = parse_process_table(current.text()?)?;
    owner_ids(&e.table)?;
    // Preserve an unverifiable row, including its listening address, but remove
    // its claimed owner. The existing per-port verifier then rejects that port;
    // an unrelated listener's disappearance does not invalidate every port.
    let table = e
        .table
        .lines()
        .map(|line| {
            let mut fields = line
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            let claims = fields
                .iter()
                .enumerate()
                .skip(6)
                .filter_map(|(i, v)| {
                    v.split_once(':')
                        .and_then(|(_, p)| p.parse::<u32>().ok())
                        .map(|p| (i, p))
                })
                .collect::<Vec<_>>();
            let verified = claims.len() == 1
                && e.owners
                    .get(&claims[0].1)
                    .zip(current.get(&claims[0].1))
                    .is_some_and(|(a, b)| same(a, b));
            if !verified {
                for (i, _) in claims {
                    fields[i] = "unconfirmed_owner".into();
                }
            }
            fields.join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !(0.0..=MAX_AGE).contains(&(native::now() - e.finished)) {
        return Err(error("native_listener_stale", "系统监听采样在复核期间过期"));
    }
    Ok(Output {
        status: 0,
        stdout: format!("{FRAME_META_PREFIX}{}\n{table}", json!({
            "captured_at": e.finished, "sequence": e.sequence,
            "origin_id": format!("{}:{}:{}:{}:{}:{}", p.supervisor.pid,
                p.supervisor.start_seconds, p.supervisor.start_microseconds,
                p.collector.pid, p.collector.start_seconds, p.collector.start_microseconds),
        })).into_bytes(),
        stderr: vec![],
    })
}

pub type ListenerFailureNotice = dyn Fn(&CoreError) + Send + Sync;

#[derive(Default)]
struct ListenerFailures {
    latest: Option<(u64, CoreError)>,
    subscribers: Vec<std::sync::Weak<ListenerFailureNotice>>,
}

struct SampleRequests {
    writer: UnixStream,
    outstanding: Option<(u64, Instant)>,
    follow_up: bool,
}
impl SampleRequests {
    fn send(&mut self, revision: u64) -> Result<u64> {
        if self.writer.write_all(b"S").is_err() {
            // Wake the blocked reader so it publishes loss of this generation.
            let _ = self.writer.shutdown(std::net::Shutdown::Both);
            return Err(error("native_listener_closed", "原生采样请求通道已关闭"));
        }
        self.outstanding = Some((revision, Instant::now() + Duration::from_secs_f64(MAX_AGE)));
        Ok(revision)
    }
}

const MAX_CONSECUTIVE_RESPONSE_TIMEOUTS: u32 = 3;

pub struct ListenerStream {
    requests: Mutex<Option<SampleRequests>>,
    notifications: Arc<claude_watch_system::network_events::LocalNotifications>,
    root: PathBuf,
    worker: Identity,
    supervisor: Identity,
    state: Arc<(Mutex<Option<Result<Evidence>>>, Condvar)>,
    revision: Arc<AtomicU64>,
    last_failure: Mutex<ListenerFailures>,
    published_revision: Mutex<Option<u64>>,
    consecutive_timeouts: std::sync::atomic::AtomicU32,
    finished: Arc<AtomicBool>,
}
impl ListenerStream {
    pub fn start<R: ReadRunner + Send + Sync + 'static>(runner: Arc<R>, executable: &Path) -> Result<Arc<Self>> {
        if !fs::metadata("/dev/fd/0").is_ok_and(|m| m.file_type().is_socket()) {
            return Err(error("native_listener_socket_required", "系统监听数据必须来自固定监督进程的套接字"));
        }
        let fd = std::io::stdin().as_fd().try_clone_to_owned().map_err(|_| invalid())?;
        let listener = UnixListener::from(fd);
        let root =
            fs::canonicalize(executable.parent().ok_or_else(invalid)?).map_err(|_| invalid())?;
        let worker = runner.process_identity(std::process::id()).ok_or_else(invalid)?;
        let supervisor = runner.process_identity(worker.parent).ok_or_else(invalid)?;
        resources(&root, worker.uid)?;
        let stream = Arc::new(Self {
            requests: Mutex::default(), root, worker, supervisor, state: Arc::new((Mutex::new(None), Condvar::new())),
            revision: Arc::new(AtomicU64::new(0)), notifications: Arc::default(),
            published_revision: Mutex::new(None), last_failure: Mutex::default(),
            consecutive_timeouts: std::sync::atomic::AtomicU32::new(0),
            finished: Arc::new(AtomicBool::new(false)),
        });
        let input = stream.clone();
        thread::Builder::new().name("native-listener-input".into()).spawn(move || {
            loop {
                let (connection, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        input.finished.store(true, Ordering::Release);
                        input.record(Err(error("native_listener_transport_failed", "系统监听输入端不可用")));
                        break;
                    }
                };
                // A private pathname alone does not authenticate a same-UID
                // client. Bind the connection to its kernel lifetime first.
                let Some(peer) = claude_watch_system::unix_stream_peer_process(&connection) else { continue; };
                if peer.ppid != input.supervisor.pid || peer.uid != input.worker.uid || peer.executable_path != "/bin/zsh" {
                    continue;
                }
                let Some(collector) = runner.process_identity(peer.pid) else { continue; };
                if collector.start_seconds != peer.start_seconds || collector.start_microseconds != peer.start_microseconds {
                    continue;
                }
                let verified = verify_context(&input.supervisor, &input.worker, Some(&collector), &input.root, runner.as_ref(), false);
                if let Err(e) = verified { input.record(Err(e)); continue; }
                // Only a connection from this verified child may publish. Each
                // replacement gets its own buffered reader and sequence space.
                input.read_generation(connection, &collector);
                if input.is_finished() { break; }
            }
        }).map_err(|_| error("native_listener_start_failed", "无法启动系统采样读取线程"))?;
        Ok(stream)
    }
    /// A concurrent invalidation may arrive after collection has begun. One
    /// trailing request suffices for all such callers; they receive its revision.
    pub fn request_sample(&self) -> Result<u64> {
        let mut slot = self.requests.lock().map_err(|_| invalid())?;
        if self.is_finished() { return Err(error("native_listener_worker_failed", "原生采样输入已停止")); }
        let active = slot.as_mut().ok_or_else(|| error("native_listener_pending", "等待已核验的原生采集器连接"))?;
        if let Some((revision, _)) = active.outstanding {
            active.follow_up = true;
            return Ok(revision + 1);
        }
        active.send(self.revision.load(Ordering::Acquire) + 1)
    }

    /// Routine renewal callers (not triggered by a network/config invalidation)
    /// can share an already in-flight collection frame instead of queuing a
    /// back-to-back follow-up round.
    pub fn request_or_join_sample(&self) -> Result<u64> {
        let mut slot = self.requests.lock().map_err(|_| invalid())?;
        if self.is_finished() { return Err(error("native_listener_worker_failed", "原生采样输入已停止")); }
        let active = slot.as_mut().ok_or_else(|| error("native_listener_pending", "等待已核验的原生采集器连接"))?;
        if let Some((revision, _)) = active.outstanding {
            return Ok(revision);
        }
        active.send(self.revision.load(Ordering::Acquire) + 1)
    }

    /// A silent command may hold the authenticated socket open indefinitely.
    /// Let the daemon wait for the reply only while its evidence can be useful.
    pub fn pending_sample_deadline(&self) -> Result<Option<Instant>> {
        self.pending_sample_deadline_at(Instant::now())
    }

    fn pending_sample_deadline_at(&self, now: Instant) -> Result<Option<Instant>> {
        let mut slot = self.requests.lock().map_err(|_| invalid())?;
        let Some(active) = slot.as_ref() else { return Ok(None); };
        let Some((_, deadline)) = active.outstanding else { return Ok(None); };
        if now < deadline { return Ok(Some(deadline)); }
        let active = slot.take().expect("checked active request");
        let timeout = error("native_listener_response_timeout", "原生采集器在采样期限内未回复");
        let streak = self
            .consecutive_timeouts
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if streak >= MAX_CONSECUTIVE_RESPONSE_TIMEOUTS {
            self.finished.store(true, Ordering::Release);
        }
        self.record(Err(timeout.clone()));
        let _ = active.writer.shutdown(std::net::Shutdown::Both);
        Err(timeout)
    }

    fn read_generation(&self, connection: UnixStream, collector: &Identity) {
        let mut reader = BufReader::new(connection);
        let result = self.read_requested_frames(&mut reader, collector);
        let was_active = self.requests.lock().unwrap_or_else(|e| e.into_inner()).take().is_some();
        if was_active && !self.is_finished() {
            if let Err(e) = result { self.record(Err(e)); }
        }
    }

    fn read_requested_frames(&self, reader: &mut BufReader<UnixStream>, collector: &Identity) -> Result<()> {
        let writer = reader.get_ref().try_clone().map_err(|_| invalid())?;
        {
            let mut slot = self.requests.lock().map_err(|_| invalid())?;
            let mut active = SampleRequests { writer, outstanding: None, follow_up: false };
            active.send(self.revision.load(Ordering::Acquire) + 1)?;
            *slot = Some(active);
        }
        let mut sequence = 0;
        // Keep reading when idle: EOF or a damaged response must withdraw the
        // old evidence immediately, independently of the next sampling request.
        loop {
            let raw = frame(reader)?.ok_or_else(|| error("native_listener_closed", "系统采样子进程通道关闭，等待重新连接"))?;
            if raw.collector != collector.pid || raw.supervisor != self.supervisor.pid || raw.sequence != sequence + 1 {
                return Err(invalid());
            }
            sequence = raw.sequence;
            let sample = normalize(raw).map(|mut evidence| {
                evidence.connection_source = Some(collector.clone());
                evidence
            });
            let mut slot = self.requests.lock().map_err(|_| invalid())?;
            let active = slot.as_mut().ok_or_else(invalid)?;
            let expected = self.revision.load(Ordering::Acquire) + 1;
            if self.is_finished() || active.outstanding.take().map(|(revision, _)| revision) != Some(expected) {
                return Err(invalid());
            }
            if sample.is_ok() {
                self.consecutive_timeouts.store(0, Ordering::Release);
            }
            self.record(sample);
            if std::mem::take(&mut active.follow_up) { active.send(expected + 1)?; }
        }
    }
    fn record(&self, observation: Result<Evidence>) {
        let mut latest = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        let revision = self.revision.fetch_add(1, Ordering::AcqRel) + 1;
        if let Err(ref reason) = observation {
            let mut failures = self.last_failure.lock().unwrap_or_else(|e| e.into_inner());
            let new_loss = !matches!(latest.as_ref(), Some(Err(previous)) if previous.code == reason.code);
            failures.latest = Some((revision, reason.clone()));
            if new_loss {
                failures.subscribers.retain(|subscriber| {
                    let Some(notice) = subscriber.upgrade() else { return false; };
                    notice(reason);
                    true
                });
            }
        }
        *latest = Some(observation);
        self.state.1.notify_all();
        self.notifications.publish();
    }
    /// Failure edges survive coalesced notifications and a following good frame.
    pub fn failure_since(&self, previous: u64) -> Option<(u64, CoreError)> {
        self.last_failure.lock().unwrap_or_else(|e| e.into_inner()).latest.as_ref()
            .filter(|(revision, _)| *revision > previous).cloned()
    }
    /// The callback only enqueues a withdrawal. It shares ordering with a
    /// successful publication and never waits for outstanding controller HTTP.
    pub fn subscribe_failures(&self, notice: &Arc<ListenerFailureNotice>) {
        let mut failures = self.last_failure.lock().unwrap_or_else(|e| e.into_inner());
        failures.subscribers.retain(|sub| sub.strong_count() != 0);
        if let Some((_, error)) = &failures.latest { notice(error); }
        failures.subscribers.push(Arc::downgrade(notice));
    }
    pub fn send_if_no_new_failure(&self, previous: u64, send: impl FnOnce()) -> Result<()> {
        let failures = self.last_failure.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, error)) = failures.latest.as_ref().filter(|(at, _)| *at > previous) {
            return Err(error.clone());
        }
        send();
        Ok(())
    }
    pub fn subscribe_frames(&self) -> Result<std::os::unix::net::UnixStream> {
        self.notifications.subscribe().map_err(|_| invalid())
    }
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    /// Scheduling hint only. Callers must still read and authenticate the frame;
    /// a notification neither renews its capture time nor proves its owner.
    pub fn wait_for_revision(&self, previous: u64, timeout: Duration) -> Result<u64> {
        let state = self.state.0.lock().map_err(|_| invalid())?;
        let (_state, _) = self.state.1.wait_timeout_while(state, timeout, |_| {
            self.revision.load(Ordering::Acquire) == previous
        }).map_err(|_| invalid())?;
        Ok(self.revision.load(Ordering::Acquire))
    }
    fn latest_with_timeout(&self, timeout: Duration) -> Result<Evidence> {
        self.publication_snapshot(timeout)?.1
    }
    fn publication_snapshot(&self, timeout: Duration) -> Result<(u64, Result<Evidence>)> {
        let mut state = self.state.0.lock().map_err(|_| invalid())?;
        if state.is_none() {
            state = self
                .state
                .1
                .wait_timeout_while(state, timeout, |s| s.is_none())
                .map_err(|_| invalid())?
                .0;
        }
        let observed = state
            .clone()
            .unwrap_or_else(|| Err(error("native_listener_pending", "尚未收到系统监听采样")));
        Ok((self.revision.load(Ordering::Acquire), observed))
    }
    fn proof<R: ReadRunner>(&self, e: &Evidence, runner: &R) -> Result<Proof> {
        let collector = runner.process_identity(e.collector)
            .filter(|live| e.connection_source.as_ref().is_none_or(|source| live.same_process(source)))
            .ok_or_else(|| error("native_listener_origin_changed", "系统采样进程已退出"))?;
        Ok(Proof {
            supervisor: self.supervisor.clone(),
            worker: self.worker.clone(),
            collector,
            root: self.root.clone(),
        })
    }
    pub fn read<R: ReadRunner>(&self, runner: &R) -> Result<Output> {
        self.read_with_timeout(runner, Duration::from_secs(5))
    }
    pub(crate) fn read_with_timeout<R: ReadRunner>(&self, runner: &R, timeout: Duration) -> Result<Output> {
        let e = self.latest_with_timeout(timeout)?;
        let p = self.proof(&e, runner)?;
        output(&e, &p, runner, false)
    }
    pub fn publish<R: ReadRunner>(&self, store: &StateStore, runner: &R) -> Result<()> {
        let (revision, observed) = self.publication_snapshot(Duration::from_secs(5))?;
        self.publish_observation(store, runner, observed)?;
        *self.published_revision.lock().map_err(|_| invalid())? = Some(revision);
        Ok(())
    }
    fn publish_changed<R: ReadRunner>(&self, store: &StateStore, runner: &R,
        previous: &mut Option<u64>) -> Result<bool> {
        let (revision, observed) = {
            let state = self.state.0.lock().map_err(|_| invalid())?;
            let Some(observed) = state.as_ref() else { return Ok(false); };
            let revision = self.revision.load(Ordering::Acquire);
            if *previous == Some(revision) { return Ok(false); }
            (revision, observed.clone())
        };
        // A failed write is retried on the next input revision. Repeating the
        // same operation here would spin while storage remains unavailable.
        *previous = Some(revision);
        self.publish_observation(store, runner, observed)?;
        Ok(true)
    }
    fn publish_observation<R: ReadRunner>(&self, store: &StateStore, runner: &R,
        observed: Result<Evidence>) -> Result<()> {
        let bounded = crate::commands::DeadlineRunner::new(runner, Duration::from_secs(1));
        let runner = &bounded;
        let actor = Actor {
            supervisor: self.supervisor.clone(),
            worker: self.worker.clone(),
            root: self.root.clone(),
        };
        let value = (|| {
            verify_actor(&actor, runner, false)?;
            let observed = (|| {
                let e = observed?;
                let p = self.proof(&e, runner)?;
                output(&e, &p, runner, false)?;
                Ok(Captured {
                    proof: p,
                    evidence: e,
                })
            })();
            let (listener, failure) = match observed {
                Ok(v) => (Some(v), None),
                Err(e) => (None, Some(e)),
            };
            serde_json::to_value(Cached {
                schema: 2,
                published_at: native::now(),
                actor,
                listener,
                error: failure,
            })
            .map_err(|_| invalid())
        })();
        store.atomic_json(
            &cache_path(store),
            &value
                .unwrap_or_else(|e| json!({"schema":2,"error":e.code,"observed_at":native::now()})),
        )
    }

    /// Publish new native frames independently from UI/process collection.
    /// Identity checks happen only for a changed frame/error; unchanged frames
    /// retain both their original capture time and cache publication time.
    pub fn start_publisher<R: ReadRunner + Send + Sync + 'static>(self: &Arc<Self>,
        store: StateStore, runner: Arc<R>) -> Result<ListenerCachePublisher> {
        let stream = self.clone();
        let failure = Arc::new(Mutex::new(None));
        let thread_failure = failure.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let mut previous = *self.published_revision.lock().map_err(|_| invalid())?;
        let worker = thread::Builder::new().name("watch-native-cache-publisher".into()).spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                loop {
                    let state = stream.state.0.lock().map_err(|_| invalid())?;
                    let state = stream.state.1.wait_while(state, |_| {
                        !thread_stop.load(Ordering::Acquire)
                            && previous.unwrap_or(0) == stream.revision.load(Ordering::Acquire)
                    }).map_err(|_| invalid())?;
                    drop(state);
                    if thread_stop.load(Ordering::Acquire) { return Ok(()); }
                    match stream.publish_changed(&store, runner.as_ref(), &mut previous) {
                        Ok(true) => *thread_failure.lock().map_err(|_| invalid())? = None,
                        Ok(false) => (),
                        Err(e) => *thread_failure.lock().map_err(|_| invalid())? = Some(e),
                    }
                }
            })).unwrap_or_else(|_| Err(error("native_listener_publisher_panicked", "系统采样发布线程异常退出")));
            if let Err(ref e) = outcome {
                *thread_failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.clone());
            }
            outcome
        }).map_err(|_| error("native_listener_publisher_start_failed", "系统采样发布线程无法启动"))?;
        Ok(ListenerCachePublisher { stream: self.clone(), stop, failure, worker: Some(worker) })
    }
}

pub struct ListenerCachePublisher {
    stream: Arc<ListenerStream>,
    stop: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<CoreError>>>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl ListenerCachePublisher {
    pub fn check(&self) -> Result<()> {
        match self.failure.lock().map_err(|_| invalid())?.clone() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    pub fn finish(&mut self) -> Result<()> {
        {
            let _state = self.stream.state.0.lock().unwrap_or_else(|error| error.into_inner());
            self.stop.store(true, Ordering::Release);
            self.stream.state.1.notify_all();
            self.stream.notifications.publish();
        }
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap_or_else(|_| Err(error("native_listener_publisher_panicked", "系统采样发布线程异常退出")))?;
        }
        Ok(())
    }
}
impl Drop for ListenerCachePublisher {
    fn drop(&mut self) { let _ = self.finish(); }
}
fn cache_path(store: &StateStore) -> PathBuf {
    store.paths.watch().join("state/native-listener.json")
}
fn cached(store: &StateStore) -> Result<Cached> {
    let bytes = store
        .read_bytes(&cache_path(store), MAX_TOTAL)?
        .ok_or_else(|| error("native_listener_missing", "后台尚未发布系统监听采样"))?;
    let raw = crate::storage::strict_json(&bytes)?;
    let c: Cached = serde_json::from_value(raw)
        .map_err(|_| error("native_listener_unavailable", "后台系统监听采样当前不可用"))?;
    if c.schema != 2
        || c.actor.root != store.paths.watch().join("runtime")
        || !c.published_at.is_finite()
        || !(0.0..=30.0).contains(&(native::now() - c.published_at))
        || c.listener.is_some() == c.error.is_some()
    {
        return Err(invalid());
    }
    Ok(c)
}
pub fn read_cached<R: ReadRunner>(store: &StateStore, runner: &R) -> Result<Output> {
    let c = cached(store)?;
    let data = c.listener.ok_or_else(|| {
        c.error
            .unwrap_or_else(|| error("native_listener_unavailable", "本轮系统监听采样不可用"))
    })?;
    if !data.proof.worker.same_process(&c.actor.worker)
        || !data.proof.supervisor.same_process(&c.actor.supervisor)
        || data.proof.root != c.actor.root
    {
        return Err(invalid());
    }
    output(&data.evidence, &data.proof, runner, true)
}
pub fn registered_worker<R: ReadRunner>(store: &StateStore, runner: &R, pid: u32) -> bool {
    registered_worker_result(store, runner, pid).is_ok()
}
pub(crate) fn registered_worker_result<R: ReadRunner>(store: &StateStore, runner: &R, pid: u32) -> Result<()> {
    let c = cached(store)?;
    if c.actor.worker.pid != pid {
        return Err(error("native_listener_worker_mismatch", "采样记录中的 worker PID 与心跳 PID 不一致"));
    }
    verify_actor(&c.actor, runner, true)
}
pub fn cache_exists(store: &StateStore) -> bool {
    cache_path(store).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::ObserverAction;
    use std::io::Cursor;

    fn raw() -> Raw {
        let rows=b"100 1 501 Mon Oct 26 20:45:10 2026 /bin/zsh\n101 100 501 Mon Oct 26 20:45:11 2026 /bin/zsh\n102 1 0 Mon Oct 26 20:40:00 2026 /Applications/TAG.app/Contents/Resources/bin/mihomo-tag\n".to_vec();
        Raw {
            supervisor: 100,
            collector: 101,
            sequence: 1,
            started: 1000.,
            finished: 1001.,
            statuses: [0, 0, 0],
            before: rows.clone(),
            table: b"tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 0 0 mihomo:102\n".to_vec(),
            errors: vec![],
            after: rows,
        }
    }
    fn encoded(r: &Raw) -> Vec<u8> {
        let mut data = format!(
            "CWLISTENER1 {} {} {} {} {} {} {} {} {} {} {} {}\n",
            r.supervisor,
            r.collector,
            r.sequence,
            r.started,
            r.finished,
            r.statuses[0],
            r.statuses[1],
            r.statuses[2],
            r.before.len(),
            r.table.len(),
            r.errors.len(),
            r.after.len()
        )
        .into_bytes();
        for p in [&r.before, &r.table, &r.errors, &r.after] {
            data.extend(p);
        }
        data.push(b'\n');
        data
    }
    #[test]
    fn frame_preserves_boundaries_and_rejects_partial_or_oversized_data() {
        let mut sample = raw();
        sample.started = 1000.125;
        sample.finished = 1001.25;
        let mut data = encoded(&sample);
        let r = frame(&mut Cursor::new(&data)).unwrap().unwrap();
        assert_eq!((r.started, r.finished), (1000.125, 1001.25));
        assert_eq!(normalize(r).unwrap().owners.len(), 1);
        data.pop();
        assert!(frame(&mut Cursor::new(data)).is_err());
        assert!(frame(&mut Cursor::new(
            b"CWLISTENER1 100 101 1 1000 1001 0 0 0 999999999 0 0 0\n"
        ))
        .is_err());
        assert!(frame(&mut Cursor::new(
            b"CWLISTENER1 100 101 0 1000 1001 0 0 0 0 0 0 0\n\n"
        ))
        .is_err());
    }
    #[test]
    fn failed_command_and_changed_capture_origin_are_not_success() {
        let mut r = raw();
        r.statuses[1] = 1;
        assert_eq!(
            normalize(r).err().unwrap().code,
            "native_listener_sample_failed"
        );
        let mut r = raw();
        r.after = String::from_utf8(r.after)
            .unwrap()
            .replace("20:45:11", "20:45:12")
            .into_bytes();
        assert_eq!(normalize(r).err().unwrap().code, "native_listener_protocol");
    }
    #[test]
    fn unrelated_missing_owner_does_not_remove_the_target_listener() {
        let mut r = raw();
        r.table
            .extend_from_slice(b"tcp4 0 0 *.9999 *.* LISTEN 0 0 0 0 unknown\n");
        let e = normalize(r).unwrap();
        assert_eq!(e.owners.len(), 1);
        assert!(e.owners.contains_key(&102));
        let mut r = raw();
        r.after = String::from_utf8(r.after)
            .unwrap()
            .replace("20:40:00", "20:40:01")
            .into_bytes();
        assert!(!normalize(r).unwrap().owners.contains_key(&102));
    }
    fn identity(pid: u32, parent: u32, uid: u32, exe: String) -> Identity {
        Identity {
            pid,
            parent,
            uid,
            executable: exe,
            start_seconds: 1000,
            start_microseconds: 1,
            start_stamp: "Mon Oct 26 20:45:10 2026".into(),
        }
    }
    #[test]
    fn missing_first_listener_frame_respects_caller_budget() {
        struct Unused;
        impl ReadRunner for Unused {
            fn run(&self, _: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
                panic!("missing listener frame must not start identity queries");
            }
        }
        let stream = ListenerStream { requests: Mutex::default(), last_failure: Mutex::default(), notifications: Arc::default(),
            root: PathBuf::from("/fixture"),
            worker: identity(101, 100, 501, "/fixture/worker".into()),
            supervisor: identity(100, 1, 501, "/bin/zsh".into()),
            state: Arc::new((Mutex::new(None), Condvar::new())),
            revision: Arc::new(AtomicU64::new(0)), published_revision: Mutex::new(None),
            consecutive_timeouts: std::sync::atomic::AtomicU32::new(0),
            finished: Arc::new(AtomicBool::new(false)),
        };
        let started = std::time::Instant::now();
        let error = stream.read_with_timeout(&Unused, Duration::from_millis(40)).err().unwrap();
        assert_eq!(error.code, "native_listener_pending");
        assert!(started.elapsed() < Duration::from_millis(400), "must not wait the old five-second default");
    }
    struct Source {
        proof: Proof,
        job_pid: u32,
        changed: bool,
        extra_supervisor_argument: bool,
    }
    struct PublisherFixture {
        home: PathBuf,
        store: StateStore,
        stream: Arc<ListenerStream>,
        source: Arc<Source>,
    }
    impl PublisherFixture {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let home = std::env::temp_dir().join(format!("cw-independent-listener-{}",uuid::Uuid::new_v4()));
            fs::create_dir(&home).unwrap();
            let store = StateStore::new(crate::storage::Paths::new(&home).unwrap());
            let root = store.paths.watch().join("runtime");
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join(SCRIPT),SCRIPT_BYTES).unwrap();
            fs::write(root.join("watch-engine"),b"fixture").unwrap();
            fs::set_permissions(root.join("watch-engine"),fs::Permissions::from_mode(0o700)).unwrap();
            let uid = fs::metadata(&home).unwrap().uid();
            let mut proof = Proof { supervisor:identity(100,1,uid,"/bin/zsh".into()),
                worker:identity(103,100,uid,root.join("watch-engine").display().to_string()),
                collector:identity(101,100,uid,"/bin/zsh".into()),root:root.clone() };
            proof.collector.start_stamp = "Mon Oct 26 20:45:11 2026".into();
            let source = Arc::new(Source { proof:proof.clone(),job_pid:100,changed:false,extra_supervisor_argument:false });
            let stream = Arc::new(ListenerStream { requests: Mutex::default(), last_failure: Mutex::default(), notifications: Arc::default(), root,worker:proof.worker,supervisor:proof.supervisor,
                state:Arc::new((Mutex::new(None),Condvar::new())),revision:Arc::new(AtomicU64::new(0)),
                published_revision:Mutex::new(None),
                consecutive_timeouts: std::sync::atomic::AtomicU32::new(0),
                finished:Arc::new(AtomicBool::new(false)) });
            let fixture = Self { home,store,stream,source };
            fixture.frame(1);
            fixture
        }
        fn set(&self, observed: Result<Evidence>) {
            self.stream.record(observed);
        }
        fn frame(&self, sequence: u64) -> f64 {
            let mut raw = raw();
            raw.sequence = sequence; raw.started = native::now()-0.25; raw.finished = raw.started;
            raw.before = String::from_utf8(raw.before).unwrap().replace(" 501 ",&format!(" {} ",self.source.proof.worker.uid)).into_bytes();
            raw.after = raw.before.clone();
            let at = raw.finished;
            self.set(normalize(raw)); at
        }
    }
    impl Drop for PublisherFixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.home); }
    }
    #[test]
    fn vpn_frame_handoff_wakes_for_new_evidence_without_renewing_or_trusting_old_frames() {
        let fixture = PublisherFixture::new();
        let first = fixture.stream.wait_for_revision(0, Duration::ZERO).unwrap();
        assert_eq!(first, 1);
        assert_eq!(fixture.stream.wait_for_revision(first, Duration::from_millis(20)).unwrap(), first);
        let stream = fixture.stream.clone();
        let began = std::time::Instant::now();
        let waiter = thread::spawn(move || stream.wait_for_revision(first, Duration::from_secs(2)).unwrap());
        thread::sleep(Duration::from_millis(20));
        let captured_at = fixture.frame(2);
        assert_eq!(waiter.join().unwrap(), 2, "a pending or arriving frame must not be lost");
        assert!(began.elapsed() < Duration::from_secs(1), "new frame must interrupt the wait");
        let output = fixture.stream.read(fixture.source.as_ref()).unwrap();
        let metadata: Value = serde_json::from_str(output.text().unwrap().lines().next().unwrap()
            .strip_prefix(FRAME_META_PREFIX).unwrap()).unwrap();
        assert_eq!(metadata["captured_at"], captured_at);
        assert_eq!(metadata["sequence"], 2);
        // A changed revision only wakes the consumer; it cannot pass bad evidence.
        fixture.set(Err(error("native_listener_origin_changed", "fixture identity changed")));
        assert_eq!(fixture.stream.wait_for_revision(2, Duration::ZERO).unwrap(), 3);
        assert_eq!(fixture.stream.read(fixture.source.as_ref()).err().unwrap().code, "native_listener_origin_changed");
    }
    #[test]
    fn collector_loss_reaches_authority_before_an_inflight_observation_can_publish() {
        let fixture = PublisherFixture::new();
        let (queued, received) = std::sync::mpsc::channel();
        let notice: Arc<ListenerFailureNotice> = Arc::new(move |error| { queued.send(error.code.clone()).unwrap(); });
        fixture.stream.subscribe_failures(&notice);
        let (resume, waiting) = std::sync::mpsc::channel();
        let stream = fixture.stream.clone();
        let read = thread::spawn(move || {
            waiting.recv().unwrap();
            stream.send_if_no_new_failure(0, || panic!("stale VPN result reached authority"))
        });
        fixture.set(Err(error("native_listener_closed", "fixture EOF")));
        fixture.set(Err(error("native_listener_closed", "same outage")));
        fixture.frame(2);
        assert_eq!(received.try_recv().unwrap(), "native_listener_closed");
        assert!(received.try_recv().is_err());
        resume.send(()).unwrap();
        assert_eq!(read.join().unwrap().unwrap_err().code, "native_listener_closed");
        let (latest, _) = fixture.stream.failure_since(0).unwrap();
        fixture.stream.send_if_no_new_failure(latest, || {}).unwrap();
        drop(notice);
        fixture.set(Err(error("native_listener_closed", "second outage")));
        assert!(matches!(received.try_recv(), Err(std::sync::mpsc::TryRecvError::Disconnected)));
    }

    #[test]
    fn slow_frame_and_truncated_generation_recover_without_losing_revocation() {
        let fixture = PublisherFixture::new();
        let stream = &fixture.stream;
        let mut slow = raw();
        slow.finished = slow.started + 6.0;
        let collector = &fixture.source.proof.collector;
        let mut healthy = raw();
        healthy.sequence = 2;
        let mut partial = encoded(&healthy);
        partial.truncate(partial.len() - 3);
        let start_generation = || {
            let (peer, input) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let worker = stream.clone();
            let birth = collector.clone();
            (peer, thread::spawn(move || worker.read_generation(input, &birth)))
        };
        let read_request = |peer: &mut UnixStream| {
            let mut byte = [0];
            peer.read_exact(&mut byte).unwrap();
            assert_eq!(byte, *b"S");
        };
        let (mut peer, read) = start_generation();
        read_request(&mut peer);
        assert_eq!(stream.request_sample().unwrap(), 3);
        assert_eq!(stream.request_sample().unwrap(), 3, "concurrent invalidations coalesce");
        peer.write_all(&encoded(&slow)).unwrap();
        read_request(&mut peer);
        assert_eq!(stream.request_sample().unwrap(), 4);
        peer.write_all(&encoded(&healthy)).unwrap();
        read_request(&mut peer);
        peer.write_all(&partial).unwrap();
        drop(peer);
        read.join().unwrap();
        assert_eq!(stream.revision.load(Ordering::Acquire), 4, "slow sample, healthy sample and partial EOF all delivered");
        assert_eq!(stream.failure_since(0).unwrap().1.code, "native_listener_protocol");
        assert!(!stream.is_finished());
        // The next authentic generation starts at sequence 1. Hold its writer
        // open so read_generation sees the valid sample before its own EOF.
        let (mut writer, read) = start_generation();
        read_request(&mut writer);
        writer.write_all(&encoded(&raw())).unwrap();
        assert_eq!(stream.wait_for_revision(4, Duration::from_secs(2)).unwrap(), 5);
        assert_eq!(stream.latest_with_timeout(Duration::ZERO).unwrap().sequence, 1);
        assert_eq!(stream.failure_since(0).unwrap().0, 4, "following success cannot erase a pending withdrawal");
        assert!(stream.failure_since(4).is_none());
        assert_eq!(stream.request_sample().unwrap(), 6, "an idle connection accepts the next request");
        read_request(&mut writer);
        writer.write_all(&encoded(&healthy)).unwrap();
        assert_eq!(stream.wait_for_revision(5, Duration::from_secs(2)).unwrap(), 6);
        assert_eq!(stream.latest_with_timeout(Duration::ZERO).unwrap().sequence, 2);
        drop(writer);
        read.join().unwrap();
        assert_eq!(stream.failure_since(4).unwrap().1.code, "native_listener_closed");
        assert!(!stream.is_finished());
    }
    #[test]
    fn silent_collector_expires_only_an_outstanding_request_and_wakes_the_daemon() {
        let fixture = PublisherFixture::new();
        let stream = fixture.stream.clone();
        let collector = fixture.source.proof.collector.clone();
        let (mut peer, input) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let worker = thread::spawn(move || stream.read_generation(input, &collector));
        let mut request = [0];
        peer.read_exact(&mut request).unwrap();
        assert_eq!(request, *b"S");
        peer.write_all(&encoded(&raw())).unwrap();
        let stream = &fixture.stream;
        assert_eq!(stream.wait_for_revision(1, Duration::from_secs(2)).unwrap(), 2);
        assert!(stream.pending_sample_deadline_at(Instant::now() + Duration::from_secs(60)).unwrap().is_none());
        assert_eq!(stream.request_sample().unwrap(), 3);
        peer.read_exact(&mut request).unwrap();
        assert_eq!(request, *b"S");
        let due = stream.pending_sample_deadline().unwrap().unwrap();
        assert_eq!(stream.pending_sample_deadline_at(due).unwrap_err().code, "native_listener_response_timeout");
        assert_eq!(peer.read(&mut request).unwrap(), 0);
        worker.join().unwrap();
        // A single transient timeout fails closed immediately and disconnects the stalled
        // collector, but keeps the daemon alive so the collector supervisor can reconnect
        // without changing executor_boot_id and breaking running sandboxed apps.
        assert!(!stream.is_finished());
        assert_eq!(stream.failure_since(2).unwrap().1.code, "native_listener_response_timeout");
        assert_eq!(stream.latest_with_timeout(Duration::ZERO).err().unwrap().code, "native_listener_response_timeout");
        assert_eq!(stream.request_sample().err().unwrap().code, "native_listener_pending");

        // A replacement collector generation recovers cleanly and resets the timeout streak.
        let replacement_collector = fixture.source.proof.collector.clone();
        let (mut peer2, input2) = UnixStream::pair().unwrap();
        peer2.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let stream2 = fixture.stream.clone();
        let worker2 = thread::spawn(move || stream2.read_generation(input2, &replacement_collector));
        peer2.read_exact(&mut request).unwrap();
        assert_eq!(request, *b"S");
        peer2.write_all(&encoded(&raw())).unwrap();
        assert_eq!(stream.wait_for_revision(3, Duration::from_secs(2)).unwrap(), 4);
        assert_eq!(stream.latest_with_timeout(Duration::ZERO).unwrap().sequence, 1);
        drop(peer2);
        worker2.join().unwrap();

        // Repeated consecutive timeouts (MAX_CONSECUTIVE_RESPONSE_TIMEOUTS) with no valid
        // frame eventually mark the stream finished so launchd can restart the daemon.
        for attempt in 1..=MAX_CONSECUTIVE_RESPONSE_TIMEOUTS {
            let c = fixture.source.proof.collector.clone();
            let (mut p, inp) = UnixStream::pair().unwrap();
            p.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let s = fixture.stream.clone();
            let w = thread::spawn(move || s.read_generation(inp, &c));
            p.read_exact(&mut request).unwrap();
            assert_eq!(request, *b"S");
            let d = stream.pending_sample_deadline().unwrap().unwrap();
            assert_eq!(stream.pending_sample_deadline_at(d).unwrap_err().code, "native_listener_response_timeout");
            assert_eq!(p.read(&mut request).unwrap(), 0);
            w.join().unwrap();
            if attempt < MAX_CONSECUTIVE_RESPONSE_TIMEOUTS {
                assert!(!stream.is_finished(), "attempt {attempt} must remain recoverable");
            } else {
                assert!(stream.is_finished(), "persistent timeout streak must finish stream");
                assert_eq!(stream.request_sample().err().unwrap().code, "native_listener_worker_failed");
            }
        }
    }

    #[test]
    fn frame_subscription_and_stop_work_before_first_publication() {
        use std::os::fd::AsFd;
        let fixture = PublisherFixture::new();
        *fixture.stream.state.0.lock().unwrap() = None;
        fixture.stream.revision.store(0, Ordering::Release);
        let subscription = fixture.stream.subscribe_frames().unwrap();
        let mut events = claude_watch_system::network_events::NetworkEventWatcher::new(&[]);
        assert_eq!(events.wait_with_readers(Duration::ZERO, &[subscription.as_fd()]).1, None);
        let mut publisher = fixture.stream.start_publisher(fixture.store.clone(), fixture.source.clone()).unwrap();
        publisher.finish().unwrap();
        assert!(!cache_path(&fixture.store).exists());
        fixture.frame(2);
        assert_eq!(events.wait_with_readers(Duration::from_secs(1), &[subscription.as_fd()]).1, Some(0));
        assert_eq!(fixture.stream.wait_for_revision(0, Duration::ZERO).unwrap(), 1);
    }
    #[test]
    fn independent_publisher_updates_during_blocked_collection_without_refreshing_the_same_frame() {
        let fixture = PublisherFixture::new();
        fixture.stream.publish(&fixture.store,fixture.source.as_ref()).unwrap();
        let bootstrap = fs::read(cache_path(&fixture.store)).unwrap();
        let mut publisher = fixture.stream.start_publisher(fixture.store.clone(),fixture.source.clone()).unwrap();
        thread::sleep(Duration::from_millis(300));
        assert_eq!(fs::read(cache_path(&fixture.store)).unwrap(),bootstrap,"bootstrap frame must not be republished");
        let (release,blocked) = std::sync::mpsc::channel::<()>();
        let slow_main = thread::spawn(move || blocked.recv_timeout(Duration::from_secs(3)));
        let captured_at = fixture.frame(2);
        let deadline = std::time::Instant::now()+Duration::from_secs(2);
        while cached(&fixture.store).unwrap().listener.unwrap().evidence.sequence != 2
            && std::time::Instant::now()<deadline { thread::sleep(Duration::from_millis(10)); }
        let updated = cached(&fixture.store).unwrap();
        assert_eq!(updated.listener.unwrap().evidence.sequence,2);
        assert!(!slow_main.is_finished(),"cache must advance while the UI collector remains blocked");
        let output = read_cached(&fixture.store,fixture.source.as_ref()).unwrap();
        let metadata: Value = serde_json::from_str(output.text().unwrap().lines().next().unwrap().strip_prefix(FRAME_META_PREFIX).unwrap()).unwrap();
        assert_eq!(metadata["captured_at"],captured_at);
        let bytes = fs::read(cache_path(&fixture.store)).unwrap();
        thread::sleep(Duration::from_millis(550));
        assert_eq!(fs::read(cache_path(&fixture.store)).unwrap(),bytes,"same evidence cannot receive a fresh cache timestamp");
        publisher.finish().unwrap();
        let _ = release.send(()); let _ = slow_main.join();
    }
    #[test]
    fn native_cache_failure_retries_on_next_input_and_reports_recovery() {
        let fixture = PublisherFixture::new();
        fixture.stream.publish(&fixture.store,fixture.source.as_ref()).unwrap();
        let path = cache_path(&fixture.store);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let mut publisher = fixture.stream.start_publisher(fixture.store.clone(),fixture.source.clone()).unwrap();
        fixture.frame(2);
        let deadline = std::time::Instant::now()+Duration::from_secs(2);
        while publisher.check().is_ok() && std::time::Instant::now()<deadline { thread::sleep(Duration::from_millis(10)); }
        assert!(publisher.check().is_err());
        fs::remove_dir(&path).unwrap();
        fixture.frame(3);
        let deadline = std::time::Instant::now()+Duration::from_secs(2);
        // The atomic rename is visible before the publisher reports the write
        // complete. Wait for that acknowledgement before checking both results.
        while publisher.check().is_err() && std::time::Instant::now()<deadline { thread::sleep(Duration::from_millis(10)); }
        assert_eq!(cached(&fixture.store).unwrap().listener.unwrap().evidence.sequence, 3);
        assert!(publisher.check().is_ok());
        publisher.finish().unwrap();
    }
    #[test]
    fn native_publication_shares_one_total_validation_budget() {
        struct Slow { source: Arc<Source>, calls: Mutex<Vec<Duration>> }
        impl ReadRunner for Slow {
            fn process_identity(&self,pid:u32)->Option<Identity> { self.source.as_ref().process_identity(pid) }
            fn run(&self,c:ReadCommand,input:&[u8],timeout:Duration,limit:usize)->Result<Output> {
                self.calls.lock().unwrap().push(timeout);
                if timeout < Duration::from_millis(600) {
                    thread::sleep(timeout); return Err(error("command_timeout","fixture bounded timeout"));
                }
                thread::sleep(Duration::from_millis(600));
                self.source.run(c,input,timeout,limit)
            }
        }
        let fixture=PublisherFixture::new();
        let slow=Slow {source:fixture.source.clone(),calls:Mutex::new(vec![])};
        let started=std::time::Instant::now();
        fixture.stream.publish(&fixture.store,&slow).unwrap();
        assert!(started.elapsed()<Duration::from_millis(1500));
        let calls=slow.calls.lock().unwrap();
        assert!(calls.len()>=2,"calls={calls:?}; cache={}",fs::read_to_string(cache_path(&fixture.store)).unwrap());
        assert!(calls[0]<=Duration::from_secs(1));
        assert!(calls[1]<Duration::from_millis(500));
        assert_eq!(cached(&fixture.store).unwrap().error.unwrap().code,"command_timeout");
    }
    impl ReadRunner for Source {
        fn process_identity(&self, pid: u32) -> Option<Identity> {
            let mut identity = [&self.proof.supervisor, &self.proof.worker, &self.proof.collector]
                .into_iter().find(|identity| identity.pid == pid)?.clone();
            if self.changed && pid == self.proof.worker.pid { identity.start_microseconds += 1; }
            Some(identity)
        }
        fn run(&self, c: ReadCommand, input: &[u8], _: Duration, _: usize) -> Result<Output> {
            if let ReadCommand::ProcessTablePids { ref pids } = c {
                let table = String::from_utf8(raw().after).unwrap();
                return Ok(Output {
                    status: 0,
                    stdout: table.lines().filter(|row| row.split_whitespace().next()
                        .and_then(|pid| pid.parse::<u32>().ok()).is_some_and(|pid| pids.contains(&pid)))
                        .collect::<Vec<_>>().join("\n").into_bytes(),
                    stderr: vec![],
                });
            }
            if matches!(c, ReadCommand::LaunchctlGuiAgent { .. }) {
                return Ok(Output {
                    status: 0,
                    stdout: format!("state = running\npid = {}\n", self.job_pid).into_bytes(),
                    stderr: vec![],
                });
            }
            let r: Value = serde_json::from_slice(input).unwrap();
            let now = native::now();
            let mut v = json!({"schema":1,"status":"ok","uid":self.proof.worker.uid,"started_at":now,"finished_at":now,"round_id":r["round_id"]});
            let ids = [
                self.proof.supervisor.clone(),
                self.proof.worker.clone(),
                self.proof.collector.clone(),
            ];
            match c {
                ReadCommand::Observer(ObserverAction::Identities) => {
                    v["identities"] = json!(ids
                        .iter()
                        .filter(|i| r["targets"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|t| t["pid"] == i.pid))
                        .map(|i| {
                            let mut id = i.clone();
                            if self.changed && id.pid == self.proof.worker.pid {
                                id.start_microseconds += 1;
                            }
                            json!({"pid":i.pid,"state":"ok","identity":id})
                        })
                        .collect::<Vec<_>>());
                }
                ReadCommand::Observer(ObserverAction::Arguments) => {
                    v["argument_prefixes"]=json!([(&self.proof.supervisor,false),(&self.proof.collector,true)].iter().filter(|(id,_)|r["targets"].as_array().unwrap().iter().any(|t|t["pid"]==id.pid)).map(|(id,collect)|{let mut args=vec!["/bin/zsh".to_string(),"-f".into(),self.proof.root.join(SCRIPT).display().to_string()];if *collect{args.extend(["--collect".into(),self.proof.supervisor.pid.to_string()]);}else{args.extend(["daemon".into(),"--apply".into()]);if self.extra_supervisor_argument{args.push("--observe-only".into());}}json!({"pid":id.pid,"state":"ok","identity":id,"arguments":args,"cwd":"/tmp","truncated":false})}).collect::<Vec<_>>());
                }
                _ => panic!("unexpected source operation"),
            }
            Ok(Output {
                status: 0,
                stdout: serde_json::to_vec(&v).unwrap(),
                stderr: vec![],
            })
        }
    }
    #[test]
    fn source_requires_fixed_job_live_birth_identity_and_unchanged_component() {
        let root =
            std::env::temp_dir().join(format!("cw-listener-origin-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join(SCRIPT), SCRIPT_BYTES).unwrap();
        fs::write(root.join("watch-engine"), b"fixture").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("watch-engine"), fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let uid = fs::metadata(&root).unwrap().uid();
        let p = Proof {
            supervisor: identity(100, 1, uid, "/bin/zsh".into()),
            worker: identity(
                102,
                100,
                uid,
                root.join("watch-engine").display().to_string(),
            ),
            collector: identity(101, 100, uid, "/bin/zsh".into()),
            root: root.clone(),
        };
        let mut r = Source {
            proof: p.clone(),
            job_pid: 100,
            changed: false,
            extra_supervisor_argument: false,
        };
        verify(&p, &r, true).unwrap();
        r.extra_supervisor_argument = true;
        assert_eq!(
            verify(&p, &r, true).unwrap_err().code,
            "native_listener_origin_invalid"
        );
        r.extra_supervisor_argument = false;
        r.job_pid = 999;
        assert_eq!(
            verify(&p, &r, true).unwrap_err().code,
            "native_listener_unregistered"
        );
        r.job_pid = 100;
        r.changed = true;
        assert_eq!(
            verify(&p, &r, true).unwrap_err().code,
            "native_listener_origin_changed"
        );
        r.changed = false;
        // Exercise the actual stream fast path using a read runner that rejects
        // every whole-machine operation. Two reads of one frame retain its
        // capture time and each use just one argv + one targeted ps command.
        struct Counted<'a> { source: &'a Source, calls: std::cell::RefCell<Vec<&'static str>> }
        impl ReadRunner for Counted<'_> {
            fn process_identity(&self, pid: u32) -> Option<Identity> {
                self.calls.borrow_mut().push("fixed_identity");
                self.source.process_identity(pid)
            }
            fn run(&self, command: ReadCommand, input: &[u8], timeout: Duration, limit: usize) -> Result<Output> {
                self.calls.borrow_mut().push(match &command {
                    ReadCommand::Observer(ObserverAction::Arguments) => "fixed_arguments",
                    ReadCommand::ProcessTablePids { pids } => { assert_eq!(pids, &vec![102]); "targeted_ps" },
                    _ => panic!("fast listener path attempted a global/unexpected read: {command:?}"),
                });
                self.source.run(command, input, timeout, limit)
            }
        }
        let mut frame = normalize(raw()).unwrap();
        frame.started = native::now() - 1.0;
        frame.finished = frame.started;
        frame.origins.insert(100, json!({"uid":uid,"executable":"/bin/zsh","stamp":p.supervisor.start_stamp}));
        frame.origins.insert(101, json!({"uid":uid,"executable":"/bin/zsh","stamp":p.collector.start_stamp}));
        let captured_at = frame.finished;
        let stream = ListenerStream { requests: Mutex::default(), last_failure: Mutex::default(), notifications: Arc::default(), root: root.clone(), supervisor: p.supervisor.clone(), worker: p.worker.clone(),
            state: Arc::new((Mutex::new(Some(Ok(frame))), Condvar::new())), revision: Arc::new(AtomicU64::new(1)),
            published_revision: Mutex::new(None),
            consecutive_timeouts: std::sync::atomic::AtomicU32::new(0),
            finished: Arc::new(AtomicBool::new(false)) };
        let counted = Counted { source: &r, calls: std::cell::RefCell::new(Vec::new()) };
        for _ in 0..2 {
            let out = stream.read_with_timeout(&counted, Duration::from_secs(1)).unwrap();
            let metadata = out.text().unwrap().lines().next().unwrap().strip_prefix(FRAME_META_PREFIX).unwrap();
            let metadata: Value = serde_json::from_str(metadata).unwrap();
            assert_eq!(metadata["captured_at"].as_f64(), Some(captured_at));
            assert_eq!(metadata["sequence"], 1);
        }
        let calls = counted.calls.borrow();
        assert_eq!(calls.iter().filter(|&&kind| kind == "fixed_arguments").count(), 2);
        assert_eq!(calls.iter().filter(|&&kind| kind == "targeted_ps").count(), 2);
        assert_eq!(calls.iter().filter(|&&kind| kind == "fixed_identity").count(), 14);
        drop(calls);
        fs::write(root.join(SCRIPT), b"changed").unwrap();
        assert_eq!(
            verify(&p, &r, true).unwrap_err().code,
            "native_listener_component_changed"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn sampling_failure_does_not_erase_actor_identity_or_yield_listener_data() {
        let home = std::env::temp_dir().join(format!("cw-listener-cache-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(crate::storage::Paths::new(&home).unwrap());
        let root = store.paths.watch().join("runtime");
        let uid = fs::metadata(&home).unwrap().uid();
        let mut p = Proof {
            supervisor: identity(100, 1, uid, "/bin/zsh".into()),
            worker: identity(
                103,
                100,
                uid,
                root.join("watch-engine").display().to_string(),
            ),
            collector: identity(101, 100, uid, "/bin/zsh".into()),
            root,
        };
        p.collector.start_stamp = "Mon Oct 26 20:45:11 2026".into();
        fs::create_dir_all(&p.root).unwrap();
        fs::write(p.root.join(SCRIPT), SCRIPT_BYTES).unwrap();
        fs::write(p.root.join("watch-engine"), b"fixture").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                p.root.join("watch-engine"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let r = Source {
            proof: p.clone(),
            job_pid: 100,
            changed: false,
            extra_supervisor_argument: false,
        };
        let mut e = raw();
        let now = native::now().floor();
        e.started = now;
        e.finished = now;
        e.before = String::from_utf8(e.before)
            .unwrap()
            .replace(" 501 ", &format!(" {uid} "))
            .into_bytes();
        e.after = e.before.clone();
        let mut c = Cached {
            schema: 2,
            published_at: native::now(),
            actor: Actor {
                supervisor: p.supervisor.clone(),
                worker: p.worker.clone(),
                root: p.root.clone(),
            },
            listener: Some(Captured {
                proof: p,
                evidence: normalize(e).unwrap(),
            }),
            error: None,
        };
        let save = |c: &Cached| {
            store
                .atomic_json(&cache_path(&store), &serde_json::to_value(c).unwrap())
                .unwrap()
        };
        save(&c);
        assert!(registered_worker(&store, &r, 103));
        assert!(read_cached(&store, &r).is_ok());
        c.error = Some(error(
            "native_listener_sample_failed",
            "contradictory cache",
        ));
        save(&c);
        assert!(!registered_worker(&store, &r, 103));
        assert!(read_cached(&store, &r).is_err());
        c.error = None;
        let data = c.listener.as_mut().unwrap();
        data.evidence.finished -= 60.0;
        data.evidence.started -= 60.0;
        save(&c);
        assert!(registered_worker(&store, &r, 103));
        assert_eq!(
            read_cached(&store, &r).err().unwrap().code,
            "native_listener_stale"
        );
        c.published_at -= 31.0;
        save(&c);
        assert!(!registered_worker(&store, &r, 103));
        c.published_at = native::now();
        c.listener = None;
        c.error = Some(error("native_listener_sample_failed", "failed source"));
        save(&c);
        assert!(registered_worker(&store, &r, 103));
        assert_eq!(
            read_cached(&store, &r).err().unwrap().code,
            "native_listener_sample_failed"
        );
        let mut r = r;
        r.changed = true;
        assert!(!registered_worker(&store, &r, 103));
        store
            .atomic_json(
                &cache_path(&store),
                &json!({"schema":2,"error":"origin unavailable"}),
            )
            .unwrap();
        assert!(!registered_worker(&store, &r, 103));
        fs::remove_dir_all(home).unwrap();
    }
}
