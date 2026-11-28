//! Event-driven network and local VPN configuration change notification bridge.
//!
//! Combines Darwin notifications (`com.apple.system.config.network_change` and
//! `io.local.claudewatch.vpn-observation`),watched local config file metadata
//! (`dev`, `ino`, `mtime`, `len`), and explicit test/wake triggers with safe
//! descriptor registration and drop cleanup.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    os::fd::{AsRawFd, BorrowedFd},
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEventKind {
    DarwinNotification(String),
    WatchedFileChanged(PathBuf),
    WatchedProcessExited(u32),
    WakeSignal,
    ClockDiscontinuity,
    Timeout,
}

// Scheduler latency advances both clocks. Only disagreement invalidates clock-based evidence.
fn clock_discontinuity(wall: Option<Duration>, elapsed: Duration) -> bool {
    wall.is_none_or(|wall| wall.abs_diff(elapsed) > Duration::from_millis(1500))
}

type WakeStamp = (i64, i32);

#[cfg(target_os = "macos")]
fn kernel_wake_stamp() -> Option<WakeStamp> {
    let mut stamp = std::mem::MaybeUninit::<libc::timeval>::uninit();
    let mut size = std::mem::size_of::<libc::timeval>();
    // kern.waketime is a read-only timeval. Only read the initialized result
    // when sysctl reports the exact expected size.
    let rc = unsafe { libc::sysctlbyname(c"kern.waketime".as_ptr(), stamp.as_mut_ptr().cast(),
        &mut size, std::ptr::null_mut(), 0) };
    if rc != 0 || size != std::mem::size_of::<libc::timeval>() { return None; }
    let stamp = unsafe { stamp.assume_init() };
    (stamp.tv_sec > 0).then_some((stamp.tv_sec, stamp.tv_usec))
}

#[cfg(not(target_os = "macos"))]
fn kernel_wake_stamp() -> Option<WakeStamp> { None }

fn power_or_clock_event(event: &NetworkEventKind) -> bool {
    matches!(event, NetworkEventKind::ClockDiscontinuity)
        || matches!(event, NetworkEventKind::DarwinNotification(name) if name == "com.apple.powermanagement.systempowerstate")
}

fn confirm_wake(previous: &mut Option<WakeStamp>, events: &mut Vec<NetworkEventKind>, current: Option<WakeStamp>) {
    if let Some(stamp) = current {
        if previous.replace(stamp).is_some_and(|old| stamp != old) && !events.contains(&NetworkEventKind::WakeSignal) {
            events.push(NetworkEventKind::WakeSignal);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    entry: Option<FileStamp>,
    target: Option<FileStamp>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    size: u64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

impl FileFingerprint {
    fn capture(path: &Path) -> Self {
        use std::os::unix::fs::MetadataExt;
        let stamp = |m: std::fs::Metadata| FileStamp { dev: m.dev(), ino: m.ino(),
            mtime_sec: m.mtime(), mtime_nsec: m.mtime_nsec(), size: m.len(),
            ctime_sec: m.ctime(), ctime_nsec: m.ctime_nsec() };
        let entry = std::fs::symlink_metadata(path).ok();
        let target = entry.as_ref().filter(|m| m.is_symlink())
            .and_then(|_| std::fs::metadata(path).ok()).map(stamp);
        Self { entry: entry.map(stamp), target }
    }
}

struct NotifyRegistration {
    name: String,
    fd: i32,
    token: i32,
}

impl NotifyRegistration {
    fn register(name: &str) -> Option<Self> {
        #[cfg(target_os = "macos")]
        unsafe {
            let Ok(c_name) = std::ffi::CString::new(name) else {
                return None;
            };
            let mut fd = -1;
            let mut token = -1;
            let status = super::notify_register_file_descriptor(
                c_name.as_ptr(),
                &mut fd,
                0,
                &mut token,
            );
            if status != 0 || fd < 0 || token < 0 {
                return None;
            }
            if libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) < 0 {
                super::notify_cancel(token);
                return None;
            }
            Some(Self {
                name: name.to_string(),
                fd,
                token,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = name;
            None
        }
    }

    fn drain(&self) -> bool {
        if self.fd < 0 {
            return false;
        }
        let mut bytes = [0u8; 256];
        let mut read_any = false;
        unsafe {
            while libc::read(self.fd, bytes.as_mut_ptr().cast(), bytes.len()) > 0 {
                read_any = true;
            }
        }
        read_any
    }
}

impl Drop for NotifyRegistration {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.token >= 0 {
            unsafe {
                super::notify_cancel(self.token);
            }
            self.token = -1;
            self.fd = -1;
        }
    }
}

/// In-process invalidations that can share a blocking wait with native events.
/// A full socket already has an outstanding notification.
#[derive(Default)]
pub struct LocalNotifications(std::sync::Mutex<Vec<std::os::unix::net::UnixStream>>);
impl LocalNotifications {
    pub fn subscribe(&self) -> std::io::Result<std::os::unix::net::UnixStream> {
        let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        writer.set_nonblocking(true)?;
        self.0.lock().unwrap().push(writer);
        Ok(reader)
    }
    pub fn publish(&self) {
        use std::io::Write;
        self.0.lock().unwrap().retain(|mut writer| match writer.write(&[1]) {
            Ok(_) => true, Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
        });
    }
}

// A parent vnode covers creates and atomic replacement; the current file
// vnode also covers in-place writes. Fingerprints filter unrelated siblings.
#[cfg(target_os = "macos")]
#[derive(Default)]
struct FileEvents {
    queue: Option<std::os::fd::OwnedFd>,
    bindings: BTreeMap<PathBuf, (u64, u64, u32, std::fs::File)>,
    incomplete: bool,
}

#[cfg(target_os = "macos")]
impl FileEvents {
    fn bind(&mut self, paths: impl Iterator<Item = PathBuf>) {
        use std::os::{fd::FromRawFd, unix::fs::{MetadataExt, OpenOptionsExt}};
        let mut wanted = BTreeMap::<PathBuf, u32>::new();
        let replaced = libc::NOTE_DELETE | libc::NOTE_RENAME | libc::NOTE_REVOKE;
        let content = replaced | libc::NOTE_WRITE | libc::NOTE_ATTRIB;
        let mut watch = |path: &Path, flags| *wanted.entry(path.to_owned()).or_default() |= flags;
        self.incomplete = false;
        for mut path in paths {
            // Link replacement wakes its directory. A missing target can be
            // created in another directory, so subscribe to that side as well.
            let mut links = std::collections::BTreeSet::new();
            loop {
                let mut closest = true;
                for parent in path.ancestors().skip(1).filter(|p| p.is_dir()) {
                    // Moving a whole bundle doesn't touch its nested files.
                    // Higher ancestors need rename/delete events, not writes
                    // from unrelated children elsewhere on the same volume.
                    watch(parent, if closest { content } else { replaced });
                    closest = false;
                    if parent.is_symlink() {
                        if let Some(directory) = parent.parent() { watch(directory, content); }
                    }
                }
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) if meta.is_symlink() => {
                        if !links.insert(path.clone()) || links.len() > 40 { break; }
                        match std::fs::read_link(&path) {
                            Ok(target) => path = path.parent().unwrap_or(Path::new(".")).join(target),
                            Err(_) => { self.incomplete = true; break; }
                        }
                    }
                    Ok(_) => { watch(&path, content); break; }
                    Err(e) => { self.incomplete |= e.kind() != std::io::ErrorKind::NotFound; break; }
                }
            }
        }
        self.bindings.retain(|p, _| wanted.contains_key(p));
        if wanted.is_empty() { return; }
        if self.queue.is_none() {
            let fd = unsafe { libc::kqueue() };
            if fd < 0 { self.incomplete = true; return; }
            let queue = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 { self.incomplete = true; return; }
            self.queue = Some(queue);
        }
        let queue = self.queue.as_ref().unwrap().as_raw_fd();
        let count = wanted.len();
        for (path, flags) in wanted {
            let Ok(meta) = std::fs::metadata(&path) else { self.bindings.remove(&path); continue; };
            if self.bindings.get(&path).is_some_and(|(dev, ino, old_flags, _)| (*dev, *ino, *old_flags) == (meta.dev(), meta.ino(), flags)) { continue; }
            self.bindings.remove(&path);
            let Ok(file) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_EVTONLY | libc::O_CLOEXEC).open(&path) else { continue; };
            let Ok(meta) = file.metadata() else { continue; };
            let change = libc::kevent {
                ident: file.as_raw_fd() as _, filter: libc::EVFILT_VNODE, flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: flags,
                data: 0, udata: std::ptr::null_mut(),
            };
            if unsafe { libc::kevent(queue, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } == 0 {
                self.bindings.insert(path, (meta.dev(), meta.ino(), flags, file));
            }
        }
        self.incomplete |= self.bindings.len() != count;
    }

    fn drain(&self) {
        if let Some(queue) = &self.queue {
            let mut batch = [unsafe { std::mem::zeroed::<libc::kevent>() }; 64];
            let immediate = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            unsafe { libc::kevent(queue.as_raw_fd(), std::ptr::null(), 0, batch.as_mut_ptr(), batch.len() as _, &immediate); }
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct ProcessEvents {
    queue: Option<std::os::fd::OwnedFd>,
    watched: std::collections::BTreeSet<u32>,
    pending_exited: Vec<u32>,
}

#[cfg(target_os = "macos")]
impl ProcessEvents {
    fn bind(&mut self, pids: &[u32]) {
        use std::os::fd::FromRawFd;
        let desired: std::collections::BTreeSet<u32> = pids.iter().copied().filter(|&pid| pid > 1).collect();
        if desired == self.watched {
            return;
        }
        if desired.is_empty() {
            if let Some(queue) = &self.queue {
                let fd = queue.as_raw_fd();
                for pid in std::mem::take(&mut self.watched) {
                    let change = libc::kevent {
                        ident: pid as _,
                        filter: libc::EVFILT_PROC,
                        flags: libc::EV_DELETE,
                        fflags: 0,
                        data: 0,
                        udata: std::ptr::null_mut(),
                    };
                    let _ = unsafe { libc::kevent(fd, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
                }
            } else {
                self.watched.clear();
            }
            return;
        }
        if self.queue.is_none() {
            let fd = unsafe { libc::kqueue() };
            if fd < 0 { return; }
            let queue = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 { return; }
            self.queue = Some(queue);
        }
        let queue_fd = self.queue.as_ref().unwrap().as_raw_fd();
        let removed: Vec<u32> = self.watched.difference(&desired).copied().collect();
        for pid in removed {
            let change = libc::kevent {
                ident: pid as _,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_DELETE,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let _ = unsafe { libc::kevent(queue_fd, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            self.watched.remove(&pid);
        }
        for pid in desired {
            if self.watched.contains(&pid) {
                continue;
            }
            let change = libc::kevent {
                ident: pid as _,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                fflags: libc::NOTE_EXIT,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            if unsafe { libc::kevent(queue_fd, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } == 0 {
                self.watched.insert(pid);
            } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                if !self.pending_exited.contains(&pid) {
                    self.pending_exited.push(pid);
                }
            }
        }
    }

    fn take_pending_exited(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.pending_exited)
    }

    fn drain(&mut self) -> Vec<u32> {
        let mut exited = Vec::new();
        if let Some(queue) = &self.queue {
            let mut batch = [unsafe { std::mem::zeroed::<libc::kevent>() }; 32];
            let immediate = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            let count = unsafe {
                libc::kevent(queue.as_raw_fd(), std::ptr::null(), 0, batch.as_mut_ptr(), batch.len() as _, &immediate)
            };
            if count > 0 {
                for ev in &batch[..count as usize] {
                    if let Ok(pid) = u32::try_from(ev.ident) {
                        self.watched.remove(&pid);
                        if !exited.contains(&pid) {
                            exited.push(pid);
                        }
                    }
                }
            }
        }
        exited
    }
}

pub struct NetworkEventWatcher {
    registrations: Vec<NotifyRegistration>,
    #[cfg(target_os = "macos")]
    files: FileEvents,
    #[cfg(target_os = "macos")]
    processes: ProcessEvents,
    watched_files: BTreeMap<PathBuf, FileFingerprint>,
    check_after_bind: bool,
    retry_binding_at: Option<std::time::Instant>,
    last_wake: Option<WakeStamp>,
    last_wall_clock: Option<std::time::SystemTime>,
    last_mono_clock: Option<std::time::Instant>,
}

impl Default for NetworkEventWatcher {
    fn default() -> Self {
        Self::new(&[
            "com.apple.system.config.network_change",
            "com.apple.system.clock_set",
            "io.local.claudewatch.vpn-observation",
            "io.local.claudewatch.channel-update",
            "com.apple.powermanagement.systempowerstate",
            "io.local.claudewatch.system-wake",
        ])
    }
}

impl NetworkEventWatcher {
    pub fn new(notification_names: &[&str]) -> Self {
        let mut registrations = Vec::new();
        for name in notification_names {
            if let Some(reg) = NotifyRegistration::register(name) {
                registrations.push(reg);
            }
        }
        Self {
            registrations,
            #[cfg(target_os = "macos")]
            files: FileEvents::default(),
            #[cfg(target_os = "macos")]
            processes: ProcessEvents::default(),
            watched_files: BTreeMap::new(),
            check_after_bind: false,
            retry_binding_at: None,
            last_wake: kernel_wake_stamp(),
            last_wall_clock: Some(std::time::SystemTime::now()),
            last_mono_clock: Some(std::time::Instant::now()),
        }
    }

    pub fn set_watched_pids(&mut self, pids: &[u32]) {
        #[cfg(target_os = "macos")]
        self.processes.bind(pids);
        #[cfg(not(target_os = "macos"))]
        let _ = pids;
    }

    pub fn watch_file(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        let fp = FileFingerprint::capture(&path);
        self.watched_files.insert(path, fp);
        self.bind_file_events();
        self.check_after_bind = true;
    }

    pub fn set_watched_files<I, P>(&mut self, paths: I)
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let mut next = BTreeMap::new();
        for raw in paths {
            let path = raw.into();
            let fp = self
                .watched_files
                .remove(&path)
                .unwrap_or_else(|| FileFingerprint::capture(&path));
            next.insert(path, fp);
        }
        self.watched_files = next;
        self.bind_file_events();
        self.check_after_bind = true;
    }

    fn bind_file_events(&mut self) {
        #[cfg(target_os = "macos")]
        self.files.bind(self.watched_files.keys().cloned());
        self.retry_binding_at = (!self.has_file_subscriptions()).then(|| std::time::Instant::now() + Duration::from_secs(1));
    }

    fn has_file_subscriptions(&self) -> bool {
        #[cfg(target_os = "macos")]
        { !self.files.incomplete }
        #[cfg(not(target_os = "macos"))]
        { self.watched_files.is_empty() }
    }

    fn poll_file_changes(&mut self) -> Vec<PathBuf> {
        let mut changed = Vec::new();
        for (path, previous) in &mut self.watched_files {
            let current = FileFingerprint::capture(path);
            if &current != previous {
                *previous = current;
                changed.push(path.clone());
            }
        }
        changed
    }

    pub fn wait(&mut self, timeout: Duration) -> Vec<NetworkEventKind> {
        self.wait_with_readers(timeout, &[]).0
    }

    /// Co-wait for file/network evidence, a request socket, or cancellation.
    /// Readiness is only a hint: callers still validate the accepted request.
    pub fn wait_with_readers(&mut self, timeout: impl Into<Option<Duration>>, readers: &[BorrowedFd<'_>]) -> (Vec<NetworkEventKind>, Option<usize>) {
        let timeout = timeout.into();
        let start = std::time::Instant::now();
        loop {
            let mut remaining = timeout.map(|budget| budget.saturating_sub(start.elapsed()));
            if let Some(at) = self.retry_binding_at {
                let retry = at.saturating_duration_since(std::time::Instant::now());
                remaining = Some(remaining.map_or(retry, |budget| budget.min(retry)));
            }
            let (events, ready) = self.wait_once(remaining, readers);
            if ready.is_some() || timeout.is_some_and(|budget| start.elapsed() >= budget) || events != [NetworkEventKind::Timeout] {
                return (events, ready);
            }
        }
    }

    fn wait_once(&mut self, timeout: Option<Duration>, readers: &[BorrowedFd<'_>]) -> (Vec<NetworkEventKind>, Option<usize>) {
        let mut events = Vec::new();
        if std::mem::take(&mut self.check_after_bind) {
            events.extend(self.poll_file_changes().into_iter().map(NetworkEventKind::WatchedFileChanged));
        }
        #[cfg(target_os = "macos")]
        events.extend(self.processes.take_pending_exited().into_iter().map(NetworkEventKind::WatchedProcessExited));

        let now_wall = std::time::SystemTime::now();
        let now_mono = std::time::Instant::now();

        if let (Some(prev_wall), Some(prev_mono)) = (self.last_wall_clock, self.last_mono_clock) {
            if clock_discontinuity(now_wall.duration_since(prev_wall).ok(), now_mono.duration_since(prev_mono)) {
                events.push(NetworkEventKind::ClockDiscontinuity);
            }
        }

        if !events.is_empty() {
            self.last_wall_clock = Some(now_wall);
            self.last_mono_clock = Some(now_mono);
            self.bind_file_events();
            if events.iter().any(power_or_clock_event) { confirm_wake(&mut self.last_wake, &mut events, kernel_wake_stamp()); }
            return (events, None);
        }

        let mut pollfds: Vec<libc::pollfd> = self.registrations.iter()
            .map(|r| libc::pollfd { fd: r.fd, events: libc::POLLIN, revents: 0 }).collect();
        let readers_start = pollfds.len();
        pollfds.extend(readers.iter().map(|r| libc::pollfd { fd: r.as_raw_fd(), events: libc::POLLIN, revents: 0 }));
        #[cfg(target_os = "macos")]
        let queue_index = self.files.queue.as_ref().map(|fd| {
            let index = pollfds.len();
            pollfds.push(libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 });
            index
        });
        #[cfg(target_os = "macos")]
        let proc_queue_index = self.processes.queue.as_ref().map(|fd| {
            let index = pollfds.len();
            pollfds.push(libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 });
            index
        });
        let mut reader_ready = None;
        #[allow(unused_mut)]
        let mut file_event = false;
        let wait_ms = timeout.map_or(-1, |budget| budget.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32);
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, wait_ms) };
        if ready > 0 {
            reader_ready = pollfds[readers_start..readers_start + readers.len()].iter().position(|p| p.revents != 0);
            #[cfg(target_os = "macos")]
            if queue_index.is_some_and(|index| pollfds[index].revents != 0) {
                self.files.drain();
                file_event = true;
            }
            #[cfg(target_os = "macos")]
            if proc_queue_index.is_some_and(|index| pollfds[index].revents != 0) {
                events.extend(self.processes.drain().into_iter().map(NetworkEventKind::WatchedProcessExited));
            }
            for (idx, pfd) in pollfds[..readers_start].iter().enumerate() {
                if pfd.revents & libc::POLLIN != 0 && self.registrations[idx].drain() {
                    let notif_name = self.registrations[idx].name.clone();
                    if notif_name == "io.local.claudewatch.system-wake" {
                        events.push(NetworkEventKind::WakeSignal);
                    } else {
                        events.push(NetworkEventKind::DarwinNotification(notif_name));
                    }
                }
            }
        }

        let after_wall = std::time::SystemTime::now();
        let after_mono = std::time::Instant::now();
        self.last_wall_clock = Some(after_wall);
        self.last_mono_clock = Some(after_mono);

        if clock_discontinuity(after_wall.duration_since(now_wall).ok(), after_mono.duration_since(now_mono)) {
            events.push(NetworkEventKind::ClockDiscontinuity);
        }
        if file_event || self.retry_binding_at.is_some_and(|at| after_mono >= at) {
            self.bind_file_events();
            events.extend(self.poll_file_changes().into_iter().map(NetworkEventKind::WatchedFileChanged));
        }
        if events.iter().any(power_or_clock_event) { confirm_wake(&mut self.last_wake, &mut events, kernel_wake_stamp()); }
        if events.is_empty() {
            events.push(NetworkEventKind::Timeout);
        }
        (events, reader_ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_scheduler_does_not_report_a_system_wake() {
        let mut watcher = NetworkEventWatcher::new(&[]);
        let delay = Duration::from_secs(4);
        watcher.last_wall_clock = Some(std::time::SystemTime::now() - delay);
        watcher.last_mono_clock = Some(std::time::Instant::now() - delay);
        assert_eq!(watcher.wait(Duration::ZERO), [NetworkEventKind::Timeout]);
        watcher.last_wall_clock = Some(std::time::SystemTime::now() - delay);
        assert_eq!(watcher.wait(Duration::ZERO), [NetworkEventKind::ClockDiscontinuity]);
        use std::{io::Write, os::unix::net::UnixStream};
        let (input, mut producer) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        watcher.registrations.push(NotifyRegistration { name: "io.local.claudewatch.system-wake".into(),
            fd: input.as_raw_fd(), token: -1 });
        producer.write_all(&[1]).unwrap();
        assert_eq!(watcher.wait(Duration::ZERO), [NetworkEventKind::WakeSignal]);
    }

    #[test]
    fn empty_wait_reaches_its_deadline() {
        let mut watcher = NetworkEventWatcher::new(&[]);
        let budget = Duration::from_millis(320);
        let started = std::time::Instant::now();
        assert_eq!(watcher.wait(budget), [NetworkEventKind::Timeout]);
        assert!(started.elapsed() >= budget);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dangling_link_wakes_on_target_creation_and_edits() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("cw-linked-events-{}", std::process::id()));
        let targets = root.join("targets");
        std::fs::create_dir_all(&targets).unwrap();
        let link = root.join("config");
        let target = targets.join("current");
        symlink("targets/current", &link).unwrap();
        let mut watcher = NetworkEventWatcher::new(&[]);
        watcher.watch_file(&link);
        assert!(watcher.has_file_subscriptions());
        assert_eq!(watcher.wait(Duration::ZERO), [NetworkEventKind::Timeout]);
        for contents in ["first", "updated"] {
            let target = target.clone();
            let writer = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                std::fs::write(target, contents).unwrap();
            });
            assert_eq!(watcher.wait(Duration::from_secs(2)), [NetworkEventKind::WatchedFileChanged(link.clone())]);
            assert!(watcher.has_file_subscriptions());
            writer.join().unwrap();
        }
        drop(watcher);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn moving_an_enclosing_directory_invalidates_the_nested_input() {
        let root = std::env::temp_dir().join(format!("cw-directory-event-{}", std::process::id()));
        let bundle = root.join("installed");
        let file = bundle.join("Contents/config");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "config").unwrap();
        let mut watcher = NetworkEventWatcher::new(&[]);
        watcher.watch_file(&file);
        assert_eq!(watcher.wait(Duration::ZERO), [NetworkEventKind::Timeout]);
        std::fs::rename(bundle, root.join("previous")).unwrap();
        let events = watcher.wait(Duration::from_millis(500));
        drop(watcher);
        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(events, [NetworkEventKind::WatchedFileChanged(file)]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn subscription_recovery_survives_a_ready_request_socket() {
        use std::{io::Write, os::{fd::AsFd, unix::net::UnixStream}, time::Instant};
        let dir = std::env::temp_dir().join(format!("cw-event-rebind-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("config");
        std::fs::write(&file, "before").unwrap();
        let mut watcher = NetworkEventWatcher::new(&[]);
        watcher.watch_file(&file);
        assert_eq!(watcher.wait(Duration::ZERO), [NetworkEventKind::Timeout]);
        // Model a failed registration with a retry already due and no vnode to wake us.
        watcher.files = FileEvents::default();
        watcher.retry_binding_at = Some(Instant::now());
        std::fs::write(&file, "changed").unwrap();
        let (mut tx, rx) = UnixStream::pair().unwrap();
        tx.write_all(&[1]).unwrap();
        let (events, ready) = watcher.wait_with_readers(None, &[rx.as_fd()]);
        assert_eq!(ready, Some(0));
        assert_eq!(events, [NetworkEventKind::WatchedFileChanged(file)]);
        assert!(watcher.retry_binding_at.is_none());
        drop(watcher);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn power_notifications_confirm_one_wake_per_new_kernel_stamp() {
        let power = NetworkEventKind::DarwinNotification("com.apple.powermanagement.systempowerstate".into());
        let mut events = vec![power.clone()];
        let mut previous = Some((20, 100));
        super::confirm_wake(&mut previous, &mut events, None);
        super::confirm_wake(&mut previous, &mut events, Some((20, 100)));
        assert_eq!(events, [power.clone()]);
        super::confirm_wake(&mut previous, &mut events, Some((31, 200)));
        assert_eq!(events, [power.clone(), NetworkEventKind::WakeSignal]);
        events = vec![power.clone()];
        super::confirm_wake(&mut previous, &mut events, Some((31, 200)));
        assert_eq!(events, [power]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn file_replacement_and_control_socket_interrupt_a_blocked_wait() {
        use std::{io::Write, os::fd::AsFd, os::unix::net::UnixStream, time::Instant};
        let dir = std::env::temp_dir().join(format!("cw-event-source-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("snapshot");
        let mut watcher = NetworkEventWatcher::new(&[]);
        watcher.watch_file(&file);
        for n in 0..2 {
            let file = file.clone();
            let writer = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(40));
                let staging = file.with_extension("new");
                std::fs::write(&staging, [n]).unwrap();
                std::fs::rename(staging, file).unwrap();
            });
            let start = Instant::now();
            assert!(watcher.wait(Duration::from_secs(3)).contains(&NetworkEventKind::WatchedFileChanged(dir.join("snapshot"))));
            assert!(start.elapsed() < Duration::from_secs(2), "must wake before the evidence deadline");
            writer.join().unwrap();
        }
        let (mut tx, rx) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            tx.write_all(&[1]).unwrap();
        });
        let start = Instant::now();
        assert_eq!(watcher.wait_with_readers(Duration::from_secs(3), &[rx.as_fd()]).1, Some(0));
        assert!(start.elapsed() < Duration::from_secs(2));
        writer.join().unwrap();
        drop(watcher);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn watcher_detects_file_mutation_and_drops_cleanly() {
        let dir = std::env::temp_dir().join(format!(
            "cw-net-events-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yaml");
        std::fs::write(&file, "mode: rule\n").unwrap();

        let mut watcher = NetworkEventWatcher::default();
        watcher.watch_file(&file);
        assert!(watcher.poll_file_changes().is_empty());

        std::fs::write(&file, "mode: direct\n").unwrap();
        let events = watcher.wait(Duration::from_millis(10));
        assert!(events
            .iter()
            .any(|e| e == &NetworkEventKind::WatchedFileChanged(file.clone())));
        drop(watcher);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn watched_process_exit_wakes_immediately() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("10")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let mut watcher = NetworkEventWatcher::new(&[]);
        watcher.set_watched_pids(&[pid]);
        assert_eq!(watcher.wait(Duration::ZERO), [NetworkEventKind::Timeout]);
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            let _ = child.kill();
            let _ = child.wait();
        });
        let started = std::time::Instant::now();
        let events = watcher.wait(Duration::from_secs(3));
        killer.join().unwrap();
        assert!(
            events.contains(&NetworkEventKind::WatchedProcessExited(pid)),
            "expected WatchedProcessExited({pid}), got {events:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "process exit event must wake promptly"
        );
    }
}

