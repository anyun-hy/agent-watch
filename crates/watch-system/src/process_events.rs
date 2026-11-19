//! Kernel notifications are wakeups. Callers still verify the bound lifetime,
//! child status or pipe contents before accepting any result.
use std::{io, os::fd::BorrowedFd, time::Instant};

pub struct ProcessEvents {
    #[cfg(target_os = "macos")]
    queue: std::os::fd::OwnedFd,
}

#[cfg(target_os = "macos")]
impl ProcessEvents {
    pub fn new() -> io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let fd = unsafe { libc::kqueue() };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let queue = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { queue })
    }

    fn register(&self, ident: usize, filter: i16, flags: u16, fflags: u32) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let change = libc::kevent { ident, filter, flags: libc::EV_ADD | flags, fflags, data: 0, udata: std::ptr::null_mut() };
        let result = unsafe { libc::kevent(self.queue.as_raw_fd(), &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if result < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub fn watch_exit(&self, pid: u32) -> io::Result<()> {
        self.register(pid as usize, libc::EVFILT_PROC, libc::EV_ONESHOT, libc::NOTE_EXIT)
    }

    pub fn watch_exec_or_exit(&self, pid: u32) -> io::Result<()> {
        self.register(pid as usize, libc::EVFILT_PROC, libc::EV_CLEAR, libc::NOTE_EXEC | libc::NOTE_EXIT)
    }

    pub fn watch_read(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        self.register(fd.as_raw_fd() as usize, libc::EVFILT_READ, libc::EV_CLEAR, 0)
    }

    pub fn wait(&self, deadline: Option<Instant>) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        loop {
            let timeout = deadline.map(|at| {
                let remaining = at.saturating_duration_since(Instant::now());
                libc::timespec { tv_sec: remaining.as_secs() as _, tv_nsec: remaining.subsec_nanos() as _ }
            });
            let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
            let count = unsafe { libc::kevent(self.queue.as_raw_fd(), std::ptr::null(), 0, event.as_mut_ptr(), 1,
                timeout.as_ref().map_or(std::ptr::null(), |t| t)) };
            if count >= 0 { return Ok(count > 0); }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted { return Err(err); }
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl ProcessEvents {
    pub fn new() -> io::Result<Self> { Err(io::ErrorKind::Unsupported.into()) }
    pub fn watch_exit(&self, _: u32) -> io::Result<()> { Err(io::ErrorKind::Unsupported.into()) }
    pub fn watch_exec_or_exit(&self, _: u32) -> io::Result<()> { Err(io::ErrorKind::Unsupported.into()) }
    pub fn watch_read(&self, _: BorrowedFd<'_>) -> io::Result<()> { Err(io::ErrorKind::Unsupported.into()) }
    pub fn wait(&self, _: Option<Instant>) -> io::Result<bool> { Err(io::ErrorKind::Unsupported.into()) }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::{io::{BufRead, BufReader, Write}, process::{Command, Stdio}, time::Duration};

    #[test]
    fn idle_exec_and_exit_wake_at_their_own_events() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "echo ready; read go || exit 1; exec /bin/cat"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut ready).unwrap();
        assert_eq!(ready, "ready\n");
        let events = ProcessEvents::new().unwrap();
        events.watch_exec_or_exit(child.id()).unwrap();
        assert!(!events.wait(Some(Instant::now() + Duration::from_millis(50))).unwrap());
        input.write_all(b"go\n").unwrap();
        assert!(events.wait(Some(Instant::now() + Duration::from_secs(2))).unwrap());
        assert!(child.try_wait().unwrap().is_none());
        drop(input);
        assert!(events.wait(Some(Instant::now() + Duration::from_secs(2))).unwrap());
        assert!(child.wait().unwrap().success());
    }
}
