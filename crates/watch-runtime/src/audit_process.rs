//! Audit work runs in an owned process group: a deadline stops the actual work,
//! including its sampling helpers, rather than merely abandoning a Rust thread.
use claude_watch_core::error::{CoreError, Result};
use claude_watch_system::{network_events::LocalNotifications, process_events::ProcessEvents};
use std::{
    io::{Read, Write},
    os::fd::AsFd,
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

static PENDING_REAP: Mutex<Vec<Child>> = Mutex::new(Vec::new());
const LIMIT: usize = 2_000_000;
#[cfg(test)]
thread_local! { static WAIT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[derive(Default)]
pub struct AuditCancellation {
    cancelled: AtomicBool,
    worker: OnceLock<std::thread::Thread>,
    readers: LocalNotifications,
}
impl std::fmt::Debug for AuditCancellation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditCancellation").field("cancelled", &self.is_cancelled()).finish()
    }
}
impl AuditCancellation {
    pub fn is_cancelled(&self) -> bool { self.cancelled.load(Ordering::Acquire) }
    pub(crate) fn watch_worker(&self) { let _ = self.worker.set(std::thread::current()); }
    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            if let Some(worker) = self.worker.get() { worker.unpark(); }
            self.readers.publish();
        }
    }
}

fn reap_group(child: &mut Child) -> bool {
    // Only the process group created by process_group(0) below is signalled.
    claude_watch_system::terminate_owned_group(child);
    if child.try_wait().ok().flatten().is_some() { return true; }
    let until = Instant::now() + Duration::from_millis(500);
    if let Ok(events) = ProcessEvents::new() {
        if events.watch_exit(child.id()).is_ok() && child.try_wait().ok().flatten().is_none() {
            let _ = events.wait(Some(until));
        }
    }
    child.try_wait().ok().flatten().is_some()
}

pub fn run_json(
    command: &mut Command,
    input: &serde_json::Value,
    deadline: Instant,
    cancelled: &AuditCancellation,
) -> Result<serde_json::Value> {
    {
        let mut pending = PENDING_REAP
            .lock()
            .map_err(|_| CoreError::new("audit_cleanup_failed", "审计回收状态不可用"))?;
        pending.retain_mut(|child| child.try_wait().ok().flatten().is_none());
        if !pending.is_empty() {
            return Err(CoreError::new(
                "audit_cleanup_pending",
                "前次审计尚未回收，未重复启动",
            ));
        }
    }
    if cancelled.is_cancelled() || Instant::now() >= deadline {
        return Err(CoreError::new("audit_cancelled", "审计已取消或超过期限"));
    }
    let bytes = serde_json::to_vec(input)
        .map_err(|_| CoreError::new("invalid_audit_request", "审计请求无法编码"))?;
    if bytes.len() > 4096 {
        return Err(CoreError::new("invalid_audit_request", "审计请求过大"));
    }
    let mut child = command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CoreError::new("audit_worker_start_failed", "审计子进程启动失败"))?;
    let result = (|| {
        child
            .stdin
            .take()
            .ok_or_else(|| CoreError::new("audit_worker_io_failed", "审计输入不可用"))?
            .write_all(&bytes)
            .map_err(|_| CoreError::new("audit_worker_io_failed", "审计输入失败"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| CoreError::new("audit_worker_io_failed", "审计输出不可用"))?;
        claude_watch_system::set_nonblocking(&output)
            .map_err(|_| CoreError::new("audit_worker_io_failed", "审计管道无法设置期限"))?;
        let wait_failed = |_| CoreError::new("audit_worker_wait_failed", "无法订阅审计进程事件");
        let wake = cancelled.readers.subscribe().map_err(wait_failed)?;
        let events = ProcessEvents::new().map_err(wait_failed)?;
        events.watch_read(output.as_fd()).map_err(wait_failed)?;
        events.watch_read(wake.as_fd()).map_err(wait_failed)?;
        if let Err(err) = events.watch_exit(child.id()) {
            if !claude_watch_system::child_has_exited(&child).map_err(wait_failed)? { return Err(wait_failed(err)); }
        }
        let mut output = Some(output);
        let mut data = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            if cancelled.is_cancelled() || Instant::now() >= deadline {
                return Err(CoreError::new(
                    "audit_cancelled",
                    "审计超时，已终止本次采样进程组",
                ));
            }
            while let Some(pipe) = output.as_mut() {
                match pipe.read(&mut buffer) {
                    Ok(0) => { output.take(); break; }
                    Ok(n) => {
                        data.extend_from_slice(&buffer[..n]);
                        if data.len() > LIMIT {
                            return Err(CoreError::new(
                                "audit_output_oversize",
                                "审计结果超过上限",
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(CoreError::new("audit_worker_io_failed", "审计输出失败")),
                }
            }
            if claude_watch_system::child_has_exited(&child)
                .map_err(|_| CoreError::new("audit_worker_wait_failed", "审计进程状态不可读取"))?
            {
                // Consume the final bytes written immediately before exit.
                if let Some(pipe) = output {
                    let _ = pipe.take((LIMIT - data.len() + 1) as u64).read_to_end(&mut data);
                }
                if data.len() > LIMIT {
                    return Err(CoreError::new(
                        "audit_worker_failed",
                        "审计子进程未成功完成",
                    ));
                }
                return crate::storage::strict_json(&data);
            }
            #[cfg(test)]
            WAIT_CALLS.set(WAIT_CALLS.get() + 1);
            events.wait(Some(deadline)).map_err(wait_failed)?;
        }
    })();
    if !reap_group(&mut child) {
        PENDING_REAP
            .lock()
            .map_err(|_| CoreError::new("audit_cleanup_failed", "审计回收状态不可用"))?
            .push(child);
        return Err(CoreError::new(
            "audit_cleanup_pending",
            "审计进程未在回收期限内退出",
        ));
    }
    let status = child.try_wait().ok().flatten();
    if !status.is_some_and(|s| s.success()) && result.is_ok() {
        let exit = status.map(|s| s.to_string()).unwrap_or_else(|| "exit status unavailable".into());
        if let Ok(value) = &result {
            if value["schema"] == 1 && value["status"] == "error" {
                if let Ok(error) = serde_json::from_value::<CoreError>(value.clone()) {
                    if !error.code.is_empty() && error.code.len() <= 128
                        && error.code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        return Err(CoreError::new(&error.code, &format!("{} ({exit})", error.message)));
                    }
                }
            }
        }
        return Err(CoreError::new(
            "audit_worker_failed",
            &format!("审计子进程未成功完成 ({exit})"),
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_stdout_leaves_only_exit_or_cancellation_to_wake_the_reader() {
        WAIT_CALLS.set(0);
        let result = run_json(Command::new("/bin/sh").args(["-c", "printf '{}'; exec 1>&-; sleep 0.2; exit 7"]),
            &serde_json::json!({}), Instant::now() + Duration::from_secs(3), &AuditCancellation::default());
        let error = result.unwrap_err();
        assert_eq!(error.code, "audit_worker_failed");
        assert!(error.message.contains("exit status: 7"));
        assert!(WAIT_CALLS.get() <= 4, "the closed output pipe kept waking the audit reader");
    }
    #[test]
    fn worker_error_retains_original_code_and_exit_status() {
        for (script, code, detail) in [
            (r#"cat >/dev/null; printf '%s' '{"schema":1,"status":"error","code":"evidence_response_failed","message":"probe failed"}'; exit 4"#,
                "evidence_response_failed", "exit status: 4"),
            (r#"cat >/dev/null; printf '%s' '{"schema":1,"status":"ok"}'; exit 7"#,
                "audit_worker_failed", "exit status: 7"),
            (r#"cat >/dev/null; printf '{}'; kill -KILL $$"#,
                "audit_worker_failed", "signal: 9"),
        ] {
            let result = run_json(Command::new("/bin/sh").args(["-c", script]),
                &serde_json::json!({}), Instant::now() + Duration::from_secs(2), &AuditCancellation::default());
            let error = result.unwrap_err();
            assert_eq!(error.code, code);
            assert!(error.message.contains(detail), "{}", error.message);
        }
    }

    #[test]
    fn audit_deadline_reaps_owned_work_and_next_audit_can_execute() {
        let cancel = AuditCancellation::default();
        let started = Instant::now();
        let marker = std::env::temp_dir().join(format!("cw-late-audit-{}", uuid::Uuid::new_v4()));
        let result = run_json(
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "cat >/dev/null; (sleep 0.4; echo late > \"$1\") & wait",
                    "--",
                ])
                .arg(&marker),
            &serde_json::json!({}),
            started + Duration::from_millis(100),
            &cancel,
        );
        assert_eq!(result.unwrap_err().code, "audit_cancelled");
        assert!(started.elapsed() < Duration::from_secs(2));
        let next = run_json(
            Command::new("/bin/sh").args(["-c", "cat >/dev/null; printf '{\"completed\":true}'"]),
            &serde_json::json!({}),
            Instant::now() + Duration::from_secs(2),
            &cancel,
        )
        .unwrap();
        assert_eq!(next["completed"], true);
        std::thread::sleep(Duration::from_millis(450));
        assert!(
            !marker.exists(),
            "timed-out helper must not publish a late result"
        );
    }
}
