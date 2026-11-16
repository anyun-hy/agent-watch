//! Bounded, correlated IPC for the existing resident evidence worker.
use crate::{
    background_evidence::{self, EvidenceSystem},
    storage::{Paths, StateStore},
};
use claude_watch_core::{
    error::{CoreError, Result},
    evidence::EvidenceRequest,
};
use serde_json::{json, Value};
use std::{
    io::Write,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    time::{Duration, Instant},
};

const REQUEST_LIMIT: usize = 8192;
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
pub fn evidence_socket_path(paths: &Paths) -> PathBuf {
    paths.watch().join("state/evidence.sock")
}
fn failure(code: &str) -> CoreError {
    CoreError::new(
        code,
        match code {
            "daemon_unavailable" => "后台检测服务不可用，请等待守护服务就绪",
            "evidence_timeout" => "等待后台检测响应超时",
            _ => "后台检测通信格式或请求代次无效",
        },
    )
}
fn read_frame(stream: &mut UnixStream, limit: usize, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = claude_watch_system::read_unix_before(stream, &mut chunk, deadline).map_err(|e| {
            failure(
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) {
                    "evidence_timeout"
                } else {
                    "evidence_response_failed"
                },
            )
        })?;
        if n == 0 {
            return Err(failure("evidence_response_failed"));
        }
        data.extend_from_slice(&chunk[..n]);
        if data.len() > limit {
            return Err(failure("evidence_payload_oversize"));
        }
        if let Some(end) = data.iter().position(|v| *v == b'\n') {
            if end + 1 != data.len() {
                return Err(failure("evidence_response_invalid"));
            }
            return Ok(data);
        }
    }
}
fn write_frame(stream: &mut UnixStream, value: &Value) -> Result<()> {
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| failure("evidence_request_failed"))?;
    let mut bytes = serde_json::to_vec(value).map_err(|_| failure("evidence_response_invalid"))?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .map_err(|_| failure("evidence_request_failed"))
}
/// Socket availability is the liveness check; an old sampling heartbeat is not
/// a second authority for a responsive service. Receipt freshness is independent.
pub fn request_daemon_evidence(
    paths: &Paths,
    request: &EvidenceRequest,
    timeout: Duration,
) -> Result<Value> {
    request.validate()?;
    let path = evidence_socket_path(paths);
    let store = StateStore::new(paths.clone());
    store.guarded(&path)?;
    let meta = std::fs::symlink_metadata(&path).map_err(|_| failure("daemon_unavailable"))?;
    let owner = std::fs::metadata(paths.watch())
        .map_err(|_| failure("daemon_unavailable"))?
        .uid();
    if !meta.file_type().is_socket() || meta.uid() != owner || meta.mode() & 0o077 != 0 {
        return Err(failure("daemon_unavailable"));
    }
    let mut stream = UnixStream::connect(&path).map_err(|_| failure("daemon_unavailable"))?;
    write_frame(
        &mut stream,
        &serde_json::to_value(request).map_err(|_| failure("invalid_evidence_request"))?,
    )?;
    let response: Value =
        serde_json::from_slice(&read_frame(&mut stream, RESPONSE_LIMIT, timeout)?)
            .map_err(|_| failure("evidence_response_invalid"))?;
    if response["schema"] != 1 || response["id"] != request.id {
        return Err(failure("evidence_response_invalid"));
    }
    if response["status"] != "ok" {
        return Err(CoreError::new(
            response["code"].as_str().unwrap_or("evidence_failed"),
            response["message"].as_str().unwrap_or("检测未完成"),
        ));
    }
    let result = &response["result"];
    if result["schema"] != 1 || result["id"] != request.id || !result["items"].is_object() {
        return Err(failure("evidence_response_invalid"));
    }
    Ok(result.clone())
}

/// The daemon owns this listener on its existing evidence thread. Integration
/// tests use this same handler with injected facts, never a second protocol.
pub struct EvidenceServer {
    listener: UnixListener,
    path: PathBuf,
    inode: u64,
}
impl EvidenceServer {
    pub fn bind(store: &StateStore) -> Result<Self> {
        let path = evidence_socket_path(&store.paths);
        store.guarded(&path)?;
        store.private_dir(&store.paths.watch().join("state"))?;
        if path.exists() {
            if UnixStream::connect(&path).is_ok() {
                return Err(failure("evidence_service_already_running"));
            }
            let meta =
                std::fs::symlink_metadata(&path).map_err(|_| failure("daemon_unavailable"))?;
            if !meta.file_type().is_socket() {
                return Err(failure("evidence_endpoint_invalid"));
            }
            std::fs::remove_file(&path).map_err(|_| failure("evidence_endpoint_invalid"))?;
        }
        let listener = UnixListener::bind(&path).map_err(|_| failure("daemon_unavailable"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| failure("evidence_endpoint_invalid"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| failure("evidence_endpoint_invalid"))?;
        let inode = std::fs::metadata(&path)
            .map_err(|_| failure("evidence_endpoint_invalid"))?
            .ino();
        Ok(Self {
            listener,
            path,
            inode,
        })
    }
    pub fn poll<S: EvidenceSystem>(&self, store: &StateStore, system: &mut S) -> Result<bool> {
        let (mut stream, _) = match self.listener.accept() {
            Ok(value) => value,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err(failure("evidence_response_failed")),
        };
        // macOS inherits the listener's nonblocking flag. A connected request
        // uses the bounded read/write timeouts below, including split frames.
        stream.set_nonblocking(false).map_err(|_| failure("evidence_response_failed"))?;
        let request: EvidenceRequest = serde_json::from_slice(&read_frame(
            &mut stream,
            REQUEST_LIMIT,
            Duration::from_secs(2),
        )?)
        .map_err(|_| failure("invalid_evidence_request"))?;
        let response = match background_evidence::serve_evidence_request(store, system, &request) {
            Ok(value) => json!({"schema":1,"id":request.id,"status":"ok","result":value}),
            Err(e) => {
                json!({"schema":1,"id":request.id,"status":"error","code":e.code,"message":e.message})
            }
        };
        write_frame(&mut stream, &response)?;
        Ok(true)
    }
}
impl Drop for EvidenceServer {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && m.ino() == self.inode)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_frame_survives_peer_close_across_read_chunks() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let bytes = format!("{{\"detail\":\"{}\"}}\n", "x".repeat(6000)).into_bytes();
        writer.write_all(&bytes).unwrap();
        drop(writer); // macOS used to reject SO_RCVTIMEO despite buffered data.
        assert_eq!(read_frame(&mut reader, RESPONSE_LIMIT, Duration::from_secs(1)).unwrap(), bytes);
    }

    #[test]
    fn framing_rejects_truncation_extra_frames_and_oversize() {
        for (bytes, limit, code) in [
            (b"{\"partial\":true}".to_vec(), 100, "evidence_response_failed"),
            (b"{}\n{}\n".to_vec(), 100, "evidence_response_invalid"),
            (format!("{}\n", "x".repeat(6000)).into_bytes(), 4096, "evidence_payload_oversize"),
        ] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(&bytes).unwrap();
            drop(writer);
            assert_eq!(read_frame(&mut reader, limit, Duration::from_secs(1)).unwrap_err().code, code);
        }
    }

    #[test]
    fn partial_data_does_not_extend_the_original_deadline() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            writer.write_all(b"{").unwrap();
            std::thread::sleep(Duration::from_millis(70));
            let _ = writer.write_all(b" ");
            std::thread::sleep(Duration::from_millis(150));
        });
        let start = Instant::now();
        let result = read_frame(&mut reader, 100, Duration::from_millis(100));
        let elapsed = start.elapsed();
        worker.join().unwrap();
        assert_eq!(result.unwrap_err().code, "evidence_timeout");
        assert!(elapsed < Duration::from_millis(160), "deadline extended: {elapsed:?}");
    }
}
