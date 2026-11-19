//! The supervisor owns each immutable history window. A runtime snapshot pins the
//! same inode so its full reader can finish after a newer boot or state transition.
use crate::{
    channel_policy_status::read_frame,
    channel_supervisor::MAX_PERSISTED_EVENTS,
    storage::{sha256, strict_json, StateStore},
};
use claude_watch_core::{
    channel::ChannelMonitorEvent,
    error::{CoreError, Result},
};
use serde_json::{json, Value};
use std::{fs, io::ErrorKind, path::Path};

const LIVE: &str = "state/channel-events";
const PINNED: &str = "state/runtime-channel-events";
const LIMIT: usize = 8 * 1024 * 1024;

fn unavailable() -> CoreError {
    CoreError::new("channel_history_unavailable", "当前通道历史不可读取")
}

fn filename(frame: &Value) -> Option<String> {
    let boot = frame["producer_boot_id"]
        .as_str()
        .filter(|id| !id.is_empty())?;
    let seq = frame["snapshot_seq"].as_u64()?;
    Some(sha256(format!("{boot}/{seq}").as_bytes()))
}

// Both directories contain only private, immutable files named by this writer.
fn prune(store: &StateStore, dir: &Path, keep: &str, previous: Option<&str>) {
    let Ok(entries) = store
        .guarded(dir)
        .and_then(|path| fs::read_dir(path).map_err(|_| unavailable()))
    else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name != keep
            && Some(name) != previous
            && name.len() == 64
            && name.bytes().all(|b| b.is_ascii_hexdigit())
            && entry.file_type().is_ok_and(|ty| ty.is_file())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

pub(crate) fn write(
    store: &StateStore,
    frame: &Value,
    events: &[ChannelMonitorEvent],
) -> Result<()> {
    let name = filename(frame).ok_or_else(unavailable)?;
    let dir = store.paths.watch().join(LIVE);
    // Preserve the last committed window even when successive authority writes fail.
    let previous = filename(&read_frame(store));
    let mut bytes = serde_json::to_vec(events).map_err(|_| unavailable())?;
    bytes.push(b'\n');
    if bytes.len() > LIMIT {
        return Err(unavailable());
    }
    store.atomic_bytes(&dir.join(&name), &bytes, 0o600)?;
    prune(store, &dir, &name, previous.as_deref());
    Ok(())
}

fn pin(store: &StateStore, frame: &Value) -> Result<()> {
    let name = filename(frame).ok_or_else(unavailable)?;
    let dir = store.paths.watch().join(PINNED);
    let dest = store.guarded(&dir.join(&name))?;
    if dest.is_file() {
        return Ok(());
    }
    let src = store.guarded(&store.paths.watch().join(LIVE).join(&name))?;
    let previous = store
        .read_bytes(&crate::monitor_snapshot::published_path(store), LIMIT)?
        .map(|raw| strict_json(&raw))
        .transpose()?
        .and_then(|value| filename(&value["snapshot"]["channelSupervision"]));
    store.private_dir(&dir)?;
    match fs::hard_link(src, dest) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::AlreadyExists => return Ok(()),
        Err(_) => return Err(unavailable()),
    }
    // A failed subsequent runtime publication must leave its previous window readable.
    prune(store, &dir, &name, previous.as_deref());
    fs::File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(|_| unavailable())?;
    Ok(())
}

pub(crate) fn runtime_frame(store: &StateStore) -> Value {
    let mut frame = read_frame(store);
    if frame["event_history"] == "separate" && pin(store, &frame).is_err() {
        // The supervisor may have advanced between the frame read and link creation.
        frame = read_frame(store);
        if frame["event_history"] == "separate" && pin(store, &frame).is_err() {
            frame["event_history"] = json!("unavailable");
        }
    }
    frame
}

pub(crate) fn events(store: &StateStore, frame: &Value, pinned: bool) -> Result<Value> {
    if frame["event_history"] != "separate" {
        return Err(unavailable());
    }
    let seq = frame["snapshot_seq"].as_u64().ok_or_else(unavailable)?;
    let dir = if pinned { PINNED } else { LIVE };
    let path = store
        .paths
        .watch()
        .join(dir)
        .join(filename(frame).ok_or_else(unavailable)?);
    let value = strict_json(&store.read_bytes(&path, LIMIT)?.ok_or_else(unavailable)?)?;
    let rows = value.as_array().ok_or_else(unavailable)?;
    let count = seq.min(MAX_PERSISTED_EVENTS as u64);
    if rows.len() as u64 != count
        || rows.iter().enumerate().any(|(i, row)| {
            row["producer_boot_id"] != frame["producer_boot_id"]
                || row["event_seq"].as_u64() != Some(seq - count + i as u64 + 1)
        })
    {
        return Err(unavailable());
    }
    Ok(value)
}
