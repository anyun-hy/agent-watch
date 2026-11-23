use super::{secondary_root, Slot};
use crate::{
    commands::ReadRunner,
    storage::StateStore,
    target_discovery::{DiscoveryHandle, BUNDLED_CLI_ENTRIES},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use subprocess::{Exec, Redirection};

pub(super) fn service_home(store: &StateStore, slot: Slot) -> PathBuf {
    match slot {
        Slot::A => store.paths.home.join(".codex"),
        Slot::B => secondary_root(store).join("codex"),
    }
}

pub(super) struct Reading {
    slot: Slot,
    directory: (u64, u64),
    state: &'static str,
}

pub(super) fn directory(store: &StateStore, slot: Slot) -> (&'static str, Option<(u64, u64)>) {
    match store.guarded(&service_home(store, slot)) {
        Ok(path) => match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => ("present", Some((meta.dev(), meta.ino()))),
            Err(e) if e.kind() == ErrorKind::NotFound => ("absent", None),
            _ => ("unknown", None),
        },
        Err(_) => ("unknown", None),
    }
}

pub(super) fn slot_info(
    store: &StateStore,
    slot: Slot,
    current: bool,
    readings: &[Reading],
) -> Value {
    let (profile, id) = directory(store, slot);
    let login = if slot == Slot::B && profile == "absent" {
        "uninitialized"
    } else {
        readings
            .iter()
            .find(|r| r.slot == slot && Some(r.directory) == id)
            .map_or("unknown", |r| r.state)
    };
    json!({"id":slot,"current":current,"stored":id.is_some(),"profile_state":profile,"login_state":login})
}

pub(super) fn check_slots<R: ReadRunner>(store: &StateStore, runner: &R) -> Vec<Reading> {
    let uid = claude_watch_system::effective_uid();
    if uid == 0 || store.paths.require_owner(uid).is_err() {
        return Vec::new();
    }
    let homes: Vec<_> = [Slot::A, Slot::B]
        .into_iter()
        .filter_map(|slot| directory(store, slot).1.map(|id| (slot, id)))
        .collect();
    if homes.is_empty() {
        return Vec::new();
    }
    let catalog =
        DiscoveryHandle::for_home(&store.paths.home).refresh(runner, crate::native::now());
    let Some(cli) = catalog
        .chatgpt_account_source()
        .ok()
        .and_then(|bundle| signed_client(&bundle))
    else {
        return Vec::new();
    };
    homes
        .into_iter()
        .map(|(slot, directory)| Reading {
            slot,
            directory,
            state: check_local_login(&cli, store, slot),
        })
        .collect()
}

// The application catalog also accepts user-installed bundles. Only execute
// an OpenAI-signed native Codex binary, never a PATH command or shell wrapper.
pub(super) fn signed_client(bundle: &Path) -> Option<PathBuf> {
    let root = bundle.canonicalize().ok()?;
    BUNDLED_CLI_ENTRIES.iter().find_map(|entry| {
        let path = root.join(entry).canonicalize().ok()?;
        if !path.starts_with(&root) || !path.is_file() { return None }
        let requirement = r#"=anchor apple generic and certificate leaf[subject.OU] = "2DC432GLL2" and identifier "codex""#;
        let verify = Exec::cmd("/usr/bin/codesign").args(&["--verify", "--strict", "-R", requirement]).arg(&path);
        let (code, _) = bounded_status(verify)?;
        (code == 0).then_some(path)
    })
}

fn check_local_login(cli: &Path, store: &StateStore, slot: Slot) -> &'static str {
    let Ok(home) = store.guarded(&service_home(store, slot)) else {
        return "unknown";
    };
    let command = Exec::cmd(cli)
        .args(&["login", "status"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &store.paths.home)
        .env("CODEX_HOME", home);
    bounded_status(command).map_or("unknown", |(code, output)| login_state(code, &output))
}

fn login_state(code: u32, output: &[u8]) -> &'static str {
    // Other modes (including API keys), localized/unrecognized responses,
    // timeouts and CLI errors must never be presented as a desktop login.
    let line = std::str::from_utf8(output)
        .ok()
        .and_then(|s| s.trim_end().lines().next_back());
    match (code, line) {
        (0, Some("Logged in using ChatGPT")) => "logged_in",
        (1, Some("Not logged in")) => "signed_out",
        _ => "unknown",
    }
}

fn bounded_status(command: Exec) -> Option<(u32, Vec<u8>)> {
    const TIMEOUT: Duration = Duration::from_secs(2);
    const MAX: usize = 4096;
    let started = Instant::now();
    let mut job = command
        .cwd("/")
        .env("LC_ALL", "C")
        .stdin(Redirection::Null)
        .stdout(Redirection::Null)
        .stderr(Redirection::Pipe)
        .start()
        .ok()?;
    if let Ok((_, stderr)) = job
        .communicate()
        .and_then(|c| c.limit_time(TIMEOUT).limit_size(MAX + 1).read())
    {
        if stderr.len() <= MAX {
            if let Ok(Some(status)) = job.wait_timeout(TIMEOUT.saturating_sub(started.elapsed())) {
                return status.code().map(|code| (code, stderr));
            }
        }
    }
    let _ = job.kill();
    if !matches!(job.wait_timeout(Duration::from_millis(300)), Ok(Some(_))) {
        job.detach()
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn chatgpt_account_directory_is_not_login_evidence() {
        let home = std::env::temp_dir().join(format!("cw-login-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        assert_eq!(slot_info(&store, Slot::A, false, &[])["stored"], false);
        assert_eq!(
            slot_info(&store, Slot::B, false, &[])["login_state"],
            "uninitialized"
        );
        super::super::Profile::prepare(&store, Slot::B).unwrap();
        let row = slot_info(&store, Slot::B, true, &[]);
        assert_eq!(row["profile_state"], "present");
        assert_eq!(row["login_state"], "unknown");
        let prior = [Reading {
            slot: Slot::B,
            directory: directory(&store, Slot::B).1.unwrap(),
            state: "logged_in",
        }];
        assert_eq!(
            slot_info(&store, Slot::B, false, &prior)["login_state"],
            "logged_in"
        );
        let b = service_home(&store, Slot::B);
        fs::rename(&b, b.with_file_name("old-home")).unwrap();
        fs::create_dir(&b).unwrap();
        assert_eq!(
            slot_info(&store, Slot::B, false, &prior)["login_state"],
            "unknown"
        );
        symlink(service_home(&store, Slot::B), service_home(&store, Slot::A)).unwrap();
        assert_eq!(
            slot_info(&store, Slot::A, false, &[])["profile_state"],
            "unknown"
        );
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn chatgpt_login_requires_a_recognized_provider_result_and_exit_code() {
        assert_eq!(login_state(0, b"Logged in using ChatGPT\n"), "logged_in");
        assert_eq!(login_state(1, b"warning\nNot logged in\n"), "signed_out");
        for (code, output) in [
            (0, "Logged in using an API key"),
            (1, "Logged in using ChatGPT"),
            (0, "Not logged in"),
            (1, "Provider unavailable"),
            (0, "Logged in using ChatGPT\nError"),
        ] {
            assert_eq!(login_state(code, output.as_bytes()), "unknown");
        }
    }

    #[test]
    fn chatgpt_login_probe_reads_the_requested_home_and_only_the_provider_status() {
        let home = std::env::temp_dir().join(format!("cw-login-provider-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        let a = service_home(&store, Slot::A);
        let b = service_home(&store, Slot::B);
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        let cli = home.join("synthetic-provider");
        fs::write(
            &cli,
            br#"#!/bin/sh
test "$#" -eq 2 && test "$1" = login && test "$2" = status || exit 2
if test -f "$CODEX_HOME/fixture-signed-in"; then
    echo 'Logged in using ChatGPT' >&2
    exit 0
fi
echo 'Not logged in' >&2
exit 1
"#,
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(a.join("fixture-signed-in"), "").unwrap();
        assert_eq!(check_local_login(&cli, &store, Slot::A), "logged_in");
        assert_eq!(check_local_login(&cli, &store, Slot::B), "signed_out");
        fs::rename(a.join("fixture-signed-in"), b.join("fixture-signed-in")).unwrap();
        assert_eq!(check_local_login(&cli, &store, Slot::B), "logged_in");
        assert_eq!(check_local_login(&cli, &store, Slot::A), "signed_out");
        fs::remove_dir_all(home).unwrap();
    }
}
