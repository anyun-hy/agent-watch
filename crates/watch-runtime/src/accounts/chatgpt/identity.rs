//! Manual public account read. A source receipt is tied to a running desktop,
//! its profile directory and the identity returned by its signed app-server.
use super::{login, process_is_live, selection, Slot};
use crate::{
    commands::{ReadCommand, ReadRunner},
    native::{self, Observer},
    storage::StateStore,
    target_discovery::DiscoveryHandle,
};
use claude_watch_core::{
    error::Result,
    processes::{Identity, Kind},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use subprocess::{Exec, Redirection};

const EXTERNAL: &str =
    "已找到 ChatGPT，但无法确认它正在使用哪份资料。请从本页打开对应的账号，再读取当前登录。";
const CHANGED: &str = "读取期间桌面进程或账号资料已变化，请重新读取。";

struct Source {
    process: Identity,
    slot: Slot,
    profile: Slot,
    cli: PathBuf,
    service: Option<Identity>,
}

fn notice(state: &str, detail: &str) -> Value {
    json!({"state":state, "detail":detail})
}

fn profile_from_open_state(store: &StateStore, pid: u32, listing: &str) -> Option<Slot> {
    let homes = [
        login::service_home(store, Slot::A),
        login::service_home(store, Slot::B),
    ];
    let mut matches = [false; 2];
    let mut expected_pid = false;
    let mut file_fd = false;
    for line in listing.lines() {
        if let Some(id) = line.strip_prefix('p') {
            expected_pid = id.parse::<u32>().ok() == Some(pid);
            file_fd = false;
        } else if let Some(fd) = line.strip_prefix('f') {
            file_fd = fd.parse::<u32>().is_ok();
        } else if let Some(name) = line.strip_prefix('n').filter(|_| expected_pid && file_fd) {
            let file = Path::new(name);
            let version = file
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("state_"))
                .and_then(|s| s.strip_suffix(".sqlite"));
            if !version.is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())) {
                continue;
            }
            for (index, home) in homes.iter().enumerate() {
                if file.parent() == Some(home) {
                    matches[index] = true
                }
            }
        }
    }
    match matches {
        [true, false] => Some(Slot::A),
        [false, true] => Some(Slot::B),
        _ => None,
    }
}

fn open_profile<R: ReadRunner>(store: &StateStore, runner: &R, pid: u32) -> Result<Option<Slot>> {
    let output = runner.run(
        ReadCommand::LsofFiles { pids: vec![pid] },
        &[],
        Duration::from_secs(2),
        1024 * 1024,
    )?;
    Ok((output.status == 0)
        .then(|| output.text().ok())
        .flatten()
        .and_then(|s| profile_from_open_state(store, pid, s)))
}

fn external_source<R: ReadRunner>(
    store: &StateStore,
    runner: &R,
) -> Result<std::result::Result<Source, Value>> {
    let observer = Observer { runner };
    let inventory = observer.inventory()?;
    if !inventory.complete {
        return Ok(Err(notice(
            "unknown",
            "系统暂时无法完整核对桌面进程，请重试。",
        )));
    }
    let catalog = DiscoveryHandle::for_home(&store.paths.home).refresh(runner, native::now());
    let mut roots = inventory.processes.values().filter_map(|row| {
        let app = catalog.targets.iter().find(|app| {
            app.valid()
                && app.kind() == Some(Kind::OpenaiMain)
                && app.executable.as_deref() == Some(Path::new(&row.identity.executable))
        })?;
        Some((&row.identity, app.bundle.as_ref()?))
    });
    let Some((root, bundle)) = roots.next() else {
        return Ok(Err(if catalog.complete {
            notice("app_closed", "请先打开支持 A/B 资料的 ChatGPT 桌面端。")
        } else {
            notice("unknown", "暂时无法核对 ChatGPT 桌面应用。")
        }));
    };
    if roots.next().is_some() {
        return Ok(Err(notice("unknown", EXTERNAL)));
    }
    let Some(cli) = login::signed_client(bundle) else {
        return Ok(Err(notice(
            "unknown",
            "无法核验当前 ChatGPT 随附的账号读取组件。",
        )));
    };
    // Only a direct app-server child of this desktop establishes the link.
    // A CLI started from an integrated terminal belongs to another process tree.
    let mut services = inventory
        .processes
        .values()
        .map(|row| &row.identity)
        .filter(|p| p.parent == root.pid && p.uid == root.uid && Path::new(&p.executable) == cli);
    let Some(service) = services.next() else {
        return Ok(Err(notice("unknown", EXTERNAL)));
    };
    if services.next().is_some() {
        return Ok(Err(notice("unknown", EXTERNAL)));
    }
    let round = uuid::Uuid::new_v4().to_string();
    let argv = observer.arguments(std::slice::from_ref(service), &round)?;
    if !argv
        .get(&service.pid)
        .is_some_and(|a| !a.truncated && a.tokens.get(1).is_some_and(|s| s == "app-server"))
    {
        return Ok(Err(notice("unknown", EXTERNAL)));
    }
    let profile = open_profile(store, runner, service.pid)?;
    let Some(profile) = profile else {
        return Ok(Err(notice("unknown", EXTERNAL)));
    };
    let slot = selection(store)?.map_or(profile, |s| s.physical_slot(profile));
    Ok(Ok(Source {
        process: root.clone(),
        slot,
        profile,
        cli,
        service: Some(service.clone()),
    }))
}

fn current_source<R: ReadRunner>(
    store: &StateStore,
    runner: &R,
) -> Result<std::result::Result<Source, Value>> {
    if let Some(saved) = selection(store)?.filter(|s| process_is_live(runner, &s.process)) {
        let bundle = Path::new(&saved.process.executable)
            .ancestors()
            .find(|p| p.extension().is_some_and(|x| x == "app"));
        let Some(cli) = bundle.and_then(login::signed_client) else {
            return Ok(Err(notice(
                "unknown",
                "当前 ChatGPT 缺少可验证的账号读取组件。",
            )));
        };
        return Ok(Ok(Source {
            slot: saved.slot,
            profile: saved.profile(),
            process: saved.process,
            cli,
            service: None,
        }));
    }
    external_source(store, runner)
}

pub fn read<R: ReadRunner>(store: &StateStore, runner: &R) -> Result<Value> {
    let uid = claude_watch_system::effective_uid();
    if uid == 0 {
        return Ok(notice(
            "unknown",
            "请在当前登录用户的 Agent Watch 中读取账号。",
        ));
    }
    store.paths.require_owner(uid)?;
    let source = match current_source(store, runner)? {
        Ok(s) => s,
        Err(info) => return Ok(info),
    };
    let Some(directory) = login::directory(store, source.profile).1 else {
        return Ok(notice("unknown", "当前资料目录不可读。"));
    };
    let home = store.guarded(&login::service_home(store, source.profile))?;
    let account = read_public_account(&source.cli, &store.paths.home, &home);
    let latest = selection(store)?;
    let mapping_matches = latest
        .as_ref()
        .map_or(source.profile, |s| s.physical_slot(source.profile))
        == source.slot;
    let source_matches = match source.service.as_ref() {
        Some(service) => {
            open_profile(store, runner, service.pid)? == Some(source.profile)
                && process_is_live(runner, service)
                && !latest.as_ref().is_some_and(|s| {
                    !s.process.same_process(&source.process) && process_is_live(runner, &s.process)
                })
        }
        None => latest
            .as_ref()
            .is_some_and(|s| s.process.same_process(&source.process)),
    };
    if !mapping_matches
        || !source_matches
        || !process_is_live(runner, &source.process)
        || login::directory(store, source.profile).1 != Some(directory)
    {
        return Ok(notice("unknown", CHANGED));
    }
    Ok(match account {
        PublicAccount::SignedOut => notice("signed_out", "当前资料未登录 ChatGPT。"),
        PublicAccount::Unknown => notice(
            "unknown",
            "ChatGPT 暂未返回账号邮箱，请确认桌面端已完成登录并可连接到工作区。",
        ),
        PublicAccount::SignedIn { email, user_id } => {
            let id = &source.process;
            let public_facts = json!([
                1,
                id.pid,
                id.uid,
                id.start_seconds,
                id.start_microseconds,
                id.executable,
                source.profile,
                source.slot,
                directory,
                email,
                user_id
            ]);
            let digest = super::super::hex_digest(
                Sha256::digest(public_facts.to_string().as_bytes()).as_slice(),
            );
            json!({"state":"logged_in","detail":"已从当前桌面资料核对 ChatGPT 账号。",
                "email":email,"source_token":digest,"slot":source.slot,"profile":source.profile,"process":id})
        }
    })
}

#[derive(Debug, PartialEq)]
enum PublicAccount {
    SignedIn {
        email: String,
        user_id: Option<String>,
    },
    SignedOut,
    Unknown,
}

fn parse_account(result: &Value) -> PublicAccount {
    let Some(account) = result.get("account") else {
        return PublicAccount::Unknown;
    };
    if account.is_null() && result["requiresOpenaiAuth"] == true {
        return PublicAccount::SignedOut;
    }
    let Some(email) = account["email"].as_str() else {
        return PublicAccount::Unknown;
    };
    let valid = email.len() <= 320
        && !email.chars().any(|c| c.is_control() || c.is_whitespace())
        && email
            .split_once('@')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && !b.contains('@'));
    if account["type"] != "chatgpt" || !valid {
        return PublicAccount::Unknown;
    }
    PublicAccount::SignedIn {
        email: email.to_owned(),
        user_id: result["userId"]
            .as_str()
            .filter(|v| v.len() <= 512)
            .map(str::to_owned),
    }
}

fn read_public_account(cli: &Path, user_home: &Path, profile_home: &Path) -> PublicAccount {
    fn exchange(cli: &Path, user_home: &Path, profile_home: &Path) -> Option<PublicAccount> {
        let (parent, child) = UnixStream::pair().ok()?;
        let stdin = File::from(OwnedFd::from(child.try_clone().ok()?));
        let stdout = File::from(OwnedFd::from(child));
        let job = Exec::cmd(cli)
            .args(&["app-server", "--listen", "stdio://"])
            .env_clear()
            .env("HOME", user_home)
            .env("CODEX_HOME", profile_home)
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .cwd("/")
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Redirection::Null)
            .start()
            .ok()?;
        let result = rpc(parent);
        // Closing stdio lets app-server finish outstanding disk writes. Only the
        // temporary provider is terminated if shutdown does not finish in time.
        if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
            let _ = job.terminate();
            if !matches!(job.wait_timeout(Duration::from_millis(300)), Ok(Some(_))) {
                let _ = job.kill();
                if !matches!(job.wait_timeout(Duration::from_millis(300)), Ok(Some(_))) {
                    job.detach();
                }
            }
        }
        result
    }
    exchange(cli, user_home, profile_home).unwrap_or(PublicAccount::Unknown)
}

fn rpc(stream: UnixStream) -> Option<PublicAccount> {
    const MAX_FRAME: usize = 32 * 1024;
    const MAX_FRAMES: usize = 30;
    let deadline = Instant::now() + Duration::from_secs(7);
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .ok()?;
    let mut io = BufReader::new(stream);
    fn send(io: &mut BufReader<UnixStream>, data: Value) -> Option<()> {
        let mut line = serde_json::to_vec(&data).ok()?;
        line.push(b'\n');
        io.get_mut().write_all(&line).ok()
    }
    send(
        &mut io,
        json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"claude_watch","version":"1"}}}),
    )?;
    let mut id = 1u64;
    for _ in 0..MAX_FRAMES {
        let mut frame = Vec::new();
        loop {
            io.get_ref()
                .set_read_timeout(Some(deadline.checked_duration_since(Instant::now())?))
                .ok()?;
            let available = io.fill_buf().ok()?;
            if available.is_empty() {
                return None;
            }
            let n = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            if frame.len() + n > MAX_FRAME {
                return None;
            }
            frame.extend_from_slice(&available[..n]);
            io.consume(n);
            if frame.ends_with(b"\n") {
                break;
            }
        }
        let message: Value = serde_json::from_slice(&frame).ok()?;
        if message["id"].as_u64() != Some(id) {
            continue;
        }
        let result = message.get("result")?;
        if id == 2 {
            return Some(parse_account(result));
        }
        send(&mut io, json!({"method":"initialized"}))?;
        send(
            &mut io,
            json!({"method":"account/read","id":2,"params":{"refreshToken":false}}),
        )?;
        id = 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn manual_identity_only_accepts_a_public_chatgpt_email() {
        assert_eq!(
            parse_account(&json!({"account": null,"requiresOpenaiAuth": true})),
            PublicAccount::SignedOut
        );
        for account in [
            json!({"type":"apiKey","email":"a@example.invalid"}),
            json!({"type":"chatgpt","email":null}),
            json!({"type":"chatgpt","email":"another\nfield@example.invalid"}),
        ] {
            assert_eq!(
                parse_account(&json!({"account":account})),
                PublicAccount::Unknown
            );
        }
        let signed_in = json!({"account":{"type":"chatgpt","email":"a@example.invalid","workspaceName":"other field"},"userId":"public-id"});
        assert_eq!(
            parse_account(&signed_in),
            PublicAccount::SignedIn {
                email: "a@example.invalid".into(),
                user_id: Some("public-id".into())
            }
        );
    }

    #[test]
    fn manual_identity_provider_reads_only_requested_profile_a_b_a() {
        let root =
            std::env::temp_dir().join(format!("cw-manual-identity-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let cli = root.join("fixture");
        fs::write(
            &cli,
            r#"#!/bin/sh
[ "$*" = "app-server --listen stdio://" ] || exit 1
IFS= read -r init || exit 1
case "$init" in *'"method":"initialize"'*) ;; *) exit 1;; esac
printf '%s\n' '{"id":1,"result":{}}'
IFS= read -r ready || exit 1
case "$ready" in *'"method":"initialized"'*) ;; *) exit 1;; esac
IFS= read -r request || exit 1
case "$request" in *'"method":"account/read"'*) ;; *) exit 1;; esac
case "$request" in *'"refreshToken":false'*) ;; *) exit 1;; esac
IFS= read -r email < "$CODEX_HOME/public-fixture-email" || exit 1
printf '{"id":2,"result":{"account":{"type":"chatgpt","email":"%s"}}}\n' "$email"
"#,
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let a = login::service_home(&store, Slot::A);
        let b = login::service_home(&store, Slot::B);
        for (dir, email) in [(&a, "one@example.invalid"), (&b, "two@example.invalid")] {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join("public-fixture-email"), format!("{email}\n")).unwrap();
        }
        for (dir, email) in [
            (&a, "one@example.invalid"),
            (&b, "two@example.invalid"),
            (&a, "one@example.invalid"),
        ] {
            assert_eq!(
                read_public_account(&cli, &root, dir),
                PublicAccount::SignedIn {
                    email: email.into(),
                    user_id: None
                }
            );
        }
        let rows =
            |slot: &Path, fd: &str| format!("p74\nf{fd}\nau\nn{}/state_5.sqlite\n", slot.display());
        let first = rows(&a, "20");
        assert_eq!(profile_from_open_state(&store, 74, &first), Some(Slot::A));
        assert_eq!(profile_from_open_state(&store, 75, &first), None);
        assert_eq!(profile_from_open_state(&store, 74, &rows(&b, "cwd")), None);
        assert_eq!(
            profile_from_open_state(&store, 74, &(first + &rows(&b, "27"))),
            None
        );
        fs::remove_dir_all(root).unwrap();
    }
}
