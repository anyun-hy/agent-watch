//! Network-only integration with the pinned nono library, plus explicit Keychain
//! Mach service restoration and optional canonicalized sensitive-directory denies
//! for desktop `--no-sandbox` compatibility mode (`B2`).
use nono::CapabilitySet;
use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub const KEYCHAIN_MACH_SERVICES: [&str; 5] = [
    "com.apple.SecurityServer",
    "com.apple.securityd",
    "com.apple.security.keychaind",
    "com.apple.secd",
    "com.apple.security.agent",
];

#[cfg(test)]
pub fn capabilities(gateway: SocketAddr, denied_ports: &[u16]) -> Result<CapabilitySet, String> {
    capabilities_with_denied_paths(gateway, denied_ports, &[])
}

pub fn capabilities_with_denied_paths(
    gateway: SocketAddr,
    denied_ports: &[u16],
    extra_deny_read_write_paths: &[String],
) -> Result<CapabilitySet, String> {
    if gateway.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        || gateway.port() == 0
        || denied_ports.contains(&gateway.port())
    {
        return Err("gateway must be a distinct nonzero 127.0.0.1 endpoint".into());
    }
    // nono emits non-network platform rules after its hardcoded keychain Mach
    // denies and before its ProxyOnly network section. Preserve the application's
    // normal non-network access and explicitly re-allow macOS Keychain Mach
    // services so desktop safeStorage and CLI keychain lookups work cleanly.
    let mut caps = CapabilitySet::new()
        .proxy_only(gateway.port())
        .block_dns()
        .platform_rule("(allow default)")
        .map_err(|error| error.to_string())?;
    for service in KEYCHAIN_MACH_SERVICES {
        caps.add_platform_rule(format!("(allow mach-lookup (global-name \"{service}\"))"))
            .map_err(|error| error.to_string())?;
    }
    // Chromium / Electron applications (e.g. ChatGPT / Codex / Claude) require
    // AF_UNIX bind in system temp folders for ProcessSingleton locking.
    caps.add_platform_rule("(allow system-socket (socket-domain AF_UNIX))")
        .map_err(|error| error.to_string())?;
    caps.add_platform_rule(
        "(allow network-bind (subpath \"/var/folders\") (subpath \"/private/var/folders\") (subpath \"/tmp\") (subpath \"/private/tmp\"))",
    )
    .map_err(|error| error.to_string())?;

    let mut deny_subpaths = BTreeSet::new();
    for raw in extra_deny_read_write_paths {
        if !raw.starts_with('/')
            || raw.len() > 1024
            || raw.chars().any(char::is_control)
            || raw.contains(['"', '\\'])
        {
            return Err("extra_deny_read_write_paths must be clean absolute paths".into());
        }
        let resolved = canonicalize_or_resolve_parent(Path::new(raw));
        let resolved_str = resolved
            .to_str()
            .ok_or_else(|| "canonicalized deny path is not valid UTF-8".to_string())?;
        if !resolved_str.starts_with('/')
            || resolved_str.chars().any(char::is_control)
            || resolved_str.contains(['"', '\\'])
        {
            return Err("canonicalized deny path contains unsupported characters".into());
        }
        deny_subpaths.insert(resolved_str.to_owned());
        deny_subpaths.insert(raw.clone());
    }
    for subpath in deny_subpaths {
        caps.add_platform_rule(format!(
            "(deny file-read* file-write* (subpath \"{subpath}\"))"
        ))
        .map_err(|error| error.to_string())?;
    }

    // Seatbelt only accepts `localhost` or `*` here, not a literal IP. Its
    // localhost grant includes more than the configured 127.0.0.1 spelling.
    // Production therefore requires the system broker to reserve this port
    // on BOTH IPv4 and IPv6 wildcard listeners, with no port sharing. The
    // application is configured for 127.0.0.1; IPv6 is reserved, not forwarded.
    for &port in denied_ports.iter().filter(|port| **port != 0) {
        caps.add_platform_rule(format!(
            "(deny network-outbound (remote tcp \"localhost:{port}\"))"
        ))
        .map_err(|error| error.to_string())?;
    }
    Ok(caps)
}

fn canonicalize_or_resolve_parent(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon;
    }
    let mut suffix = Vec::new();
    let mut cur = path;
    while let Some(name) = cur.file_name() {
        suffix.push(name.to_os_string());
        let Some(parent) = cur.parent() else {
            break;
        };
        if let Ok(canon_parent) = fs::canonicalize(parent) {
            let mut out = canon_parent;
            for part in suffix.into_iter().rev() {
                out.push(part);
            }
            return out;
        }
        cur = parent;
    }
    path.to_path_buf()
}

pub fn apply(capabilities: &CapabilitySet) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        nono::Sandbox::apply_auto(capabilities).map_err(|error| error.to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = capabilities;
        Err("Watch's nono backend requires macOS".into())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream, UdpSocket},
        os::{fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd}, unix::net::{UnixListener, UnixStream}},
        process::Command,
        sync::{atomic::{AtomicBool, Ordering}, Arc},
        time::{Duration, Instant},
    };

    fn exchange(addr: SocketAddr, marker: u8) -> std::io::Result<()> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.set_write_timeout(Some(Duration::from_secs(1)))?;
        stream.write_all(&[marker])?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response)?;
        assert_eq!(response, [b'G', marker], "must reach the genuine gateway");
        Ok(())
    }

    fn raw_listener(address: SocketAddr, reuse_addr: bool, reuse_port: bool) -> std::io::Result<TcpListener> {
        // Component fixture, not system launchd evidence. Keep the two address
        // families distinct, just as the production broker contract requires.
        unsafe {
            let raw = libc::socket(if address.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 }, libc::SOCK_STREAM, libc::IPPROTO_TCP);
            if raw < 0 { return Err(std::io::Error::last_os_error()); }
            let fd = OwnedFd::from_raw_fd(raw);
            let one: libc::c_int = 1;
            let set_option = |level, option| {
                if libc::setsockopt(fd.as_raw_fd(), level, option,
                    (&one as *const libc::c_int).cast(), std::mem::size_of_val(&one) as _) != 0 {
                    Err(std::io::Error::last_os_error())
                } else { Ok(()) }
            };
            if reuse_addr { set_option(libc::SOL_SOCKET, libc::SO_REUSEADDR)?; }
            if reuse_port { set_option(libc::SOL_SOCKET, libc::SO_REUSEPORT)?; }
            assert_eq!(libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC), 0);
            let result = match address {
                SocketAddr::V4(address) => {
                    let mut addr: libc::sockaddr_in = std::mem::zeroed();
                    addr.sin_len = std::mem::size_of_val(&addr) as u8;
                    addr.sin_family = libc::AF_INET as u8;
                    addr.sin_port = address.port().to_be();
                    addr.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
                    libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_in).cast(), std::mem::size_of_val(&addr) as _)
                }
                SocketAddr::V6(address) => {
                    set_option(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)?;
                    let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
                    addr.sin6_len = std::mem::size_of_val(&addr) as u8;
                    addr.sin6_family = libc::AF_INET6 as u8;
                    addr.sin6_port = address.port().to_be();
                    addr.sin6_addr.s6_addr = address.ip().octets();
                    libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_in6).cast(), std::mem::size_of_val(&addr) as _)
                }
            };
            if result != 0 { return Err(std::io::Error::last_os_error()); }
            if libc::listen(fd.as_raw_fd(), 16) != 0 { return Err(std::io::Error::last_os_error()); }
            Ok(TcpListener::from_raw_fd(fd.into_raw_fd()))
        }
    }

    fn assert_wildcard_descriptors_remain_bound(port: u16) {
        // This checks descriptor lifetime only. On macOS a same-UID wildcard
        // holder does NOT prevent a more-specific bind. System protection must
        // establish root-created sockets and reject SO_REUSESHAREUID; it needs
        // a separately authorized cross-UID acceptance test.
        for address in [format!("0.0.0.0:{port}"), format!("[::]:{port}")] {
            match TcpListener::bind(&address) {
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{address}: {error}"),
                Ok(_) => panic!("another process could take the reserved endpoint: {address}"),
            }
            for reuse_port in [false, true] {
                match raw_listener(address.parse().unwrap(), true, reuse_port) {
                    Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "contender reuseaddr=1 reuseport={reuse_port}, {address}: {error}"),
                    Ok(_) => panic!("contender could listen: reuseaddr=1 reuseport={reuse_port}, {address}"),
                }
            }
        }
    }

    #[test]
    fn same_uid_wildcard_listener_is_not_system_endpoint_proof() {
        let owner = raw_listener("0.0.0.0:0".parse().unwrap(), false, false).unwrap();
        let port = owner.local_addr().unwrap().port();
        let _specific = TcpListener::bind(format!("127.0.0.1:{port}")).expect("macOS permits a same-UID more-specific listener; do not use this fixture as root ownership evidence");
        println!("same_uid_specific_bind=succeeds; system_cross_uid_protection=not_verified");
    }

    #[test]
    fn unprivileged_specific_reserved_port_bind_is_denied_before_gateway_start() {
        assert_ne!(unsafe { libc::geteuid() }, 0, "this is specifically an ordinary-user control");
        let mut available = None;
        for port in [1021, 1022, 1023] {
            if let Ok(ipv4) = raw_listener(format!("0.0.0.0:{port}").parse().unwrap(), true, false) {
                if let Ok(ipv6) = raw_listener(format!("[::]:{port}").parse().unwrap(), true, false) {
                    drop((ipv4, ipv6));
                    available = Some(port);
                    break;
                }
            }
        }
        let port = available.expect("one of the isolated reserved test ports must be available");
        let mut specific = vec![format!("127.0.0.1:{port}"), format!("[::1]:{port}")];
        let host = Command::new("/usr/sbin/ipconfig").args(["getifaddr", "en0"]).output().ok()
            .filter(|result| result.status.success())
            .and_then(|result| String::from_utf8(result.stdout).ok())
            .and_then(|raw| raw.trim().parse::<std::net::Ipv4Addr>().ok());
        if let Some(ip) = host { specific.push(SocketAddr::new(ip.into(), port).to_string()); }
        for address in &specific {
            for reuse_port in [false, true] {
                match raw_listener(address.parse().unwrap(), true, reuse_port) {
                    Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied,
                        "ordinary user must not prebind a specific low-port address (reuseport={reuse_port}): {error}"),
                    Ok(_) => panic!("ordinary user acquired a specific reserved-port listener"),
                }
            }
        }
        println!("reserved_specific_prebind=permission_denied; en0_control={}", host.is_some());
        let _ipv4 = raw_listener(format!("0.0.0.0:{port}").parse().unwrap(), true, false).unwrap();
        let _ipv6 = raw_listener(format!("[::]:{port}").parse().unwrap(), true, false).unwrap();
        assert_wildcard_descriptors_remain_bound(port);
        println!("reserved_wildcard_rebind=address_in_use; root_launchd_cross_uid=not_run");
    }

    #[test]
    fn gateway_capabilities_reject_addresses_outside_the_protected_listener() {
        for addr in ["[::1]:18789", "127.0.0.2:18789", "[::ffff:127.0.0.1]:18789", "0.0.0.0:18789", "127.0.0.1:0"] {
            assert!(capabilities(addr.parse().unwrap(), &[]).is_err(), "{addr}");
        }
        assert!(capabilities("127.0.0.1:18789".parse().unwrap(), &[18789]).is_err());
        assert!(capabilities("127.0.0.1:18789".parse().unwrap(), &[7890]).is_ok());
    }

    #[test]
    fn pinned_nono_apply_enforces_network_only_gateway_policy_in_child() {
        if std::env::var("CW_NONO_POLICY_CHILD").as_deref() == Ok("1") {
            let gw: SocketAddr = std::env::var("CW_NONO_GATEWAY").unwrap().parse().unwrap();
            let direct: SocketAddr = std::env::var("CW_NONO_DIRECT").unwrap().parse().unwrap();
            let vpn: SocketAddr = std::env::var("CW_NONO_VPN").unwrap().parse().unwrap();
            let v6: SocketAddr = std::env::var("CW_NONO_IPV6_ALIAS").unwrap().parse().unwrap();
            let mapped: SocketAddr = format!("[::ffff:127.0.0.1]:{}", gw.port()).parse().unwrap();
            let file = std::env::var("CW_NONO_FILE").unwrap();
            let unix = std::env::var("CW_NONO_UNIX").unwrap();
            apply(&capabilities(gw, &[vpn.port()]).unwrap()).unwrap();
            fs::write(file, b"normal file access retained").unwrap();
            exchange(gw, b'Q').unwrap();
            assert!(TcpStream::connect_timeout(&v6, Duration::from_millis(200)).is_ok(), "Seatbelt localhost includes IPv6; reservation is therefore mandatory");
            println!("same_port_ipv6=reachable_reserved_listener_no_forwarder");
            // A mapped spelling may be normalized by the kernel to the exact
            // protected IPv4 socket. If permitted it must reach THAT socket,
            // never a separately bindable IPv6 listener.
            match exchange(mapped, b'M') {
                Ok(()) => println!("mapped_exact_ipv4=reached_genuine_gateway"),
                Err(error) => println!("mapped_exact_ipv4=blocked:{error}"),
            }
            if std::env::var("CW_NONO_IPV4_ALIAS_REACHABLE").as_deref() == Ok("1") {
                let alias: SocketAddr = format!("127.0.0.2:{}", gw.port()).parse().unwrap();
                match exchange(alias, b'A') {
                    Ok(()) => println!("same_port_ipv4_alias=reached_genuine_gateway"),
                    Err(error) => println!("same_port_ipv4_alias=blocked:{error}"),
                }
                let mapped_alias: SocketAddr = format!("[::ffff:127.0.0.2]:{}", gw.port()).parse().unwrap();
                match exchange(mapped_alias, b'B') {
                    Ok(()) => println!("mapped_ipv4_alias=reached_genuine_gateway"),
                    Err(error) => println!("mapped_ipv4_alias=blocked:{error}"),
                }
            }
            if let Ok(host_addr) = std::env::var("CW_NONO_HOST_ADDR") {
                match exchange(host_addr.parse().unwrap(), b'H') {
                    Ok(()) => println!("same_port_host_interface=reached_genuine_gateway"),
                    Err(error) => println!("same_port_host_interface=blocked:{error}"),
                }
            }
            assert!(TcpStream::connect_timeout(&direct, Duration::from_millis(200)).is_err());
            assert!(TcpStream::connect_timeout(&vpn, Duration::from_millis(200)).is_err());
            assert!(UnixStream::connect(unix).is_err());
            assert!(UdpSocket::bind("127.0.0.1:0")
                .and_then(|socket| socket.send_to(b"Q", direct))
                .is_err());
            return;
        }
        let scratch = std::env::temp_dir().join(format!("cw-nono-policy-{}", std::process::id()));
        fs::create_dir_all(&scratch).unwrap();
        let gateway_owner = raw_listener("0.0.0.0:0".parse().unwrap(), false, false).unwrap();
        let direct = TcpListener::bind("127.0.0.1:0").unwrap();
        let vpn = TcpListener::bind("127.0.0.1:0").unwrap();
        let unix_path = scratch.join("relay.sock");
        let _unix = UnixListener::bind(&unix_path).unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{}", gateway_owner.local_addr().unwrap().port()).parse().unwrap();
        let _v6_owner = raw_listener(format!("[::]:{}", addr.port()).parse().unwrap(), false, false).unwrap();
        let v6_addr: SocketAddr = format!("[::1]:{}", addr.port()).parse().unwrap();
        // Positive controls prove the destinations exist for ordinary software.
        assert!(TcpStream::connect(direct.local_addr().unwrap()).is_ok());
        assert!(TcpStream::connect(vpn.local_addr().unwrap()).is_ok());
        assert!(UnixStream::connect(&unix_path).is_ok());
        assert!(TcpStream::connect(v6_addr).is_ok());
        assert_wildcard_descriptors_remain_bound(addr.port());
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        gateway_owner.set_nonblocking(true).unwrap();
        let gateway = gateway_owner.try_clone().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !server_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                match gateway.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                        let mut byte = [0u8; 1];
                        stream.read_exact(&mut byte).unwrap();
                        stream.write_all(&[b'G', byte[0]]).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                    Err(error) => panic!("gateway accept failed: {error}"),
                }
            }
        });
        exchange(addr, b'C').unwrap();
        exchange(format!("[::ffff:127.0.0.1]:{}", addr.port()).parse().unwrap(), b'C').unwrap();
        let alias_reachable = exchange(format!("127.0.0.2:{}", addr.port()).parse().unwrap(), b'C').is_ok();
        if !alias_reachable { println!("same_port_ipv4_alias=not_run:no_reachable_host_alias"); }
        let host_addr = Command::new("/usr/sbin/ipconfig").args(["getifaddr", "en0"]).output().ok()
            .filter(|result| result.status.success())
            .and_then(|result| String::from_utf8(result.stdout).ok())
            .and_then(|raw| raw.trim().parse::<std::net::Ipv4Addr>().ok())
            .map(|ip| SocketAddr::new(ip.into(), addr.port()));
        if let Some(host) = host_addr { exchange(host, b'C').expect("positive control for the host interface"); }
        else { println!("same_port_host_interface=not_run:no_en0_ipv4"); }
        let test_thread = std::thread::current();
        let test_name = test_thread.name().expect("test harness thread name");
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", test_name, "--nocapture"])
            .env("CW_NONO_POLICY_CHILD", "1").env("CW_NONO_GATEWAY", addr.to_string())
            .env("CW_NONO_DIRECT", direct.local_addr().unwrap().to_string())
            .env("CW_NONO_VPN", vpn.local_addr().unwrap().to_string())
            .env("CW_NONO_IPV6_ALIAS", v6_addr.to_string())
            .env("CW_NONO_IPV4_ALIAS_REACHABLE", if alias_reachable { "1" } else { "0" })
            .env("CW_NONO_FILE", scratch.join("file"))
            .env("CW_NONO_UNIX", &unix_path);
        if let Some(host) = host_addr { child.env("CW_NONO_HOST_ADDR", host.to_string()); }
        else { child.env_remove("CW_NONO_HOST_ADDR"); }
        let output = child.output().unwrap();
        stop.store(true, Ordering::Release);
        server.join().unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("same_port_ipv6=reachable_reserved_listener_no_forwarder"), "sandbox child assertions must actually execute");
        // A worker drops its own listening FD; the independent owner still
        // prevents takeover. This is FD lifetime evidence, not launchd proof.
        assert_wildcard_descriptors_remain_bound(addr.port());
        println!("listener_worker_exit=wildcard_descriptors_still_bound; cross_uid_takeover=not_run");
        // Ordinary software remains able to reach all non-gateway controls.
        assert!(TcpStream::connect(v6_addr).is_ok());
        assert!(TcpStream::connect(direct.local_addr().unwrap()).is_ok());
        assert!(TcpStream::connect(vpn.local_addr().unwrap()).is_ok());
        assert!(UnixStream::connect(&unix_path).is_ok());
        fs::remove_dir_all(&scratch).unwrap();
    }

    #[test]
    fn nono_apply_allows_keychain_and_enforces_canonical_denied_paths_in_child() {
        if std::env::var("CW_NONO_B2_CHILD").as_deref() == Ok("1") {
            let gw: SocketAddr = std::env::var("CW_NONO_B2_GW").unwrap().parse().unwrap();
            let denied_dir = PathBuf::from(std::env::var("CW_NONO_B2_DENIED").unwrap());
            let allowed_file = PathBuf::from(std::env::var("CW_NONO_B2_ALLOWED").unwrap());
            let secret_file = denied_dir.join("secret.txt");
            let caps = capabilities_with_denied_paths(
                gw,
                &[],
                &[denied_dir.to_string_lossy().into_owned()],
            )
            .unwrap();
            apply(&caps).unwrap();

            // 1. Normal file access outside denied paths remains allowed.
            fs::write(&allowed_file, b"allowed").unwrap();
            assert_eq!(fs::read(&allowed_file).unwrap(), b"allowed");

            // 2. Canonicalized sensitive directory read & write must be denied by Seatbelt.
            let read_err = fs::read(&secret_file).unwrap_err();
            assert_eq!(
                read_err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected PermissionDenied reading denied path, got: {read_err:?}"
            );
            let write_err = fs::write(denied_dir.join("new.txt"), b"blocked").unwrap_err();
            assert_eq!(
                write_err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected PermissionDenied writing denied path, got: {write_err:?}"
            );

            // 3. Keychain Mach services are explicitly allowed (`security list-keychains` succeeds).
            let sec = Command::new("/usr/bin/security")
                .arg("list-keychains")
                .output()
                .expect("run /usr/bin/security list-keychains");
            assert!(
                sec.status.success(),
                "security list-keychains failed under nono Seatbelt: stderr={}",
                String::from_utf8_lossy(&sec.stderr)
            );
            println!("b2_keychain_and_canonical_deny=verified");
            return;
        }

        // Use `/tmp/...` (which is a symlink to `/private/tmp/...` on macOS) to prove
        // that `canonicalize_or_resolve_parent` resolves `/tmp` -> `/private/tmp` so
        // Seatbelt subpath matching cannot be bypassed by symlinked parent directories.
        let scratch = PathBuf::from("/tmp").join(format!("cw-nono-b2-{}", std::process::id()));
        let denied_dir = scratch.join("sensitive-dir");
        fs::create_dir_all(&denied_dir).unwrap();
        fs::write(denied_dir.join("secret.txt"), b"top-secret").unwrap();
        let allowed_file = scratch.join("allowed.txt");

        let test_thread = std::thread::current();
        let test_name = test_thread.name().expect("test harness thread name");
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env("CW_NONO_B2_CHILD", "1")
            .env("CW_NONO_B2_GW", "127.0.0.1:18799")
            .env("CW_NONO_B2_DENIED", &denied_dir)
            .env("CW_NONO_B2_ALLOWED", &allowed_file)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        fs::remove_dir_all(&scratch).unwrap();
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains("b2_keychain_and_canonical_deny=verified"));
    }
}
