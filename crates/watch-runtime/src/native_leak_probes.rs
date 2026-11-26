//! Sub-second pure-Rust DNS recursive-egress and ICE (`host` + `srflx`) collectors.
//!
//! Replaces the retired `watch-leak-worker` AppKit/WKWebView helper while producing
//! structured probe payloads validated by `claude_watch_core::receipts`.
//! Policy decisions remain exclusively in `watch-core`.

use crate::{
    commands::{ReadCommand, ReadRunner},
    network_client::{NetworkClient, Transport},
};
use claude_watch_core::{network::public_unicast, stun};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DNS_UDP_TIMEOUT: Duration = Duration::from_millis(1200);
const DNS_TCP_TIMEOUT: Duration = Duration::from_millis(1800);
const STUN_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1200);
const STUN_TOTAL_BUDGET: Duration = Duration::from_millis(2600);
const STUN_QUORUM_TAIL: Duration = Duration::from_millis(80);
const HTTP_TRACE_TIMEOUT: Duration = Duration::from_millis(3500);
const GEOIP_TIMEOUT: Duration = Duration::from_millis(2200);
const GEO_CACHE_TTL_SECS: f64 = 1800.0;

const STUN_SERVERS: [(&str, u16); 3] = [
    ("stun.cloudflare.com", 3478),
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
];

#[derive(Clone, Debug)]
struct GeoMeta {
    country_code: String,
    region: String,
    city: String,
    isp: String,
    cached_at: f64,
}

fn geo_cache() -> &'static Mutex<BTreeMap<String, GeoMeta>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, GeoMeta>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn wallclock() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |v| v.as_secs_f64())
}

fn canonical_public_ip(raw: &str) -> Option<(String, u8)> {
    if raw.contains('%') {
        return None;
    }
    let parsed: IpAddr = raw.trim().parse().ok()?;
    let normalized = match parsed {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => IpAddr::V4(v6.to_ipv4_mapped().unwrap()),
        other => other,
    };
    let canonical = public_unicast(&normalized.to_string())?;
    let family = if canonical.parse::<Ipv4Addr>().is_ok() { 4 } else { 6 };
    Some((canonical, family))
}

fn valid_country_code(raw: &str) -> Option<String> {
    let code = raw.trim().to_ascii_uppercase();
    (code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()) && code != "XX" && code != "T1")
        .then_some(code)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsEchoSource {
    Akamai,
    Google,
}

impl DnsEchoSource {
    fn qname(self) -> &'static str {
        match self {
            Self::Akamai => "whoami.ds.akahelp.net",
            Self::Google => "o-o.myaddr.l.google.com",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Akamai => "Akamai 权威 DNS (whoami.ds.akahelp.net)",
            Self::Google => "Google 权威 DNS (o-o.myaddr.l.google.com)",
        }
    }
}

/// Encode a minimal RFC 1035 standard query (`RD = 1`, `QTYPE = TXT (16)`, `QCLASS = IN (1)`).
pub fn encode_dns_txt_query(qname: &str, txid: u16) -> Option<Vec<u8>> {
    let trimmed = qname.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&txid.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&16u16.to_be_bytes()); // QTYPE = TXT
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Some(buf)
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize, &'static str> {
    let mut jumps = 0usize;
    loop {
        let Some(&len) = packet.get(offset) else {
            return Err("truncated_name");
        };
        if len == 0 {
            return Ok(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err("truncated_pointer");
            }
            return Ok(offset + 2);
        }
        if (len & 0xC0) != 0 {
            return Err("invalid_label_flags");
        }
        offset += 1 + (len as usize);
        if offset > packet.len() {
            return Err("label_out_of_bounds");
        }
        jumps += 1;
        if jumps > 64 {
            return Err("name_too_long");
        }
    }
}

/// Decode TXT strings per answer RR from an RFC 1035 response packet.
pub fn decode_dns_txt_answers(packet: &[u8], expected_txid: u16) -> Result<Vec<Vec<String>>, &'static str> {
    if packet.len() < 12 {
        return Err("short_header");
    }
    let txid = u16::from_be_bytes([packet[0], packet[1]]);
    if txid != expected_txid {
        return Err("txid_mismatch");
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        return Err("not_response");
    }
    if (flags & 0x0200) != 0 {
        return Err("truncated");
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err("rcode_error");
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if qdcount > 8 || ancount > 64 {
        return Err("excessive_counts");
    }
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(packet, offset)?;
        if offset + 4 > packet.len() {
            return Err("truncated_question");
        }
        offset += 4;
    }
    let mut records = Vec::new();
    for _ in 0..ancount {
        offset = skip_dns_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err("truncated_rr_header");
        }
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > packet.len() {
            return Err("truncated_rdata");
        }
        if rtype == 16 {
            let rdata = &packet[offset..offset + rdlength];
            let mut pos = 0usize;
            let mut chunks = Vec::new();
            while pos < rdata.len() {
                let slen = rdata[pos] as usize;
                pos += 1;
                if pos + slen > rdata.len() {
                    return Err("truncated_txt_chunk");
                }
                if let Ok(s) = std::str::from_utf8(&rdata[pos..pos + slen]) {
                    chunks.push(s.to_owned());
                }
                pos += slen;
            }
            if !chunks.is_empty() {
                records.push(chunks);
            }
        }
        offset += rdlength;
    }
    Ok(records)
}

pub fn extract_echo_resolvers(source: DnsEchoSource, records: &[Vec<String>]) -> Vec<(String, u8)> {
    let mut found = BTreeMap::new();
    for chunks in records {
        match source {
            DnsEchoSource::Akamai => {
                if chunks.len() >= 2 && chunks[0].trim().eq_ignore_ascii_case("ns") {
                    if let Some((ip, fam)) = canonical_public_ip(&chunks[1]) {
                        found.insert(ip.clone(), (ip, fam));
                    }
                } else if chunks.len() == 1 {
                    let parts: Vec<_> = chunks[0].split_whitespace().collect();
                    if parts.len() >= 2 && parts[0].trim_matches('"').eq_ignore_ascii_case("ns") {
                        if let Some((ip, fam)) = canonical_public_ip(parts[1].trim_matches('"')) {
                            found.insert(ip.clone(), (ip, fam));
                        }
                    }
                }
            }
            DnsEchoSource::Google => {
                for chunk in chunks {
                    let trimmed = chunk.trim().trim_matches('"');
                    if trimmed.to_ascii_lowercase().starts_with("edns0-client-subnet") {
                        continue;
                    }
                    if let Some((ip, fam)) = canonical_public_ip(trimmed) {
                        found.insert(ip.clone(), (ip, fam));
                    }
                }
            }
        }
    }
    found.into_values().collect()
}

fn query_dns_txt_udp_or_tcp(server: SocketAddr, qname: &str) -> Result<Vec<Vec<String>>, &'static str> {
    let mut tx_bytes = [0u8; 2];
    getrandom::fill(&mut tx_bytes).map_err(|_| "rng_failed")?;
    let txid = u16::from_be_bytes(tx_bytes);
    let query = encode_dns_txt_query(qname, txid).ok_or("invalid_qname")?;

    let bind_addr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    if let Ok(sock) = UdpSocket::bind(bind_addr) {
        let _ = sock.set_write_timeout(Some(DNS_UDP_TIMEOUT));
        let _ = sock.set_read_timeout(Some(DNS_UDP_TIMEOUT));
        if sock.send_to(&query, server).is_ok() {
            let mut buf = [0u8; 2048];
            if let Ok((n, from)) = sock.recv_from(&mut buf) {
                if from.ip() == server.ip() {
                    match decode_dns_txt_answers(&buf[..n], txid) {
                        Ok(records) if !records.is_empty() => return Ok(records),
                        Err("truncated") => {} // fall through to TCP
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
            }
        }
    }

    // TCP DNS fallback on port 53 (handles truncated answers or UDP-filtered paths)
    let mut stream = TcpStream::connect_timeout(&server, DNS_TCP_TIMEOUT).map_err(|_| "tcp_connect_failed")?;
    let _ = stream.set_write_timeout(Some(DNS_TCP_TIMEOUT));
    let _ = stream.set_read_timeout(Some(DNS_TCP_TIMEOUT));
    let len_prefix = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).map_err(|_| "tcp_write_failed")?;
    stream.write_all(&query).map_err(|_| "tcp_write_failed")?;
    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf).map_err(|_| "tcp_read_failed")?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    if resp_len == 0 || resp_len > 16384 {
        return Err("tcp_oversize");
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(|_| "tcp_read_failed")?;
    decode_dns_txt_answers(&resp, txid)
}

pub fn parse_nameservers(scutil_dns: &str, resolv_conf: &str) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push_ip = |raw: &str| {
        let clean = raw.split('%').next().unwrap_or(raw).trim();
        if let Ok(ip) = clean.parse::<IpAddr>() {
            if !ip.is_unspecified() && seen.insert(ip) && addrs.len() < 4 {
                addrs.push(SocketAddr::new(ip, 53));
            }
        }
    };
    for line in scutil_dns.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("nameserver[") {
            if let Some((_, ip_part)) = rest.split_once(':') {
                push_ip(ip_part);
            }
        }
    }
    for line in resolv_conf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(ip_part) = parts.next() {
                push_ip(ip_part);
            }
        }
    }
    if addrs.is_empty() {
        addrs.push(SocketAddr::from(([1, 1, 1, 1], 53)));
        addrs.push(SocketAddr::from(([8, 8, 8, 8], 53)));
    }
    addrs
}

fn discover_system_nameservers<R: ReadRunner>(runner: &R) -> Vec<SocketAddr> {
    let scutil = runner
        .run(ReadCommand::ScutilDns, &[], Duration::from_millis(800), 64 * 1024)
        .ok()
        .filter(|o| o.status == 0)
        .and_then(|o| o.text().ok().map(str::to_owned))
        .unwrap_or_default();
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    parse_nameservers(&scutil, &resolv)
}

struct TraceRef {
    ip: String,
    family: u8,
    country: Option<String>,
    source: &'static str,
}

fn fetch_http_trace<T: Transport>(network: &NetworkClient<T>) -> Result<TraceRef, (String, String)> {
    let client = network
        .clone()
        .with_timeout(HTTP_TRACE_TIMEOUT)
        .with_connect_timeout(Duration::from_millis(2000));
    for (url, label) in [
        ("https://www.cloudflare.com/cdn-cgi/trace", "Cloudflare Trace · 本机代理 HTTP"),
        ("https://1.1.1.1/cdn-cgi/trace", "1.1.1.1 Trace · 本机代理 HTTP"),
    ] {
        let receipt = client.trace(url);
        if receipt.status != "complete" || receipt.raw.len() > 32 * 1024 {
            continue;
        }
        let mut ip_found = None;
        let mut loc_found = None;
        for line in receipt.raw.lines() {
            if let Some(v) = line.strip_prefix("ip=") {
                ip_found = canonical_public_ip(v);
            } else if let Some(v) = line.strip_prefix("loc=") {
                loc_found = valid_country_code(v);
            }
        }
        if let Some((ip, family)) = ip_found {
            return Ok(TraceRef {
                ip,
                family,
                country: loc_found,
                source: label,
            });
        }
    }
    Err(("timeout".into(), "未能通过代理取得同轮 HTTP 出口参考".into()))
}

fn lookup_geo_single<T: Transport>(
    network: &NetworkClient<T>,
    ip: &str,
    fallback_country: Option<&str>,
    now: f64,
) -> Option<GeoMeta> {
    if let Ok(cache) = geo_cache().lock() {
        if let Some(hit) = cache.get(ip) {
            if (0.0..=GEO_CACHE_TTL_SECS).contains(&(now - hit.cached_at)) {
                return Some(hit.clone());
            }
        }
    }
    let client = network
        .clone()
        .with_timeout(GEOIP_TIMEOUT)
        .with_connect_timeout(Duration::from_millis(1500));

    // Primary: Net.Coffee geoip endpoint via proxy
    let receipt = client.metadata("geoip", ip);
    if receipt.status == "complete" && receipt.http_status == Some(200) && receipt.query == ip {
        if let Some(data) = receipt.data.as_ref().filter(|d| d.is_object()) {
            let code = ["countryCode", "country_code", "country"]
                .iter()
                .filter_map(|k| data.get(*k).and_then(Value::as_str))
                .find_map(valid_country_code)
                .or_else(|| fallback_country.and_then(valid_country_code));
            if let Some(country_code) = code {
                let str_field = |keys: &[&str]| -> String {
                    keys.iter()
                        .filter_map(|k| data.get(*k).and_then(Value::as_str))
                        .map(str::trim)
                        .find(|s| !s.is_empty())
                        .unwrap_or("")
                        .chars()
                        .take(120)
                        .collect()
                };
                let meta = GeoMeta {
                    country_code,
                    region: str_field(&["region", "regionName", "region_name"]),
                    city: str_field(&["city", "city_name"]),
                    isp: str_field(&["isp", "asOrganization", "org", "isp_name"]),
                    cached_at: now,
                };
                if let Ok(mut cache) = geo_cache().lock() {
                    if cache.len() >= 256 {
                        cache.clear();
                    }
                    cache.insert(ip.to_owned(), meta.clone());
                }
                return Some(meta);
            }
        }
    }

    // Secondary fallback: IPLeak JSON attribution via proxy
    let url = format!("https://ipleak.net/json/{ip}");
    let fallback = client.trace(&url);
    if fallback.status == "complete" && fallback.raw.len() <= 32 * 1024 {
        if let Ok(data) = serde_json::from_str::<Value>(&fallback.raw) {
            if data.get("ip").and_then(Value::as_str).is_some_and(|v| v.eq_ignore_ascii_case(ip)) {
                if let Some(country_code) = data
                    .get("country_code")
                    .and_then(Value::as_str)
                    .and_then(valid_country_code)
                    .or_else(|| fallback_country.and_then(valid_country_code))
                {
                    let str_field = |k: &str| -> String {
                        data.get(k)
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .trim()
                            .chars()
                            .take(120)
                            .collect()
                    };
                    let meta = GeoMeta {
                        country_code,
                        region: str_field("region_name"),
                        city: str_field("city_name"),
                        isp: str_field("isp_name"),
                        cached_at: now,
                    };
                    if let Ok(mut cache) = geo_cache().lock() {
                        if cache.len() >= 256 {
                            cache.clear();
                        }
                        cache.insert(ip.to_owned(), meta.clone());
                    }
                    return Some(meta);
                }
            }
        }
    }

    // Same-IP trace country fallback (guaranteed accurate for the HTTP egress IP itself)
    fallback_country.and_then(valid_country_code).map(|country_code| GeoMeta {
        country_code,
        region: String::new(),
        city: String::new(),
        isp: String::new(),
        cached_at: now,
    })
}

fn enrich_public_ips<T: Transport>(
    network: &NetworkClient<T>,
    ips: &BTreeSet<String>,
    trace_ref: Option<&TraceRef>,
    now: f64,
) -> BTreeMap<String, GeoMeta> {
    let mut results = BTreeMap::new();
    let targets: Vec<String> = ips.iter().take(16).cloned().collect();
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for ip in &targets {
            let trace_cc = trace_ref
                .filter(|t| t.ip == *ip)
                .and_then(|t| t.country.as_deref());
            handles.push((
                ip.clone(),
                scope.spawn(move || lookup_geo_single(network, ip, trace_cc, now)),
            ));
        }
        for (ip, handle) in handles {
            if let Ok(Some(meta)) = handle.join() {
                results.insert(ip, meta);
            }
        }
    });
    results
}

/// Collect a complete native DNS recursive-egress probe payload in ~150-350ms.
pub fn collect_dns<R: ReadRunner, T: Transport>(runner: &R, network: &NetworkClient<T>) -> Value {
    let started = wallclock();
    let nameservers = discover_system_nameservers(runner);

    let (trace_res, echo_results) = thread::scope(|scope| {
        let trace_job = scope.spawn(|| fetch_http_trace(network));
        let mut dns_jobs = Vec::new();
        for &server in nameservers.iter().take(2) {
            for source in [DnsEchoSource::Akamai, DnsEchoSource::Google] {
                dns_jobs.push((
                    source,
                    scope.spawn(move || {
                        query_dns_txt_udp_or_tcp(server, source.qname())
                            .map(|records| extract_echo_resolvers(source, &records))
                    }),
                ));
            }
        }
        let mut resolvers: BTreeMap<String, (u8, &'static str, u64)> = BTreeMap::new();
        for (source, job) in dns_jobs {
            if let Ok(Ok(found)) = job.join() {
                for (ip, fam) in found {
                    let entry = resolvers.entry(ip).or_insert((fam, source.label(), 0));
                    entry.2 += 1;
                }
            }
        }
        (trace_job.join().unwrap_or_else(|_| Err(("error".into(), "HTTP 线程异常".into()))), resolvers)
    });

    let mut resolvers = echo_results;
    // Fallback via `dig` CLI command only if direct sockets returned nothing (e.g. restricted sandbox test)
    if resolvers.is_empty() {
        if let Ok(out) = runner.run(
            ReadCommand::DnsProbeWhoamiTxt,
            &[],
            Duration::from_millis(2000),
            32 * 1024,
        ) {
            if out.status == 0 {
                if let Ok(text) = out.text() {
                    let mut dummy_errs = Vec::new();
                    for row in crate::dns_probe::parse_dns_ns(text, &mut dummy_errs) {
                        if let Some(addr) = row["address"].as_str() {
                            if let Some((ip, fam)) = canonical_public_ip(addr) {
                                resolvers.insert(ip, (fam, "Akamai 权威 DNS (dig TXT)", 1));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut errors = Vec::new();
    let mut public_ips = BTreeSet::new();
    for ip in resolvers.keys() {
        public_ips.insert(ip.clone());
    }
    if let Ok(ref tr) = trace_res {
        public_ips.insert(tr.ip.clone());
    }

    let now = wallclock();
    let geo_map = enrich_public_ips(network, &public_ips, trace_res.as_ref().ok(), now);

    let mut observations = Vec::new();
    let mut dns_servers_json = serde_json::Map::new();
    let mut geoip_json = Vec::new();

    if resolvers.is_empty() {
        errors.push(json!({
            "stage": "dns",
            "code": "no_resolver",
            "message": "未能从权威 DNS 回显服务取得递归出口 IP"
        }));
    } else {
        for (ip, (fam, source_label, count)) in &resolvers {
            dns_servers_json.insert(ip.clone(), json!(*count));
            let mut obs = json!({
                "address": ip,
                "kind": "resolver",
                "source": source_label,
                "family": fam,
            });
            if let Some(meta) = geo_map.get(ip) {
                obs["country"] = json!(meta.country_code);
                if !meta.region.is_empty() {
                    obs["region"] = json!(meta.region);
                }
                if !meta.city.is_empty() {
                    obs["city"] = json!(meta.city);
                }
                if !meta.isp.is_empty() {
                    obs["isp"] = json!(meta.isp);
                }
                geoip_json.push(json!({
                    "ip": ip,
                    "country_code": meta.country_code,
                    "region": meta.region,
                    "city": meta.city,
                    "isp": meta.isp,
                }));
            } else {
                errors.push(json!({
                    "stage": "geoip",
                    "code": "country_missing",
                    "message": format!("未能取得递归出口 {ip} 的国家归属")
                }));
            }
            observations.push(obs);
        }
    }

    let http_evidence = match &trace_res {
        Ok(tr) => {
            let cc = geo_map
                .get(&tr.ip)
                .map(|m| m.country_code.clone())
                .or_else(|| tr.country.clone())
                .unwrap_or_default();
            let mut obs = json!({
                "address": tr.ip,
                "kind": "http",
                "source": tr.source,
                "family": tr.family,
            });
            if !cc.is_empty() {
                obs["country"] = json!(cc);
            } else {
                errors.push(json!({
                    "stage": "http",
                    "code": "country_missing",
                    "message": "HTTP 出口未取得国家归属"
                }));
            }
            if let Some(meta) = geo_map.get(&tr.ip) {
                if !meta.region.is_empty() {
                    obs["region"] = json!(meta.region);
                }
                if !meta.city.is_empty() {
                    obs["city"] = json!(meta.city);
                }
                if !meta.isp.is_empty() {
                    obs["isp"] = json!(meta.isp);
                }
            }
            observations.push(obs);
            json!({
                "address": tr.ip,
                "country": cc,
            })
        }
        Err((code, msg)) => {
            errors.push(json!({
                "stage": "http",
                "code": code,
                "message": msg,
            }));
            Value::Null
        }
    };

    let finished = wallclock();
    let status = if errors.is_empty() && !resolvers.is_empty() && trace_res.is_ok() {
        "complete"
    } else if resolvers.is_empty() && trace_res.is_err() {
        "timeout"
    } else {
        "partial"
    };

    let external_evidence = json!({
        "provider": "native",
        "dns_servers": dns_servers_json,
        "http": http_evidence,
        "geoip": geoip_json,
    });

    json!({
        "provider": "native",
        "kind": "dns",
        "status": status,
        "startedAt": started,
        "finishedAt": finished,
        "scope": "原生多源权威 DNS 递归出口核对（Akamai / Google）",
        "observations": observations,
        "errors": errors,
        "contextChanged": false,
        "details": [
            "直接向系统生效 DNS 解析器并发发起 Akamai 与 Google 权威 TXT 递归回显查询。",
            "同轮对照经本机代理的公网 HTTP 出口国家归属，无需加载外部检测网页。"
        ],
        "externalJSON": external_evidence.to_string(),
    })
}

fn stun_single_attempt(target: SocketAddr, deadline: Instant) -> Option<(String, u8)> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    let bind_addr = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind_addr).ok()?;
    let timeout = remaining.min(STUN_ATTEMPT_TIMEOUT);
    sock.set_write_timeout(Some(timeout)).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    let mut tx = [0u8; 12];
    getrandom::fill(&mut tx).ok()?;
    sock.send_to(&stun::binding_request(tx), target).ok()?;
    let mut buf = [0u8; 2048];
    let (n, sender) = sock.recv_from(&mut buf).ok()?;
    if sender != target {
        return None;
    }
    let decoded = stun::decode(&buf[..n], &tx).ok()?;
    canonical_public_ip(&decoded)
}

/// Fast concurrent dual-stack UDP STUN collector with Quorum early return (`>= 2` servers + `80ms` tail).
pub fn collect_stun_srflx_quorum(servers: &[(&str, u16)], budget: Duration) -> Vec<(String, u8, String)> {
    let deadline = Instant::now() + budget;
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<(usize, String, u8, String)>();

    for (idx, &(host, port)) in servers.iter().enumerate() {
        let tx = tx.clone();
        let cancel = Arc::clone(&cancel);
        let host_owned = host.to_owned();
        thread::spawn(move || {
            let Ok(resolved) = (host_owned.as_str(), port).to_socket_addrs() else {
                return;
            };
            let mut v4_target = None;
            let mut v6_target = None;
            for addr in resolved {
                if addr.is_ipv4() && v4_target.is_none() {
                    v4_target = Some(addr);
                } else if addr.is_ipv6() && v6_target.is_none() {
                    v6_target = Some(addr);
                }
            }
            for target in [v4_target, v6_target].into_iter().flatten() {
                for attempt in 0..2 {
                    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                        return;
                    }
                    if let Some((ip, fam)) = stun_single_attempt(target, deadline) {
                        let source_label = format!("{host_owned}:{port}");
                        let _ = tx.send((idx, ip, fam, source_label));
                        break;
                    }
                    if attempt == 0 {
                        thread::sleep(Duration::from_millis(80));
                    }
                }
            }
        });
    }
    drop(tx);

    let mut results = Vec::new();
    let mut answered_servers = BTreeSet::new();
    let mut quorum_deadline: Option<Instant> = None;

    loop {
        let effective_deadline = quorum_deadline.map_or(deadline, |qd| qd.min(deadline));
        let wait = effective_deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            break;
        }
        match rx.recv_timeout(wait) {
            Ok((server_idx, ip, fam, label)) => {
                answered_servers.insert(server_idx);
                results.push((ip, fam, label));
                if answered_servers.len() >= servers.len() {
                    break;
                }
                if answered_servers.len() >= 2 && quorum_deadline.is_none() {
                    quorum_deadline = Some(Instant::now() + STUN_QUORUM_TAIL);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    cancel.store(true, Ordering::Release);
    results
}

/// Collect a complete native ICE (`host` + `srflx`) candidate probe payload in ~150-300ms.
pub fn collect_webrtc<T: Transport>(network: &NetworkClient<T>) -> Value {
    let started = wallclock();
    let interfaces = claude_watch_system::active_interface_addresses();

    let (trace_res, srflx_rows) = thread::scope(|scope| {
        let trace_job = scope.spawn(|| fetch_http_trace(network));
        let stun_job = scope.spawn(|| collect_stun_srflx_quorum(&STUN_SERVERS, STUN_TOTAL_BUDGET));
        (
            trace_job.join().unwrap_or_else(|_| Err(("error".into(), "HTTP 线程异常".into()))),
            stun_job.join().unwrap_or_default(),
        )
    });

    let mut errors = Vec::new();
    let mut public_ips = BTreeSet::new();
    let mut raw_candidates: Vec<(String, &'static str, String, u8, bool)> = Vec::new();
    let mut seen_keys = BTreeSet::new();

    // 1. Local & public interface `host` candidates from `getifaddrs`
    for iface in interfaces {
        let addr_str = iface.ip.to_string();
        let fam = if iface.ip.is_ipv4() { 4u8 } else { 6u8 };
        let source = format!("本机网卡 {}", iface.interface);
        if let Some((pub_ip, pub_fam)) = canonical_public_ip(&addr_str) {
            if seen_keys.insert((pub_ip.clone(), "host", source.clone())) {
                public_ips.insert(pub_ip.clone());
                raw_candidates.push((pub_ip, "host", source, pub_fam, true));
            }
        } else if seen_keys.insert((addr_str.clone(), "host", source.clone())) {
            raw_candidates.push((addr_str, "host", source, fam, false));
        }
    }

    // 2. UDP STUN `srflx` public candidates
    if srflx_rows.is_empty() {
        errors.push(json!({
            "stage": "ice",
            "code": "stun_unreachable",
            "message": "未取得公网 UDP / STUN 反射候选"
        }));
    } else {
        for (ip, fam, source) in srflx_rows {
            if seen_keys.insert((ip.clone(), "srflx", source.clone())) {
                public_ips.insert(ip.clone());
                raw_candidates.push((ip, "srflx", source, fam, true));
            }
        }
    }

    if let Ok(ref tr) = trace_res {
        public_ips.insert(tr.ip.clone());
    }

    let now = wallclock();
    let geo_map = enrich_public_ips(network, &public_ips, trace_res.as_ref().ok(), now);

    let mut observations = Vec::new();
    let mut external_geo_rows = Vec::new();
    for (ip, meta) in &geo_map {
        external_geo_rows.push(json!({
            "kind": "geoip",
            "status": "complete",
            "query": ip,
            "data": {
                "country_code": meta.country_code,
                "region": meta.region,
                "city": meta.city,
                "isp": meta.isp,
            }
        }));
    }

    match &trace_res {
        Ok(tr) => {
            let cc = geo_map
                .get(&tr.ip)
                .map(|m| m.country_code.clone())
                .or_else(|| tr.country.clone())
                .unwrap_or_default();
            let mut obs = json!({
                "address": tr.ip,
                "kind": "http",
                "source": tr.source,
                "family": tr.family,
            });
            if !cc.is_empty() {
                obs["country"] = json!(cc);
            }
            if let Some(meta) = geo_map.get(&tr.ip) {
                if !meta.region.is_empty() {
                    obs["region"] = json!(meta.region);
                }
                if !meta.city.is_empty() {
                    obs["city"] = json!(meta.city);
                }
                if !meta.isp.is_empty() {
                    obs["isp"] = json!(meta.isp);
                }
            }
            observations.push(obs);
        }
        Err((code, msg)) => {
            errors.push(json!({
                "stage": "http",
                "code": code,
                "message": msg,
            }));
        }
    }

    for (ip, kind, source, fam, is_pub) in raw_candidates {
        let mut obs = json!({
            "address": ip,
            "kind": kind,
            "source": source,
            "family": fam,
        });
        if is_pub {
            if let Some(meta) = geo_map.get(&ip) {
                obs["country"] = json!(meta.country_code);
                if !meta.region.is_empty() {
                    obs["region"] = json!(meta.region);
                }
                if !meta.city.is_empty() {
                    obs["city"] = json!(meta.city);
                }
                if !meta.isp.is_empty() {
                    obs["isp"] = json!(meta.isp);
                }
            }
        }
        observations.push(obs);
    }

    let finished = wallclock();
    let has_public_candidate = observations
        .iter()
        .any(|o| matches!(o["kind"].as_str(), Some("srflx" | "host")) && canonical_public_ip(o["address"].as_str().unwrap_or("")).is_some());
    let status = if errors.is_empty() && has_public_candidate && trace_res.is_ok() {
        "complete"
    } else if !has_public_candidate && trace_res.is_err() {
        "timeout"
    } else {
        "partial"
    };

    json!({
        "provider": "native",
        "kind": "webrtc",
        "status": status,
        "startedAt": started,
        "finishedAt": finished,
        "scope": "原生本机双栈网卡与并发 UDP / STUN 候选核对",
        "observations": observations,
        "errors": errors,
        "contextChanged": false,
        "details": [
            "直接扫描本机活跃网卡直连地址（host）并向多组 Anycast STUN 并发采集反射地址（srflx）。",
            "与同轮代理公网 HTTP 出口比对；受控 AI 进程在 Seatbelt 沙箱内默认进一步阻断直连 UDP。"
        ],
        "externalJSON": Value::Array(external_geo_rows).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude_watch_core::receipts;

    fn build_dns_txt_response(txid: u16, qname: &str, txt_records: &[&[&str]]) -> Vec<u8> {
        let mut pkt = encode_dns_txt_query(qname, txid).unwrap();
        pkt[2] = 0x81; // QR=1, RD=1
        pkt[3] = 0x80; // RA=1, RCODE=0
        let ancount = txt_records.len() as u16;
        pkt[6..8].copy_from_slice(&ancount.to_be_bytes());
        for chunks in txt_records {
            pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname at offset 12
            pkt.extend_from_slice(&16u16.to_be_bytes()); // TXT
            pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
            pkt.extend_from_slice(&60u32.to_be_bytes()); // TTL
            let mut rdata = Vec::new();
            for chunk in *chunks {
                rdata.push(chunk.len() as u8);
                rdata.extend_from_slice(chunk.as_bytes());
            }
            pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            pkt.extend_from_slice(&rdata);
        }
        pkt
    }

    #[test]
    fn dns_txt_codec_and_akamai_google_extractors_roundtrip_cleanly() {
        let akamai_pkt = build_dns_txt_response(
            0x4242,
            "whoami.ds.akahelp.net",
            &[&["ns", "172.68.110.12"], &["ecs", "106.178.150.0/24/24"]],
        );
        let decoded = decode_dns_txt_answers(&akamai_pkt, 0x4242).unwrap();
        let akamai_ips = extract_echo_resolvers(DnsEchoSource::Akamai, &decoded);
        assert_eq!(akamai_ips, vec![("172.68.110.12".to_string(), 4)]);

        let google_pkt = build_dns_txt_response(
            0x9999,
            "o-o.myaddr.l.google.com",
            &[&["74.125.73.81"], &["edns0-client-subnet 106.178.150.0/24"]],
        );
        let decoded_g = decode_dns_txt_answers(&google_pkt, 0x9999).unwrap();
        let google_ips = extract_echo_resolvers(DnsEchoSource::Google, &decoded_g);
        assert_eq!(google_ips, vec![("74.125.73.81".to_string(), 4)]);

        assert_eq!(decode_dns_txt_answers(&akamai_pkt, 0x1111), Err("txid_mismatch"));
    }

    #[test]
    fn native_dns_and_webrtc_payloads_pass_core_receipt_validation() {
        let now = 1_750_000_000.0;
        let local = json!({
            "context": "ctx-1",
            "context_id": "ctx-1",
            "proxy": "ok",
            "tun": "ok",
            "evidence_network_bound": true,
            "evidence_egress_ip": "106.178.150.201",
            "tag": {
                "entry": {"endpoint": "http://127.0.0.1:7890"},
                "api": {"mode": "global", "global_node": "JP-01", "selected_node": "JP-01"}
            }
        });

        let dns_probe = json!({
            "provider": "native",
            "kind": "dns",
            "status": "complete",
            "startedAt": now - 0.25,
            "finishedAt": now,
            "scope": "原生多源权威 DNS 递归出口核对",
            "contextChanged": false,
            "errors": [],
            "observations": [
                {"address": "172.68.110.12", "kind": "resolver", "source": "Akamai", "family": 4, "country": "JP", "isp": "Cloudflare"},
                {"address": "106.178.150.201", "kind": "http", "source": "Cloudflare Trace", "family": 4, "country": "JP", "isp": "KDDI"}
            ],
            "externalJSON": json!({
                "provider": "native",
                "dns_servers": {"172.68.110.12": 2},
                "http": {"address": "106.178.150.201", "country": "JP"},
                "geoip": [{"ip": "172.68.110.12", "country_code": "JP", "isp": "Cloudflare"}]
            }).to_string()
        });

        let recorded_dns = receipts::record_dns(&dns_probe, &local, Some("ctx-1"), now + 0.1).unwrap();
        assert_eq!(recorded_dns["provider"], "native");
        assert_eq!(recorded_dns["comparison"]["state"], "ok");
        assert!(receipts::dns_last_valid(&recorded_dns, "ctx-1", now + 0.2));
        assert_eq!(
            receipts::dns_status_for_network(&recorded_dns, &Value::Null, "ctx-1", Some("106.178.150.201"), true, now + 1.0, |t| t.to_string())["state"],
            "ok"
        );

        let rtc_probe = json!({
            "provider": "native",
            "kind": "webrtc",
            "status": "complete",
            "startedAt": now - 0.20,
            "finishedAt": now,
            "scope": "原生本机双栈网卡与并发 UDP / STUN 候选核对",
            "contextChanged": false,
            "errors": [],
            "observations": [
                {"address": "106.178.150.201", "kind": "http", "source": "Cloudflare Trace", "family": 4, "country": "JP"},
                {"address": "106.178.150.201", "kind": "srflx", "source": "stun.cloudflare.com:3478", "family": 4, "country": "JP"},
                {"address": "192.168.1.25", "kind": "host", "source": "本机网卡 en0", "family": 4}
            ],
            "externalJSON": json!([
                {"kind": "geoip", "status": "complete", "query": "106.178.150.201", "data": {"country_code": "JP"}}
            ]).to_string()
        });

        let recorded_rtc = receipts::record_webrtc(&rtc_probe, &local, Some("ctx-1"), now + 0.1).unwrap();
        assert_eq!(recorded_rtc["provider"], "native");
        assert_eq!(recorded_rtc["risk"]["state"], "ok");
        assert_eq!(recorded_rtc["local_observations"].as_array().unwrap().len(), 1);
    }
}
