//! Multi-source pure-Rust IP risk & routing intelligence collector.
//!
//! Queries `api.ipapi.is`, `ipinfo.io`, `RIPEstat` (`rir-stats-country` + `rpki-validation`),
//! Cloudflare `/cdn-cgi/trace`, and encrypted DoH `PTR` (`in-addr.arpa` / `ip6.arpa`)
//! concurrently through the explicit controlled proxy tunnel, then delegates all
//! classification and scoring to `claude_watch_core::ip_intel`.

use crate::{
    network_client::{ripe_registered_country, NetworkClient, Transport},
    storage::sha256,
};
use claude_watch_core::{
    ip_intel::{evaluate_ip_intelligence, parse_cloudflare_trace, CloudflareTraceInfo, IpIntelInput},
    network::public_unicast,
};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |v| v.as_secs_f64())
}

/// Read the host macOS IANA timezone from `/etc/localtime` symlink without spawning a subprocess.
pub fn host_system_timezone() -> Option<String> {
    if let Ok(link) = std::fs::read_link("/etc/localtime") {
        let text = link.to_string_lossy();
        if let Some((_, zone)) = text.split_once("zoneinfo/") {
            let trimmed = zone.trim().trim_matches('/');
            if !trimmed.is_empty() && trimmed.len() <= 64 {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

fn default_prefix_for_ip(ip: &str) -> Option<String> {
    match ip.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
        }
        std::net::IpAddr::V6(v6) => {
            let segs = v6.segments();
            Some(format!("{:x}:{:x}:{:x}::/48", segs[0], segs[1], segs[2]))
        }
    }
}

fn fetch_current_trace<T: Transport>(network: &NetworkClient<T>) -> Result<(CloudflareTraceInfo, String), String> {
    let fast = network
        .clone()
        .with_timeout(Duration::from_secs(5))
        .with_connect_timeout(Duration::from_secs(3));
    for url in [
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://1.1.1.1/cdn-cgi/trace",
    ] {
        let receipt = fast.trace(url);
        if receipt.status == "complete" {
            if let Some(parsed) = parse_cloudflare_trace(&receipt.raw) {
                return Ok((parsed, receipt.transport));
            }
        }
    }
    Err("未能通过当前受控代理通道读取公网出口 IP，请检查代理或独立内置 VPN 是否运行".into())
}

/// Collect comprehensive pure-Rust IP intelligence for either an explicit public IP
/// or (when `requested_ip` is empty/None) the current controlled proxy exit IP.
pub fn collect_ip_intel<T: Transport>(
    network: &NetworkClient<T>,
    requested_ip: Option<&str>,
    system_timezone_override: Option<&str>,
) -> Value {
    let started = now();
    let trimmed = requested_ip.map(str::trim).unwrap_or("");

    let (target_ip, live_trace) = if trimmed.is_empty() {
        match fetch_current_trace(network) {
            Ok((tr, _)) => {
                let ip = tr.ip.clone();
                (ip, Some(tr))
            }
            Err(err) => {
                return json!({
                    "schema": 1,
                    "status": "error",
                    "query": "",
                    "queriedAt": started,
                    "finishedAt": now(),
                    "transport": network.proxy_description(),
                    "error": err
                });
            }
        }
    } else {
        let Some(valid_ip) = public_unicast(trimmed) else {
            return json!({
                "schema": 1,
                "status": "error",
                "query": trimmed,
                "queriedAt": started,
                "finishedAt": now(),
                "transport": network.proxy_description(),
                "error": "请输入有效的公网单播 IPv4 或 IPv6；本机、局域网与保留地址不提交查询"
            });
        };
        (valid_ip, None)
    };

    let client = network
        .clone()
        .with_timeout(Duration::from_secs(8))
        .with_connect_timeout(Duration::from_secs(4));

    let ip_ref = target_ip.as_str();
    let probe_live_trace = live_trace.is_none();

    // Stage 1: Concurrently query ipapi.is, ipinfo.io, DoH PTR, and (if needed) live edge trace
    let (ipapi_receipt, ipinfo_receipt, ptr_domains, matched_trace) = std::thread::scope(|scope| {
        let c1 = &client;
        let ipapi_task = scope.spawn(move || c1.metadata("lookup", ip_ref));
        let ipinfo_task = scope.spawn(move || c1.metadata("geoip", ip_ref));
        let ptr_task = scope.spawn(move || c1.doh_ptr(ip_ref));
        let trace_task = probe_live_trace.then(|| {
            scope.spawn(move || {
                let r = c1
                    .clone()
                    .with_timeout(Duration::from_secs(3))
                    .trace("https://1.1.1.1/cdn-cgi/trace");
                (r.status == "complete")
                    .then(|| parse_cloudflare_trace(&r.raw))
                    .flatten()
                    .filter(|t| t.ip == ip_ref)
            })
        });

        let ipapi_r = ipapi_task.join().unwrap();
        let ipinfo_r = ipinfo_task.join().unwrap();
        let ptr_r = ptr_task.join().unwrap();
        let tr_r = trace_task.and_then(|t| t.join().ok()).flatten();
        (ipapi_r, ipinfo_r, ptr_r, tr_r)
    });

    let effective_trace = live_trace.or(matched_trace);

    let ipapi_data = (ipapi_receipt.status == "complete" && ipapi_receipt.http_status == Some(200))
        .then_some(ipapi_receipt.data.as_ref())
        .flatten();
    let ipinfo_data = (ipinfo_receipt.status == "complete" && ipinfo_receipt.http_status == Some(200))
        .then_some(ipinfo_receipt.data.as_ref())
        .flatten();

    // Extract ASN and route prefix for Stage 2 RIR / RPKI verification
    let asn_num = crate::network_client::lookup_asn(&ipapi_receipt)
        .or_else(|| crate::network_client::lookup_asn(&ipinfo_receipt));
    let route_prefix = ipapi_data
        .and_then(|d| {
            d.pointer("/asn/route")
                .or_else(|| d.pointer("/datacenter/route"))
                .or_else(|| d.get("cidr"))
                .and_then(Value::as_str)
        })
        .filter(|s| s.contains('/'))
        .map(str::to_owned)
        .or_else(|| default_prefix_for_ip(&target_ip));

    let (ripe_country_receipt, ripe_rpki_receipt) = std::thread::scope(|scope| {
        let c2 = &client;
        let country_task = asn_num.map(|asn| scope.spawn(move || c2.ripe_asn(asn)));
        let rpki_task = asn_num.zip(route_prefix.as_deref()).map(|(asn, pfx)| {
            scope.spawn(move || c2.ripe_rpki(asn, pfx))
        });
        (
            country_task.and_then(|t| t.join().ok()),
            rpki_task.and_then(|t| t.join().ok()),
        )
    });

    let ripe_country = asn_num.and_then(|asn| {
        ripe_country_receipt
            .as_ref()
            .and_then(|r| ripe_registered_country(r, asn))
    });
    let ripe_rpki_data = ripe_rpki_receipt
        .as_ref()
        .filter(|r| r.status == "complete" && r.http_status == Some(200))
        .and_then(|r| r.data.as_ref());

    let source_statuses = json!({
        "ipapi_is": {
            "status": ipapi_receipt.status,
            "http_status": ipapi_receipt.http_status,
            "cache_state": ipapi_receipt.cache_state,
            "error": ipapi_receipt.error,
        },
        "ipinfo_io": {
            "status": ipinfo_receipt.status,
            "http_status": ipinfo_receipt.http_status,
            "cache_state": ipinfo_receipt.cache_state,
            "error": ipinfo_receipt.error,
        },
        "ripestat_rir": ripe_country_receipt.as_ref().map(|r| json!({
            "status": r.status,
            "http_status": r.http_status,
            "cache_state": r.cache_state,
        })),
        "ripestat_rpki": ripe_rpki_receipt.as_ref().map(|r| json!({
            "status": r.status,
            "http_status": r.http_status,
            "cache_state": r.cache_state,
        })),
        "doh_ptr": {
            "status": if ptr_domains.is_empty() { "empty" } else { "complete" },
            "count": ptr_domains.len(),
        }
    });

    let sys_tz = system_timezone_override
        .map(str::to_owned)
        .or_else(host_system_timezone);
    let finished = now();
    let transport_desc = network.proxy_description();

    let mut report = evaluate_ip_intelligence(&IpIntelInput {
        query_ip: &target_ip,
        ipapi: ipapi_data,
        ipinfo: ipinfo_data,
        ripe_rpki: ripe_rpki_data,
        ripe_country: ripe_country.as_deref(),
        ptr_domains: &ptr_domains,
        trace: effective_trace.as_ref(),
        system_timezone: sys_tz.as_deref(),
        queried_at: started,
        finished_at: finished,
        transport: &transport_desc,
        source_statuses: &source_statuses,
    });

    if let Some(obj) = report.as_object_mut() {
        let digest_input = format!(
            "{}\n{}",
            ipapi_receipt.raw,
            ipinfo_receipt.raw
        );
        obj.insert("sha256".into(), json!(sha256(digest_input.as_bytes())));
        obj.insert(
            "cache_state".into(),
            json!(ipapi_receipt.cache_state),
        );
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_client::{Request, Response, TransportError};
    use std::{collections::HashMap, sync::Arc};

    struct MockIntelTransport;
    impl Transport for MockIntelTransport {
        fn get(&self, req: &Request) -> Result<Response, TransportError> {
            let body = if req.url.contains("cloudflare.com/cdn-cgi/trace")
                || req.url.contains("1.1.1.1/cdn-cgi/trace")
            {
                "ip=106.178.149.35\nloc=JP\ncolo=NRT\ntls=TLSv1.3\nhttp=http/2\nsni=plaintext\nwarp=off\n"
                    .to_owned()
            } else if req.url.starts_with("https://api.ipapi.is/?q=106.178.149.35") {
                r#"{"ip":"106.178.149.35","rir":"APNIC","is_datacenter":false,"is_vpn":false,"company":{"name":"KDDI CORPORATION","type":"isp","abuser_score":"0.0004 (Very Low)"},"asn":{"asn":2516,"org":"KDDI CORPORATION","country":"jp","type":"isp","route":"106.178.0.0/16","abuser_score":"0.0005 (Very Low)"},"location":{"country":"Japan","country_code":"JP","state":"Tokyo","city":"Tokyo","latitude":35.6895,"longitude":139.6917,"timezone":"Asia/Tokyo"}}"#.to_owned()
            } else if req.url.starts_with("https://ipinfo.io/106.178.149.35/json") {
                r#"{"ip":"106.178.149.35","country":"JP","region":"Tokyo","city":"Tokyo","loc":"35.6895,139.6917","org":"AS2516 KDDI CORPORATION","timezone":"Asia/Tokyo"}"#.to_owned()
            } else if req.url.contains("dns-query") {
                r#"{"Status":0,"Answer":[{"name":"35.149.178.106.in-addr.arpa.","type":12,"TTL":3600,"data":"KD106178149035.ppp.dion.ne.jp."}]}"#.to_owned()
            } else if req.url.contains("rir-stats-country") {
                r#"{"data":{"located_resources":[{"resource":"2516","location":"JP"}]}}"#.to_owned()
            } else if req.url.contains("rpki-validation") {
                r#"{"data":{"status":"valid","prefix":"106.178.0.0/16","resource":"2516","validating_roas":[{"origin":"AS2516","prefix":"106.178.0.0/16","max_length":16,"validity":"valid"}]}}"#.to_owned()
            } else {
                return Err(TransportError::new("unexpected_url", &req.url));
            };
            Ok(Response {
                status: 200,
                headers: HashMap::new(),
                body: body.into_bytes(),
            })
        }
    }

    #[test]
    fn collector_fetches_current_egress_and_merges_five_authoritative_sources() {
        let client = NetworkClient::new(
            Arc::new(MockIntelTransport),
            Some("http://127.0.0.1:7890".into()),
        )
        .unwrap();
        let report = collect_ip_intel(&client, None, Some("Asia/Tokyo"));
        assert_eq!(report["status"], "complete");
        assert_eq!(report["ip"], "106.178.149.35");
        assert_eq!(report["score"]["value"], 100);
        assert_eq!(report["rdns"], "KD106178149035.ppp.dion.ne.jp");
        assert_eq!(report["rpki"]["status"], "valid");
        assert_eq!(report["edge_trace"]["colo"], "NRT");
        assert_eq!(report["usage"]["native_status"], "native");
    }

    #[test]
    fn collector_rejects_private_or_loopback_ips_without_network() {
        let client = NetworkClient::new(
            Arc::new(MockIntelTransport),
            Some("http://127.0.0.1:7890".into()),
        )
        .unwrap();
        let report = collect_ip_intel(&client, Some("127.0.0.1"), None);
        assert_eq!(report["status"], "error");
    }
}
