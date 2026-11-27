//! Pure IP risk intelligence normalization, multi-source geo consistency,
//! Cloudflare edge trace parsing, PTR classification, and explainable 0-100 scoring.
//!
//! No network I/O or system clocks live here; `watch-runtime` collects raw
//! responses through the explicit proxy and passes them into these pure functions.

use crate::network::public_unicast;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbuserMetric {
    pub raw: String,
    pub ratio: Option<f64>,
    pub tier: String,
    pub tier_zh: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreFactor {
    pub id: String,
    pub label: String,
    pub delta: i32,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeoSourceRow {
    pub source: String,
    pub country_code: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudflareTraceInfo {
    pub ip: String,
    pub country_code: String,
    pub colo: String,
    pub colo_city: String,
    pub tls: String,
    pub http: String,
    pub sni: String,
    pub warp: String,
    pub kex: String,
    pub gateway: String,
}

pub struct IpIntelInput<'a> {
    pub query_ip: &'a str,
    pub ipapi: Option<&'a Value>,
    pub ipinfo: Option<&'a Value>,
    pub ripe_rpki: Option<&'a Value>,
    pub ripe_country: Option<&'a str>,
    pub ptr_domains: &'a [String],
    pub trace: Option<&'a CloudflareTraceInfo>,
    pub system_timezone: Option<&'a str>,
    pub queried_at: f64,
    pub finished_at: f64,
    pub transport: &'a str,
    pub source_statuses: &'a Value,
}

fn clip(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
}

fn clean_country_code(raw: &str) -> Option<String> {
    let code = raw.trim().to_ascii_uppercase();
    (code.len() == 2
        && code.bytes().all(|b| b.is_ascii_uppercase())
        && !matches!(code.as_str(), "XX" | "ZZ" | "T1"))
    .then_some(code)
}

/// Map common Cloudflare IATA airport POP codes to human-readable edge locations.
pub fn colo_city_name(colo: &str) -> &'static str {
    match colo.trim().to_ascii_uppercase().as_str() {
        "NRT" => "东京 (Narita)",
        "HND" => "东京 (Haneda)",
        "KIX" => "大阪 (Kansai)",
        "FUK" => "福冈 (Fukuoka)",
        "OKA" => "冲绳 (Okinawa)",
        "ICN" => "首尔 (Incheon)",
        "TPE" => "台北 (Taipei)",
        "KHH" => "高雄 (Kaohsiung)",
        "HKG" => "香港 (Hong Kong)",
        "SIN" => "新加坡 (Singapore)",
        "KUL" => "吉隆坡 (Kuala Lumpur)",
        "BKK" => "曼谷 (Bangkok)",
        "MNL" => "马尼拉 (Manila)",
        "CGK" => "雅加达 (Jakarta)",
        "BOM" => "孟买 (Mumbai)",
        "DEL" => "新德里 (Delhi)",
        "SYD" => "悉尼 (Sydney)",
        "MEL" => "墨尔本 (Melbourne)",
        "AKL" => "奥克兰 (Auckland)",
        "LAX" => "洛杉矶 (Los Angeles)",
        "SJC" => "圣何塞 (San Jose)",
        "SFO" => "旧金山 (San Francisco)",
        "SEA" => "西雅图 (Seattle)",
        "PDX" => "波特兰 (Portland)",
        "DEN" => "丹佛 (Denver)",
        "DFW" => "达拉斯 (Dallas)",
        "IAH" => "休斯顿 (Houston)",
        "ORD" => "芝加哥 (Chicago)",
        "ATL" => "亚特兰大 (Atlanta)",
        "MIA" => "迈阿密 (Miami)",
        "IAD" => "弗吉尼亚 (Ashburn)",
        "EWR" => "纽瓦克/纽约 (Newark)",
        "JFK" => "纽约 (JFK)",
        "BOS" => "波士顿 (Boston)",
        "YYZ" => "多伦多 (Toronto)",
        "YVR" => "温哥华 (Vancouver)",
        "LHR" => "伦敦 (London)",
        "MAN" => "曼彻斯特 (Manchester)",
        "AMS" => "阿姆斯特丹 (Amsterdam)",
        "FRA" => "法兰克福 (Frankfurt)",
        "MUC" => "慕尼黑 (Munich)",
        "DUS" => "杜塞尔多夫 (Dusseldorf)",
        "CDG" => "巴黎 (Paris)",
        "MRS" => "马赛 (Marseille)",
        "ZRH" => "苏黎世 (Zurich)",
        "VIE" => "维也纳 (Vienna)",
        "MAD" => "马德里 (Madrid)",
        "MXP" => "米兰 (Milan)",
        "ARN" => "斯德哥尔摩 (Stockholm)",
        "WAW" => "华沙 (Warsaw)",
        "DXB" => "迪拜 (Dubai)",
        "GRU" => "圣保罗 (Sao Paulo)",
        _ => "",
    }
}

/// Parse all diagnostic protocol fields from a Cloudflare `/cdn-cgi/trace` body.
pub fn parse_cloudflare_trace(raw: &str) -> Option<CloudflareTraceInfo> {
    let mut map = BTreeMap::new();
    for line in raw.lines().take(64) {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_ascii_lowercase(), clip(v, 128));
        }
    }
    let raw_ip = map.get("ip")?.as_str();
    let mapped_v4 = raw_ip
        .parse::<std::net::Ipv6Addr>()
        .ok()
        .and_then(|v6| v6.to_ipv4_mapped())
        .map(|v4| v4.to_string());
    let ip = public_unicast(mapped_v4.as_deref().unwrap_or(raw_ip))?;
    let country_code = map
        .get("loc")
        .and_then(|v| clean_country_code(v))
        .unwrap_or_default();
    let colo = map
        .get("colo")
        .map(|v| v.to_ascii_uppercase())
        .filter(|v| v.len() <= 8 && v.bytes().all(|b| b.is_ascii_alphanumeric()))
        .unwrap_or_default();
    let colo_city = colo_city_name(&colo).to_owned();
    Some(CloudflareTraceInfo {
        ip,
        country_code,
        colo,
        colo_city,
        tls: map.get("tls").cloned().unwrap_or_default(),
        http: map.get("http").cloned().unwrap_or_default(),
        sni: map.get("sni").cloned().unwrap_or_default(),
        warp: map.get("warp").cloned().unwrap_or_default(),
        kex: map.get("kex").cloned().unwrap_or_default(),
        gateway: map.get("gateway").cloned().unwrap_or_default(),
    })
}

/// Parse `ipapi.is` quantitative abuser strings such as `"0.0005 (Very Low)"` or `"0.0117 (Elevated)"`.
pub fn parse_abuser_score(raw: Option<&str>) -> AbuserMetric {
    let text = raw.map(|s| clip(s, 80)).unwrap_or_default();
    if text.is_empty() {
        return AbuserMetric {
            raw: String::new(),
            ratio: None,
            tier: "unknown".into(),
            tier_zh: "未披露".into(),
        };
    }
    let number_token = text.split_whitespace().next().unwrap_or("");
    let ratio = number_token
        .parse::<f64>()
        .ok()
        .filter(|n| n.is_finite() && (0.0..=1.0).contains(n));
    let lower = text.to_ascii_lowercase();
    let (tier, tier_zh) = if lower.contains("very high") || ratio.is_some_and(|r| r >= 0.10) {
        ("very_high", "极高危")
    } else if lower.contains("high") || ratio.is_some_and(|r| r >= 0.03) {
        ("high", "高风险")
    } else if lower.contains("elevated") || ratio.is_some_and(|r| r >= 0.006) {
        ("elevated", "偏高")
    } else if lower.contains("low") && !lower.contains("very low")
        || ratio.is_some_and(|r| r >= 0.0015)
    {
        ("low", "低风险")
    } else if lower.contains("very low") || ratio.is_some_and(|r| r < 0.0015) {
        ("very_low", "极度纯净")
    } else {
        ("unknown", "未知")
    };
    AbuserMetric {
        raw: text,
        ratio,
        tier: tier.into(),
        tier_zh: tier_zh.into(),
    }
}

/// Classify reverse-DNS (PTR) hostnames into broadband vs cloud/datacenter patterns.
pub fn classify_rdns(hostname: &str) -> (&'static str, &'static str) {
    let lower = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty() {
        return ("none", "未配置反向 PTR 解析");
    }
    let cloud_markers = [
        "amazonaws.com",
        "googleusercontent.com",
        "1e100.net",
        "vultrusercontent.com",
        "choopa.net",
        "linodeusercontent.com",
        "akamai",
        "digitalocean",
        "hetzner",
        "your-server.de",
        "contaboserver",
        "ovh.net",
        "packethub",
        "datapacket",
        "m247",
        "tzulo",
        "zenlayer",
        "cloud",
        "vps",
        "dedicated",
        "hosting",
    ];
    if lower == "dns.google" || lower == "one.one.one.one" {
        return ("public_infra", "公共基础设施任播节点");
    }
    if cloud_markers.iter().any(|m| lower.contains(m)) {
        return ("cloud_hosting", "主机名呈云厂商 / IDC 机房托管特征");
    }
    let mobile_markers = ["spmode.ne.jp", "panda-world.ne.jp", "LTE", "mobile", "cellular", "wireless"];
    if mobile_markers
        .iter()
        .any(|m| lower.contains(&m.to_ascii_lowercase()))
    {
        return ("mobile_carrier", "主机名呈移动蜂窝运营商网关特征");
    }
    let broadband_markers = [
        "ppp",
        "ftth",
        "adsl",
        "vdsl",
        "dhcp",
        "dyn",
        "dynamic",
        "cable",
        "hsd1",
        "fios",
        "dion.ne.jp",
        "ocn.ne.jp",
        "so-net.ne.jp",
        "plala.or.jp",
        "infoweb.ne.jp",
        "bbtec.net",
        "enabler.ne.jp",
        "comcast.net",
        "rr.com",
        "sbcglobal.net",
        "verizon.net",
        "btcentralplus",
        "t-ipconnect.de",
        "wanadoo",
        "hinet.net",
    ];
    if broadband_markers.iter().any(|m| lower.contains(m)) {
        return ("residential_dialup", "主机名呈家庭宽带动态拨号 / FTTH 接入特征");
    }
    ("generic", "常规运营商或静态反向解析记录")
}

/// Pure Haversine distance in kilometers between two WGS84 coordinates.
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> Option<f64> {
    if ![lat1, lon1, lat2, lon2].iter().all(|v| v.is_finite())
        || !(-90.0..=90.0).contains(&lat1)
        || !(-90.0..=90.0).contains(&lat2)
        || !(-180.0..=180.0).contains(&lon1)
        || !(-180.0..=180.0).contains(&lon2)
    {
        return None;
    }
    const EARTH_RADIUS_KM: f64 = 6371.0088;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let rlat1 = lat1.to_radians();
    let rlat2 = lat2.to_radians();
    let a = (dlat / 2.0).sin().powi(2) + rlat1.cos() * rlat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.clamp(0.0, 1.0).sqrt().atan2((1.0 - a.clamp(0.0, 1.0)).sqrt());
    Some(((EARTH_RADIUS_KM * c) * 10.0).round() / 10.0)
}

/// Normalize RIPEstat `rpki-validation` JSON output.
pub fn normalize_rpki(ripe_rpki: Option<&Value>) -> Value {
    let Some(data) = ripe_rpki.and_then(|v| v.get("data")).filter(|d| d.is_object()) else {
        return json!({
            "status": "unknown",
            "label": "未取证 / 无 ROA",
            "prefix": "",
            "resource": "",
            "roas": []
        });
    };
    let raw_status = data
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .trim()
        .to_ascii_lowercase();
    let label = match raw_status.as_str() {
        "valid" => "Valid（合法签名宣告）",
        "invalid" | "invalid_asn" => "Invalid（自治系统起源签名不匹配）",
        "invalid_length" => "Invalid Length（宣告掩码超出 ROA 上限）",
        _ => "Unknown（未注册 ROA 记录）",
    };
    let roas: Vec<Value> = data
        .get("validating_roas")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .take(6)
                .map(|r| {
                    json!({
                        "origin": r.get("origin").and_then(Value::as_str).unwrap_or(""),
                        "prefix": r.get("prefix").and_then(Value::as_str).unwrap_or(""),
                        "max_length": r.get("max_length").and_then(Value::as_u64),
                        "validity": r.get("validity").and_then(Value::as_str).unwrap_or("")
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "status": raw_status,
        "label": label,
        "prefix": data.get("prefix").and_then(Value::as_str).unwrap_or(""),
        "resource": data.get("resource").and_then(Value::as_str).unwrap_or(""),
        "roas": roas
    })
}

fn parse_ipinfo_asn_org(org: &str) -> (Option<u32>, String) {
    let trimmed = org.trim();
    if let Some(rest) = trimmed.strip_prefix("AS") {
        let mut parts = rest.splitn(2, char::is_whitespace);
        let digits = parts.next().unwrap_or("");
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(asn) = digits.parse::<u32>() {
                let name = parts.next().unwrap_or("").trim().to_owned();
                return (Some(asn), name);
            }
        }
    }
    (None, trimmed.to_owned())
}

/// Evaluate complete, multi-source IP intelligence into a unified JSON report
/// consumed by both the Panorama UI (`IpIntelStore`) and background risk audit.
pub fn evaluate_ip_intelligence(input: &IpIntelInput<'_>) -> Value {
    let Some(canonical_ip) = public_unicast(input.query_ip) else {
        return json!({
            "schema": 1,
            "status": "error",
            "query": input.query_ip,
            "error": "仅允许公网单播 IPv4 或 IPv6 地址"
        });
    };

    let ipapi = input
        .ipapi
        .filter(|v| {
            v.get("ip")
                .and_then(Value::as_str)
                .and_then(public_unicast)
                .as_deref()
                == Some(canonical_ip.as_str())
        });
    let ipinfo = input.ipinfo.filter(|v| {
        v.get("ip")
            .and_then(Value::as_str)
            .and_then(public_unicast)
            .as_deref()
            == Some(canonical_ip.as_str())
    });

    if ipapi.is_none() && ipinfo.is_none() {
        return json!({
            "schema": 1,
            "status": "error",
            "query": canonical_ip,
            "ip": canonical_ip,
            "queriedAt": input.queried_at,
            "finishedAt": input.finished_at,
            "transport": input.transport,
            "sourceStatuses": input.source_statuses,
            "error": "主备权威情报源均未返回当前 IP 的核验数据"
        });
    }

    let flag = |key: &str| -> bool {
        ipapi
            .and_then(|v| v.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let is_bogon = flag("is_bogon");
    let is_datacenter = flag("is_datacenter");
    let is_vpn = flag("is_vpn");
    let is_proxy = flag("is_proxy");
    let is_tor = flag("is_tor");
    let is_crawler = flag("is_crawler");
    let is_abuser = flag("is_abuser");
    let is_mobile = flag("is_mobile");
    let is_satellite = flag("is_satellite");
    let is_anycast = flag("is_anycast");

    // Geo sources aggregation
    let mut geo_sources: Vec<GeoSourceRow> = Vec::new();
    if let Some(loc) = ipapi.and_then(|v| v.get("location")).filter(|l| l.is_object()) {
        if let Some(cc) = loc.get("country_code").and_then(Value::as_str).and_then(clean_country_code)
        {
            geo_sources.push(GeoSourceRow {
                source: "ipapi.is".into(),
                country_code: cc,
                country: clip(loc.get("country").and_then(Value::as_str).unwrap_or(""), 80),
                region: clip(loc.get("state").and_then(Value::as_str).unwrap_or(""), 80),
                city: clip(loc.get("city").and_then(Value::as_str).unwrap_or(""), 80),
                latitude: loc.get("latitude").and_then(Value::as_f64),
                longitude: loc.get("longitude").and_then(Value::as_f64),
                timezone: clip(loc.get("timezone").and_then(Value::as_str).unwrap_or(""), 64),
            });
        }
    }
    if let Some(info) = ipinfo {
        if let Some(cc) = info.get("country").and_then(Value::as_str).and_then(clean_country_code) {
            let (lat, lon) = info
                .get("loc")
                .and_then(Value::as_str)
                .and_then(|s| s.split_once(','))
                .map(|(a, b)| (a.trim().parse::<f64>().ok(), b.trim().parse::<f64>().ok()))
                .unwrap_or((None, None));
            geo_sources.push(GeoSourceRow {
                source: "ipinfo.io".into(),
                country_code: cc.clone(),
                country: clip(
                    info.get("country_name")
                        .and_then(Value::as_str)
                        .unwrap_or(&cc),
                    80,
                ),
                region: clip(info.get("region").and_then(Value::as_str).unwrap_or(""), 80),
                city: clip(info.get("city").and_then(Value::as_str).unwrap_or(""), 80),
                latitude: lat,
                longitude: lon,
                timezone: clip(info.get("timezone").and_then(Value::as_str).unwrap_or(""), 64),
            });
        }
    }
    if let Some(tr) = input.trace.filter(|t| t.ip == canonical_ip && !t.country_code.is_empty()) {
        geo_sources.push(GeoSourceRow {
            source: "Cloudflare Edge".into(),
            country_code: tr.country_code.clone(),
            country: tr.country_code.clone(),
            region: String::new(),
            city: tr.colo_city.clone(),
            latitude: None,
            longitude: None,
            timezone: String::new(),
        });
    }

    let mut max_drift_km: Option<f64> = None;
    for i in 0..geo_sources.len() {
        for j in (i + 1)..geo_sources.len() {
            if let (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) = (
                geo_sources[i].latitude,
                geo_sources[i].longitude,
                geo_sources[j].latitude,
                geo_sources[j].longitude,
            ) {
                if let Some(d) = haversine_km(lat1, lon1, lat2, lon2) {
                    max_drift_km = Some(max_drift_km.map_or(d, |cur| cur.max(d)));
                }
            }
        }
    }

    let reported_countries: BTreeSet<String> = geo_sources
        .iter()
        .map(|g| g.country_code.clone())
        .filter(|c| !c.is_empty())
        .collect();
    let country_consistent = reported_countries.len() <= 1;

    let primary_geo = geo_sources.first();
    let country_code = primary_geo
        .map(|g| g.country_code.clone())
        .unwrap_or_default();
    let country = primary_geo
        .map(|g| {
            if g.country.is_empty() {
                g.country_code.clone()
            } else {
                g.country.clone()
            }
        })
        .unwrap_or_default();
    let region = geo_sources
        .iter()
        .find_map(|g| (!g.region.is_empty()).then(|| g.region.clone()))
        .unwrap_or_default();
    let city = geo_sources
        .iter()
        .find_map(|g| (!g.city.is_empty()).then(|| g.city.clone()))
        .unwrap_or_default();
    let timezone = geo_sources
        .iter()
        .find_map(|g| (!g.timezone.is_empty()).then(|| g.timezone.clone()))
        .unwrap_or_default();
    let local_time = ipapi
        .and_then(|v| v.pointer("/location/local_time"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 64))
        .unwrap_or_default();
    let coordinates = geo_sources
        .iter()
        .find_map(|g| g.latitude.zip(g.longitude));

    // ASN & Company extraction
    let asn_obj = ipapi.and_then(|v| v.get("asn")).filter(|o| o.is_object());
    let company_obj = ipapi.and_then(|v| v.get("company")).filter(|o| o.is_object());
    let (ipinfo_asn, ipinfo_org) = ipinfo
        .and_then(|v| v.get("org"))
        .and_then(Value::as_str)
        .map(parse_ipinfo_asn_org)
        .unwrap_or((None, String::new()));

    let asn_number: Option<u32> = asn_obj
        .and_then(|o| o.get("asn"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)
        .or(ipinfo_asn);
    let asn_org = asn_obj
        .and_then(|o| o.get("org").or_else(|| o.get("descr")))
        .and_then(Value::as_str)
        .map(|s| clip(s, 120))
        .filter(|s| !s.is_empty())
        .unwrap_or(ipinfo_org);
    let asn_type = asn_obj
        .and_then(|o| o.get("type"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 40).to_ascii_lowercase())
        .unwrap_or_default();
    let asn_route = asn_obj
        .and_then(|o| o.get("route"))
        .or_else(|| ipapi.and_then(|v| v.pointer("/datacenter/route")))
        .or_else(|| company_obj.and_then(|o| o.get("network")))
        .and_then(Value::as_str)
        .map(|s| clip(s, 64))
        .unwrap_or_default();
    let rir = asn_obj
        .and_then(|o| o.get("rir"))
        .or_else(|| ipapi.and_then(|v| v.get("rir")))
        .and_then(Value::as_str)
        .map(|s| clip(s, 24).to_ascii_uppercase())
        .unwrap_or_default();
    let asn_created = asn_obj
        .and_then(|o| o.get("created"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 32))
        .unwrap_or_default();
    let asn_domain = asn_obj
        .and_then(|o| o.get("domain"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 80))
        .unwrap_or_default();
    let ipapi_asn_country = asn_obj
        .and_then(|o| o.get("country"))
        .and_then(Value::as_str)
        .and_then(clean_country_code);
    let registered_country_code = input
        .ripe_country
        .and_then(clean_country_code)
        .or(ipapi_asn_country)
        .unwrap_or_default();
    let registered_country_source = if input.ripe_country.and_then(clean_country_code).is_some() {
        "RIPEstat RIR"
    } else if !registered_country_code.is_empty() {
        "ipapi.is RIR"
    } else {
        "unknown"
    };

    let company_name = company_obj
        .and_then(|o| o.get("name"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 120))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| asn_org.clone());
    let company_type = company_obj
        .and_then(|o| o.get("type"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 40).to_ascii_lowercase())
        .unwrap_or_else(|| asn_type.clone());
    let company_domain = company_obj
        .and_then(|o| o.get("domain"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 80))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| asn_domain.clone());
    let company_network = company_obj
        .and_then(|o| o.get("network"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 80))
        .unwrap_or_default();
    let abuse_email = ipapi
        .and_then(|v| v.pointer("/abuse/email"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 100))
        .unwrap_or_default();

    let company_abuser = parse_abuser_score(
        company_obj
            .and_then(|o| o.get("abuser_score"))
            .and_then(Value::as_str),
    );
    let asn_abuser = parse_abuser_score(
        asn_obj
            .and_then(|o| o.get("abuser_score"))
            .and_then(Value::as_str),
    );

    let datacenter_name = ipapi
        .and_then(|v| v.pointer("/datacenter/datacenter"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 100))
        .unwrap_or_default();
    let vpn_service = ipapi
        .and_then(|v| v.pointer("/vpn/service"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 80))
        .unwrap_or_default();
    let vpn_region = ipapi
        .and_then(|v| v.pointer("/vpn/exit_node_region"))
        .and_then(Value::as_str)
        .map(|s| clip(s, 80))
        .unwrap_or_default();

    // Reverse DNS (PTR)
    let primary_rdns = input
        .ptr_domains
        .first()
        .map(|s| clip(s, 128))
        .or_else(|| {
            ipinfo
                .and_then(|v| v.get("hostname"))
                .and_then(Value::as_str)
                .map(|s| clip(s, 128))
        })
        .unwrap_or_default();
    let (rdns_class, rdns_note) = classify_rdns(&primary_rdns);

    let is_hosting = is_datacenter
        || company_type == "hosting"
        || asn_type == "hosting"
        || rdns_class == "cloud_hosting";
    let is_residential = !is_hosting
        && !is_bogon
        && !is_anycast
        && (company_type == "isp" || asn_type == "isp" || rdns_class == "residential_dialup");

    let (usage_kind, usage_label) = if is_bogon {
        ("bogon", "保留 / Bogon 非公网地址")
    } else if is_hosting {
        ("hosting", "数据中心 / 云服务器托管 (IDC)")
    } else if is_mobile {
        ("mobile", "移动蜂窝运营商网络")
    } else if is_residential {
        ("isp", "家庭住宅宽带 (ISP)")
    } else if company_type == "business" || asn_type == "business" {
        ("business", "商业企业专线网络")
    } else if company_type == "education" || asn_type == "education" {
        ("education", "高校与科研教育网")
    } else if company_type == "government" || asn_type == "government" {
        ("government", "政府与公共机构网络")
    } else {
        ("unknown", "常规公网自治网络")
    };

    // Native vs Broadcast verdict
    let (native_status, native_label, native_detail) = if !country_consistent {
        (
            "conflicted",
            "多源冲突",
            format!(
                "多源地理库返回不同国家（{}），常见于刚迁移宣告的广播段或任播节点",
                reported_countries.iter().cloned().collect::<Vec<_>>().join(" / ")
            ),
        )
    } else if !country_code.is_empty() && !registered_country_code.is_empty() {
        if country_code == registered_country_code {
            (
                "native",
                "原生 IP",
                format!("落地定位国 ({country_code}) 与 RIR 注册分配国 ({registered_country_code}) 完全一致"),
            )
        } else {
            (
                "broadcast",
                "广播 IP",
                format!("RIR 原始注册于 {registered_country_code}，当前跨国路由广播落地于 {country_code}"),
            )
        }
    } else {
        ("unknown", "待核验", "缺少完整 RIR 注册国对照数据".into())
    };

    // Timezone alignment
    let sys_tz = input.system_timezone.map(|s| clip(s, 64)).unwrap_or_default();
    let timezone_aligned = if !timezone.is_empty() && !sys_tz.is_empty() {
        Some(timezone == sys_tz)
    } else {
        None
    };

    // RPKI normalization
    let rpki = normalize_rpki(input.ripe_rpki);
    let rpki_status = rpki["status"].as_str().unwrap_or("unknown");

    // Explainable 0..=100 scoring
    let mut score: i32 = 100;
    let mut factors: Vec<ScoreFactor> = Vec::new();

    match usage_kind {
        "isp" => factors.push(ScoreFactor {
            id: "host_type".into(),
            label: "ISP 家庭宽带宿主".into(),
            delta: 0,
            status: "pass".into(),
            detail: "归属正规宽带接入商 (ISP)，未命中机房或云托管特征".into(),
        }),
        "mobile" => {
            score -= 3;
            factors.push(ScoreFactor {
                id: "host_type".into(),
                label: "移动蜂窝网络".into(),
                delta: -3,
                status: "info".into(),
                detail: "运营商 CGNAT 移动网关出口，自然人度高但共享 IP 用户较多".into(),
            });
        }
        "business" | "education" => {
            score -= 6;
            factors.push(ScoreFactor {
                id: "host_type".into(),
                label: "商业 / 教育专线".into(),
                delta: -6,
                status: "info".into(),
                detail: format!("主体分类为 {usage_label}，信誉优于云机房但次于原生家宽"),
            });
        }
        "hosting" => {
            score -= 24;
            let dc_suffix = if datacenter_name.is_empty() {
                company_name.clone()
            } else {
                datacenter_name.clone()
            };
            factors.push(ScoreFactor {
                id: "host_type".into(),
                label: "数据中心 / 云机房托管".into(),
                delta: -24,
                status: "warn".into(),
                detail: format!("识别为机房托管网段（{dc_suffix}），AI 平台对机房段风控阈值更严格"),
            });
        }
        "bogon" => {
            score -= 60;
            factors.push(ScoreFactor {
                id: "host_type".into(),
                label: "Bogon / 保留地址".into(),
                delta: -60,
                status: "fail".into(),
                detail: "属于非标准公网单播路由段".into(),
            });
        }
        _ => {
            score -= 8;
            factors.push(ScoreFactor {
                id: "host_type".into(),
                label: "未明确宽带类型".into(),
                delta: -8,
                status: "info".into(),
                detail: "缺少明确 ISP 住宅标记".into(),
            });
        }
    }

    match native_status {
        "native" => factors.push(ScoreFactor {
            id: "native_ip".into(),
            label: "RIR 原生归属 IP".into(),
            delta: 0,
            status: "pass".into(),
            detail: native_detail.clone(),
        }),
        "broadcast" => {
            score -= 8;
            factors.push(ScoreFactor {
                id: "native_ip".into(),
                label: "跨国广播 IP".into(),
                delta: -8,
                status: "warn".into(),
                detail: native_detail.clone(),
            });
        }
        "conflicted" => {
            score -= 18;
            factors.push(ScoreFactor {
                id: "native_ip".into(),
                label: "多源地理国家冲突".into(),
                delta: -18,
                status: "fail".into(),
                detail: native_detail.clone(),
            });
        }
        _ => {}
    }

    let worst_ratio = match (company_abuser.ratio, asn_abuser.ratio) {
        (Some(c), Some(a)) => Some(c.max(a * 0.85)),
        (Some(c), None) => Some(c),
        (None, Some(a)) => Some(a),
        (None, None) => None,
    };
    if let Some(r) = worst_ratio {
        let pct = r * 100.0;
        let (delta, st, title) = if r < 0.0012 {
            (0, "pass", "网段历史滥用率极低")
        } else if r < 0.005 {
            (-5, "info", "网段存在少量历史噪声")
        } else if r < 0.02 {
            (-14, "warn", "网段历史滥用率偏高")
        } else if r < 0.08 {
            (-24, "fail", "网段历史滥用率高")
        } else {
            (-36, "fail", "高危滥用网段")
        };
        score += delta;
        factors.push(ScoreFactor {
            id: "abuser_ratio".into(),
            label: title.into(),
            delta,
            status: st.into(),
            detail: format!("企业滥用度 {:.2}% · ASN 滥用度 {:.2}%", company_abuser.ratio.unwrap_or(0.0) * 100.0, asn_abuser.ratio.unwrap_or(0.0) * 100.0 + pct * 0.0),
        });
    }

    if is_tor {
        score -= 45;
        factors.push(ScoreFactor {
            id: "tor".into(),
            label: "命中 Tor 匿名出口节点".into(),
            delta: -45,
            status: "fail".into(),
            detail: "AI 服务普遍直接封禁 Tor 出口".into(),
        });
    }
    if is_abuser {
        score -= 28;
        factors.push(ScoreFactor {
            id: "abuser".into(),
            label: "当前 IP 存在直接滥用记录".into(),
            delta: -28,
            status: "fail".into(),
            detail: "该单 IP 近期曾触发垃圾请求、扫描或恶意行为情报库".into(),
        });
    }
    if is_proxy {
        score -= 20;
        factors.push(ScoreFactor {
            id: "proxy".into(),
            label: "命中公开/商业共享代理库".into(),
            delta: -20,
            status: "fail".into(),
            detail: "已被主流反欺诈指纹库标记为公开或共享 Proxy".into(),
        });
    }
    if is_vpn {
        score -= 16;
        let svc = if vpn_service.is_empty() {
            "已知商业 VPN 出口".to_owned()
        } else {
            format!("识别为商业 VPN（{vpn_service}）")
        };
        factors.push(ScoreFactor {
            id: "vpn".into(),
            label: svc,
            delta: -16,
            status: "warn".into(),
            detail: "已知商业 VPN 出口易触发 Cloudflare 质询及 AI 账号连坐风控".into(),
        });
    }
    if is_crawler {
        score -= 14;
        factors.push(ScoreFactor {
            id: "crawler".into(),
            label: "命中爬虫 / 自动化机器人地址库".into(),
            delta: -14,
            status: "warn".into(),
            detail: "存在自动化抓取标记".into(),
        });
    }
    if is_anycast {
        score -= 10;
        factors.push(ScoreFactor {
            id: "anycast".into(),
            label: "全球任播 (Anycast) 地址".into(),
            delta: -10,
            status: "info".into(),
            detail: "任播基础设施地址，非自然人独享终端出口".into(),
        });
    }
    if rpki_status.starts_with("invalid") {
        score -= 10;
        factors.push(ScoreFactor {
            id: "rpki".into(),
            label: "RPKI 路由签名校验失败".into(),
            delta: -10,
            status: "warn".into(),
            detail: rpki["label"].as_str().unwrap_or("").to_owned(),
        });
    } else if rpki_status == "valid" {
        factors.push(ScoreFactor {
            id: "rpki".into(),
            label: "RPKI 路由起源签名合法".into(),
            delta: 0,
            status: "pass".into(),
            detail: "RIPE NCC Routinator 验证 ROA 签名通过".into(),
        });
    }
    if country_code == "CN" || registered_country_code == "CN" {
        score -= 35;
        factors.push(ScoreFactor {
            id: "cn_region".into(),
            label: "涉及中国大陆归属或注册主体".into(),
            delta: -35,
            status: "fail".into(),
            detail: "Claude / OpenAI 不支持中国大陆区域访问，且 CN 注册 ASN 存在高封号风险".into(),
        });
    }

    let final_score = score.clamp(0, 100);
    let (purity_tier, purity_label) = match final_score {
        88..=100 => ("excellent", "极度纯净"),
        72..=87 => ("good", "纯净良好"),
        55..=71 => ("fair", "一般可用"),
        35..=54 => ("elevated", "风险偏高"),
        _ => ("high_risk", "高危阻断"),
    };

    // AI Platform Scenario Assessments
    let unsupported_region = matches!(country_code.as_str(), "CN" | "HK" | "MO" | "RU" | "BY" | "IR" | "KP");
    let claude_verdict = if unsupported_region || registered_country_code == "CN" {
        json!({"grade": "高危阻断", "status": "fail", "detail": "命中不支持服务区或中国注册 ASN，严禁登录真实 Claude 账号"})
    } else if final_score >= 85 && is_residential {
        json!({"grade": "极佳 · 原生家宽级", "status": "pass", "detail": "ISP 家宽宿主且滥用率极低，适合长期稳定登录 Claude Pro/Max 主力号"})
    } else if final_score >= 68 {
        json!({"grade": "良好 · 注意环境一致", "status": "info", "detail": "无严重黑名单记录，但存在机房/商宽或广播特征，建议保持固定节点与一致时区"})
    } else {
        json!({"grade": "谨慎 · 易触发封控", "status": "warn", "detail": "机房共享/商业 VPN 或高滥用段，Claude 对此类出口风控极严"})
    };

    let chatgpt_verdict = if unsupported_region {
        json!({"grade": "地区受限", "status": "fail", "detail": "当前落地国家/地区不在 OpenAI 官方支持列表内"})
    } else if final_score >= 82 {
        json!({"grade": "极佳 · 畅通无感", "status": "pass", "detail": "低滥用纯净出口，不易触发 Cloudflare Turnstile 盾或降智限流"})
    } else if final_score >= 60 && !is_tor && !is_abuser {
        json!({"grade": "可用 · 偶发质询", "status": "info", "detail": "正常对话可用，机房/VPN 标记在高并发时可能触发验证码或网页降级"})
    } else {
        json!({"grade": "高风险 · 易降智/拦截", "status": "warn", "detail": "高滥用或公开代理段，易遭遇 403 拒绝访问与账号审查"})
    };

    let api_verdict = if unsupported_region {
        json!({"grade": "API 403 封锁区", "status": "fail", "detail": "Cloudflare 边缘网关会按地区拦截 API 调用"})
    } else if !is_tor && !is_abuser && final_score >= 58 {
        json!({"grade": "极佳 · 稳定直通", "status": "pass", "detail": "API 密钥调用对机房宿主宽容度较高，当前网段信誉满足生产/CLI 调用"})
    } else {
        json!({"grade": "存在拦截隐患", "status": "warn", "detail": "网段存在滥用黑名单，可能触发 Cloudflare WAF 403/429 拦截"})
    };

    let related_domains: Vec<Value> = input
        .ptr_domains
        .iter()
        .take(16)
        .map(|d| json!({"domain": clip(d, 128), "via": "DoH PTR (in-addr.arpa)"}))
        .collect();

    json!({
        "schema": 1,
        "status": "complete",
        "ip": canonical_ip,
        "query": canonical_ip,
        "queriedAt": input.queried_at,
        "finishedAt": input.finished_at,
        "transport": input.transport,
        // Legacy-compatible top-level mirrors so existing audit/snapshot readers keep working seamlessly:
        "trust_score": final_score,
        "country": country,
        "countryCode": country_code,
        "country_code": country_code,
        "registered_country_code": registered_country_code,
        "region": region,
        "city": city,
        "timezone": timezone,
        "local_time": local_time,
        "cidr": asn_route,
        "rdns": primary_rdns,
        "rdns_class": rdns_class,
        "rdns_note": rdns_note,
        "asn": asn_number,
        "asOrganization": asn_org,
        "asn_kind": asn_type,
        "asn_allocated": asn_created,
        "rir": rir,
        "company_name": company_name,
        "company_type": company_type,
        "company_domain": company_domain,
        "company_network": company_network,
        "datacenter_name": datacenter_name,
        "vpn_service": vpn_service,
        "vpn_region": vpn_region,
        "abuse_email": abuse_email,
        "isResidential": is_residential,
        "is_residential": is_residential,
        "is_datacenter": is_datacenter,
        "is_hosting": is_hosting,
        "is_vpn": is_vpn,
        "is_proxy": is_proxy,
        "is_tor": is_tor,
        "is_crawler": is_crawler,
        "is_abuser": is_abuser,
        "is_mobile": is_mobile,
        "is_satellite": is_satellite,
        "is_anycast": is_anycast,
        "is_bogon": is_bogon,
        // Rich structured sections for NetworkPanoramaPage:
        "score": {
            "value": final_score,
            "tier": purity_tier,
            "label": purity_label,
            "factors": factors,
        },
        "usage": {
            "kind": usage_kind,
            "label": usage_label,
            "native_status": native_status,
            "native_label": native_label,
            "native_detail": native_detail,
            "registered_country_code": registered_country_code,
            "registered_country_source": registered_country_source,
            "system_timezone": sys_tz,
            "timezone_aligned": timezone_aligned,
        },
        "abuser": {
            "company": company_abuser,
            "asn": asn_abuser,
        },
        "rpki": rpki,
        "geo_consistency": {
            "consistent": country_consistent,
            "countries": reported_countries.into_iter().collect::<Vec<_>>(),
            "max_drift_km": max_drift_km,
            "coordinates": coordinates.map(|(lat, lon)| json!({"lat": lat, "lon": lon})),
            "sources": geo_sources,
        },
        "ai_scenarios": {
            "claude": claude_verdict,
            "chatgpt": chatgpt_verdict,
            "api": api_verdict,
        },
        "edge_trace": input.trace,
        "related_domains": related_domains,
        "source_statuses": input.source_statuses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn residential_native_kddi_ip_scores_excellent_with_transparent_factors() {
        let ipapi = json!({
            "ip": "106.178.149.35",
            "rir": "APNIC",
            "is_bogon": false,
            "is_datacenter": false,
            "is_vpn": false,
            "is_proxy": false,
            "is_tor": false,
            "is_crawler": false,
            "is_abuser": false,
            "is_mobile": false,
            "is_satellite": false,
            "is_anycast": false,
            "company": {
                "name": "KDDI CORPORATION",
                "domain": "kddi.com",
                "network": "106.128.0.0 - 106.191.255.255",
                "abuser_score": "0.0004 (Very Low)",
                "type": "isp"
            },
            "asn": {
                "asn": 2516,
                "org": "KDDI CORPORATION",
                "country": "jp",
                "type": "isp",
                "route": "106.178.0.0/16",
                "rir": "APNIC",
                "created": "2002-04-05",
                "abuser_score": "0.0005 (Very Low)"
            },
            "location": {
                "country": "Japan",
                "country_code": "JP",
                "state": "Tokyo",
                "city": "Tokyo",
                "latitude": 35.6895,
                "longitude": 139.6917,
                "timezone": "Asia/Tokyo"
            }
        });
        let ipinfo = json!({
            "ip": "106.178.149.35",
            "country": "JP",
            "region": "Tokyo",
            "city": "Shinjuku",
            "loc": "35.6938,139.7034",
            "org": "AS2516 KDDI CORPORATION",
            "timezone": "Asia/Tokyo"
        });
        let trace = parse_cloudflare_trace("ip=106.178.149.35\nloc=JP\ncolo=NRT\ntls=TLSv1.3\nhttp=http/2\nsni=plaintext\nwarp=off\n").unwrap();
        let ptr = vec!["KD106178149035.ppp.dion.ne.jp".to_owned()];
        let rpki = json!({"data":{"status":"valid","prefix":"106.178.0.0/16","resource":"2516","validating_roas":[{"origin":"AS2516","prefix":"106.178.0.0/16","max_length":16,"validity":"valid"}]}});

        let out = evaluate_ip_intelligence(&IpIntelInput {
            query_ip: "106.178.149.35",
            ipapi: Some(&ipapi),
            ipinfo: Some(&ipinfo),
            ripe_rpki: Some(&rpki),
            ripe_country: Some("JP"),
            ptr_domains: &ptr,
            trace: Some(&trace),
            system_timezone: Some("Asia/Tokyo"),
            queried_at: 100.0,
            finished_at: 100.4,
            transport: "explicit proxy",
            source_statuses: &json!({"ipapi":"ok"}),
        });

        assert_eq!(out["status"], "complete");
        assert_eq!(out["score"]["value"], 100);
        assert_eq!(out["score"]["tier"], "excellent");
        assert_eq!(out["usage"]["native_status"], "native");
        assert_eq!(out["usage"]["timezone_aligned"], true);
        assert_eq!(out["isResidential"], true);
        assert_eq!(out["rdns_class"], "residential_dialup");
        assert_eq!(out["rpki"]["status"], "valid");
        assert_eq!(out["edge_trace"]["colo_city"], "东京 (Narita)");
        assert!(out["geo_consistency"]["max_drift_km"].as_f64().unwrap() < 5.0);
    }

    #[test]
    fn datacenter_vpn_broadcast_ip_receives_itemized_deductions() {
        let ipapi = json!({
            "ip": "187.13.197.43",
            "is_datacenter": true,
            "is_vpn": true,
            "vpn": { "service": "NordVPN", "exit_node_region": "France #1168" },
            "datacenter": { "datacenter": "PacketHub S.A.", "route": "187.13.197.0/24" },
            "company": { "name": "PacketHub S.A.", "abuser_score": "0.0250 (High)", "type": "hosting" },
            "asn": { "asn": 212238, "org": "Datacamp Limited", "country": "GB", "type": "hosting", "abuser_score": "0.0150 (Elevated)" },
            "location": { "country": "France", "country_code": "FR", "city": "Marseille", "timezone": "Europe/Paris" }
        });
        let out = evaluate_ip_intelligence(&IpIntelInput {
            query_ip: "187.13.197.43",
            ipapi: Some(&ipapi),
            ipinfo: None,
            ripe_rpki: None,
            ripe_country: Some("GB"),
            ptr_domains: &[],
            trace: None,
            system_timezone: Some("Asia/Shanghai"),
            queried_at: 10.0,
            finished_at: 10.2,
            transport: "explicit proxy",
            source_statuses: &json!({"ipapi":"ok"}),
        });

        let score = out["score"]["value"].as_i64().unwrap();
        assert!(score < 50, "hosting + broadcast + VPN + high abuser must score below 50, got {score}");
        assert_eq!(out["usage"]["native_status"], "broadcast");
        assert_eq!(out["usage"]["timezone_aligned"], false);
        assert_eq!(out["vpn_service"], "NordVPN");
        assert_eq!(out["datacenter_name"], "PacketHub S.A.");
    }
}
