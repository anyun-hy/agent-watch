//! Bounded, credential-free AI service & edge-protocol observations for the monitor UI.
//!
//! Probes Claude, Anthropic API, ChatGPT, and OpenAI API concurrently through the
//! explicit controlled proxy tunnel, extracting Cloudflare edge POP (`colo`), TLS,
//! HTTP protocol version, SNI, WARP, and challenge headers alongside exit IP & geo.
//! An anonymous HTTP response is a reachability observation, never an account-health claim.

use crate::network_client::{NetworkClient, Receipt, Transport};
use claude_watch_core::{ip_intel::parse_cloudflare_trace, network::public_unicast};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROXY: &str = "http://127.0.0.1:7890";
pub const REFERENCE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";

struct EndpointSpec {
    url: &'static str,
    family: &'static str,
    label: &'static str,
    primary_for_service: bool,
}

const CLAUDE: [EndpointSpec; 2] = [
    EndpointSpec {
        url: "https://claude.ai/cdn-cgi/trace",
        family: "claude",
        label: "Claude Web",
        primary_for_service: true,
    },
    EndpointSpec {
        url: "https://www.anthropic.com/cdn-cgi/trace",
        family: "claude",
        label: "Anthropic 官网",
        primary_for_service: false,
    },
];

const GPT: [EndpointSpec; 2] = [
    EndpointSpec {
        url: "https://chatgpt.com/cdn-cgi/trace",
        family: "gpt",
        label: "ChatGPT Web",
        primary_for_service: true,
    },
    EndpointSpec {
        url: "https://api.openai.com/v1/models",
        family: "gpt",
        label: "OpenAI Platform API",
        primary_for_service: false,
    },
];

const ALL_PANORAMA: [EndpointSpec; 5] = [
    EndpointSpec {
        url: "https://claude.ai/cdn-cgi/trace",
        family: "claude",
        label: "Claude Web",
        primary_for_service: true,
    },
    EndpointSpec {
        url: "https://www.anthropic.com/cdn-cgi/trace",
        family: "claude",
        label: "Anthropic 官网",
        primary_for_service: false,
    },
    EndpointSpec {
        url: "https://api.anthropic.com/v1/models",
        family: "claude",
        label: "Anthropic Messages API",
        primary_for_service: false,
    },
    EndpointSpec {
        url: "https://chatgpt.com/cdn-cgi/trace",
        family: "gpt",
        label: "ChatGPT Web",
        primary_for_service: false,
    },
    EndpointSpec {
        url: "https://api.openai.com/v1/models",
        family: "gpt",
        label: "OpenAI Platform API",
        primary_for_service: false,
    },
];

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |v| v.as_secs_f64())
}
fn clip(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}
fn issue(stage: &str, code: &str, message: impl Into<String>) -> Value {
    json!({"stage":stage,"code":code,"message":clip(&message.into(), 256)})
}
fn endpoint_message(status: Option<u16>, problem: Option<&str>, cf_challenge: bool) -> &'static str {
    match problem {
        Some("timeout") | Some("budget_timeout") => "请求超时",
        Some(_) => "请求未完成",
        None => match status {
            Some(401) => "服务已响应；该端点需要认证",
            Some(403) if cf_challenge => "服务已响应；触发 Cloudflare 质询",
            Some(403) => "服务已响应；访问被拒绝",
            Some(429) => "服务已响应；请求受限",
            Some(500..=599) => "服务已响应；服务端异常",
            _ => "服务已响应",
        },
    }
}

/// Minimal, injectable response boundary; tests never create real sockets.
pub trait AiProbeTransport: Send + Sync {
    fn get(&self, url: &str) -> ProbeResponse;
    fn proxy_label(&self) -> String {
        format!("HTTPS CONNECT via {PROXY}")
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResponse {
    pub http_status: Option<u16>,
    pub body: String,
    pub problem: Option<String>,
    pub cf_mitigated: Option<String>,
}
impl ProbeResponse {
    pub fn failed(code: &str) -> Self {
        Self {
            http_status: None,
            body: String::new(),
            problem: Some(code.into()),
            cf_mitigated: None,
        }
    }
}

/// Production adapter backed by `NetworkClient`, retaining its explicit loopback-proxy
/// validation, disabled redirects, and TLS defaults.
pub struct NetworkAiProbeTransport<T: Transport> {
    client: NetworkClient<T>,
}
impl<T: Transport> NetworkAiProbeTransport<T> {
    pub fn new(client: NetworkClient<T>) -> Self {
        Self {
            client: client
                .with_timeout(std::time::Duration::from_secs(6))
                .with_connect_timeout(std::time::Duration::from_secs(6)),
        }
    }
    fn receipt(receipt: Receipt) -> ProbeResponse {
        let cf_mitigated = receipt.response_headers.get("cf-mitigated").cloned();
        ProbeResponse {
            http_status: receipt.http_status,
            body: receipt.raw,
            problem: if receipt.http_status.is_some() {
                None
            } else {
                receipt.error
            },
            cf_mitigated,
        }
    }
}
impl<T: Transport> AiProbeTransport for NetworkAiProbeTransport<T> {
    fn get(&self, url: &str) -> ProbeResponse {
        Self::receipt(self.client.ai_probe(url))
    }
    fn proxy_label(&self) -> String {
        self.client.proxy_description()
    }
}

fn trace_ip(body: &str) -> Option<String> {
    body.lines()
        .find_map(|line| line.strip_prefix("ip="))
        .and_then(canonical_probe_ip)
}

fn canonical_probe_ip(value: &str) -> Option<String> {
    let value = value.trim();
    let mapped = value
        .parse::<std::net::Ipv6Addr>()
        .ok()
        .and_then(|address| address.to_ipv4_mapped())
        .map(|address| address.to_string());
    public_unicast(mapped.as_deref().unwrap_or(value))
}

fn endpoints(service: &str) -> Option<&'static [EndpointSpec]> {
    match service {
        "claude" => Some(&CLAUDE),
        "gpt" => Some(&GPT),
        "all" => Some(&ALL_PANORAMA),
        _ => None,
    }
}

fn observed_endpoint<T: AiProbeTransport>(
    transport: &T,
    spec: Option<&EndpointSpec>,
    url: &str,
) -> (Value, Option<String>, Vec<Value>) {
    let mut local_errors = Vec::new();
    let started = now();
    let response = transport.get(url);
    let elapsed = ((now() - started).max(0.0) * 1000.0 * 1000.0).round() / 1000.0;
    let family = spec.map(|s| s.family).unwrap_or("reference");
    let label = spec.map(|s| s.label).unwrap_or("Cloudflare 1.1.1.1 对照");
    let cf_challenge = response
        .cf_mitigated
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("challenge"));

    if let Some(problem) = response.problem.as_deref() {
        let code = if matches!(problem, "timeout" | "budget_timeout") {
            "timeout"
        } else {
            problem
        };
        local_errors.push(issue("endpoint", code, format!("{url} 请求未完成")));
        return (
            json!({
                "url": url,
                "family": family,
                "label": label,
                "status": if code == "timeout" { "timeout" } else { "error" },
                "httpStatus": response.http_status,
                "elapsedMs": elapsed,
                "message": endpoint_message(response.http_status, Some(problem), cf_challenge),
            }),
            None,
            local_errors,
        );
    }
    let status = response.http_status;
    if !status.is_some_and(|code| (100..=599).contains(&code)) {
        local_errors.push(issue(
            "endpoint",
            "invalid_http_status",
            format!("{url} 返回无效 HTTP 状态"),
        ));
        return (
            json!({
                "url": url,
                "family": family,
                "label": label,
                "status": "error",
                "httpStatus": status,
                "elapsedMs": elapsed,
                "message": "请求未完成",
            }),
            None,
            local_errors,
        );
    }
    let status = status.unwrap();
    if status != 401 && !(200..300).contains(&status) {
        local_errors.push(issue(
            "endpoint",
            "http_status",
            format!("{url} 返回 HTTP {status}"),
        ));
    }

    let mut row = json!({
        "url": url,
        "family": family,
        "label": label,
        "status": "responded",
        "httpStatus": status,
        "elapsedMs": elapsed,
        "message": endpoint_message(Some(status), None, cf_challenge),
        "cfChallenge": cf_challenge,
    });
    if url.ends_with("/cdn-cgi/trace") && (200..300).contains(&status) {
        if let Some(tr) = parse_cloudflare_trace(&response.body) {
            row["exitIP"] = json!(tr.ip);
            row["countryCode"] = json!(tr.country_code);
            row["colo"] = json!(tr.colo);
            row["coloCity"] = json!(tr.colo_city);
            row["tls"] = json!(tr.tls);
            row["httpProtocol"] = json!(tr.http);
            row["sni"] = json!(tr.sni);
            row["warp"] = json!(tr.warp);
            row["kex"] = json!(tr.kex);
        }
    }
    (row, Some(response.body), local_errors)
}

fn geo<T: AiProbeTransport>(transport: &T, address: &str, errors: &mut Vec<Value>) -> Value {
    let url = format!("https://ipinfo.io/{address}/json");
    let (endpoint, body, ep_errs) = observed_endpoint(transport, None, &url);
    errors.extend(ep_errs);
    if endpoint["status"] != "responded"
        || !endpoint["httpStatus"]
            .as_u64()
            .is_some_and(|v| (200..300).contains(&v))
    {
        errors.push(issue("geo", "lookup_failed", "出口 IP 地理信息查询未完成"));
        return json!({});
    }
    let Ok(payload) = serde_json::from_str::<Value>(&body.unwrap_or_default()) else {
        errors.push(issue("geo", "invalid_json", "出口 IP 地理信息格式无效"));
        return json!({});
    };
    let country = payload.get("country").and_then(Value::as_str).unwrap_or("");
    if payload.get("error").is_some()
        || payload.get("ip").and_then(Value::as_str) != Some(address)
        || country.len() != 2
        || !country.is_ascii()
        || !country.bytes().all(|b| b.is_ascii_alphabetic())
    {
        errors.push(issue(
            "geo",
            "identity_mismatch",
            "地理信息未验证为当前出口 IP",
        ));
        return json!({});
    }
    let text = |key| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .map(|v| clip(v, 256))
            .unwrap_or_default()
    };
    let country_name = text("country_name");
    let country_name = if country_name.is_empty() {
        country.to_ascii_uppercase()
    } else {
        country_name
    };
    json!({"countryCode":country.to_ascii_uppercase(),"country":country_name,"region":text("region"),"city":text("city"),"organization":text("org"),"ipTimezone":text("timezone")})
}

/// Collect a JSON value that decodes directly into Swift `AIProbeResult`.
/// Supports `"claude"`, `"gpt"`, and `"all"` (Panorama unified dual-platform sweep).
pub fn collect<T: AiProbeTransport>(service: &str, transport: &T) -> Value {
    let started = now();
    let Some(targets) = endpoints(service) else {
        return json!({"service":service,"status":"error","startedAt":started,"finishedAt":now(),"exitIP":"","referenceIP":"","exitSource":"","countryCode":"","country":"","region":"","city":"","organization":"","ipTimezone":"","endpoints":[],"errors":[issue("collector","invalid_service","不支持的 AI 服务")],"details":[format!("所有请求经受控代理通道（{}）；未跟随重定向或回退直连。", transport.proxy_label())]});
    };

    let (probed_targets, probed_ref) = std::thread::scope(|scope| {
        let jobs: Vec<_> = targets
            .iter()
            .map(|spec| scope.spawn(move || observed_endpoint(transport, Some(spec), spec.url)))
            .collect();
        let ref_job = scope.spawn(|| observed_endpoint(transport, None, REFERENCE_URL));
        let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
        let reference = ref_job.join().unwrap();
        (results, reference)
    });

    let mut errors: Vec<Value> = Vec::new();
    let mut details: Vec<String> = Vec::new();
    let mut output: Vec<Value> = Vec::new();
    let mut exit_ip: Option<String> = None;
    let mut exit_source = "";
    let mut claude_exit_ip: Option<String> = None;
    let mut gpt_exit_ip: Option<String> = None;

    for (idx, (endpoint, body, ep_errs)) in probed_targets.into_iter().enumerate() {
        errors.extend(ep_errs);
        let spec = &targets[idx];
        let ok_2xx = endpoint["status"] == "responded"
            && endpoint["httpStatus"]
                .as_u64()
                .is_some_and(|v| (200..300).contains(&v));
        if spec.url == "https://claude.ai/cdn-cgi/trace" && ok_2xx {
            claude_exit_ip = body.as_deref().and_then(trace_ip);
        }
        if spec.url == "https://chatgpt.com/cdn-cgi/trace" && ok_2xx {
            gpt_exit_ip = body.as_deref().and_then(trace_ip);
        }
        if spec.primary_for_service {
            if ok_2xx {
                exit_ip = body.as_deref().and_then(trace_ip);
                if exit_ip.is_some() {
                    exit_source = spec.url;
                } else {
                    errors.push(issue(
                        "exit",
                        "invalid_exit_ip",
                        "主服务 trace 未返回有效公网出口 IP",
                    ));
                }
            } else {
                details.push("主服务 trace 未成功，未使用其他端点替代 AI 出口。".into());
            }
        }
        output.push(endpoint);
    }

    // In `"all"` mode, if Claude primary failed/blocked, still surface GPT primary exit if available
    if service == "all" && exit_ip.is_none() {
        if let Some(ref ip) = gpt_exit_ip {
            exit_ip = Some(ip.clone());
            exit_source = "https://chatgpt.com/cdn-cgi/trace";
        }
    }

    let (reference, ref_body, ref_errs) = probed_ref;
    errors.extend(ref_errs);
    let reference_ip = if reference["status"] == "responded"
        && reference["httpStatus"]
            .as_u64()
            .is_some_and(|v| (200..300).contains(&v))
    {
        let value = ref_body.as_deref().and_then(trace_ip);
        if value.is_none() {
            errors.push(issue(
                "reference",
                "invalid_reference_ip",
                "HTTP 参考未返回有效公网 IP",
            ));
        }
        value
    } else {
        errors.push(issue("reference", "unavailable", "HTTP 参考未完成"));
        None
    };

    let location = exit_ip
        .as_deref()
        .map(|ip| geo(transport, ip, &mut errors))
        .unwrap_or_else(|| json!({}));

    let all_timeout = output
        .iter()
        .chain(std::iter::once(&reference))
        .all(|row| row["status"] == "timeout");
    let status = if all_timeout {
        "timeout"
    } else if !errors.is_empty() || exit_ip.is_none() {
        "partial"
    } else {
        "complete"
    };
    details.push(format!(
        "所有诊断请求强制经受控代理（{}）；禁用重定向，零直连回退。",
        transport.proxy_label()
    ));

    let exit_ip = exit_ip.unwrap_or_default();
    let mut result = json!({
        "service": service,
        "status": status,
        "startedAt": started,
        "finishedAt": now(),
        "exitIP": exit_ip,
        "claudeExitIP": claude_exit_ip.unwrap_or_default(),
        "gptExitIP": gpt_exit_ip.unwrap_or_default(),
        "referenceIP": reference_ip.unwrap_or_default(),
        "referenceEndpoint": reference,
        "exitSource": exit_source,
        "transport": transport.proxy_label(),
        "countryCode": "",
        "country": "",
        "region": "",
        "city": "",
        "organization": "",
        "ipTimezone": "",
        "endpoints": output,
        "errors": errors,
        "details": details,
    });
    for key in [
        "countryCode",
        "country",
        "region",
        "city",
        "organization",
        "ipTimezone",
    ] {
        if let Some(value) = location.get(key) {
            result[key] = value.clone();
        }
    }
    result
}

pub fn production<T: Transport>(client: NetworkClient<T>, service: &str) -> Value {
    collect(service, &NetworkAiProbeTransport::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_client::{Request, Response, TransportError};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    struct Fake(HashMap<String, ProbeResponse>);
    impl AiProbeTransport for Fake {
        fn get(&self, url: &str) -> ProbeResponse {
            self.0
                .get(url)
                .cloned()
                .unwrap_or_else(|| ProbeResponse::failed("missing"))
        }
    }
    fn fake(service: &str, primary: u16, secondary: u16) -> Fake {
        let mut map = HashMap::new();
        let main = endpoints(service).unwrap();
        map.insert(
            main[0].url.into(),
            ProbeResponse {
                http_status: Some(primary),
                body: "ip=8.8.8.8\nloc=US\ncolo=LAX\ntls=TLSv1.3\nhttp=http/2\nsni=plaintext\nwarp=off\n".into(),
                problem: None,
                cf_mitigated: None,
            },
        );
        map.insert(
            main[1].url.into(),
            ProbeResponse {
                http_status: Some(secondary),
                body: String::new(),
                problem: None,
                cf_mitigated: None,
            },
        );
        map.insert(
            REFERENCE_URL.into(),
            ProbeResponse {
                http_status: Some(200),
                body: "ip=1.1.1.1\nloc=US\ncolo=LAX\n".into(),
                problem: None,
                cf_mitigated: None,
            },
        );
        map.insert(
            "https://ipinfo.io/8.8.8.8/json".into(),
            ProbeResponse {
                http_status: Some(200),
                body: r#"{"ip":"8.8.8.8","country":"US","country_name":"United States"}"#.into(),
                problem: None,
                cf_mitigated: None,
            },
        );
        Fake(map)
    }
    #[test]
    fn gpt_401_is_response_not_auth_claim_and_extracts_edge_colo() {
        let value = collect("gpt", &fake("gpt", 200, 401));
        assert_eq!(value["status"], "complete");
        assert_eq!(value["endpoints"][0]["colo"], "LAX");
        assert_eq!(value["endpoints"][0]["coloCity"], "洛杉矶 (Los Angeles)");
        assert_eq!(value["endpoints"][0]["tls"], "TLSv1.3");
        assert_eq!(value["endpoints"][1]["status"], "responded");
        assert_eq!(value["endpoints"][1]["httpStatus"], 401);
    }
    #[test]
    fn panorama_all_probes_both_claude_and_openai_concurrently() {
        let mut map = HashMap::new();
        for url in [
            "https://claude.ai/cdn-cgi/trace",
            "https://www.anthropic.com/cdn-cgi/trace",
            "https://chatgpt.com/cdn-cgi/trace",
            REFERENCE_URL,
        ] {
            map.insert(
                url.into(),
                ProbeResponse {
                    http_status: Some(200),
                    body: "ip=8.8.8.8\nloc=JP\ncolo=NRT\ntls=TLSv1.3\nhttp=http/2\nsni=plaintext\nwarp=off\n".into(),
                    problem: None,
                    cf_mitigated: None,
                },
            );
        }
        for api_url in [
            "https://api.anthropic.com/v1/models",
            "https://api.openai.com/v1/models",
        ] {
            map.insert(
                api_url.into(),
                ProbeResponse {
                    http_status: Some(401),
                    body: String::new(),
                    problem: None,
                    cf_mitigated: None,
                },
            );
        }
        map.insert(
            "https://ipinfo.io/8.8.8.8/json".into(),
            ProbeResponse {
                http_status: Some(200),
                body: r#"{"ip":"8.8.8.8","country":"JP","country_name":"Japan"}"#.into(),
                problem: None,
                cf_mitigated: None,
            },
        );
        let value = collect("all", &Fake(map));
        assert_eq!(value["status"], "complete");
        assert_eq!(value["endpoints"].as_array().unwrap().len(), 5);
        assert_eq!(value["claudeExitIP"], "8.8.8.8");
        assert_eq!(value["gptExitIP"], "8.8.8.8");
    }
    #[test]
    fn primary_403_does_not_use_secondary_exit() {
        let value = collect("claude", &fake("claude", 403, 200));
        assert_eq!(value["status"], "partial");
        assert_eq!(value["exitIP"], "");
        assert_eq!(value["referenceIP"], "1.1.1.1");
    }
    #[test]
    fn injected_timeout_remains_a_timeout_receipt() {
        let mut transport = fake("claude", 200, 200);
        transport
            .0
            .insert(CLAUDE[0].url.into(), ProbeResponse::failed("timeout"));
        transport
            .0
            .insert(CLAUDE[1].url.into(), ProbeResponse::failed("timeout"));
        transport
            .0
            .insert(REFERENCE_URL.into(), ProbeResponse::failed("timeout"));
        let value = collect("claude", &transport);
        assert_eq!(value["status"], "timeout");
        assert!(value["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["status"] == "timeout"));
    }
    #[test]
    fn mapped_trace_ip_uses_python_ipv4_canonical_form() {
        assert_eq!(trace_ip("ip=::ffff:8.8.8.8\n"), Some("8.8.8.8".into()));
        assert_eq!(trace_ip("xip=1.1.1.1\n"), None);
    }
    #[test]
    fn invalid_geo_is_discarded() {
        let mut transport = fake("claude", 200, 200);
        transport
            .0
            .get_mut("https://ipinfo.io/8.8.8.8/json")
            .unwrap()
            .body = r#"{"ip":"1.1.1.1","country":"US"}"#.into();
        let value = collect("claude", &transport);
        assert_eq!(value["countryCode"], "");
        assert_eq!(value["status"], "partial");
    }
    #[derive(Default)]
    struct NativeFake(Mutex<Vec<Request>>);
    impl Transport for NativeFake {
        fn get(&self, request: &Request) -> Result<Response, TransportError> {
            self.0.lock().unwrap().push(request.clone());
            Ok(Response {
                status: 401,
                headers: HashMap::new(),
                body: Vec::new(),
            })
        }
    }
    #[test]
    fn native_adapter_keeps_loopback_proxy_and_401_response() {
        let native = Arc::new(NativeFake::default());
        let client = NetworkClient::new(native.clone(), Some(PROXY.into())).unwrap();
        let response = NetworkAiProbeTransport::new(client).get("https://api.openai.com/v1/models");
        assert_eq!(response.http_status, Some(401));
        assert!(response.problem.is_none());
        let request = native.0.lock().unwrap().pop().unwrap();
        assert_eq!(request.proxy.as_deref(), Some(PROXY));
        assert_eq!(request.max_body, 32 * 1024);
        assert_eq!(request.timeout, std::time::Duration::from_secs(6));
        assert_eq!(
            request.connect_timeout,
            Some(std::time::Duration::from_secs(6))
        );
    }
}
