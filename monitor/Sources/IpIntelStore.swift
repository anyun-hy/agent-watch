import Foundation
import Combine

struct IpScoreFactor: Codable, Identifiable, Sendable {
    let id: String
    let label: String
    let delta: Int
    let status: String
    let detail: String
}

struct IpScoreSummary: Codable, Sendable {
    let value: Int
    let tier: String
    let label: String
    let factors: [IpScoreFactor]
}

struct IpUsageProfile: Codable, Sendable {
    let kind: String
    let label: String
    let native_status: String
    let native_label: String
    let native_detail: String
    let registered_country_code: String
    let registered_country_source: String
    let system_timezone: String
    let timezone_aligned: Bool?
}

struct IpAbuserMetric: Codable, Sendable {
    let raw: String
    let ratio: Double?
    let tier: String
    let tier_zh: String
}

struct IpAbuserSummary: Codable, Sendable {
    let company: IpAbuserMetric
    let asn: IpAbuserMetric
}

struct IpRpkiRoa: Codable, Sendable {
    let origin: String
    let prefix: String
    let max_length: Int?
    let validity: String
}

struct IpRpkiSummary: Codable, Sendable {
    let status: String
    let label: String
    let prefix: String
    let resource: String
    let roas: [IpRpkiRoa]
}

struct IpGeoSourceRow: Codable, Identifiable, Sendable {
    let source: String
    let country_code: String
    let country: String
    let region: String
    let city: String
    let latitude: Double?
    let longitude: Double?
    let timezone: String
    var id: String { source }
}

struct IpCoordinates: Codable, Sendable {
    let lat: Double
    let lon: Double
}

struct IpGeoConsistency: Codable, Sendable {
    let consistent: Bool
    let countries: [String]
    let max_drift_km: Double?
    let coordinates: IpCoordinates?
    let sources: [IpGeoSourceRow]
}

struct IpScenarioVerdict: Codable, Sendable {
    let grade: String
    let status: String
    let detail: String
}

struct IpAiScenarios: Codable, Sendable {
    let claude: IpScenarioVerdict
    let chatgpt: IpScenarioVerdict
    let api: IpScenarioVerdict
}

struct IpEdgeTrace: Codable, Sendable {
    let ip: String
    let country_code: String
    let colo: String
    let colo_city: String
    let tls: String
    let http: String
    let sni: String
    let warp: String
    let kex: String
    let gateway: String
}

struct IpRelatedDomain: Codable, Identifiable, Sendable {
    let domain: String
    let via: String
    var id: String { domain + ":" + via }
}

struct IpIntelReport: Codable, Sendable {
    let schema: Int?
    let status: String
    var ip: String? = nil
    var query: String? = nil
    var queriedAt: Double? = nil
    var finishedAt: Double? = nil
    var transport: String? = nil
    var error: String? = nil
    var sha256: String? = nil
    var cache_state: String? = nil

    var country: String? = nil
    var countryCode: String? = nil
    var registered_country_code: String? = nil
    var region: String? = nil
    var city: String? = nil
    var timezone: String? = nil
    var local_time: String? = nil
    var cidr: String? = nil
    var rdns: String? = nil
    var rdns_class: String? = nil
    var rdns_note: String? = nil
    var asn: Int? = nil
    var asOrganization: String? = nil
    var asn_kind: String? = nil
    var asn_allocated: String? = nil
    var rir: String? = nil
    var company_name: String? = nil
    var company_type: String? = nil
    var company_domain: String? = nil
    var company_network: String? = nil
    var datacenter_name: String? = nil
    var vpn_service: String? = nil
    var vpn_region: String? = nil
    var abuse_email: String? = nil

    var is_residential: Bool? = nil
    var is_datacenter: Bool? = nil
    var is_hosting: Bool? = nil
    var is_vpn: Bool? = nil
    var is_proxy: Bool? = nil
    var is_tor: Bool? = nil
    var is_crawler: Bool? = nil
    var is_abuser: Bool? = nil
    var is_mobile: Bool? = nil
    var is_satellite: Bool? = nil
    var is_anycast: Bool? = nil
    var is_bogon: Bool? = nil

    var score: IpScoreSummary? = nil
    var usage: IpUsageProfile? = nil
    var abuser: IpAbuserSummary? = nil
    var rpki: IpRpkiSummary? = nil
    var geo_consistency: IpGeoConsistency? = nil
    var ai_scenarios: IpAiScenarios? = nil
    var edge_trace: IpEdgeTrace? = nil
    var related_domains: [IpRelatedDomain]? = nil
    var source_statuses: CoffeeJSON? = nil

    var isComplete: Bool {
        status == "complete" && score != nil && (ip?.isEmpty == false)
    }

    static func failure(query: String, message: String) -> IpIntelReport {
        let now = Date().timeIntervalSince1970
        return IpIntelReport(
            schema: 1,
            status: "error",
            ip: query.isEmpty ? nil : query,
            query: query,
            queriedAt: now,
            finishedAt: now,
            error: message
        )
    }
}

private final class IpIntelRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        let child = process
        lock.unlock()
        if child?.isRunning == true { child?.terminate() }
    }

    func run(ip: String?) -> IpIntelReport {
        let query = ip?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil),
              FileManager.default.isExecutableFile(atPath: engine.path) else {
            return .failure(query: query, message: "找不到 Rust 权威 IP 情报引擎组件（watch-engine）。")
        }
        let task = Process()
        let out = Pipe()
        task.executableURL = engine
        task.arguments = query.isEmpty ? ["ip-intel"] : ["ip-intel", "--ip", query]
        task.standardOutput = out
        task.standardError = FileHandle.nullDevice

        lock.lock()
        if cancelled {
            lock.unlock()
            return .failure(query: query, message: "查询已取消")
        }
        process = task
        do {
            try task.run()
        } catch {
            process = nil
            lock.unlock()
            return .failure(query: query, message: "启动 IP 情报组件失败")
        }
        lock.unlock()

        let killer = DispatchWorkItem { [weak self] in self?.cancel() }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 22, execute: killer)
        let bytes = out.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        killer.cancel()

        lock.lock()
        process = nil
        let wasCancelled = cancelled
        lock.unlock()

        if wasCancelled {
            return .failure(query: query, message: "查询已取消或超过时限")
        }
        guard bytes.count <= 1_048_576,
              let decoded = try? JSONDecoder().decode(IpIntelReport.self, from: bytes) else {
            return .failure(query: query, message: "IP 情报回执解析失败")
        }
        return decoded
    }
}

@MainActor
final class IpIntelStore: ObservableObject {
    @Published var queryInput = ""
    @Published private(set) var selectedIP = ""
    @Published private(set) var currentExitIP = ""
    @Published private(set) var reports: [String: IpIntelReport] = [:]
    @Published private(set) var isRunning = false
    @Published private(set) var errorMessage: String?

    let isFixture: Bool
    private let ttl: TimeInterval = 300
    private var runner: IpIntelRunner?
    private var activeGeneration: UUID?

    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
        if self.isFixture {
            loadFixture()
        }
    }

    var currentReport: IpIntelReport? {
        if !selectedIP.isEmpty, let r = reports[selectedIP] { return r }
        if !currentExitIP.isEmpty, let r = reports[currentExitIP] { return r }
        return nil
    }

    func report(for ip: String) -> IpIntelReport? {
        guard let canonical = LeakIPAddress(ip)?.canonical else { return nil }
        return reports[canonical]
    }

    func isFresh(_ ip: String, now: Date = Date()) -> Bool {
        guard let r = report(for: ip), let ts = r.finishedAt else { return false }
        let age = now.timeIntervalSince1970 - ts
        return age >= 0 && age < ttl
    }

    func noteEnvironmentExit(_ rawIP: String) {
        guard let parsed = LeakIPAddress(rawIP), parsed.isPublic else { return }
        let ip = parsed.canonical
        currentExitIP = ip
        if selectedIP.isEmpty {
            selectedIP = ip
        }
        if !isFixture && reports[ip] == nil && !isRunning {
            query(ip: ip, force: false)
        }
    }

    func focusAndQuery(_ rawIP: String) {
        let trimmed = rawIP.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            queryInput = ""
            queryCurrentExit(force: true)
            return
        }
        guard let parsed = LeakIPAddress(trimmed), parsed.isPublic else {
            errorMessage = "请输入有效的公网单播 IPv4 或 IPv6；本机与保留网段不提交查询。"
            return
        }
        queryInput = parsed.canonical
        selectedIP = parsed.canonical
        query(ip: parsed.canonical, force: false)
    }

    func queryCurrentExit(force: Bool = true) {
        queryInput = ""
        query(ip: nil, force: force)
    }

    func submitCustomOrCurrent() {
        let trimmed = queryInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            queryCurrentExit(force: true)
        } else {
            guard let parsed = LeakIPAddress(trimmed), parsed.isPublic else {
                errorMessage = "请输入有效的公网单播 IPv4 或 IPv6；本机与保留网段不提交查询。"
                return
            }
            selectedIP = parsed.canonical
            query(ip: parsed.canonical, force: true)
        }
    }

    func cancel() {
        activeGeneration = nil
        runner?.cancel()
        runner = nil
        isRunning = false
    }

    func query(ip: String?, force: Bool) {
        if let ip, !ip.isEmpty, !force, isFresh(ip) {
            selectedIP = ip
            errorMessage = nil
            return
        }
        if isFixture {
            loadFixture()
            if let ip, !ip.isEmpty {
                selectedIP = ip
                if reports[ip] == nil {
                    reports[ip] = Self.fixtureReport(for: ip)
                }
            }
            errorMessage = nil
            return
        }

        cancel()
        let gen = UUID()
        let activeRunner = IpIntelRunner()
        activeGeneration = gen
        runner = activeRunner
        isRunning = true
        errorMessage = nil
        if let ip, !ip.isEmpty {
            selectedIP = ip
        }

        Task { [weak self] in
            let report = await Task.detached(priority: .utility) {
                activeRunner.run(ip: ip)
            }.value
            guard let self, self.activeGeneration == gen else { return }
            self.activeGeneration = nil
            self.runner = nil
            self.isRunning = false

            if report.isComplete, let resolvedIP = report.ip, let canonical = LeakIPAddress(resolvedIP)?.canonical {
                self.reports[canonical] = report
                self.selectedIP = canonical
                if ip == nil || ip?.isEmpty == true {
                    self.currentExitIP = canonical
                }
                self.errorMessage = nil
            } else {
                self.errorMessage = report.error ?? "未取得权威 IP 风控画像"
            }
        }
    }

    func loadFixture() {
        let sample = Self.fixtureReport(for: "203.0.113.88")
        reports["203.0.113.88"] = sample
        reports["8.8.8.8"] = Self.fixtureReport(for: "8.8.8.8", datacenter: true)
        if selectedIP.isEmpty {
            selectedIP = "203.0.113.88"
            currentExitIP = "203.0.113.88"
        }
    }

    static func fixtureReport(for ip: String, datacenter: Bool = false) -> IpIntelReport {
        let now = Date().timeIntervalSince1970
        let val = datacenter ? 62 : 98
        return IpIntelReport(
            schema: 1,
            status: "complete",
            ip: ip,
            query: ip,
            queriedAt: now - 0.5,
            finishedAt: now,
            transport: "HTTPS CONNECT via http://127.0.0.1:7890",
            country: "Japan",
            countryCode: "JP",
            registered_country_code: "JP",
            region: "Tokyo",
            city: "Tokyo",
            timezone: "Asia/Tokyo",
            local_time: "2026-11-27T11:00:00+09:00",
            cidr: "\(ip)/24",
            rdns: datacenter ? "dns.google" : "ftth-tokyo-residential.jp.example",
            rdns_class: datacenter ? "public_infra" : "residential_dialup",
            rdns_note: datacenter ? "公共基础设施任播节点" : "主机名呈家庭宽带动态拨号 / FTTH 接入特征",
            asn: datacenter ? 15169 : 2516,
            asOrganization: datacenter ? "Google LLC" : "KDDI CORPORATION",
            asn_kind: datacenter ? "hosting" : "isp",
            asn_allocated: "2002-04-05",
            rir: "APNIC",
            company_name: datacenter ? "Google LLC" : "KDDI CORPORATION",
            company_type: datacenter ? "hosting" : "isp",
            company_domain: datacenter ? "google.com" : "kddi.com",
            company_network: "106.128.0.0/10",
            is_residential: !datacenter,
            is_datacenter: datacenter,
            is_hosting: datacenter,
            is_vpn: false,
            is_proxy: false,
            is_tor: false,
            is_crawler: false,
            is_abuser: false,
            is_mobile: false,
            is_satellite: false,
            is_anycast: datacenter,
            is_bogon: false,
            score: IpScoreSummary(
                value: val,
                tier: datacenter ? "fair" : "excellent",
                label: datacenter ? "一般可用" : "极度纯净",
                factors: [
                    IpScoreFactor(id: "host_type", label: datacenter ? "数据中心托管" : "ISP 家庭宽带宿主", delta: datacenter ? -24 : 0, status: datacenter ? "warn" : "pass", detail: datacenter ? "识别为机房托管网段" : "归属正规宽带接入商 (ISP)"),
                    IpScoreFactor(id: "native_ip", label: "RIR 原生归属 IP", delta: 0, status: "pass", detail: "落地定位国 (JP) 与 RIR 注册分配国 (JP) 完全一致"),
                    IpScoreFactor(id: "abuser_ratio", label: "网段历史滥用率极低", delta: 0, status: "pass", detail: "企业滥用度 0.04% · ASN 滥用度 0.05%"),
                    IpScoreFactor(id: "rpki", label: "RPKI 路由起源签名合法", delta: 0, status: "pass", detail: "RIPE NCC Routinator 验证 ROA 签名通过")
                ]
            ),
            usage: IpUsageProfile(
                kind: datacenter ? "hosting" : "isp",
                label: datacenter ? "数据中心 / 云服务器托管 (IDC)" : "家庭住宅宽带 (ISP)",
                native_status: "native",
                native_label: "原生 IP",
                native_detail: "落地定位国 (JP) 与 RIR 注册分配国 (JP) 完全一致",
                registered_country_code: "JP",
                registered_country_source: "RIPEstat RIR",
                system_timezone: "Asia/Tokyo",
                timezone_aligned: true
            ),
            abuser: IpAbuserSummary(
                company: IpAbuserMetric(raw: "0.0004 (Very Low)", ratio: 0.0004, tier: "very_low", tier_zh: "极度纯净"),
                asn: IpAbuserMetric(raw: "0.0005 (Very Low)", ratio: 0.0005, tier: "very_low", tier_zh: "极度纯净")
            ),
            rpki: IpRpkiSummary(
                status: "valid",
                label: "Valid（合法签名宣告）",
                prefix: "106.178.0.0/16",
                resource: "2516",
                roas: [IpRpkiRoa(origin: "AS2516", prefix: "106.178.0.0/16", max_length: 16, validity: "valid")]
            ),
            geo_consistency: IpGeoConsistency(
                consistent: true,
                countries: ["JP"],
                max_drift_km: 1.8,
                coordinates: IpCoordinates(lat: 35.6895, lon: 139.6917),
                sources: [
                    IpGeoSourceRow(source: "ipapi.is", country_code: "JP", country: "Japan", region: "Tokyo", city: "Tokyo", latitude: 35.6895, longitude: 139.6917, timezone: "Asia/Tokyo"),
                    IpGeoSourceRow(source: "ipinfo.io", country_code: "JP", country: "Japan", region: "Tokyo", city: "Shinjuku", latitude: 35.6938, longitude: 139.7034, timezone: "Asia/Tokyo"),
                    IpGeoSourceRow(source: "Cloudflare Edge", country_code: "JP", country: "JP", region: "", city: "东京 (Narita)", latitude: nil, longitude: nil, timezone: "")
                ]
            ),
            ai_scenarios: IpAiScenarios(
                claude: IpScenarioVerdict(grade: "极佳 · 原生家宽级", status: "pass", detail: "ISP 家宽宿主且滥用率极低，适合长期稳定登录 Claude 主力号"),
                chatgpt: IpScenarioVerdict(grade: "极佳 · 畅通无感", status: "pass", detail: "低滥用纯净出口，不易触发 Cloudflare 质询或降智限流"),
                api: IpScenarioVerdict(grade: "极佳 · 稳定直通", status: "pass", detail: "当前网段信誉满足生产与 CLI 高频调用")
            ),
            edge_trace: IpEdgeTrace(
                ip: ip,
                country_code: "JP",
                colo: "NRT",
                colo_city: "东京 (Narita)",
                tls: "TLSv1.3",
                http: "http/2",
                sni: "plaintext",
                warp: "off",
                kex: "X25519MLKEM768",
                gateway: "off"
            ),
            related_domains: [IpRelatedDomain(domain: "ftth-tokyo-residential.jp.example", via: "DoH PTR (in-addr.arpa)")]
        )
    }
}
