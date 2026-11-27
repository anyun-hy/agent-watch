import Foundation
import Combine

enum AIService: String, CaseIterable, Sendable {
    case claude, gpt, all
    var title: String {
        switch self {
        case .claude: return "Claude AI 检测"
        case .gpt: return "GPT / Codex 检测"
        case .all: return "全平台 AI 端点与协议栈探测"
        }
    }
    var product: MonitoredProduct { self == .claude ? .claude : .openAI }
}

struct AIEndpointResult: Codable, Identifiable, Sendable {
    let url, status: String
    var family: String? = nil
    var label: String? = nil
    let httpStatus: Int?
    let elapsedMs: Double?
    let message: String
    var cfChallenge: Bool? = nil
    var exitIP: String? = nil
    var countryCode: String? = nil
    var colo: String? = nil
    var coloCity: String? = nil
    var tls: String? = nil
    var httpProtocol: String? = nil
    var sni: String? = nil
    var warp: String? = nil
    var kex: String? = nil
    var id: String { url }
}

struct AIProbeResult: Codable, Sendable {
    let service, status: String
    let startedAt, finishedAt: Double
    let exitIP, referenceIP, exitSource: String
    var claudeExitIP: String? = nil
    var gptExitIP: String? = nil
    var referenceEndpoint: AIEndpointResult? = nil
    var transport: String? = nil
    let countryCode, country, region, city, organization, ipTimezone: String
    let endpoints: [AIEndpointResult]
    let errors: [LeakProbeError]
    let details: [String]
    static func failure(_ service: AIService, code: String, message: String) -> AIProbeResult {
        let epoch = Date().timeIntervalSince1970
        return .init(service: service.rawValue, status: code == "timeout" ? "timeout" : "error",
            startedAt: epoch, finishedAt: epoch, exitIP: "", referenceIP: "", exitSource: "",
            countryCode: "", country: "", region: "", city: "", organization: "", ipTimezone: "",
            endpoints: [], errors: [.init(stage: "collector", code: code, message: message)], details: [])
    }
}

struct AIProbeState {
    var running = false
    var result: AIProbeResult?
    var verdict = LeakVerdict(state: .idle, title: "未检测", detail: "点击全景扫描后并发探测双平台服务端点与边缘协议栈。")
}

enum AIProbePolicy {
    static let maximumAge: TimeInterval = 300
    static func evaluate(_ result: AIProbeResult, service: AIService, now: Double) -> LeakVerdict {
        func incomplete(_ message: String) -> LeakVerdict { .init(state: .incomplete, title: "检测未完成", detail: message) }
        guard result.service == service.rawValue, result.startedAt.isFinite, result.finishedAt.isFinite,
              result.startedAt <= result.finishedAt, result.finishedAt - result.startedAt <= 90,
              result.finishedAt <= now + 5, result.endpoints.count <= 12, result.errors.count <= 20 else {
            return incomplete("诊断结果无效，不能用于当前判断。")
        }
        guard now - result.finishedAt <= maximumAge else {
            return .init(state: .incomplete, title: "结果已过期", detail: "这次诊断已超过 5 分钟，请重新检测。")
        }
        let limited = result.endpoints.filter { $0.status == "responded" && ($0.httpStatus == 403 || $0.httpStatus == 429 || ($0.httpStatus ?? 0) >= 500) }
        if !limited.isEmpty {
            return .init(state: .difference, title: "存在入口限制或质询", detail: "部分端点返回 403/429/5xx 响应，请核对下方端点列表与 CF 质询标记。")
        }
        guard result.status == "complete", result.errors.isEmpty,
              !result.endpoints.isEmpty, result.endpoints.allSatisfy({ $0.status == "responded" && (100...599).contains($0.httpStatus ?? 0) }),
              LeakIPAddress(result.exitIP)?.isPublic == true, LeakIPAddress(result.referenceIP)?.isPublic == true else {
            return incomplete(result.errors.first?.message ?? "出口或服务响应信息不完整，已保留有效观测。")
        }
        return .init(state: .matched, title: "全端点响应正常", detail: "Claude 与 ChatGPT / API 公开诊断入口均已通过受控代理正常响应。")
    }
}

private final class AIProbeRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false
    func cancel() {
        lock.lock(); cancelled = true; let task = process; lock.unlock()
        if task?.isRunning == true { task?.terminate() }
    }
    func run(_ service: AIService) -> AIProbeResult {
        guard let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil),
              FileManager.default.isExecutableFile(atPath: engine.path) else {
            return .failure(service, code: "component_missing", message: "AI 网络诊断组件不可用，请重新构建。")
        }
        let task = Process(), output = Pipe()
        task.executableURL = engine
        task.arguments = ["ai-probe", "--service", service.rawValue]
        task.standardOutput = output
        task.standardError = FileHandle.nullDevice
        lock.lock()
        if cancelled { lock.unlock(); return .failure(service, code: "cancelled", message: "检测已取消。") }
        process = task
        do { try task.run() } catch {
            process = nil; lock.unlock()
            return .failure(service, code: "launch_failed", message: "诊断组件无法启动。")
        }
        lock.unlock()
        let timeout = DispatchWorkItem { [weak self] in self?.cancel() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 35, execute: timeout)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit(); timeout.cancel()
        lock.lock(); process = nil; let interrupted = cancelled; lock.unlock()
        guard !interrupted else { return .failure(service, code: "timeout", message: "诊断未在时限内完成。") }
        guard task.terminationStatus == 0, data.count <= 131_072,
              let result = try? JSONDecoder().decode(AIProbeResult.self, from: data) else {
            return .failure(service, code: "invalid_result", message: "诊断结果不完整或格式无效。")
        }
        return result
    }
}

enum AIProbeFixtureScenario: String, CaseIterable {
    case ready = "AI 网络响应", limited = "AI 入口限制", timeout = "AI 诊断超时", empty = "AI 暂无结果"
}

@MainActor
final class AIProbeStore: ObservableObject {
    @Published private(set) var claude = AIProbeState()
    @Published private(set) var gpt = AIProbeState()
    @Published private(set) var all = AIProbeState()
    @Published var now = Date() {
        didSet {
            for svc in AIService.allCases { refresh(svc) }
        }
    }
    let isFixture: Bool
    var onResult: ((AIProbeResult) -> Void)?
    var contextProvider: (() -> String?)?
    var fixtureScenario: AIProbeFixtureScenario = .ready
    private var runners: [AIService: AIProbeRunner] = [:]
    private var runs: [AIService: UUID] = [:]
    private struct Context { let required: Bool; let value: String? }
    private var contexts: [AIService: Context] = [:]

    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
    }

    func state(_ service: AIService) -> AIProbeState {
        switch service {
        case .claude: return claude
        case .gpt: return gpt
        case .all: return all
        }
    }

    private func set(_ state: AIProbeState, _ service: AIService) {
        switch service {
        case .claude: claude = state
        case .gpt: gpt = state
        case .all: all = state
        }
    }

    func start(_ service: AIService) {
        guard !state(service).running else { return }
        let id = UUID(); runs[service] = id
        contexts[service] = .init(required: contextProvider != nil, value: contextProvider?())
        set(.init(running: true, result: state(service).result, verdict: .init(state: .running, title: "正在并发探测", detail: "正在通过受控代理并发请求各 AI 平台端点与边缘协议栈。")), service)
        if isFixture {
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: 350_000_000)
                guard let self else { return }
                self.complete(service, id: id, result: Self.fixture(service, scenario: self.fixtureScenario))
            }
        } else {
            let runner = AIProbeRunner(); runners[service] = runner
            Task { [weak self] in
                let result = await Task.detached(priority: .utility) { runner.run(service) }.value
                self?.complete(service, id: id, result: result)
            }
        }
    }

    func cancel(_ service: AIService) {
        guard state(service).running else { return }
        runs[service] = nil; runners[service]?.cancel(); runners[service] = nil
        set(.init(running: false, result: state(service).result, verdict: .cancelled), service)
    }

    private func complete(_ service: AIService, id: UUID, result: AIProbeResult) {
        guard runs[service] == id else { return }
        runs[service] = nil; runners[service] = nil; now = Date()
        set(.init(running: false, result: result, verdict: .idle), service)
        onResult?(result)
        refresh(service)
    }

    private func refresh(_ service: AIService) {
        var value = state(service)
        guard !value.running, let result = value.result else { return }
        if let context = contexts[service], context.required,
           context.value == nil || contextProvider?() == nil || contextProvider?() != context.value {
            value.verdict = .init(state: .incomplete, title: "上下文待核对", detail: "代理采样未就绪或检测期间发生变化，请在环境稳定后重新检测。")
        } else {
            value.verdict = AIProbePolicy.evaluate(result, service: service, now: now.timeIntervalSince1970)
        }
        set(value, service)
    }

    func loadFixture(_ scenario: AIProbeFixtureScenario) {
        guard isFixture else { return }
        fixtureScenario = scenario; now = Date()
        for service in AIService.allCases {
            cancel(service); contexts[service] = nil
            set(.init(result: Self.fixture(service, scenario: scenario)), service); refresh(service)
        }
    }

    static func fixture(_ service: AIService, scenario: AIProbeFixtureScenario) -> AIProbeResult {
        let epoch = Date().timeIntervalSince1970
        let empty = scenario == .empty || scenario == .timeout
        let hasExit = !empty && scenario != .limited
        let endpoints: [AIEndpointResult] = empty ? [] : [
            AIEndpointResult(url: "https://claude.ai/cdn-cgi/trace", status: "responded", family: "claude", label: "Claude Web", httpStatus: scenario == .limited ? 403 : 200, elapsedMs: 145, message: "服务已响应", cfChallenge: scenario == .limited, exitIP: "203.0.113.88", countryCode: "JP", colo: "NRT", coloCity: "东京 (Narita)", tls: "TLSv1.3", httpProtocol: "http/2", sni: "plaintext", warp: "off", kex: "X25519MLKEM768"),
            AIEndpointResult(url: "https://www.anthropic.com/cdn-cgi/trace", status: "responded", family: "claude", label: "Anthropic 官网", httpStatus: 200, elapsedMs: 132, message: "服务已响应", exitIP: "203.0.113.88", countryCode: "JP", colo: "NRT", coloCity: "东京 (Narita)", tls: "TLSv1.3", httpProtocol: "http/2", sni: "plaintext", warp: "off"),
            AIEndpointResult(url: "https://api.anthropic.com/v1/models", status: "responded", family: "claude", label: "Anthropic Messages API", httpStatus: 401, elapsedMs: 168, message: "服务已响应；该端点需要认证"),
            AIEndpointResult(url: "https://chatgpt.com/cdn-cgi/trace", status: "responded", family: "gpt", label: "ChatGPT Web", httpStatus: 200, elapsedMs: 154, message: "服务已响应", exitIP: "203.0.113.88", countryCode: "JP", colo: "NRT", coloCity: "东京 (Narita)", tls: "TLSv1.3", httpProtocol: "http/2", sni: "plaintext", warp: "off"),
            AIEndpointResult(url: "https://api.openai.com/v1/models", status: "responded", family: "gpt", label: "OpenAI Platform API", httpStatus: 401, elapsedMs: 179, message: "服务已响应；该端点需要认证")
        ]
        let filtered = service == .all ? endpoints : endpoints.filter { $0.family == service.rawValue }
        return .init(
            service: service.rawValue,
            status: scenario == .ready ? "complete" : scenario == .timeout ? "timeout" : "partial",
            startedAt: epoch - 1.2,
            finishedAt: epoch,
            exitIP: hasExit ? "203.0.113.88" : "",
            referenceIP: empty ? "" : "203.0.113.88",
            exitSource: hasExit ? "https://claude.ai/cdn-cgi/trace" : "",
            claudeExitIP: hasExit ? "203.0.113.88" : "",
            gptExitIP: hasExit ? "203.0.113.88" : "",
            transport: "HTTPS CONNECT via http://127.0.0.1:7890",
            countryCode: hasExit ? "JP" : "",
            country: hasExit ? "Japan" : "",
            region: hasExit ? "Tokyo" : "",
            city: hasExit ? "Tokyo" : "",
            organization: hasExit ? "AS2516 KDDI CORPORATION" : "",
            ipTimezone: hasExit ? "Asia/Tokyo" : "",
            endpoints: filtered,
            errors: scenario == .ready || scenario == .limited ? [] : [.init(stage: "probe", code: scenario == .timeout ? "timeout" : "no_result", message: "模拟未完成结果")],
            details: ["所有诊断请求强制经受控代理；禁用重定向，零直连回退。"]
        )
    }
}
