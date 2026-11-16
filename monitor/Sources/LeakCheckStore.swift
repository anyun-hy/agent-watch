import Foundation
import SwiftUI

enum LeakFixtureScenario: String, CaseIterable {
    case matched = "样本一致", difference = "出口差异", timeout = "检测超时", empty = "没有结果"
    case partial = "部分失败", missingReference = "缺少 HTTP 参考", ipv6 = "缺少 IPv6 参考", stale = "结果过期", noPolicy = "DNS 未设预期"
}

@MainActor
final class LeakCheckStore: ObservableObject {
    @Published private(set) var progress: [LeakKind: String] = [:]
    @Published var rtcExpected = ""
    @Published private(set) var dns = LeakCheckState()
    @Published private(set) var rtc = LeakCheckState()
    @Published private(set) var diagnostics: [LeakKind: String] = [:]
    @Published var now = Date() { didSet { invalidateDisplayedBindings() } }
    let isFixture: Bool
    var fixtureDelayNanoseconds: UInt64 = 350_000_000
    var fixtureScenario: LeakFixtureScenario = .matched
    var contextProvider: (() -> String?)?
    var automaticContextProvider: (() -> String?)?
    /// Inject transport input in tests; decoding and completion are production.
    var evidenceTransport: ((LeakEvidenceRequest) async throws -> Data)?
    var onEvidenceReceived: ((LeakKind, LeakEvidenceReply, LeakEvidenceItem) -> Void)?
    var onEvidenceFailed: ((LeakKind, String) -> Void)?
    private var tasks: [LeakKind: Task<Void, Never>] = [:]
    private var requests: [LeakKind: String] = [:]
    private var replies: [LeakKind: (context: String, item: LeakEvidenceItem)] = [:]

    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
    }
    private func state(_ kind: LeakKind) -> LeakCheckState { kind == .dns ? dns : rtc }
    private func set(_ value: LeakCheckState, for kind: LeakKind) { if kind == .dns { dns = value } else { rtc = value } }
    private func currentContext() -> String? {
        if let provider = automaticContextProvider { return provider() }
        return contextProvider?()
    }
    func start(_ kind: LeakKind) { start(kind, force: false) }
    private func start(_ kind: LeakKind, force: Bool) {
        guard !state(kind).running else { return }
        guard let context = currentContext(), !context.isEmpty else {
            fail(kind, code: "context_unavailable", detail: "当前代理上下文不可用，请等待后台采样就绪。")
            return
        }
        let request = LeakEvidenceRequest(id: UUID().uuidString, kinds: [kind.rawValue],
            expected_context: context, expected_ip: kind == .webrtc ? rtcExpected : nil, force: force)
        if replies[kind]?.item.validity != "network" { onEvidenceFailed?(kind, "") }
        requests[kind] = request.id
        var value = state(kind); value.running = true; value.verdict = .running; value.inputError = nil
        set(value, for: kind); progress[kind] = "正在等待后台检测回执"
        tasks[kind] = Task { [weak self] in
            guard let self else { return }
            do {
                let bytes: Data
                if let transport = self.evidenceTransport { bytes = try await transport(request) }
                else if self.isFixture {
                    try await Task.sleep(nanoseconds: self.fixtureDelayNanoseconds)
                    bytes = try self.fixtureReply(request)
                } else {
                    let input = try JSONEncoder().encode(request)
                    bytes = try await Task.detached { try SwitcherCommandRunner.run(["evidence", "refresh", "--apply"], input: input) }.value
                }
                guard self.requests[kind] == request.id, !Task.isCancelled else { return }
                let reply = try LeakEvidenceFailure.decode(bytes)
                try self.accept(reply, request: request, kind: kind)
            } catch {
                guard self.requests[kind] == request.id, !Task.isCancelled else { return }
                let failure = error as? LeakEvidenceFailure
                self.fail(kind, code: failure?.code ?? "evidence_response_failed", detail: error.localizedDescription)
            }
            self.tasks[kind] = nil
        }
    }
    /// Protocol/context checks protect UI request relevance, never infer risk.
    private func accept(_ reply: LeakEvidenceReply, request: LeakEvidenceRequest, kind: LeakKind) throws {
        guard reply.schema == 1, reply.id == request.id, !reply.context_id.isEmpty,
              let item = reply.items[kind.rawValue], ["ok", "fail", "unknown"].contains(item.state),
              reply.evaluated_at.isFinite,
              item.state == "unknown" || (item.stored && (item.validity == "network" || item.valid_until?.isFinite == true)) else {
            throw LeakEvidenceFailure(code: "evidence_response_invalid", detail: "后台检测回执格式或代次无效。")
        }
        guard currentContext() == request.expected_context, reply.context_key == request.expected_context else {
            throw LeakEvidenceFailure(code: "context_changed", detail: "网络已变更，本轮回执不再适用于当前页面。")
        }
        if item.stored {
            guard let receipt = item.receipt, let probe = item.probe,
                  receipt.context_id == reply.context_id, probe.kind == kind.rawValue,
                  (receipt.finished_at ?? receipt.sampled_at) == probe.finishedAt else {
                throw LeakEvidenceFailure(code: "evidence_response_invalid", detail: "后台回执与本轮采样不一致。")
            }
        }
        var value = state(kind)
        value.running = false; value.result = item.probe; value.verdict = item.verdict
        value.inputError = item.code == "invalid_expected_ip" ? item.detail : nil
        value.lastSuccessfulResult = item.display_probe
        value.lastSuccessfulContext = item.display_probe == nil ? nil : reply.context_key
        value.lastSuccessfulContextRequired = item.display_probe != nil
        set(value, for: kind)
        replies[kind] = (reply.context_key, item)
        diagnostics[kind] = item.sampling_error ?? item.diagnostic?.detail
        requests[kind] = nil; progress[kind] = nil
        onEvidenceReceived?(kind, reply, item)
        now = Date()
    }
    private func fail(_ kind: LeakKind, code: String, detail: String) {
        var value = state(kind)
        value.running = false
        if let reply = replies[kind], reply.item.validity == "network", reply.item.state == "ok",
           !code.contains("context_changed"), !code.contains("policy_changed"),
           currentContext() == nil || currentContext() == reply.context {
            value.verdict = reply.item.verdict
            diagnostics[kind] = "后台采样异常：" + detail + " 已通过结果及原采样时间保留。"
            set(value, for: kind)
            requests[kind] = nil; progress[kind] = nil
            return
        }
        value.result = .failure(kind, code: code.contains("timeout") ? "timeout" : code, message: detail)
        value.verdict = .init(state: .incomplete,
            title: code.contains("context_changed") ? "网络已变更" : code.contains("timeout") ? "检测超时" : code == "daemon_unavailable" ? "后台不可用" : "检测未完成", detail: detail)
        value.inputError = code == "invalid_expected_ip" ? detail : nil
        // Historical display is only supplied by the backend, never promoted here.
        value.lastSuccessfulResult = nil
        set(value, for: kind)
        replies[kind] = nil; requests[kind] = nil; progress[kind] = nil
        onEvidenceFailed?(kind, detail)
    }
    private func invalidateDisplayedBindings() {
        for kind in LeakKind.allCases {
            guard let reply = replies[kind], !state(kind).running else { continue }
            let code: String, detail: String
            if currentContext() == nil && reply.item.validity == "network" {
                diagnostics[kind] = "后台网络采样暂不可用；已通过检测记录保留。"
                continue
            }
            if currentContext() != reply.context {
                code = currentContext() == nil ? "context_unavailable" : "context_changed"
                detail = currentContext() == nil ? "当前代理上下文不可用。" : "网络已变更，请重新检测。"
            } else if let deadline = reply.item.valid_until, now.timeIntervalSince1970 > deadline {
                code = "evidence_expired"; detail = "检测结果已过期，请重新检测。"
            } else {
                var value = state(kind); value.verdict = reply.item.verdict; set(value, for: kind)
                continue
            }
            var value = state(kind)
            value.verdict = .init(state: .incomplete, title: code == "evidence_expired" ? "结果已过期" : "上下文已失效", detail: detail)
            value.lastSuccessfulResult = nil
            set(value, for: kind)
            if code != "context_unavailable" { replies[kind] = nil }
        }
    }
    func initializationReceiptProblem(_ kind: LeakKind, at date: Date = Date()) -> (code: String, detail: String)? {
        let value = state(kind)
        guard !value.running else { return (kind.rawValue + "_running", "检测仍在进行。") }
        guard currentContext() != nil else { return (kind.rawValue + "_context_unavailable", "当前代理上下文不可用。") }
        if let deadline = replies[kind]?.item.valid_until, date.timeIntervalSince1970 > deadline {
            return (kind.rawValue + "_expired", "检测结果已过期，请重新检测。")
        }
        guard let reply = replies[kind], reply.context == currentContext(), reply.item.stored,
              reply.item.validity == "network" || reply.item.valid_until.map({ date.timeIntervalSince1970 <= $0 }) == true,
              value.verdict.state == .matched else {
            return (kind.rawValue + "_not_passed", value.verdict.detail)
        }
        return nil
    }
    /// Consume Rust's network comparison. Swift does not compare IPs or rules.
    func acceptEnvironment(_ environment: CurrentEnvironmentReceipt) {
        for kind in LeakKind.allCases {
            guard let reply = replies[kind], reply.item.validity == "network" else { continue }
            let observed = kind == .dns ? environment.initialization_receipts?.dns : environment.initialization_receipts?.webrtc
            if observed?.network_state == "unavailable" {
                diagnostics[kind] = "后台网络采样暂不可用；已通过检测记录保留。"
            } else if observed?.network_state == "changed" {
                fail(kind, code: "context_changed", detail: "后台确认网络配置或出口已变化，需要重新检测。")
            } else if observed?.network_state == "confirmed" {
                diagnostics[kind] = reply.item.diagnostic?.detail
                if observed?.state == "fail" {
                    replies[kind] = nil
                    var value = state(kind)
                    value.verdict = .init(state: .difference, title: "发现泄漏风险", detail: "后台检测未通过，请查看当前环境结果。")
                    set(value, for: kind)
                }
            }
        }
    }
    func initializationReceiptIsCurrent(_ kind: LeakKind, at date: Date = Date()) -> Bool {
        initializationReceiptProblem(kind, at: date) == nil
    }
    func invalidateInitializationReceipt(_ kind: LeakKind) { replies[kind] = nil }
    func ensureInitializationReceipt(_ kind: LeakKind, forceNew: Bool = false) async -> Bool {
        now = Date()
        if !forceNew && initializationReceiptIsCurrent(kind) { return true }
        if !state(kind).running { start(kind, force: forceNew) }
        await tasks[kind]?.value
        return initializationReceiptIsCurrent(kind)
    }
    func cancel(_ kind: LeakKind) {
        tasks[kind]?.cancel(); tasks[kind] = nil; requests[kind] = nil; replies[kind] = nil; progress[kind] = nil
        var value = state(kind); value.running = false; value.result = nil; value.verdict = .cancelled
        set(value, for: kind)
    }
    /// Canned backend input for visual previews only. No probe is evaluated here.
    func fixtureReply(_ request: LeakEvidenceRequest) throws -> Data {
        let context = "fixture-context-0001"
        let time = Date().timeIntervalSince1970
        var items: [String: LeakEvidenceItem] = [:]
        for name in request.kinds {
            guard let kind = LeakKind(rawValue: name) else { continue }
            let sample = Self.fixture(kind, scenario: fixtureScenario, at: Date())
            let state: String
            switch fixtureScenario {
            case .matched, .noPolicy: state = "ok"
            case .difference: state = "fail"
            default: state = "unknown"
            }
            let code = fixtureScenario == .timeout ? "timeout" : state
            items[name] = LeakEvidenceItem(state: state, code: code, detail: "预览回执：" + fixtureScenario.rawValue,
                stored: true, valid_until: sample.finishedAt + 300,
                receipt: LeakEvidenceMetadata(context_id: context, finished_at: kind == .dns ? sample.finishedAt : nil, sampled_at: sample.finishedAt),
                probe: sample, display_probe: nil, diagnostic: nil)
        }
        return try JSONEncoder().encode(LeakEvidenceReply(schema: 1, id: request.id, status: "ok", context_id: context,
            context_key: request.expected_context ?? "fixture", evaluated_at: time, items: items))
    }
    func loadFixture(_ scenario: LeakFixtureScenario) {
        guard isFixture else { return }
        fixtureScenario = scenario
        for kind in LeakKind.allCases {
            cancel(kind)
            let request = LeakEvidenceRequest(id: UUID().uuidString, kinds: [kind.rawValue], expected_context: currentContext(), expected_ip: nil)
            if let data = try? fixtureReply(request), let reply = try? LeakEvidenceFailure.decode(data), let item = reply.items[kind.rawValue] {
                set(.init(result: item.probe, verdict: item.verdict), for: kind)
            }
        }
    }
    func loadLiveFixture() { loadFixture(.matched) }
    func loadReviewWebRTC(_ result: LeakProbeResult) {
        guard isFixture else { return }
        set(.init(result: result, verdict: .init(state: .incomplete, title: "历史样本", detail: "仅展示已录制事实；没有本轮后台判定。")), for: .webrtc)
    }
    static func fixture(_ kind: LeakKind, scenario: LeakFixtureScenario, at date: Date) -> LeakProbeResult {
        let epoch = date.timeIntervalSince1970 - (scenario == .stale ? 400 : 0)
        var observations: [LeakObservation] = [.init(address: "1.1.1.1", kind: "http", source: "HTTP 参考（模拟）", family: 4, country: "JP")]
        if kind == .dns {
            observations.append(.init(address: scenario == .difference ? "8.8.4.4" : "8.8.8.8", kind: "resolver", source: "Akamai NS（模拟）", family: 4, country: scenario == .difference ? "CN" : "JP"))
        } else {
            observations += ["Google STUN（模拟）", "Cloudflare STUN（模拟）"].map {
                LeakObservation(address: scenario == .difference ? "8.8.4.4" : "1.1.1.1", kind: "srflx", source: $0, family: 4, country: scenario == .difference ? "CN" : "JP")
            }
        }
        var errors: [LeakProbeError] = []; var status = "complete"
        if scenario == .timeout { status = "timeout"; errors = [.init(stage: "probe", code: "timeout", message: "模拟超时；已有地址不能构成完整检测。") ] }
        if scenario == .partial { status = "partial"; errors = [.init(stage: "probe", code: "service_failed", message: "一个诊断服务未完成，保留其他有效观测。") ] }
        if scenario == .empty { observations = [] }
        if scenario == .missingReference { observations.removeAll { $0.kind == "http" } }
        if scenario == .ipv6 { observations.append(.init(address: "2606:4700:4700::1111", kind: kind == .dns ? "resolver" : "srflx", source: "IPv6（模拟）", family: 6)) }
        return LeakProbeResult(kind: kind.rawValue, status: status, startedAt: epoch - 2, finishedAt: epoch,
            scope: kind == .dns ? "dig/resolv.conf DNS 路径（模拟）" : "当前检测 WebView（模拟）",
            observations: observations, errors: errors, contextChanged: false,
            details: ["此结果为隔离模拟数据；未调用网络、DNS、STUN 或真实 WebView。"])
    }
}
