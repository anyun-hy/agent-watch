import Foundation
import Combine

@MainActor
final class ManagedEntryControl: ObservableObject {
    typealias Command = @Sendable ([String], TimeInterval) async throws -> Data

    struct Report: Decodable {
        let target: String
        let entry_generated: Bool
        let activation_configured: Bool
        let status_label: String
        let entry_path: String
    }

    struct State {
        var report: Report?
        var candidateSources: [String] = []
        var busy = false
        var errorMessage: String?
    }

    private struct Reply: Decodable {
        let status: String
        let status_report: Report?
        let candidate_sources: [String]?
        let result: ActionResult?
        let message: String?
    }

    private struct ActionResult: Decodable {
        let target: String
        let status: String?
        let activation_configured: Bool?
        let removed_path: String?
        let was_present: Bool?
    }

    private struct InvalidReply: LocalizedError {
        let errorDescription: String?
        init(_ message: String) { errorDescription = message }
    }

    @Published private var states: [MonitoredProduct: State] = [:]
    private var latest: [MonitoredProduct: UUID] = [:]
    private var writing: Set<MonitoredProduct> = []
    private var fixtureEnabled: Set<MonitoredProduct> = []
    let isFixture: Bool
    private let command: Command

    init(isFixture: Bool = false, command: @escaping Command = { args, timeout in
        try await Task.detached(priority: .utility) {
            try AIProcessInventory.runEngine(args, timeout: timeout)
        }.value
    }) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
        self.command = command
    }

    func state(for product: MonitoredProduct) -> State { states[product] ?? State() }

    static func target(for product: MonitoredProduct) -> String {
        switch product {
        case .claude: return "claude-desktop"
        case .openAI: return "chatgpt-desktop"
        }
    }

    private func begin(_ product: MonitoredProduct) -> UUID {
        let id = UUID()
        latest[product] = id
        let previous = state(for: product)
        states[product] = State(report: previous.report, candidateSources: previous.candidateSources, busy: true, errorMessage: nil)
        return id
    }

    private func readStatus(for product: MonitoredProduct) async throws -> State {
        let target = Self.target(for: product)
        if isFixture {
            let enabled = fixtureEnabled.contains(product)
            return State(report: Report(target: target, entry_generated: enabled, activation_configured: enabled,
                                        status_label: enabled ? "示例入口已生成" : "示例入口未生成", entry_path: ""))
        }
        let reply = try await request(["entry", "status", "--target", target], timeout: 10)
        guard let report = reply.status_report, report.target == target else {
            throw InvalidReply("未收到当前应用的入口状态回执。")
        }
        return State(report: report, candidateSources: reply.candidate_sources ?? [])
    }

    private func request(_ args: [String], timeout: TimeInterval) async throws -> Reply {
        try Task.checkCancellation()
        let data = try await command(args, timeout)
        try Task.checkCancellation()
        let reply = try JSONDecoder().decode(Reply.self, from: data)
        guard reply.status == "ok" else { throw InvalidReply(reply.message ?? "入口请求未完成。") }
        return reply
    }

    func refresh(for product: MonitoredProduct) async {
        guard !Task.isCancelled, !writing.contains(product) else { return }
        let id = begin(product)
        do {
            let state = try await readStatus(for: product)
            try Task.checkCancellation()
            guard latest[product] == id else { return }
            states[product] = state
        } catch {
            guard latest[product] == id else { return }
            let previous = state(for: product)
            states[product] = State(report: previous.report, candidateSources: previous.candidateSources,
                                    busy: false, errorMessage: Task.isCancelled ? nil : error.localizedDescription)
        }
    }

    func setEnabled(_ enable: Bool, for product: MonitoredProduct) async -> Bool {
        let current = state(for: product)
        guard !Task.isCancelled, !current.busy, let report = current.report,
              report.activation_configured != enable else { return false }
        let id = begin(product)
        writing.insert(product)
        defer { writing.remove(product) }
        let target = Self.target(for: product)
        do {
            if isFixture {
                if enable { fixtureEnabled.insert(product) } else { fixtureEnabled.remove(product) }
            } else {
                let action = enable ? "activate" : "deactivate"
                let reply = try await request(["entry", action, "--target", target, "--apply"], timeout: 25)
                guard let result = reply.result, result.target == target,
                      enable ? (result.status == "activated" && result.activation_configured == true)
                             : (result.was_present != nil && result.removed_path?.isEmpty == false) else {
                    throw InvalidReply("未收到当前应用的入口操作回执。")
                }
            }
            let state = try await readStatus(for: product)
            try Task.checkCancellation()
            guard latest[product] == id else { return false }
            guard state.report?.entry_generated == enable, state.report?.activation_configured == enable else {
                throw InvalidReply("当前应用的入口状态与请求不符，请重新读取。")
            }
            states[product] = state
            return true
        } catch {
            guard latest[product] == id else { return false }
            let previous = state(for: product)
            states[product] = State(report: previous.report, candidateSources: previous.candidateSources,
                                    busy: false, errorMessage: Task.isCancelled ? nil : error.localizedDescription)
            return false
        }
    }
}
