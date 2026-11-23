import Foundation

/// A user-requested reading. The token binds a save to the observed desktop
/// session. It is kept in memory and never displayed or included in argv.
struct DesktopAccountCapture: Decodable {
    let state: String
    let detail: String
    var display_name: String?
    var email: String?
    var slot: String?
    var source_token: String?
    var observedAt = Date()

    enum CodingKeys: String, CodingKey {
        case state, detail, display_name, email, slot, source_token
    }

    var label: String? {
        let fields = [display_name, email].compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
        let names = fields.filter { !$0.isEmpty }
        guard let first = names.first else { return nil }
        if names.count > 1, names[1] != first { return first + " · " + names[1] }
        return first
    }

    var canSave: Bool { state == "logged_in" && label != nil && source_token?.isEmpty == false }

    static func checkedReceipt(_ data: Data) throws -> Data {
        if let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
           object["status"] as? String == "error" {
            throw NSError(domain: "Switcher", code: 4, userInfo: [
                NSLocalizedDescriptionKey: object["message"] as? String ?? "后台未完成账号操作。"
            ])
        }
        return data
    }

    static func read(_ product: MonitoredProduct) throws -> Self {
        if product == .openAI {
            let data = try SwitcherCommandRunner.run(["account", "identity", "--product", "chatgpt"])
            return try JSONDecoder().decode(Self.self, from: checkedReceipt(data))
        }
        struct Source: Decodable, Equatable {
            let process_id: Int
            let slot: String?
            let source_token: String
        }
        func source() throws -> Source {
            let data = try SwitcherCommandRunner.run(["account", "current", "--product", "claude"])
            return try JSONDecoder().decode(Source.self, from: data)
        }
        let before = try? source()
        let login = ClaudeLoginProbe.probe()
        let label = login.account?.menuLabel ?? login.account?.displayName
        var capture = Self(state: login.state, detail: login.detail, display_name: label, email: login.account?.email)
        guard login.state == "logged_in" else { return capture }
        guard let before, before.process_id == login.processId, let after = try? source(), before == after else {
            return Self(state: "unknown", detail: "读取期间无法核对同一个 Claude 桌面实例，请重新加载。")
        }
        capture.slot = before.slot
        capture.source_token = before.source_token
        return capture
    }
}
