import Foundation

/// Versioned mirror of watch-core::evidence::EvidenceRequest. The backend owns
/// collection, receipt validity, and risk; Swift only binds and displays replies.
struct LeakEvidenceRequest: Codable, Sendable {
    var schema = 1
    let id: String
    var action = "refresh"
    var purpose = "display"
    let kinds: [String]
    let expected_context: String?
    let expected_ip: String?
    var force = false
}
struct LeakEvidenceDiagnostic: Codable, Sendable {
    let state, detail: String
    let expected_ips: [String]
}
struct LeakEvidenceMetadata: Codable, Sendable {
    let context_id: String
    var finished_at: Double?
    var sampled_at: Double?
}
struct LeakEvidenceItem: Codable, Sendable {
    let state, code, detail: String
    let stored: Bool
    let valid_until: Double?
    let receipt: LeakEvidenceMetadata?
    let probe: LeakProbeResult?
    let display_probe: LeakProbeResult?
    let diagnostic: LeakEvidenceDiagnostic?
    var validity: String? = nil
    var sampling_error: String? = nil
    var verdict: LeakVerdict {
        switch state {
        case "ok": return .init(state: .matched, title: "通过", detail: detail)
        case "fail": return .init(state: .difference, title: "发现泄漏风险", detail: detail)
        default: return .init(state: .incomplete, title: code == "timeout" ? "检测超时" : "检测未完成", detail: detail)
        }
    }
}
struct LeakEvidenceReply: Codable, Sendable {
    let schema: Int
    let id, status, context_id, context_key: String
    let evaluated_at: Double
    let items: [String: LeakEvidenceItem]
}
struct LeakEvidenceFailure: Error, LocalizedError {
    let code, detail: String
    var errorDescription: String? { detail }
    static func decode(_ data: Data) throws -> LeakEvidenceReply {
        let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        if raw?["status"] as? String == "error" {
            throw Self(code: raw?["code"] as? String ?? "evidence_failed", detail: raw?["message"] as? String ?? "后台检测未完成")
        }
        return try JSONDecoder().decode(LeakEvidenceReply.self, from: data)
    }
}
