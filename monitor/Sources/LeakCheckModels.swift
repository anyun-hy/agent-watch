import Foundation
import Darwin

enum LeakKind: String, CaseIterable, Sendable { case dns, webrtc }
enum LeakVerdictState: String, Sendable { case idle, running, matched, difference, incomplete, unconfigured, cancelled }

struct LeakVerdict: Equatable, Sendable {
    let state: LeakVerdictState
    let title, detail: String
    static let idle = LeakVerdict(state: .idle, title: "未检测", detail: "点击开始后进行一次检测，页面刷新不会自动发起探测。")
    static let running = LeakVerdict(state: .running, title: "正在检测", detail: "等待本轮完整结果；上轮结论不参与本次判断。")
    static let cancelled = LeakVerdict(state: .cancelled, title: "已取消", detail: "本轮未完成，不能作出出口是否符合预期的结论。")
}

struct LeakObservation: Codable, Identifiable, Equatable, Sendable {
    let address, kind, source: String
    var family: Int? = nil
    var country: String? = nil
    var region: String? = nil
    var city: String? = nil
    var isp: String? = nil
    var geoSource: String? = nil
    var geoQueriedAt: Double? = nil
    var id: String { [kind, address, source].joined(separator: "|") }
}
struct LeakProbeError: Codable, Identifiable, Equatable, Sendable {
    let stage, code, message: String
    var id: String { [stage, code, message].joined(separator: "|") }
}
struct LeakProbeResult: Codable, Sendable {
    let kind, status: String
    let startedAt, finishedAt: Double
    let scope: String
    let observations: [LeakObservation]
    var errors: [LeakProbeError]
    var contextChanged: Bool
    let details: [String]
    var externalJSON: String? = nil

    init(kind: String, status: String, startedAt: Double, finishedAt: Double, scope: String,
         observations: [LeakObservation], errors: [LeakProbeError], contextChanged: Bool,
         details: [String], externalJSON: String? = nil) {
        self.kind = kind; self.status = status; self.startedAt = startedAt; self.finishedAt = finishedAt
        self.scope = scope; self.observations = observations; self.errors = errors
        self.contextChanged = contextChanged; self.details = details; self.externalJSON = externalJSON
    }

    private enum CodingKeys: String, CodingKey {
        case kind, status, startedAt, finishedAt, scope, observations, errors, contextChanged, details, externalJSON
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decode(String.self, forKey: .kind)
        status = try c.decode(String.self, forKey: .status)
        startedAt = try c.decode(Double.self, forKey: .startedAt)
        finishedAt = try c.decode(Double.self, forKey: .finishedAt)
        scope = try c.decode(String.self, forKey: .scope)
        observations = try c.decode([LeakObservation].self, forKey: .observations)
        errors = try c.decode([LeakProbeError].self, forKey: .errors)
        contextChanged = try c.decodeIfPresent(Bool.self, forKey: .contextChanged) ?? false
        details = try c.decodeIfPresent([String].self, forKey: .details) ?? []
        externalJSON = try c.decodeIfPresent(String.self, forKey: .externalJSON)
    }

    static func failure(_ kind: LeakKind, code: String, message: String, at now: Date = Date()) -> LeakProbeResult {
        LeakProbeResult(kind: kind.rawValue, status: code == "timeout" ? "timeout" : "error",
            startedAt: now.timeIntervalSince1970, finishedAt: now.timeIntervalSince1970,
            scope: "后台 WebKit 检测",
            observations: [], errors: [.init(stage: "collector", code: code, message: message)],
            contextChanged: false, details: [])
    }
}
struct LeakCheckState {
    var running = false
    /// Always the latest collection result.  Policy and backend persistence use
    /// this value, never the previous successful display sample.
    var result: LeakProbeResult? = nil
    /// Kept only to explain a transient collector failure to the user.
    var lastSuccessfulResult: LeakProbeResult? = nil
    var lastSuccessfulContext: String? = nil
    var lastSuccessfulContextRequired = false
    var verdict: LeakVerdict = .idle
    var inputError: String? = nil

    var displaysPreviousSuccessfulResult: Bool {
        guard let result, lastSuccessfulResult != nil, !result.contextChanged,
              !result.errors.contains(where: { $0.code == "context_unavailable" }) else { return false }
        if case .difference = verdict.state { return false }
        return result.status != "complete" || !result.errors.isEmpty
    }
    var displayResult: LeakProbeResult? {
        displaysPreviousSuccessfulResult ? lastSuccessfulResult : result
    }
}

/// Canonical address comparison; local, synthetic and documentation addresses
/// are retained as observations but cannot establish a public egress match.
struct LeakIPAddress: Hashable, Sendable {
    let canonical: String
    let family: Int
    let isPublic: Bool

    init?(_ input: String) {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= 64, !value.contains("%") else { return nil }
        var v4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            let bytes = withUnsafeBytes(of: &v4) { Array($0) }
            canonical = bytes.map(String.init).joined(separator: ".")
            family = 4
            isPublic = Self.publicV4(bytes)
            return
        }
        var v6 = in6_addr()
        guard value.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &v6) { Array($0) }
        if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 255, bytes[11] == 255 {
            let mapped = Array(bytes.suffix(4))
            canonical = mapped.map(String.init).joined(separator: ".")
            family = 4; isPublic = Self.publicV4(mapped)
            return
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &v6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        canonical = String(cString: buffer).lowercased(); family = 6
        let documentation = bytes[0...3].elementsEqual([0x20, 0x01, 0x0d, 0xb8])
        // Conservatively exclude the IETF protocol-assignment block here;
        // supported egress comparisons need ordinary global unicast addresses.
        let special2001 = bytes[0] == 0x20 && bytes[1] == 0x01 && (bytes[2] & 0xfe) == 0
        let documentation3fff = bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0
        let sixToFourPrivate = bytes[0] == 0x20 && bytes[1] == 0x02 && !Self.publicV4(Array(bytes[2...5]))
        isPublic = (bytes[0] & 0xe0) == 0x20 && !documentation && !documentation3fff && !special2001 && !sixToFourPrivate
    }

    private static func publicV4(_ b: [UInt8]) -> Bool {
        let a = Int(b[0]), c = Int(b[1]), d = Int(b[2])
        if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
        if a == 100 && (64...127).contains(c) { return false }
        if a == 169 && c == 254 { return false }
        if a == 172 && (16...31).contains(c) { return false }
        if a == 192 && c == 168 { return false }
        if a == 192 && c == 0 && d == 0 { return b[3] == 9 || b[3] == 10 }
        if a == 192 && ((c == 0 && d == 2) || (c == 88 && d == 99)) { return false }
        if a == 198 && (c == 18 || c == 19 || (c == 51 && d == 100)) { return false }
        if a == 203 && c == 0 && d == 113 { return false }
        return true
    }
}
