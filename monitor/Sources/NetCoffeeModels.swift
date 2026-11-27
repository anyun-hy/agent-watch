import Foundation

// Preserve unknown fields and nested source data across wire receipt schema revisions.
indirect enum CoffeeJSON: Codable, Sendable {
    case object([String: CoffeeJSON]), array([CoffeeJSON]), string(String), number(Double), bool(Bool), null
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([String: CoffeeJSON].self) { self = .object(v) }
        else { self = .array(try c.decode([CoffeeJSON].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }
    subscript(_ key: String) -> CoffeeJSON? { if case .object(let v) = self { return v[key] }; return nil }
    var text: String? {
        switch self { case .string(let v): return v; case .number(let v): return v.rounded() == v ? String(format: "%.0f", v) : String(v); case .bool(let v): return v ? "是" : "否"; default: return nil }
    }
    var number: Double? { if case .number(let v) = self { return v }; return nil }
    var flag: Bool? { if case .bool(let v) = self { return v }; return nil }
    var pretty: String { guard let d = try? JSONEncoder.pretty.encode(self) else { return "null" }; return String(decoding: d, as: UTF8.self) }
}

private extension JSONEncoder {
    static var pretty: JSONEncoder { let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]; return e }
}

struct CoffeeReceipt: Codable, Sendable {
    let kind, query, sourceURL: String
    let queriedAt, finishedAt: Double
    let status: String
    let httpStatus: Int?
    let raw: String
    let data: CoffeeJSON?
    let error: String?
    var sha256: String? = nil
    var transport: String? = nil
    var cache_state: String? = nil
    var last_good: CoffeeJSON? = nil
    var score: Int? {
        guard status == "complete", httpStatus == 200,
              data?["ip"]?.text.flatMap(LeakIPAddress.init)?.canonical == LeakIPAddress(query)?.canonical,
              let n = data?["trust_score"]?.number, n.isFinite, n >= 0, n <= 100, n.rounded() == n else { return nil }
        return Int(n)
    }
    func field(_ key: String) -> String {
        let value = data?[key]?.text?.trimmingCharacters(in: .whitespacesAndNewlines)
        return value?.isEmpty == false ? value! : "未提供"
    }
}
