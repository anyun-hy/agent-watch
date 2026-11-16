import AppKit
import Darwin
import Foundation

enum MonitoredProduct: Equatable, Sendable { case claude, openAI }

@main
struct WatchProcessHelper {
    static func regionalStatus(_ references: [String]) throws -> [String: Any] {
        guard references.count <= 32, references.allSatisfy({
            $0.range(of: "^[a-z]{2,3}_[A-Z]{2}$", options: .regularExpression) != nil
        }) else { throw NSError(domain: "invalid_locale_reference", code: 1) }
        let sample = Date(timeIntervalSince1970: 1792713600)
        let styles: [(String, DateFormatter.Style)] = [("short", .short), ("medium", .medium), ("long", .long)]
        func formats(_ locale: Locale?) -> [String: String] {
            var value: [String: String] = [:]
            for (name, style) in styles {
                let formatter = DateFormatter()
                if let locale { formatter.locale = locale }
                formatter.dateStyle = style; formatter.timeStyle = .none
                value[name] = formatter.dateFormat ?? ""
            }
            return value
        }
        let actual = DateFormatter(); actual.dateStyle = .short; actual.timeStyle = .none
        var referencePatterns: [String: [String: String]] = [:], samples: [String: String] = [:]
        for identifier in Set(references) {
            referencePatterns[identifier] = formats(Locale(identifier: identifier))
            let formatter = DateFormatter(); formatter.locale = Locale(identifier: identifier)
            formatter.dateStyle = .short; formatter.timeStyle = .none
            samples[identifier] = formatter.string(from: sample)
        }
        let preferences = UserDefaults.standard.persistentDomain(forName: UserDefaults.globalDomain) ?? [:]
        return ["status": "ok", "regional": ["state": "available",
            "configured_locale": preferences["AppleLocale"] as? String ?? "",
            "effective_locale": Locale.current.identifier, "patterns": formats(nil),
            "short_sample": actual.string(from: sample), "reference_patterns": referencePatterns,
            "reference_samples": samples, "has_custom_formats": preferences["AppleICUDateFormatStrings"] != nil]]
    }

    static func main() {
        do {
            guard getuid() != 0 else { throw AIProcessInventoryFailure.malformed }
            let args = Array(CommandLine.arguments.dropFirst())
            let result: [String: Any]
            if args.first == "regional-status" {
                result = try regionalStatus(Array(args.dropFirst()))
            } else if args.count == 2, args[0] == "request-quit", args[1].utf8.count <= 16384 {
                let expected = try JSONDecoder().decode(AIProcessIdentity.self, from: Data(args[1].utf8))
                guard expected.uid == getuid() else { throw AIProcessInventoryFailure.malformed }
                let accepted = AIProcessNativeAction.applyToMatchingIdentity(expected, lookup: AIProcessInventory.identity) {
                    NSRunningApplication(processIdentifier: $0)?.terminate() ?? false
                }
                result = ["schema": 1, "pid": expected.pid, "accepted": accepted]
            } else { throw AIProcessInventoryFailure.malformed }
            let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
            print(String(decoding: data, as: UTF8.self))
        } catch {
            print(#"{"status":"error","code":"invalid_quit_request","message":"原生退出请求未被接受"}"#)
            exit(4)
        }
    }
}
