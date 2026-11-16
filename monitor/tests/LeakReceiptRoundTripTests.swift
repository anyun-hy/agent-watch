import Foundation

/// Started by the Rust integration test with two owned temporary services.
/// Uses the real CLI, Unix socket handler, ReceiptStore and UI receiver.
@main
struct LeakReceiptRoundTripTests {
    @MainActor static func main() async throws {
        guard CommandLine.arguments.count == 4, CommandLine.arguments[3] == "--isolated-home" else {
            fputs("usage: LeakReceiptRoundTripTests <engine> <owned-test-root> --isolated-home\n", stderr); exit(2)
        }
        let engine = CommandLine.arguments[1]
        let supplied = URL(fileURLWithPath: CommandLine.arguments[2]).standardizedFileURL
        let root = supplied.resolvingSymlinksInPath()
        let real = FileManager.default.homeDirectoryForCurrentUser.resolvingSymlinksInPath()
        let tmp = URL(fileURLWithPath: "/tmp", isDirectory: true).resolvingSymlinksInPath()
        guard root != real, root.path.hasPrefix(tmp.path + "/cwp-"), root.lastPathComponent.hasPrefix("cwp-"),
              root.deletingLastPathComponent() == tmp,
              FileManager.default.fileExists(atPath: root.appendingPathComponent("isolated-evidence-test").path),
              engine.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: engine) else {
            fputs("SECURITY VIOLATION: requires the Rust harness owned temporary root; real HOME and aliases rejected\n", stderr); exit(2)
        }
        var assertions = 0, commands = 0
        func expect(_ value: Bool, _ message: String) {
            assertions += 1
            if !value { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        let signature = "127.0.0.1:7890|rule|fixture|fixture"
        let home = root.appendingPathComponent("home")
        let ttlHome = root.appendingPathComponent("ttl-home")
        func control(_ home: URL, _ value: [String: Any]) throws {
            try JSONSerialization.data(withJSONObject: value).write(to: home.appendingPathComponent("control.json"), options: .atomic)
        }
        func call(_ request: LeakEvidenceRequest, home: URL) async throws -> Data {
            commands += 1
            let payload = try JSONEncoder().encode(request)
            return try await Task.detached {
                let process = Process(); process.executableURL = URL(fileURLWithPath: engine)
                process.arguments = ["evidence", request.action, "--home", home.path] + (request.action == "refresh" ? ["--apply"] : [])
                process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": home.path, "LC_ALL": "C"]
                return try SwitcherCommandRunner.execute(process, input: payload)
            }.value
        }
        let store = LeakCheckStore(isFixture: false)
        store.contextProvider = { signature }
        store.automaticContextProvider = { signature }
        store.evidenceTransport = { try await call($0, home: home) }
        let switcher = SwitcherStore(isFixture: true)
        store.onEvidenceReceived = { switcher.acceptEvidence($0, reply: $1, item: $2) }
        let cold = await store.ensureInitializationReceipt(.dns)
        expect(cold && store.dns.verdict.state == .matched, "cold start without a session successfully consumes a persisted DNS receipt")
        expect(switcher.initializationDNSReceipt?.sampled == store.dns.result?.finishedAt, "UI and initialization share the exact Rust receipt")
        expect(!FileManager.default.fileExists(atPath: home.appendingPathComponent("Library/Application Support/ClaudeWatch/switcher/session-guard.json").path), "no session was manufactured")
        store.rtcExpected = "9.9.9.9"
        let rtc = await store.ensureInitializationReceipt(.webrtc)
        expect(rtc && store.rtc.verdict.state == .matched, "diagnostic expectation cannot rewrite protective verdict")
        expect(store.diagnostics[.webrtc]?.contains("不一致") == true, "manual expected IP reaches Rust and its mismatch is displayed")
        try control(home, ["change": true])
        let changed = await store.ensureInitializationReceipt(.dns, forceNew: true)
        expect(!changed && store.dns.result?.errors.first?.code == "evidence_context_changed", "actual daemon before/after context change is precisely rejected")
        try control(home, [:])
        expect(await store.ensureInitializationReceipt(.dns, forceNew: true), "restore a real successful receipt before timeout")
        let prior = store.dns.result!.finishedAt
        try control(home, ["timeout": true])
        let timedOut = await store.ensureInitializationReceipt(.dns, forceNew: true)
        expect(!timedOut && store.dns.verdict.state == .incomplete && store.dns.verdict.title == "检测超时", "current timeout wins over prior success")
        expect(store.dns.lastSuccessfulResult?.finishedAt == prior && store.dns.result?.status == "timeout", "previous addresses stay historical with their original timestamp")
        try control(ttlHome, ["age_seconds": 45])
        let display = LeakCheckStore(isFixture: false)
        display.contextProvider = { signature }; display.automaticContextProvider = { signature }
        display.evidenceTransport = { try await call($0, home: ttlHome) }
        expect(await display.ensureInitializationReceipt(.dns), "45 second receipt remains display-grade usable")
        var launch = LeakEvidenceRequest(id: UUID().uuidString, kinds: ["dns"], expected_context: signature, expected_ip: nil)
        launch.action = "inspect"; launch.purpose = "launch"
        let checked = try LeakEvidenceFailure.decode(await call(launch, home: ttlHome))
        expect(checked.items["dns"]?.state == "unknown" && checked.items["dns"]?.code == "evidence_expired", "same stored receipt fails specifically at launch freshness")
        expect(checked.items["dns"]?.probe?.finishedAt == display.dns.result?.finishedAt, "TTL comparison reads the same sample from the actual ReceiptStore path")
        display.now = Date(timeIntervalSince1970: display.dns.result!.finishedAt + 301)
        expect(display.dns.verdict.state == .incomplete, "UI expires the backend declared validity without a new probe")
        expect(commands >= 7, "all required cases actually invoked the production CLI")
        print("Phase1RoundTrip: \(assertions) assertions passed; \(commands) production CLI requests; owned UDS services and injected network facts; no installed-service acceptance")
    }
}
