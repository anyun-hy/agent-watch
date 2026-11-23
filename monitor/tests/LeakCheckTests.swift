import Foundation

@main
struct LeakCheckTests {
    @MainActor static func main() async throws {
        var assertions = 0
        func expect(_ condition: Bool, _ detail: String) {
            assertions += 1
            if !condition { fputs("FAIL: \(detail)\n", stderr); exit(1) }
        }
        let first = LeakObservation(address: "2001:db8::1", kind: "srflx", source: "STUN A", family: 6, country: "JP")
        let otherSource = LeakObservation(address: "2001:0db8::1", kind: "srflx", source: "STUN B", family: 6, country: "US")
        let relay = LeakObservation(address: first.address, kind: "relay", source: first.source, family: 6)
        let unspecifiedFamily = LeakObservation(address: first.address, kind: first.kind, source: first.source)
        let groups = LeakCandidateGroup.group([first, relay, otherSource, first, unspecifiedFamily])
        expect(groups.map(\.observations) == [[first, otherSource, first], [relay], [unspecifiedFamily]],
               "candidate display preserves order and every source receipt while separating kinds and address families")
        expect(groups[0].sourceCount == 2, "duplicate observations do not inflate the visible source count")
        expect(groups[0].countries == ["JP", "US"] && groups[1].countries == ["地区未取得"],
               "a collapsed candidate shows differing countries and distinguishes missing geography")
        let store = LeakCheckStore(isFixture: true)
        var context: String? = "fixture-A"
        store.contextProvider = { context }; store.automaticContextProvider = { context }
        var calls = 0, payload: LeakEvidenceRequest?
        store.evidenceTransport = { request in calls += 1; payload = request; return try store.fixtureReply(request) }
        let initial = await store.ensureInitializationReceipt(.dns)
        expect(initial && store.dns.verdict.state == .matched, "production receiver consumes authoritative passing reply")
        expect(payload?.kinds == ["dns"] && payload?.expected_context == "fixture-A", "request binds only the requested kind and current context")
        let time = store.dns.result!.finishedAt
        expect(await store.ensureInitializationReceipt(.dns) && calls == 1, "initialization reuses the accepted receipt without another transport")
        store.now = Date(timeIntervalSince1970: time + 301)
        expect(store.dns.verdict.state == .incomplete && calls == 1, "expiry updates presentation without scheduling collection")
        store.now = Date()
        expect(await store.ensureInitializationReceipt(.dns), "explicit request obtains a new receipt")
        context = "fixture-B"; store.now = Date()
        expect(store.dns.verdict.state == .incomplete, "context change revokes current green")
        context = nil; store.now = Date()
        let before = calls
        expect(!(await store.ensureInitializationReceipt(.webrtc)) && calls == before, "unavailable current context cannot use a retained binding or start work")
        context = "fixture-A"
        store.evidenceTransport = { _ in throw LeakEvidenceFailure(code: "daemon_unavailable", detail: "daemon absent") }
        expect(!(await store.ensureInitializationReceipt(.dns)) && store.dns.verdict.title == "后台不可用", "daemon errors become a terminal visible state")
        store.evidenceTransport = { req in
            var raw = try JSONSerialization.jsonObject(with: store.fixtureReply(req)) as! [String: Any]
            raw["id"] = "wrong-request"
            return try JSONSerialization.data(withJSONObject: raw)
        }
        expect(!(await store.ensureInitializationReceipt(.dns)) && store.dns.result?.errors.first?.code == "evidence_response_invalid", "mismatched response id is rejected")
        store.evidenceTransport = { req in
            let data = try store.fixtureReply(req); context = "fixture-B"; return data
        }
        expect(!(await store.ensureInitializationReceipt(.dns)) && store.dns.result?.errors.first?.code == "context_changed", "late previous-network response cannot publish green")
        context = "fixture-A"
        store.evidenceTransport = { req in payload = req; return try store.fixtureReply(req) }
        store.rtcExpected = "1.1.1.1, 8.8.8.8"
        expect(await store.ensureInitializationReceipt(.webrtc), "WebRTC uses the same receiver")
        expect(payload?.expected_ip == store.rtcExpected && payload?.expected_context == "fixture-A", "manual reference is separate from context")
        store.evidenceTransport = { req in
            try? await Task.sleep(nanoseconds: 30_000_000)
            return try store.fixtureReply(req)
        }
        store.start(.dns); store.cancel(.dns)
        try await Task.sleep(nanoseconds: 80_000_000)
        expect(store.dns.verdict.state == .cancelled && !store.dns.running, "cancelled request cannot publish a late reply")
        let bound = LeakCheckStore(isFixture: true)
        var boundContext: String? = "stable-network"
        bound.automaticContextProvider = { boundContext }
        var boundCalls = 0
        bound.evidenceTransport = { req in
            boundCalls += 1
            var raw = try JSONSerialization.jsonObject(with: bound.fixtureReply(req)) as! [String: Any]
            var items = raw["items"] as! [String: [String: Any]]
            for key in req.kinds { items[key]!["validity"] = "network"; items[key]!["valid_until"] = NSNull() }
            raw["items"] = items
            return try JSONSerialization.data(withJSONObject: raw)
        }
        for kind in LeakKind.allCases { expect(await bound.ensureInitializationReceipt(kind), "network-bound backend success is accepted") }
        let originalDNS = bound.dns.result!.finishedAt, originalRTC = bound.rtc.result!.finishedAt
        bound.now = Date(timeIntervalSince1970: originalDNS + 86400)
        expect(bound.dns.verdict.state == .matched && bound.rtc.verdict.state == .matched && boundCalls == 2,
               "unchanged network keeps both results after a day without collection or timestamp renewal")
        boundContext = nil; bound.now = Date()
        expect(bound.dns.verdict.state == .matched && bound.rtc.verdict.state == .matched && bound.diagnostics[.dns] != nil,
               "missing sampler is a separate health diagnostic, not a failed leak check")
        boundContext = "stable-network"
        bound.evidenceTransport = { _ in throw LeakEvidenceFailure(code: "evidence_timeout", detail: "sample timeout") }
        expect(await bound.ensureInitializationReceipt(.dns, forceNew: true), "sampler timeout preserves accepted network result")
        expect(bound.dns.result!.finishedAt == originalDNS && bound.rtc.result!.finishedAt == originalRTC && bound.diagnostics[.dns]!.contains("采样异常"),
               "sampler timeout is visible and cannot renew the original sample")
        func environment(_ networkState: String) throws -> CurrentEnvironmentReceipt {
            let raw: [String: Any] = ["purpose":"environment_detection","grants_launch_permission":false,
                "observed_at":Date().timeIntervalSince1970,"expires_at":Date().timeIntervalSince1970 + 30,
                "rows":[],"candidates":[],"message":"fixture", "initialization_receipts":[
                    "dns":["state":"unknown","network_state":networkState],"webrtc":["state":"unknown","network_state":networkState]]]
            return try JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: JSONSerialization.data(withJSONObject: raw))
        }
        bound.acceptEnvironment(try environment("unavailable"))
        expect(bound.dns.verdict.state == .matched && bound.rtc.verdict.state == .matched, "Rust sampling unavailable keeps previous verdicts")
        bound.acceptEnvironment(try environment("changed"))
        expect(bound.dns.verdict.state == .incomplete && bound.rtc.verdict.state == .incomplete,
               "Rust-confirmed IP or rules change revokes both results even when UI node key stays the same")
        print("LeakCheckTests: \(assertions) assertions passed; production response/presentation path with injected transport; risk rules tested in Rust")
    }
}
