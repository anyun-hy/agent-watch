import Foundation

enum MonitoredProduct: String, Sendable { case claude, openAI }

@main
struct AIProcessExitEvidenceTests {
    static func main() throws {
        var checks = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            guard value() else { fatalError(message) }; checks += 1
        }
        let identity = AIProcessIdentity(pid: 71, parent: 1, uid: 501, startSeconds: 100,
            startMicroseconds: 42, executable: "/fixture/Claude", auditToken: [501,501,20,501,20,71,1000,1])
        var effects = 0
        expect(AIProcessNativeAction.applyToMatchingIdentity(identity, lookup: { _ in identity },
            effect: { _ in effects += 1; return true }), "matching native identity permits the specified action")
        var changed = identity; changed.auditToken?[7] += 1
        expect(!AIProcessNativeAction.applyToMatchingIdentity(identity, lookup: { _ in changed },
            effect: { _ in effects += 1; return true }), "in-place exec cannot inherit the request")
        expect(!AIProcessNativeAction.applyToMatchingIdentity(identity, lookup: { _ in nil },
            effect: { _ in effects += 1; return true }), "unknown identity cannot trigger AppKit")
        expect(effects == 1, "no action on mismatched or unknown identity")
        let id = UUID().uuidString
        let planData = try JSONSerialization.data(withJSONObject: ["schema": 1, "request_id": id, "family": "claude", "targets": []])
        let plan = try AIProcessClosePlan.decode(planData, product: .claude)
        for (schema, receiptID, family) in [(2,id,"claude"), (1,UUID().uuidString,"claude"), (1,id,"openai")] {
            let data = try JSONSerialization.data(withJSONObject: ["schema":schema,"request_id":receiptID,"family":family,
                "code":"", "message":"not trusted", "complete":true])
            do { _ = try AIProcessExitReceipt.decode(data, plan: plan); fatalError("unbound receipt accepted") }
            catch AIProcessInventoryFailure.malformed { checks += 1 }
        }
        if let directory = ProcessInfo.processInfo.environment["CW_PHASE3_EVIDENCE_DIR"] {
            for (name, complete) in [("normal-exit.json",true), ("prior-exit.json",true), ("timeout-exit.json",false)] {
                let data = try Data(contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(name))
                let wire = try JSONSerialization.jsonObject(with: data) as! [String:Any]
                let plan = try AIProcessClosePlan.decode(JSONSerialization.data(withJSONObject: wire["plan"]!), product: .claude)
                let receipt = try AIProcessExitReceipt.decode(JSONSerialization.data(withJSONObject: wire["receipt"]!), plan: plan)
                expect(receipt.complete == complete, "production Rust result survives Swift decoding: " + name)
                expect(receipt.message == (wire["receipt"] as! [String:Any])["message"] as? String, "Rust explanation is preserved")
            }
            print("Production Rust → Swift receipts: 3 verified")
        }
        print("AIProcessExitEvidenceTests: \(checks) assertions passed")
    }
}
