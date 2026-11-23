import Foundation
import Darwin

@main
struct AIProcessControlTests {
    @MainActor static func main() async throws {
        if CommandLine.arguments.contains("--owned-exec-identity") {
            // Real macOS API verification without sending any signal or sleeping:
            // pipe handshakes synchronize before and after an in-place exec to the
            // same /bin/sh binary. XNU preserves pbi_start_tvsec/usec across execve,
            // so only the kernel audit token (pidversion) distinguishes the two.
            let child = Process()
            let toChild = Pipe()
            let fromChild = Pipe()
            child.executableURL = URL(fileURLWithPath: "/bin/sh")
            child.arguments = ["-c", "printf 1; IFS= read -r _; exec /bin/sh -c 'printf 2; IFS= read -r _'"]
            child.standardInput = toChild
            child.standardOutput = fromChild
            child.standardError = FileHandle.nullDevice
            try child.run()
            defer {
                try? toChild.fileHandleForWriting.close()
                try? fromChild.fileHandleForReading.close()
                child.waitUntilExit()
            }
            let pid = child.processIdentifier
            guard let phase1 = try fromChild.fileHandleForReading.read(upToCount: 1),
                  String(data: phase1, encoding: .utf8) == "1" else {
                fatalError("owned pre-exec child did not reach phase 1")
            }
            guard let before = AIProcessInventory.identity(pid),
                  before.uid == getuid(),
                  before.auditToken != nil else {
                fatalError("owned pre-exec child identity or audit token unavailable")
            }
            var stableEffects = 0
            let acceptedBeforeExec = AIProcessNativeAction.applyToMatchingIdentity(
                before, lookup: AIProcessInventory.identity
            ) { verified in
                stableEffects += 1
                return verified == pid
            }
            guard acceptedBeforeExec && stableEffects == 1 else {
                fatalError("pre-exec identity failed verification")
            }
            try toChild.fileHandleForWriting.write(contentsOf: Data("\n".utf8))
            guard let phase2 = try fromChild.fileHandleForReading.read(upToCount: 1),
                  String(data: phase2, encoding: .utf8) == "2" else {
                fatalError("owned post-exec child did not reach phase 2")
            }
            guard let after = AIProcessInventory.identity(pid),
                  after.pid == before.pid,
                  after.uid == before.uid,
                  after.startSeconds == before.startSeconds,
                  after.startMicroseconds == before.startMicroseconds,
                  after.executable == before.executable else {
                fatalError("owned post-exec child identity unavailable or unexpected attributes")
            }
            guard after.auditToken != nil, after.auditToken != before.auditToken,
                  !before.sameProcess(as: after) else {
                fatalError("in-place exec in the same PID did not change auditToken/sameProcess")
            }
            var postExecEffects = 0
            let rejectedAfterExec = AIProcessNativeAction.applyToMatchingIdentity(
                before, lookup: AIProcessInventory.identity
            ) { _ in
                postExecEffects += 1
                return true
            }
            guard !rejectedAfterExec && postExecEffects == 0 else {
                fatalError("effect adapter accepted a post-exec incarnation of the same PID")
            }
            try toChild.fileHandleForWriting.close()
            child.waitUntilExit()
            print("PASS: real macOS audit token rejects in-place exec with identical PID, start time, and path")
            return
        }

        var passed = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            guard value() else { fatalError(message) }; passed += 1
        }
        let requestID = UUID().uuidString
        let planData = try JSONSerialization.data(withJSONObject: [
            "schema": 1, "force": true, "request_id": requestID, "family": "claude",
            "targets": [["desktop_main": true, "process": [
                "pid": 71, "ppid": 1, "uid": 501, "start_seconds": 100,
                "start_microseconds": 42, "executable_path": "/fixture/Claude",
                "audit_token": [501,501,20,501,20,71,1000,1]
            ]]]
        ])
        let backendMessage = "请求前已退出 0 项，本次请求后确认退出 1 项。目标已全部退出。"
        let response = try JSONSerialization.data(withJSONObject: [
            "schema": 1, "request_id": requestID, "family": "claude", "code": "",
            "complete": true, "message": backendMessage
        ])
        let control = AIProcessControl(command: { args, input, _ in
            if args == ["process-exit", "prepare", "--force", "--family", "claude", "--protect-pid", "99"] {
                precondition(input == nil); return planData
            }
            precondition(args == ["process-exit", "apply", "--apply", "--force"] && input == planData)
            return response
        })
        let plan = try await control.prepare(.claude, sampled: [], backendPID: 99)
        expect(plan.targets.count == 1 && plan.targets[0].pid == 71, "UI uses Rust targets, not sampled processes")
        expect(plan.payload == planData, "the confirmed Rust plan is preserved")
        var wrongAction = try JSONSerialization.jsonObject(with: planData) as! [String: Any]
        wrongAction["force"] = false
        let normalPlan = try AIProcessClosePlan.decode(JSONSerialization.data(withJSONObject: wrongAction), product: .claude)
        let rejectedAction = await control.execute(normalPlan)
        expect(rejectedAction.hasPrefix("退出方式未确认"), "a normal-exit plan cannot authorize the force button")
        let displayed = await control.execute(plan)
        expect(displayed == backendMessage, "UI shows the Rust result without a local verdict")
        expect(!control.busy, "completed request releases UI progress")
        let failed = AIProcessControl(command: { _, _, _ in throw AIProcessInventoryFailure.timeout })
        let failure = await failed.execute(plan)
        expect(failure.hasPrefix("退出结果未确认"), "transport timeout cannot report success")
        expect(!failed.busy, "failed request releases UI progress")
        let fixture = AIProcessControl(isFixture: true, command: { _, _, _ in fatalError("fixture cannot execute") })
        let fixtureResult = await fixture.execute(plan)
        expect(fixtureResult.hasPrefix("模拟强制结束"), "preview makes no production request")
        let confirmed = ProcessDispositionTargetModel(pid: 71, requested_action: "force", terminated: true,
            process_state: "confirmed_exit_after_request", timestamp: 1, signal_sent_at: 1)
        let prior = ProcessDispositionTargetModel(pid: 71, requested_action: "force", terminated: false,
            process_state: "already_exited", timestamp: 1, signal_sent_at: nil)
        expect(confirmed.statusLabel == "已确认退出" && prior.statusLabel == "请求前已退出", "automatic receipts retain the distinction")

        let echo = try AIProcessInventory.command(URL(fileURLWithPath: "/bin/cat"), arguments: [],
            deadline: ProcessInfo.processInfo.systemUptime + 2, input: planData)
        expect(echo == planData, "actual subprocess stdin preserves the plan")
        let homeOut = try AIProcessInventory.command(URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "printf '%s' \"$HOME\""],
            deadline: ProcessInfo.processInfo.systemUptime + 2)
        expect(!(String(data: homeOut, encoding: .utf8) ?? "").isEmpty, "subprocess environment preserves HOME for watch-engine")
        do {
            _ = try AIProcessInventory.command(URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf '{\"status\":\"error\",\"message\":\"测试中文错误\"}'; exit 4"],
                deadline: ProcessInfo.processInfo.systemUptime + 2)
            fatalError("non-zero subprocess exit did not fail")
        } catch let error as AIProcessInventoryFailure {
            expect(error.localizedDescription == "测试中文错误", "non-zero command surfaces backend JSON message via LocalizedError")
        }
        do {
            _ = try AIProcessInventory.command(URL(fileURLWithPath: "/bin/sleep"), arguments: ["5"],
                deadline: ProcessInfo.processInfo.systemUptime + 0.1, input: Data(repeating: 1, count: 131072))
            fatalError("non-reading child escaped the input deadline")
        } catch AIProcessInventoryFailure.timeout { passed += 1 }
        do {
            let statusReply = Data(#"{"status":"ok","status_report":{"target":"chatgpt-desktop","entry_generated":false,"activation_configured":false,"status_label":"入口未生成","entry_path":"/Applications/ClaudeWatchManagedChatGPT.app"},"candidate_sources":["/Applications/ChatGPT.app"]}"#.utf8)
            let entryControl = ManagedEntryControl(command: { args, _ in
                if args == ["entry", "status", "--target", "chatgpt-desktop"] {
                    return statusReply
                }
                return Data(#"{"status":"error","message":"激活入口失败"}"#.utf8)
            })
            await entryControl.refresh(for: .openAI)
            expect(entryControl.state(for: .openAI).report?.status_label == "入口未生成" &&
                   entryControl.state(for: .openAI).candidateSources == ["/Applications/ChatGPT.app"],
                   "ManagedEntryControl loads initial report and candidateSources")
            let activated = await entryControl.setEnabled(true, for: .openAI)
            let failedState = entryControl.state(for: .openAI)
            expect(!activated &&
                   failedState.report?.status_label == "入口未生成" &&
                   failedState.candidateSources == ["/Applications/ChatGPT.app"] &&
                   failedState.errorMessage == "激活入口失败",
                   "failed setEnabled preserves existing report and candidateSources instead of wiping state to unknown")
        }
        print("AIProcessControlTests: \(passed) assertions passed; monitored-app requests mocked")
    }
}
