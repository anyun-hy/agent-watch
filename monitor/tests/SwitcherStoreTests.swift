import Foundation

@main
struct SwitcherStoreTests {
    @MainActor
    static func main() async throws {
        var checks = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            checks += 1
            if !value() {
                FileHandle.standardError.write(Data(("FAIL: " + message + "\n").utf8))
                exit(1)
            }
        }
        let cachedRow = try JSONDecoder().decode(EnvironmentCheckRow.self, from: Data(#"{"id":"dns","name":"DNS","state":"cached","detail":"保留上次有效样本","scope":"Net.Coffee","required":true,"sampled_at":1000,"query_error":"本轮超时"}"#.utf8))
        expect(cachedRow.statusLabel == "上次有效" && cachedRow.sampled_at == 1000 && cachedRow.query_error == "本轮超时", "environment row preserves cached timing and query error")
        let infoRow = try JSONDecoder().decode(EnvironmentCheckRow.self, from: Data(#"{"id":"asn","name":"ASN 属性","state":"info","detail":"已读取资料","scope":"RIPEstat","required":false}"#.utf8))
        expect(infoRow.statusLabel == "已读取", "informational environment row uses neutral status")
        let reachableRow = try JSONDecoder().decode(EnvironmentCheckRow.self, from: Data(#"{"id":"reachability","name":"Claude 服务","state":"ok","detail":"网络可达","scope":"HTTPS","required":false}"#.utf8))
        expect(reachableRow.statusLabel == "网络可达", "service card green state names connectivity")
        let login = try JSONDecoder().decode(ClaudeLoginProbeResult.self, from: Data(#"{"state":"logged_in","observedAt":1792901000,"source":"Claude Accessibility","detail":"应用当前会话已核对","appVersion":"1.0","processId":42,"account":{"displayName":"Example","email":"example@example.com","menuLabel":"Example"}}"#.utf8))
        expect(login.state == "logged_in" && login.account?.email == "example@example.com", "current login receipt remains separate from local slots")
        expect(!SwitcherStore.isLoginHistorical(observedAt: 100, now: 190) &&
               SwitcherStore.isLoginHistorical(observedAt: 100, now: 191),
               "login status becomes historical after 90 seconds without inventing logout")
        let emptyA = SwitcherAccountSlot(id: "A", stored: false, current: false)
        let emptyB = SwitcherAccountSlot(id: "B", stored: false, current: false)
        let storedB = SwitcherAccountSlot(id: "B", stored: true, current: false)
        expect(SwitcherStore.accountSlotPresentation(emptyA, current: nil).summary == "未保存" &&
               SwitcherStore.accountSlotPresentation(emptyA, current: nil).confirmationDetail.contains("保存为 A") &&
               SwitcherStore.accountSlotPresentation(emptyB, current: "A").confirmationDetail.contains("保存当前 A") &&
               SwitcherStore.accountSlotPresentation(storedB, current: "A").actionTitle == "切换到 B",
               "A/B slot presentation preserves explicit empty-slot actions")
        do {
            let manager = SwitcherStore(isFixture: true)
            var current = DesktopAccountCapture(state: "logged_in", detail: "fixture", email: "first@example.test", source_token: "one")
            var requests = [[String]]()
            let gptStatus = Data(#"{"product":"chatgpt","selected":"B","current":"B","recovery_required":false,"detail":"test","accounts":[{"id":"A","stored":false,"current":false},{"id":"B","stored":true,"current":true,"account_label":"first@example.test"}]}"#.utf8)
            manager.accountReadFixture = { _ in current }
            manager.accountCommandFixture = { args, data in
                requests.append(args)
                if args[1] == "status" { return gptStatus }
                let input = try JSONDecoder().decode([String: String].self, from: data ?? Data())
                expect(input == ["source_token": "one"] && !args.contains("one"), "ChatGPT save sends only the bound token on stdin")
                return Data(#"{"saved":true,"account":"B","message":"已保存到 B"}"#.utf8)
            }
            await manager.saveManualAccount(.openAI, to: "B", expectedToken: "one")
            expect(requests.isEmpty, "save requires an explicit identity read")
            await manager.loadManualAccount(.openAI)
            expect(manager.manualAccounts[.openAI]?.label == "first@example.test" && manager.manualAccounts[.claude] == nil, "manual identities remain separate")
            await manager.saveManualAccount(.openAI, to: "B", expectedToken: "outdated")
            expect(requests.isEmpty, "a superseded confirmation cannot write a slot")
            await manager.saveManualAccount(.openAI, to: "B", expectedToken: "one")
            expect(requests == [["account", "save", "B", "--product", "chatgpt", "--apply"], ["account", "status", "--product", "chatgpt"]] &&
                   manager.chatGPTAccounts?.accounts.last?.account_label == "first@example.test" &&
                   manager.accountFeedback[.openAI] == "已保存到 B" && manager.manualAccounts[.openAI] == nil,
                   "validated save refreshes the slot label and consumes the reading")

            await manager.loadManualAccount(.claude)
            current.email = "second@example.test"
            let count = requests.count
            await manager.saveManualAccount(.claude, to: "A", expectedToken: "one")
            expect(requests.count == count && manager.manualAccounts[.claude] == nil, "changed Claude identity invalidates the pending save before writing")
            await manager.loadManualAccount(.claude)
            manager.accountCommandFixture = { args, data in
                let input = try JSONDecoder().decode([String: String].self, from: data ?? Data())
                expect(args == ["account", "save", "A", "--product", "claude", "--apply"] &&
                       input == ["source_token":"one", "account_label":"second@example.test"], "Claude sends the manually verified label on stdin")
                return Data(#"{"status":"error","message":"该槽已有账号"}"#.utf8)
            }
            await manager.saveManualAccount(.claude, to: "A", expectedToken: "one")
            expect(manager.accountFeedback[.claude] == "该槽已有账号" && manager.manualAccounts[.claude] == nil,
                   "occupied slot rejection is surfaced verbatim without success state")
            current.source_token = nil
            await manager.loadManualAccount(.openAI)
            expect(manager.manualAccounts[.openAI]?.canSave == false, "visible identity without verified process binding cannot enable save")

            let splitBrain = try JSONDecoder().decode(SwitcherAccountState.self, from: Data(#"{"current":"A","recovery_required":false,"detail":"test","accounts":[{"id":"A","stored":true,"current":true},{"id":"B","stored":true,"current":false}],"legacy_conflict":{"code":"external_switcher_conflict","watch_current":"A","legacy_current":"C","message":"原版切换器当前账号与 Claude Watch 不一致"}}"#.utf8))
            expect(splitBrain.legacy_conflict?.code == "external_switcher_conflict" &&
                   splitBrain.legacy_conflict?.watch_current == "A" &&
                   splitBrain.legacy_conflict?.legacy_current == "C" &&
                   splitBrain.legacy_conflict?.title == "检测到跨工具账号资料冲突" &&
                   splitBrain.legacy_conflict?.summaryDetail.contains("原版切换器记录：C") == true,
                   "Claude account state decodes split-brain legacy conflict details")
            let locked = try JSONDecoder().decode(SwitcherAccountState.self, from: Data(#"{"current":"A","recovery_required":false,"detail":"test","accounts":[{"id":"A","stored":true,"current":true},{"id":"B","stored":false,"current":false}],"legacy_conflict":{"code":"external_switcher_locked","message":"检测到原版切换器正在执行操作"}}"#.utf8))
            expect(locked.legacy_conflict?.code == "external_switcher_locked" &&
                   locked.legacy_conflict?.title == "原版切换器正在操作" &&
                   locked.legacy_conflict?.watch_current == nil &&
                   locked.legacy_conflict?.legacy_current == nil,
                   "Claude account state decodes external lock legacy conflict without slot fields")
            let clean = try JSONDecoder().decode(SwitcherAccountState.self, from: Data(#"{"current":"A","recovery_required":false,"detail":"test","accounts":[{"id":"A","stored":true,"current":true},{"id":"B","stored":false,"current":false}],"legacy_conflict":null}"#.utf8))
            expect(clean.legacy_conflict == nil, "null legacy_conflict decodes as nil")
        }
        var replaceable = try JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: SwitcherStore.fixtureCurrentEnvironment())
        let grouped = AtlasSubject.allCases.flatMap(\.ids)
        expect(grouped.count == Set(grouped).count && Set(grouped) == Set(replaceable.rows.map(\.id)),
               "all current audit rows belong to exactly one atlas section")
        let blocked = EnvironmentCheckRow(id: "ip_history", name: "IP", state: "fail", detail: "baseline", scope: "fixture", required: true)
        let extra = EnvironmentCheckRow(id: "future_probe", name: "Other", state: "ok", detail: "raw detail", scope: "fixture", required: false)
        for historical in [false, true] {
            let rows = [cachedRow, blocked, extra]
            let checks = AtlasCheckGroups(rows: rows, historical: historical)
            let displayed = checks.attention + AtlasSubject.allCases.flatMap { checks.sections[$0] ?? [] }
            expect(displayed.map(\.id).sorted() == rows.map(\.id).sorted(), "each receipt row has exactly one evidence tile")
            expect(checks.attention.map(\.id) == (historical ? [] : ["ip_history"]), "only a current blocker moves to attention")
            expect(checks.sections[.other]?.first?.detail == extra.detail && checks.sections[.leaks]?.first?.query_error == cachedRow.query_error,
                   "future and cached rows retain their source details")
        }
        replaceable.source_notices = [.init(id: "metadata", title: "IPinfo", detail: "本轮元数据查询失败", severity: "warn")]
        let originalEgress = replaceable.rows.first { $0.id == "egress" }?.current
        replaceable.replaceDNSRow(cachedRow)
        expect(replaceable.rows.first { $0.id == "dns" }?.state == "cached", "DNS record response replaces only the DNS environment row")
        expect(replaceable.source_notices?.first?.id == "metadata" && replaceable.rows.first { $0.id == "egress" }?.current == originalEgress,
               "DNS success preserves metadata source notices and unrelated environment rows")
        let store = SwitcherStore(isFixture: true)
        let reference = EgressReference(ip: "222.10.87.169", country: "JP", timezone: nil, checked_at: nil, observed_at: 900, context_id: nil)
        var service = BackgroundServiceReceipt(observed_at: 1000, backend_healthy: true, update_source_ready: false,
            guard_backend_healthy: true, backend_sampling_state: "complete",
            services: [.init(id: "guard", title: "保护", state: "running", detail: "", source: "fixture", desired: true, last_checked: 1000)],
            policy_issues: [], session_guard: .init(state: "safe", phase: "active", baseline: reference, current: reference, sampled_at: 1000, valid_until: 1010))
        expect(SessionBaselinePresentation.make(service, now: 1005).tone == "success", "automatic session baseline drives overview without legacy file")
        expect(SessionBaselinePresentation.make(service, now: 1036).title == "上次会话基准", "old receipt cannot present current safety")
        expect(SessionBaselinePresentation.make(service, now: 1011).tone != "success", "active safety expires at guard deadline")
        expect(SessionBaselinePresentation.make(service, error: "read failed", now: 1005).tone == "warning" &&
               SessionBaselinePresentation.make(service, error: "read failed", now: 1005).title == "保护状态读取失败",
               "retained live baseline plus read error matches guard warning instead of stale info")
        expect(SessionBaselinePresentation.make(service, error: "read failed", now: 1100).tone == "warning",
               "stale baseline cannot downgrade an explicit read error to a neutral update")
        let lockedReadError = SessionProtectionEvidence(
            session: .init(state: "locked", phase: "locked",
                           reason: .init(code: "dns_risk", detail: "保留的 DNS 风险")),
            observedAt: 1000, backendReady: false, readError: "read failed")
        expect(lockedReadError.presentation(at: 1100).tone == "danger" &&
               SessionBaselinePresentation.make(evidence: lockedReadError, now: 1100).tone == "danger",
               "a latched danger remains danger even when the next background read fails")
        expect(SessionProtectionPresentation.unavailable(error: "read failed").tone == "warning" &&
               SessionBaselinePresentation.make(nil, error: "read failed", now: 1005).tone == "warning",
               "no session receipt plus a read failure agrees across the guard and baseline panels")
        expect(SessionProtectionPresentation.unavailable(error: "").tone == "info" &&
               SessionBaselinePresentation.make(nil, now: 1005).tone == "info",
               "missing receipt without a known read error is still a pending observation")
        service.session_guard = .init(state: "idle", phase: "active", baseline: reference, current: reference)
        expect(SessionBaselinePresentation.make(service, now: 1005).title == "后台保护待命", "closed app displays standby with session history")
        let idle = SessionProtectionEvidence(session: service.session_guard!, observedAt: 1000, backendReady: true)
        expect(idle.presentation(at: 1005).detail.contains("后台保护待命，无需操作") && idle.presentation(at: 1005).tone == "info", "normal closed app never prompts confirmation")
        expect(idle.presentation(at: 1040).title == "正在更新保护状态", "stale idle does not claim current standby")
        func backgroundReceipt(at time: Double, sampling: Bool, guardReady: Bool?, guardState: String = "running") -> BackgroundServiceReceipt {
            .init(observed_at: time, backend_healthy: sampling, update_source_ready: false,
                  guard_backend_healthy: guardReady, backend_sampling_state: sampling ? "complete" : "incomplete",
                  services: [.init(id: "guard", title: "保护", state: guardState, detail: "", source: "fixture", desired: true, last_checked: time)],
                  policy_issues: [], session_guard: .init(state: "idle"))
        }
        let partial = backgroundReceipt(at: 1000, sampling: false, guardReady: true)
        expect(SessionProtectionEvidence.fromBackground(partial)?.presentation(at: 1005).title == SessionProtectionPresentation.idleTitle &&
               SessionBaselinePresentation.make(partial, now: 1005).title == SessionProtectionPresentation.idleTitle &&
               partial.backend_sampling_state == "incomplete", "incomplete monitoring sampling does not contradict a healthy guard or conceal sampling status")
        let failedGuard = backgroundReceipt(at: 1000, sampling: true, guardReady: false)
        let failedService = backgroundReceipt(at: 1000, sampling: true, guardReady: true, guardState: "error")
        expect(SessionProtectionEvidence.fromBackground(failedGuard)?.presentation(at: 1005).title == "保护后台不可用" &&
               SessionProtectionEvidence.fromBackground(failedService)?.presentation(at: 1005).title == "保护后台不可用", "actual guard or service failures remain unavailable")
        expect(SessionProtectionEvidence.fromBackground(backgroundReceipt(at: 1000, sampling: true, guardReady: nil))?.backendReady == true &&
               SessionProtectionEvidence.fromBackground(backgroundReceipt(at: 1000, sampling: false, guardReady: nil))?.backendReady == false,
               "older receipts without guard-specific health use the general health fallback")
        expect(SessionProtectionEvidence.fromBackground(partial, error: "read failed")?.presentation(at: 1005).title == "保护状态读取失败" &&
               idle.presentation(at: 999).title == "正在更新保护状态", "read errors and future-dated evidence are not shown as current")
        let received = SwitcherStore(isFixture: true)
        let sampleTime = Date().timeIntervalSince1970
        received.advanceLoginClock(Date(timeIntervalSince1970: sampleTime - 2))
        received.publishBackgroundForFixture(backgroundReceipt(at: sampleTime, sampling: false, guardReady: true))
        expect(received.sessionDisplay.title == SessionProtectionPresentation.idleTitle && received.loginClock.timeIntervalSince1970 >= sampleTime,
               "receipt arrival advances display clock to actual completion time")
        received.publishBackgroundForFixture(backgroundReceipt(at: sampleTime - 1, sampling: true, guardReady: false))
        expect(received.background?.observed_at == sampleTime && received.sessionDisplay.title == SessionProtectionPresentation.idleTitle,
               "late older background response cannot replace newer evidence")
        received.publishBackgroundForFixture(backgroundReceipt(at: sampleTime + 60, sampling: true, guardReady: true))
        expect(received.sessionDisplay.title == "正在更新保护状态", "future observation is never made current by the display clock")
        received.publishBackgroundForFixture(backgroundReceipt(at: sampleTime, sampling: false, guardReady: true))
        expect(received.sessionDisplay.title == SessionProtectionPresentation.idleTitle, "valid observation can recover after a future-dated receipt")
        expect(SessionProtectionPresentation.make(service.session_guard!, backendReady: false).tone == "warning", "disabled or failed backend is not mislabeled healthy idle")
        var closed = backgroundReceipt(at: 1010, sampling: true, guardReady: true)
        closed.session_guard = .init(state: "idle", sampled_at: 1)
        expect(SessionProtectionEvidence.fromBackground(closed)!.presentation(at: 1015).title == SessionProtectionPresentation.idleTitle, "fresh process observation keeps idle current despite old session sample")
        let locked = SessionGuardStatus(state: "locked", phase: "locked", reason: .init(code: "dns_risk", detail: "DNS 风险"))
        expect(SessionProtectionPresentation.make(locked, stale: true, backendReady: false).tone == "danger", "latched real risk wins over stale or missing backend state")
        let rechecking = SessionProtectionPresentation.make(.init(state: "pending", phase: "rechecking"))
        expect(rechecking.title == "正在复核新进程" && rechecking.tone == "info", "a replacement awaiting the full audit is never shown as protected")
        expect(SessionProtectionPresentation.make(.init(state: "risk"), stale: true, backendReady: false).tone == "danger", "explicit risk keeps danger priority")
        expect(SessionProtectionPresentation.make(.init(state: "unknown")).tone == "info", "unknown protection evidence uses neutral presentation")
        expect(SessionProtectionPresentation.make(.init(state: "safe", reason: .init(code: "egress_unconfirmed", detail: "unknown"))).tone == "info", "unconfirmed exit is not shown as a positive or error result")
        expect(SessionProtectionPresentation.make(.init(state: "idle"), stale: true).title != SessionProtectionPresentation.idleTitle, "expired idle cannot appear as current standby")
        expect(SessionProtectionPresentation.make(.init(state: "idle", phase: "locked")).tone == "danger", "contradictory idle cannot mask locked phase")
        for state in ["idle", "safe", "unknown", "missing", "pending"] {
            let display = SessionProtectionPresentation.make(.init(state: state))
            expect(!display.detail.contains("尚未确认"), "display names the state or next automatic step rather than an absent confirmation action")
        }
        let shared = SwitcherStore(isFixture: true)
        var sharedEnvironment = try JSONDecoder().decode(CurrentEnvironmentReceipt.self,
            from: SwitcherStore.fixtureCurrentEnvironment(settings: ["enabled": true, "guard_enabled": true]))
        sharedEnvironment.observed_at = 1010
        sharedEnvironment.session_guard = idle.session
        shared.loadReviewReceipts(sharedEnvironment, background: service)
        shared.advanceLoginClock(Date(timeIntervalSince1970: 1015))
        expect(shared.sessionDisplayEvidence?.session.state == "idle" && shared.sessionDisplay.title == SessionProtectionPresentation.idleTitle,
               "all pages select the latest shared session observation")
        expect(SessionBaselinePresentation.make(evidence: shared.sessionDisplayEvidence, now: 1015).title == shared.sessionDisplay.title,
               "overview and other pages agree on normal idle")
        sharedEnvironment.observed_at = 1020
        sharedEnvironment.session_guard = locked
        shared.loadReviewReceipts(sharedEnvironment, background: service)
        expect(shared.sessionDisplay.tone != "danger", "environment copy cannot override authoritative background session")
        service.session_guard = locked
        sharedEnvironment.session_guard = .init(state: "safe")
        sharedEnvironment.observed_at = 1030
        shared.loadReviewReceipts(sharedEnvironment, background: service)
        expect(shared.sessionDisplay.tone == "danger", "background locked session wins over environment copy")
        var oldActive = backgroundReceipt(at: 2000, sampling: true, guardReady: true)
        oldActive.session_guard = .init(state: "safe", sampled_at: 1000)
        expect(SessionProtectionEvidence.fromBackground(oldActive)!.presentation(at: 2001).tone != "success", "status read cannot renew old active evidence")
        expect(SessionProtectionEvidence.fromBackground(oldActive, error: "read failed")!.presentation(at: 2001).title == "保护状态读取失败", "read failure remains explicit")
        for (state, text) in [("failed", "退出失败"), ("confirmed", "已确认退出"), ("waiting", "等待退出确认")] {
            let value = SessionGuardStatus(state: "locked", phase: "locked", stop_state: state)
            let evidence = SessionProtectionEvidence(session: value, observedAt: 1000, backendReady: true)
            expect(evidence.presentation(at: 1005).detail.contains(text) && SessionBaselinePresentation.make(evidence: evidence, now: 1005).detail.contains(text), "stop result agrees in both presentations")
        }
        service.session_guard = .init(state: "locked", phase: "locked", baseline: reference, current: reference)
        expect(SessionBaselinePresentation.make(service, now: 5000).tone == "danger", "latched stop remains visible even with old receipt")
        service.session_guard = .init(state: "missing")
        expect(SessionBaselinePresentation.make(service, now: 1005).detail.contains("无需手动配置"), "new install explains automatic creation")
        expect(AccessibilityPermission.shouldPrompt(trusted: false, build: "296", previous: "295", bundle: "io.local.watchpanel", path: AccessibilityPermission.installedPath), "new installed build requests permission")
        expect(!AccessibilityPermission.shouldPrompt(trusted: true, build: "296", previous: nil, bundle: "io.local.watchpanel", path: AccessibilityPermission.installedPath), "existing valid access not prompted")
        expect(!AccessibilityPermission.shouldPrompt(trusted: false, build: "296", previous: "296", bundle: "io.local.watchpanel", path: AccessibilityPermission.installedPath), "no recurring prompt each refresh")
        expect(!AccessibilityPermission.shouldPrompt(trusted: false, build: "296", previous: nil, bundle: "io.local.watchpanel.review", path: AccessibilityPermission.installedPath), "isolated app cannot request production permission")
        let review = SwitcherStore(isFixture: true)
        for scenario in SwitcherReviewScenario.allCases {
            review.loadReviewScenario(scenario)
            expect(review.currentEnvironment?.purpose == "environment_detection" &&
                   review.background?.session_guard != nil,
                   "review scenario \(scenario.rawValue) stays entirely in fixture state")
        }
        review.loadReviewScenario(.ipChanged)
        expect(review.currentPolicyEvaluation?.blocked.contains("ip_history") == true &&
               review.background?.session_guard?.state == "locked",
               "IP-change review scenario links environment, preview, and session guard")
        await review.refreshBackground()
        expect(review.background?.session_guard?.state == "locked" &&
               review.background?.session_guard?.current?.ip == "8.8.4.4",
               "review background refresh preserves the selected locked session scenario")
        review.loadReviewScenario(.recovered)
        expect(review.currentPolicyEvaluation?.ready == true &&
               review.auditOperationMessage.contains("手动"),
               "recovery scenario remains manual-start only")
        let claudeLaunch = GraphLaunchTarget(product: .claude)
        let chatgptLaunch = GraphLaunchTarget(product: .openAI)
        var wireEnvironment = try JSONSerialization.jsonObject(with: SwitcherStore.fixtureCurrentEnvironment()) as! [String: Any]
        var wireChatGPT = wireEnvironment["policy_evaluation"] as! [String: Any]
        wireChatGPT["launch_target"] = "chatgpt-desktop"
        wireEnvironment["chatgpt_policy_evaluation"] = wireChatGPT
        let decodedEnvironment = try JSONDecoder().decode(CurrentEnvironmentReceipt.self,
            from: JSONSerialization.data(withJSONObject: wireEnvironment))
        expect(decodedEnvironment.chatgpt_policy_evaluation?.launch_target == "chatgpt-desktop" &&
               decodedEnvironment.chatgpt_policy_evaluation?.observation_id == decodedEnvironment.observation_id,
               "the shared environment receipt decodes the target-specific preview from the same round")
        expect(claudeLaunch.arguments == ["launch", "--apply"] &&
               chatgptLaunch.arguments == ["launch", "--target", "chatgpt-desktop", "--apply"],
               "graph starts the selected desktop using its own full launch entry")
        var presence = WorkspaceDesktopPresence()
        expect(presence.record(pid: 11, bundle: "com.openai.codex", launched: true) &&
               !chatgptLaunch.hasRunningDesktop(in: presence), "Codex presence does not block ChatGPT launch")
        expect(!presence.record(pid: 11, bundle: "com.openai.codex", launched: true), "duplicate launch does not publish a change")
        _ = presence.record(pid: 12, bundle: "com.openai.chat", launched: true)
        _ = presence.record(pid: 13, bundle: "com.openai.chat", launched: true)
        _ = presence.record(pid: 12, bundle: "com.openai.chat", launched: false)
        expect(chatgptLaunch.hasRunningDesktop(in: presence) && !claudeLaunch.hasRunningDesktop(in: presence), "one remaining ChatGPT instance is still running")
        _ = presence.record(pid: 13, bundle: "com.openai.chat", launched: false)
        expect(!chatgptLaunch.hasRunningDesktop(in: presence), "last termination clears ChatGPT independently of Codex")
        expect(presence.record(pid: 14, bundle: "com.openai.codex", bundleName: "ChatGPT.app", launched: true) &&
               chatgptLaunch.hasRunningDesktop(in: presence),
               "unified ChatGPT.app (com.openai.codex) is recognized as running ChatGPT without conflating Codex.app")
        _ = presence.record(pid: 14, bundle: "com.openai.codex", bundleName: "ChatGPT.app", launched: false)
        expect(!chatgptLaunch.hasRunningDesktop(in: presence), "closing unified ChatGPT.app clears running state while Codex stays separate")
        let cliOnly = [WatchedProcess(id: "cli", pid: 1, started: "fixture", kind: "codex-cli", authorized: nil)]
        let chatgptMain = [WatchedProcess(id: "desktop", pid: 2, started: "fixture", kind: "chatgpt-desktop-main", authorized: nil)]
        let unifiedMain = [WatchedProcess(id: "unified", pid: 3, started: "fixture", kind: "openai-desktop-main", authorized: nil)]
        expect(!chatgptLaunch.hasRunningDesktop(in: cliOnly) && chatgptLaunch.hasRunningDesktop(in: chatgptMain) &&
               chatgptLaunch.hasRunningDesktop(in: unifiedMain) && !claudeLaunch.hasRunningDesktop(in: chatgptMain) &&
               !claudeLaunch.hasRunningDesktop(in: unifiedMain),
               "a running desktop blocks only its own launch, not another product or a CLI")
        let backendLaunchMsg = SwitcherStore.resolveOperationMessage(
            raw: ["status": "ok", "message": "启动检查通过并已启动 ChatGPT。"],
            args: ["launch", "--target", "chatgpt-desktop", "--apply"],
            status: "ok", failure: false)
        expect(backendLaunchMsg == "启动检查通过并已启动 ChatGPT。" && !backendLaunchMsg.hasPrefix("上次操作："),
               "launch result preserves backend message without misleading historical prefix")
        expect(SwitcherStore.formattedVersion("6.28899.2", build: "6.28899.2") == "6.28899.2" &&
               SwitcherStore.formattedVersion("26.1117.31558", build: "29513") == "26.1117.31558 (29513)",
               "version formatter omits duplicate build numbers while keeping distinct build numbers")
        review.publishBackgroundForFixture(backgroundReceipt(at: Date().timeIntervalSince1970, sampling: true, guardReady: true))
        expect(claudeLaunch.blockReason(store: review, at: Date()) == nil &&
               chatgptLaunch.blockReason(store: review, at: Date()) == nil,
               "both buttons use the matching current ready environment preview")
        var independentEnvironment = review.currentEnvironment!
        let basePreview = review.currentPolicyEvaluation!
        independentEnvironment.policy_evaluation = EnvironmentPolicyEvaluation(
            purpose: basePreview.purpose, grants_launch_permission: false,
            observed_at: basePreview.observed_at, expires_at: basePreview.expires_at,
            observation_id: basePreview.observation_id, context_id: basePreview.context_id,
            policy: basePreview.policy, rows: basePreview.rows, blocked: ["guard"],
            ready: false, message: "Claude guard unavailable")
        review.loadReviewReceipts(independentEnvironment, background: backgroundReceipt(
            at: Date().timeIntervalSince1970, sampling: true, guardReady: false))
        expect(claudeLaunch.blockReason(store: review, at: Date()) != nil &&
               chatgptLaunch.blockReason(store: review, at: Date()) == nil,
               "a blocked Claude-only preview does not block the same-round ChatGPT preview")
        independentEnvironment.chatgpt_policy_evaluation?.launch_target = "codex-desktop"
        review.loadReviewReceipts(independentEnvironment, background: backgroundReceipt(
            at: Date().timeIntervalSince1970, sampling: true, guardReady: true))
        expect(chatgptLaunch.blockReason(store: review, at: Date()) != nil,
               "a preview for a different target cannot enable ChatGPT")
        review.loadReviewScenario(.recovered)
        review.publishBackgroundForFixture(backgroundReceipt(at: Date().timeIntervalSince1970, sampling: true, guardReady: false))
        expect(claudeLaunch.blockReason(store: review, at: Date()) != nil &&
               chatgptLaunch.blockReason(store: review, at: Date()) == nil,
               "unconfirmed Claude protection blocks Claude without pretending it protects ChatGPT")
        review.publishBackgroundForFixture(backgroundReceipt(at: Date().timeIntervalSince1970 - 40, sampling: true, guardReady: true))
        expect(claudeLaunch.blockReason(store: review, at: Date()) != nil &&
               chatgptLaunch.blockReason(store: review, at: Date()) == nil,
               "stale Claude protection cannot leave its launch button green")
        var lockedBackground = backgroundReceipt(at: Date().timeIntervalSince1970, sampling: true, guardReady: true)
        lockedBackground.session_guard = .init(state: "locked", phase: "locked")
        review.publishBackgroundForFixture(lockedBackground)
        expect(claudeLaunch.blockReason(store: review, at: Date()) != nil,
               "a latched Claude session risk cannot enable launch")
        review.publishBackgroundForFixture(backgroundReceipt(at: Date().timeIntervalSince1970, sampling: true, guardReady: true))
        let expiry = review.currentPolicyEvaluation!.expires_at
        expect(claudeLaunch.blockReason(store: review, at: Date(timeIntervalSince1970: expiry)) != nil,
               "an expired environment preview never enables launch")
        let beforeSample = review.currentPolicyEvaluation!.observed_at - 1
        expect(claudeLaunch.blockReason(store: review, at: Date(timeIntervalSince1970: beforeSample)) != nil,
               "a future-dated environment preview never enables launch")
        review.loadReviewScenario(.ipChanged)
        expect(claudeLaunch.blockReason(store: review, at: Date()) != nil &&
               chatgptLaunch.blockReason(store: review, at: Date()) != nil,
               "a blocked environment preview never enables either button")
        review.loadReviewScenario(.normal)
        review.text(Setting.country).wrappedValue = "GB"
        expect(claudeLaunch.blockReason(store: review, at: Date()) != nil,
               "unsaved settings disable graph launch")
        review.loadReviewScenario(.normal)
        review.recordDetectionFailure("fixture unavailable")
        expect(claudeLaunch.blockReason(store: review, at: Date()) != nil,
               "a failed refresh cannot keep the previous green launch state")
        review.loadReviewScenario(.normal)
        review.acceptEvidenceFailure(.webrtc, detail: "后台检测不可用")
        expect(review.webRTCReceiptError == "后台检测不可用" && review.initializationWebRTCReceipt == nil,
               "unavailable daemon invalidates the initialization receipt and preserves its reason")
        await store.load()
        expect(store.chatgptVersion == "26.1117.31558" && store.chatgptBuild == "29513" &&
               store.aiVersions?.claude.embedded_cli.latest == "2.1.328" &&
               store.aiVersions?.chatgpt.embedded_cli.bundled_in_app == true &&
               store.aiVersions?.chatgpt.standalone_cli.selected_source_label == "Homebrew Cask" &&
               store.aiVersions?.chatgpt.desktop.sandbox_compat_mode == true,
               "status load populates ChatGPT version/build and symmetrical AI product version inspection receipt")
        let coordinated = SwitcherStore(isFixture: true)
        await coordinated.load()
        coordinated.fixtureEnvironmentReadDelayNanoseconds = 150_000_000
        let readTask = Task { await coordinated.detectCurrentEnvironment() }
        try await Task.sleep(nanoseconds: 20_000_000)
        let firstAction = Task { await coordinated.perform(["account", "switch", "B", "--apply", "--ack-unverified-version"]) }
        let secondAction = Task { await coordinated.perform(["account", "switch", "B", "--apply", "--ack-unverified-version"]) }
        _ = await firstAction.value
        _ = await secondAction.value
        _ = await readTask.value
        expect(coordinated.accounts?.current == "B" && !coordinated.busy,
               "user action cancels a read and blocks overlapping mutation; evidence collection belongs to Rust")
        let timeout = SwitcherStore(isFixture: true)
        await timeout.load()
        timeout.fixtureEnvironmentReadDelayNanoseconds = 300_000_000
        timeout.environmentReadWaitTimeout = 0.02
        let timeoutRead = Task { await timeout.detectCurrentEnvironment() }
        try await Task.sleep(nanoseconds: 10_000_000)
        await timeout.perform(["account", "switch", "B", "--apply", "--ack-unverified-version"])
        expect(timeout.accounts?.current == nil && timeout.message.contains("未执行此操作"),
               "read cancellation timeout does not execute an account mutation")
        _ = await timeoutRead.value
        let automatic = SwitcherStore(isFixture: true)
        await automatic.load(automaticCheck: true)
        expect(automatic.currentEnvironment?.rows.count == 15, "opening the page starts detection without an online-policy setting")
        expect(automatic.currentEnvironment?.context_transition?.state == "stable", "real-shaped context transition decodes while opaque summaries are ignored")
        expect(automatic.currentPolicyEvaluation?.grants_launch_permission == false &&
               automatic.currentPolicyEvaluation?.observed_at == automatic.currentEnvironment?.observed_at,
               "same observation supplies a display-only launch preview")
        if let environment = automatic.currentEnvironment, let preview = automatic.currentPolicyEvaluation {
            expect(SwitcherStore.acceptsDisplayPolicy(preview, for: environment, hasUnsavedSettings: false),
                   "matching observation/context preview is displayable")
            let mismatched = EnvironmentPolicyEvaluation(purpose: preview.purpose, grants_launch_permission: false,
                                                         observed_at: preview.observed_at, expires_at: preview.expires_at,
                                                         observation_id: "other-observation", context_id: preview.context_id,
                                                         policy: preview.policy, rows: preview.rows, blocked: preview.blocked,
                                                         ready: preview.ready, message: preview.message)
            expect(!SwitcherStore.acceptsDisplayPolicy(mismatched, for: environment, hasUnsavedSettings: false) &&
                   !SwitcherStore.acceptsDisplayPolicy(preview, for: environment, hasUnsavedSettings: true),
                   "mismatched or draft-bound preview is rejected")
            var unavailableEnvironment = environment
            unavailableEnvironment.context_transition = .init(state: "sampling_unavailable", unavailable: ["代理控制接口"])
            let unavailablePreview = EnvironmentPolicyEvaluation(purpose: preview.purpose, grants_launch_permission: false,
                                                                  observed_at: preview.observed_at, expires_at: preview.expires_at,
                                                                  observation_id: preview.observation_id, context_id: preview.context_id,
                                                                  policy: preview.policy, rows: preview.rows, blocked: ["dns"],
                                                                  ready: false, message: preview.message)
            expect(SwitcherStore.acceptsDisplayPolicy(unavailablePreview, for: unavailableEnvironment, hasUnsavedSettings: false),
                   "current unavailable observation still shows its blocked display preview")
            let unsafePreview = EnvironmentPolicyEvaluation(purpose: preview.purpose, grants_launch_permission: false,
                                                             observed_at: preview.observed_at, expires_at: preview.expires_at,
                                                             observation_id: preview.observation_id, context_id: preview.context_id,
                                                             policy: preview.policy, rows: preview.rows, blocked: [],
                                                             ready: true, message: preview.message)
            expect(!SwitcherStore.acceptsDisplayPolicy(unsafePreview, for: unavailableEnvironment, hasUnsavedSettings: false),
                   "nonstable observation cannot display a satisfied preview")
        } else { fatalError("fixture must contain policy preview") }
        automatic.invalidateCurrentEnvironmentRequest()
        expect(automatic.currentEnvironmentIsHistorical && automatic.currentPolicyEvaluation == nil,
               "real context invalidation marks prior environment historical and clears current preview")
        _ = await automatic.detectCurrentEnvironment()
        expect(!automatic.currentEnvironmentIsHistorical && automatic.currentPolicyEvaluation != nil,
               "new stable observation recovers the shared display-only preview")
        expect(automatic.candidate == nil, "automatic detection does not create a configuration candidate")
        expect(automatic.settings["country"] as? String == "", "automatic detection does not save a country target")
        expect(automatic.currentEnvironment?.rows.first { $0.name == "DNS" }?.state == "ok", "fixture DNS matches the same-run public egress country")
        expect(automatic.currentEnvironment?.rows.last?.state == "warn", "401/403 remain warnings in the rendered detection fixture")
        expect((try? JSONDecoder().decode(EnvironmentAuditReceipt.self, from: SwitcherStore.fixtureCurrentEnvironment())) == nil,
               "a direct-detection receipt cannot decode as a controlled-launch audit")
        expect(store.loaded, "fixture state loads")
        expect(store.accounts?.accounts.count == 2, "A/B slots are represented")
        expect(store.accounts?.current == nil, "no invented logged-in account")
        expect(!store.hasUnsavedSettings, "initial state is clean")
        expect(store.environment?.rows.count == 11, "first open performs isolated local discovery")
        expect(store.environment?.rows.first { $0.id == "country" }?.current == "未知", "offline discovery does not invent a country")
        expect(store.candidate == nil, "first open does not request online candidates")
        expect(store.environment?.rows.first { $0.id == "network_service" }?.current == "Ethernet", "active service is observed instead of assuming Wi-Fi")
        let initialSettings = store.settings["country"] as? String
        await store.detectEnvironment()
        expect(store.candidate != nil, "one explicit detection produces a candidate")
        expect(store.settings["country"] as? String == initialSettings, "candidate does not replace saved target")
        expect(store.candidate?.rows.first { $0.id == "country" }?.proposed_source.contains("IPinfo") == true, "candidate source reaches the UI")
        await store.previewEnvironment()
        expect(store.setupCanConfirm, "candidate requires a separate preview before confirmation")
        store.setupWatchdog.toggle()
        expect(store.setupPlan == nil && !store.setupCanConfirm, "changing selected services invalidates confirmation")
        await store.previewEnvironment()
        await store.refreshBackground()
        expect(store.background?.services.count == 4, "each background service has its own actual state")
        expect(store.background?.services.first { $0.id == "original" }?.state == "scheduled", "original bodyguard remains independently visible")
        expect(store.background?.services.first { $0.id == "updater" }?.state == "unavailable", "missing publication source is not shown as active updating")
        await store.detectEnvironment()
        store.text(Setting.locale).wrappedValue = "en_GB"
        await store.previewEnvironment()
        expect(store.setupPlan == nil, "unsaved manual settings cannot be overwritten by candidate confirmation")
        await store.inspectEnvironment()
        expect(store.hasUnsavedSettings, "local discovery does not overwrite a manual draft")
        expect(store.settings["locale"] as? String == "en_GB", "manual draft survives local discovery")
        await store.refreshBackground()
        expect(store.settings["locale"] as? String == "en_GB" && store.hasUnsavedSettings, "refreshing actual services preserves a draft")
        await store.load()
        expect(store.chatgptVersion == "26.1117.31558" && store.chatgptBuild == "29513" &&
               store.aiVersions?.claude.embedded_cli.latest == "2.1.328" &&
               store.aiVersions?.chatgpt.embedded_cli.bundled_in_app == true &&
               store.aiVersions?.chatgpt.standalone_cli.selected_source_label == "Homebrew Cask" &&
               store.aiVersions?.chatgpt.desktop.sandbox_compat_mode == true,
               "status load populates ChatGPT version/build and symmetrical AI product version inspection receipt")
        expect(store.settings["locale"] as? String == "en_GB" && store.hasUnsavedSettings, "reloading authoritative status cannot replace a draft")
        store.discardChanges()
        expect(store.settings["locale"] as? String == "" && !store.hasUnsavedSettings, "discard restores the saved settings without saving")
        store.text(Setting.locale).wrappedValue = "en_GB"
        expect(!store.updateSourceReady, "missing update manifest and key remain unavailable")
        _ = await store.detectCurrentEnvironment()
        expect(store.currentEnvironment?.rows.count == 15, "current-state detection always exposes every check, including the ChatGPT service card")
        expect(store.currentEnvironment?.grants_launch_permission == false, "live observation cannot grant launch permission")
        expect(store.hasUnsavedSettings, "direct live detection does not require saving a manual draft")
        expect(store.settings["locale"] as? String == "en_GB", "direct live detection cannot replace draft settings")
        expect(store.currentEnvironment?.rows.first?.source != nil, "live row source is available to the UI")
        await store.save()
        store.text(Setting.country).wrappedValue = "GB"
        expect(store.hasUnsavedSettings, "editing policy requires save")
        await store.save()
        expect(!store.hasUnsavedSettings, "fixture save stays in memory")
        await store.perform(["checkdetail", "--online"])
        expect(store.audit?.rows.count == 15, "every row reaches the UI")
        expect(store.audit?.ready == false, "unknown STUN is not ready")
        expect(store.audit?.rows.contains { $0.state == "unknown" } == true, "unknown remains visible")
        store.text(Setting.country).wrappedValue = "JP"
        expect(store.audit == nil, "editing policy invalidates the previous launch-check display")
        store.diagnosticProxy = "socks5h://fixture:private@127.0.0.1:1080"
        await store.diagnoseProxy()
        expect(store.diagnostic?.checks.count == 2, "both independent transport checks are displayed")
        expect(store.diagnostic?.checks.first?.accessLabel == "需要账号认证", "401 is not login success")
        expect(store.diagnostic?.checks.last?.accessLabel == "访问受限", "403 remains restricted")
        expect(store.audit == nil, "transport receipt cannot restore invalidated launch readiness")
        expect(store.accounts?.current == nil, "transport check cannot initialize an account")
        expect(store.hasUnsavedSettings, "independent check does not reload or overwrite draft settings")
        expect(store.settings["proxy_url"] == nil, "private diagnostic proxy is not persisted in settings")
        expect(!store.busy, "diagnostic returns to idle")
        await store.save()
        await store.preview("repair")
        expect(store.plan?.actions.count == 1, "repair preview is reviewable")
        await store.applyPreview()
        expect(store.plan == nil, "applied preview cleared")
        await store.perform(["account", "switch", "B", "--apply", "--ack-unverified-version"])
        expect(store.accounts?.current == "B", "fixture switching updates only fixture state")
        expect(store.chatGPTAccounts?.current == "A", "Claude switching leaves the ChatGPT selection alone")
        await store.switchChatGPTAccount(to: "B")
        expect(store.chatGPTAccounts?.current == "B" && store.accounts?.current == "B",
               "the ChatGPT B action addresses its own two slots")
        await store.switchChatGPTAccount(to: "A")
        expect(store.chatGPTAccounts?.current == "A" && store.accounts?.current == "B" &&
               store.chatGPTAccounts?.accounts.last?.stored == true, "return to A retains B and the Claude slot")
        await store.switchChatGPTAccount(to: "C")
        expect(store.chatGPTAccounts?.current == "A", "unknown ChatGPT slot cannot dispatch a switch")
        do {
            let readback = SwitcherStore(isFixture: true)
            func receipt(selected: String? = nil, current: String?, checked: Bool? = nil,
                         login: [String: String] = [:]) -> [String: Any] {
                let slots: [[String: Any]] = ["A", "B"].map { id in
                    var slot: [String: Any] = ["id": id, "stored": true, "current": current == id]
                    if let value = login[id] { slot["login_state"] = value }
                    return slot
                }
                var reply: [String: Any] = ["product": "chatgpt", "accounts": slots,
                                            "recovery_required": false, "detail": "isolated receipt"]
                if let selected { reply["selected"] = selected }
                if let current { reply["current"] = current }
                if let checked { reply["login_checked"] = checked }
                return reply
            }
            func slot(_ id: String) -> SwitcherAccountSlot? {
                readback.chatGPTAccounts?.accounts.first { $0.id == id }
            }
            readback.consumeChatGPTAccounts(receipt(current: "A"))
            expect(slot("A")?.current == true && slot("A")?.login_state != "logged_in",
                   "legacy status identifies a running profile without asserting desktop login")

            readback.consumeChatGPTAccounts(receipt(selected: "A", current: "A", checked: true,
                                                   login: ["A": "logged_in", "B": "signed_out"]))
            readback.consumeChatGPTAccounts(receipt(selected: "A", current: "A", checked: false))
            expect(slot("A")?.login_state == "logged_in" && slot("B")?.login_state == "signed_out",
                   "a summary reread preserves the separate login observations for unchanged profiles")
            readback.consumeChatGPTAccounts(receipt(selected: "A", current: "A", checked: true,
                                                   login: ["A": "unknown", "B": "signed_out"]))
            expect(slot("A")?.current == true && slot("A")?.login_state != "logged_in" &&
                   slot("B")?.login_state == "signed_out",
                   "a new inconclusive login check supersedes a previous positive observation")

            readback.consumeChatGPTAccounts(receipt(selected: "B", current: nil))
            expect(readback.chatGPTAccounts?.selected == "B" && readback.chatGPTAccounts?.current == nil &&
                   slot("B")?.current == false, "selected B survives a missing current process")
            await readback.switchChatGPTAccount(to: "B")
            expect(readback.chatGPTAccounts?.current == "B" && slot("B")?.current == true &&
                   slot("B")?.login_state != "logged_in",
                   "a selected but stopped B opens again without claiming a successful login")
            await readback.switchChatGPTAccount(to: "A")
            expect(readback.chatGPTAccounts?.current == "A" && slot("A")?.stored == true &&
                   slot("B")?.stored == true && slot("A")?.login_state != "logged_in",
                   "switching back to A retains both profile slots without granting login evidence")
        }
        expect(store.message.contains("隔离预览"), "fixture boundary remains visible")
        expect(!store.busy, "operation state returns to idle")
        store.flag(Setting.requireDNS).wrappedValue = true
        expect(!store.policyWarnings.contains { $0.contains("DNS") }, "DNS has no manual trusted-resolver warning")
        store.discardChanges()
        let planJSON = Data(#"{"id":"clock","title":"设置时区","scope":"administrator","before":"Asia/Tokyo","after":"Asia/Seoul"}"#.utf8)
        let change = try JSONDecoder().decode(SwitcherRepairAction.self, from: planJSON)
        expect(change.detail == "Asia/Tokyo → Asia/Seoul", "raw backend before/after values reach the review UI")
        let booleanJSON = Data(#"{"id":"guard","title":"保护","scope":"watch","before":false,"after":true}"#.utf8)
        let booleanChange = try JSONDecoder().decode(SwitcherRepairAction.self, from: booleanJSON)
        expect(booleanChange.detail == "关闭 → 开启", "boolean changes are human-readable")
        await store.previewProtection("guard_enabled", enable: true)
        expect(store.plan != nil, "service actions first produce a concrete preview")
        expect(store.settings["guard_enabled"] as? Bool != true, "preview cannot enable a guard")
        await store.applyPreview()
        await store.refreshBackground()
        expect(store.settings["guard_enabled"] as? Bool == true, "explicit application commits only the fixture service change")
        expect(store.background?.services.first { $0.id == "original" }?.state == "scheduled", "own guard changes retain the original bodyguard")
        let cancelledRead = SwitcherReadCancellation()
        cancelledRead.cancel()
        let neverStarted = Process(); neverStarted.executableURL = URL(fileURLWithPath: "/bin/sleep"); neverStarted.arguments = ["1"]
        do { try cancelledRead.start(neverStarted); fatalError("cancelled read should not start") }
        catch is CancellationError { expect(!neverStarted.isRunning, "cancel before start cannot launch a late read process") }
        let runningRead = SwitcherReadCancellation()
        let readProcess = Process(); readProcess.executableURL = URL(fileURLWithPath: "/bin/sleep"); readProcess.arguments = ["2"]
        try runningRead.start(readProcess); runningRead.cancel(); readProcess.waitUntilExit()
        expect(runningRead.isCancelled && !readProcess.isRunning, "read cancellation terminates only its attached read process")
        if CommandLine.arguments.count > 1 {
            let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
            let audit = try JSONDecoder().decode(EnvironmentAuditReceipt.self, from: data)
            expect(audit.rows.count == 15, "Python-to-Swift JSON contract")
            expect(audit.rows.contains { $0.id == "language" }, "client language is not dropped")
            expect(audit.rows.contains { $0.id == "asn" }, "ASN is not dropped")
            expect(audit.rows.contains { $0.id == "reachability" }, "reachability is not dropped")
            expect(audit.ready == false, "offline receipt cannot become a pass")
        }
        if CommandLine.arguments.count > 2 {
            let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]))
            let diagnostic = try JSONDecoder().decode(ProxyDiagnosticReceipt.self, from: data)
            expect(diagnostic.reached, "Python transport receipt reaches its own UI model")
            expect(diagnostic.checks.first?.http_status == 401, "API authentication status is preserved")
            expect(diagnostic.checks.last?.http_status == 403, "web access restriction is preserved")
        }
        if CommandLine.arguments.count > 3 {
            let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[3]))
            let candidate = try JSONDecoder().decode(EnvironmentCandidate.self, from: data)
            expect(candidate.rows.count == 10, "Python onboarding preserves every observation row")
            expect(candidate.rows.first { $0.id == "country" }?.target == "未配置", "first-time Python target remains unset")
            expect(candidate.rows.first { $0.id == "locale" }?.proposed == "ja_JP", "Japanese date formats remain independent from English interface language")
        }
        if CommandLine.arguments.count > 4 {
            let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[4]))
            let detection = try JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: data)
            expect(detection.rows.count == 15, "Python-to-Swift direct detection contract")
            expect(!detection.grants_launch_permission, "Python detection remains separate from launch authority")
            expect(detection.rows.first { $0.id == "timezone" }?.reference == "Asia/Tokyo", "reference timezone comes from current egress")
        }
        if CommandLine.arguments.count > 5 {
            let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[5]))
            let service = try JSONDecoder().decode(BackgroundServiceReceipt.self, from: data)
            expect(service.services.count == 4, "Python actual-service contract preserves both guards, timezone and updater")
            expect(service.services.first { $0.id == "original" }?.state == "scheduled", "one-shot original guard is shown as loaded")
            expect(service.services.first { $0.id == "updater" }?.state == "unavailable", "source-less update intent cannot become an active updater")
        }
        if CommandLine.arguments.count > 6 {
            let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[6]))
            let plan = try JSONDecoder().decode(SwitcherRepairPlan.self, from: data)
            expect(plan.actions.first?.detail?.contains("开启 → 关闭") == true, "real service preview differences reach the review sheet")
        }
        let failedRoundStore = SwitcherStore(isFixture: true)
        await failedRoundStore.load()
        _ = await failedRoundStore.detectCurrentEnvironment()
        let priorTime = failedRoundStore.currentEnvironment?.observed_at
        failedRoundStore.recordDetectionFailure("fixture: entire observation reader failed")
        expect(failedRoundStore.currentPolicyEvaluation == nil, "whole-reader failure cannot retain a ready preview")
        expect(failedRoundStore.currentEnvironmentIsHistorical, "previous observation is explicitly historical after whole-reader failure")
        expect(failedRoundStore.currentEnvironment?.observed_at == priorTime, "failure does not renew previous evidence time")
        _ = await failedRoundStore.detectCurrentEnvironment()
        expect(!failedRoundStore.currentEnvironmentIsHistorical && failedRoundStore.currentPolicyEvaluation != nil, "fresh successful round restores the shared current preview")
        // Each AI service declares its own policy: no key is shared, and a
        // service can only offer actions it can perform.
        let keys = AIPolicyCatalog.services.flatMap { policy in policy.criteria.map { policy.setting($0).key } }
        expect(Set(keys).count == keys.count, "policy keys belong to exactly one service")
        expect(AIPolicyCatalog.services.allSatisfy { policy in
            policy.criteria.allSatisfy { policy.setting($0).key == "\(policy.keyPrefix)_close_\($0.id)" }
        }, "a criterion's key is derived from its own family")
        let claude = AIPolicyCatalog.services.first { $0.id == "claude" }
        let openAI = AIPolicyCatalog.services.first { $0.id == "openai" }
        expect(claude?.actions.count == 3 && claude?.criteria.filter { $0.id != "session" }.allSatisfy { policy in
            claude?.setting(policy).fallback == "force"
        } == true, "the supervised session keeps the full action set")
        expect(claude?.criteria.first { $0.id == "session" }?.fallback == "close",
               "an unestablished session keeps the historical normal exit for Claude")
        expect(openAI?.actions.map(\.id) == ["force", "close", "warn"]
                   && openAI?.criteria.filter { $0.id != "session" }.allSatisfy { policy in
                       openAI?.setting(policy).fallback == "close"
                   } == true,
               "the OpenAI service offers the full action set and assumes close")
        expect(openAI?.criteria.first { $0.id == "session" }?.fallback == "close",
               "an unestablished session keeps the historical normal exit for ChatGPT")
        expect(openAI?.actions.contains(.force) == true,
               "force is available for every supervised family")
        expect(openAI?.note == nil, "no reduced action set means no explanation note")
        // Service differences are declared, not compared against an id string.
        expect(BackgroundServiceCatalog.descriptor("guard").toggle == Setting.guardEnabled
                   && BackgroundServiceCatalog.descriptor("watchdog").toggle == Setting.timezoneWatchdog,
               "each service's switch is looked up, never derived by name")
        expect(BackgroundServiceCatalog.descriptor("original").toggle == nil,
               "a service with no switch of its own has no key to write")
        expect(BackgroundServiceCatalog.descriptor("unknown").toggle == nil,
               "an unknown service gets no switch instead of a guessed key")
        // The pre-launch check must stream its stages: a launch or a launch
        // requirements preview that reports nothing read as a frozen button.
        expect(SwitcherStore.streamsPhasesForTest(["launch", "--apply"]), "a launch streams its stages")
        expect(SwitcherStore.streamsPhasesForTest(["launch", "--target", "chatgpt-desktop", "--apply"]),
               "a ChatGPT launch streams its stages")
        expect(SwitcherStore.streamsPhasesForTest(["checkdetail", "--online"]),
               "a launch requirements preview streams its stages")
        expect(SwitcherStore.streamsPhasesForTest(["setup", "apply", "--apply"]),
               "the setup transaction keeps streaming")
        expect(!SwitcherStore.streamsPhasesForTest(["logs"]),
               "an instant command streams nothing")
        expect(!SwitcherStore.streamsPhasesForTest(["account", "import"]),
               "a read-only account command streams nothing")
        expect(SwitcherStore.streamsPhasesForTest(["account", "switch", "A", "--apply"]),
               "an applying account switch streams its stages")
        // Each announced stage maps to exactly one determinate step, so the
        // launch row can show 1/3, 2/3, 3/3 instead of an endless spinner.
        expect(SetupProgressPhase.collectEvidence.launchStage == 1
                   && SetupProgressPhase.verifyLaunchConditions.launchStage == 2
                   && SetupProgressPhase.bindSession.launchStage == 3
                   && SetupProgressPhase.openApplication.launchStage == 3,
               "every launch stage maps to one determinate step")
        expect(SetupProgressPhase.applySettings.launchStage == nil,
               "a setup phase is not a launch step")
        expect(SetupProgressPhase.launchStageCount == 3, "the launch check has three stages")
        expect(SetupProgressPhase(rawValue: "collect_evidence") == .collectEvidence
                   && SetupProgressPhase(rawValue: "verify_launch_conditions") == .verifyLaunchConditions
                   && SetupProgressPhase(rawValue: "bind_session") == .bindSession
                   && SetupProgressPhase(rawValue: "open_application") == .openApplication,
               "the interface decodes the stage codes the backend emits")
        let scheduledDefault = try JSONDecoder().decode(
            BackgroundServiceRow.self,
            from: Data(#"{"id":"guard","title":"保护","state":"scheduled","detail":"","source":"launchctl","desired":true,"last_checked":1000}"#.utf8)
        )
        expect(scheduledDefault.healthy && scheduledDefault.statusLabel == "已加载",
               "scheduled service without execution_verified keeps legacy healthy state")
        let scheduledUnverified = try JSONDecoder().decode(
            BackgroundServiceRow.self,
            from: Data(#"{"id":"guard","title":"保护","state":"scheduled","detail":"","source":"launchctl","desired":true,"last_checked":1000,"execution_verified":false,"health_basis":"launchd_loaded_only"}"#.utf8)
        )
        expect(!scheduledUnverified.healthy && scheduledUnverified.statusLabel == "已加载（执行待确认）",
               "scheduled service with execution_verified=false is not reported as healthy")

        // SwitcherCommandRunner bounded timeout categorization tests
        let queryCategory = SwitcherCommandRunner.CommandCategory.classify(args: ["status"])
        expect(queryCategory == .readOnlyQuery && queryCategory.timeoutSeconds == 20.0,
               "read-only query command is classified with 20.0s bounded timeout")

        let interactiveCategory = SwitcherCommandRunner.CommandCategory.classify(args: ["setup", "apply", "--mode", "auto"])
        expect(interactiveCategory == .longRunningInteractive && interactiveCategory.timeoutSeconds == 60.0,
               "setup/launch command is classified with 60.0s interactive timeout")

        let mutatingCategory = SwitcherCommandRunner.CommandCategory.classify(args: ["account", "switch", "--apply", "slot-b"])
        expect(mutatingCategory == .mutatingTransaction && mutatingCategory.timeoutSeconds == 120.0,
               "mutating transaction command has 120.0s journal protection timeout")
        expect(SwitcherCommandRunner.CommandCategory.timeoutSeconds(args: ["evidence", "refresh", "--apply"]) > 180,
               "evidence requests outlive the backend's two bounded native probes")
        for arguments in [["checkdetail", "--online"], ["launch", "--apply"], ["account", "switch", "--apply", "slot-b"]] {
            expect(SwitcherCommandRunner.CommandCategory.timeoutSeconds(args: arguments) > 190,
                   "preflight callers allow collection plus remaining audit work")
        }

        let state = SwitcherCommandRunner.SafeExecutionState()
        expect(!state.isTimedOut, "initial execution state is not timed out")
        expect(!state.isExceededMaxBytes, "initial execution state has not exceeded max bytes")
        state.markTimedOut()
        expect(state.isTimedOut, "thread-safe state correctly records timedOut under lock")
        state.markExceededMaxBytes()
        expect(state.isExceededMaxBytes, "thread-safe state correctly records exceededMaxBytes under lock")
        state.setExitCode(124)
        expect(state.terminationStatus == 124, "terminationStatus correctly returned")

        print("SwitcherStore: \(checks) isolated assertions passed")
    }
}
