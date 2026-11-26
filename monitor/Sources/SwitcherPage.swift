import AppKit
import SwiftUI

enum SwitcherSection: String, CaseIterable {
    case environment = "环境状态", accounts = "启动与账号", protection = "后台保护"
    var caption: String {
        switch self {
        case .environment: return "自动识别代理，按本轮实测出口核对地区、日期与时区；英文语言独立保持。"
        case .accounts: return "受控启动 Claude 与 ChatGPT，管理本地 A / B 资料槽位并核验双应用启动条件。"
        case .protection: return "统一配置公用守护底座、VPN 监督预期与双 AI 门禁及处置策略。"
        }
    }
}

struct SwitcherPage: View {
    @ObservedObject var store: SwitcherStore
    let p: Palette
    var monitor: MonitorStore? = nil
    var desktopPresence: WorkspaceDesktopPresence?
    var section: SwitcherSection = .environment
    var navigate: (SwitcherSection) -> Void = { _ in }
    var openLeakCheck: (LeakKind) -> Void = { _ in }
    var openNetwork: (MonitoredProduct) -> Void = { _ in }
    var openIPScore: (String) -> Void = { _ in }
    var channelState: (MonitoredProduct) -> FamilyChannelMonitorState? = { _ in nil }
    var leakChecks: LeakCheckStore? = nil
    var netCoffee: NetCoffeeStore? = nil
    var managedEntryControl: ManagedEntryControl? = nil
    let finished: () -> Void
    @AppStorage("returnToOverviewAfterSwitch") private var returnToOverviewAfterSwitch = true
    @State private var showEnvironmentAdjustment = false
    @State private var showSettings = false
    @State private var showVpnEditor = false
    @State private var policyProduct: MonitoredProduct = .claude
    @State private var launchProduct: MonitoredProduct = .claude
    @State private var showSource = false
    @State private var showMigration = false
    @State private var importPreview: String?
    @State private var updateResult: String?
    @State private var showAuditHistory = false
    @State private var showReview = false
    @State private var confirmation = false
    @State private var pendingTitle = ""
    @State private var pendingMessage = ""
    @State private var pendingAction = "确认"
    @State private var pendingDestructive = false
    @State private var pendingArguments: [String] = []
    @State private var applyingSetup = false

    private func confirm(_ title: String, _ message: String, _ args: [String], action: String, destructive: Bool = false) {
        pendingTitle = title; pendingMessage = message; pendingArguments = args
        pendingAction = action; pendingDestructive = destructive; applyingSetup = false; confirmation = true
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            if store.failure, !store.message.isEmpty, !showReview {
                HStack(alignment: .top) {
                    InlineNotice(title: "操作未完成", detail: store.message, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                        .textSelection(.enabled)
                    Button { store.dismissMessage() } label: { Image(systemName: "xmark") }
                        .buttonStyle(.borderless).accessibilityLabel("关闭错误提示")
                }
            }
            if store.hasUnsavedSettings {
                InlineNotice(title: "有未保存的工具设置", detail: "先保存或撤销草稿，再进行启动、切换或应用变更。实际后台状态仍按已保存设置展示。", symbol: "pencil.circle", tint: p.amber, p: p)
            }
            switch section {
            case .environment: environmentContent
            case .accounts: accountsContent
            case .protection: protectionContent
            }
        }.padding(.top, 24)
            .task(id: section) {
                if !store.loaded { await store.load() }
            }
            .alert(pendingTitle, isPresented: $confirmation) {
                Button("取消", role: .cancel) {}
                Button(pendingAction, role: pendingDestructive ? .destructive : nil) {
                    Task {
                        if applyingSetup { await store.applyEnvironment() }
                        else { await store.perform(pendingArguments) }
                        await store.refreshBackground()
                        if !store.failure && pendingArguments.contains("switch") &&
                            returnToOverviewAfterSwitch { finished() }
                    }
                }
            } message: { Text(pendingMessage) }
            .sheet(isPresented: $showReview) { changeReview }
    }
    private var header: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 7) {
                if section == .environment {
                    AtlasCaption(text: "CW   /   环境观测手记   01", tint: p.mint)
                    Text("环境图志").font(.system(size: 30, weight: .semibold, design: .monospaced))
                        .accessibilityAddTraits(.isHeader)
                } else { Text(section.rawValue).font(WatchTypography.pageTitle) }
                Text(section.caption).font(WatchTypography.body).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                if section != .environment && store.busy {
                    Label(store.activity.isEmpty ? "正在读取…" : store.activity, systemImage: "hourglass")
                        .font(WatchTypography.caption).foregroundStyle(p.blue)
                }
            }
            Spacer(minLength: 8)
            if section == .environment {
                EnvironmentDetectionControl(reading: store.readingEnvironment, disabled: store.busy && !store.readingEnvironment) {
                    if store.readingEnvironment { store.cancelCurrentDetection() }
                    else { Task { await store.detectCurrentEnvironment() } }
                }
                .help(store.readingEnvironment
                      ? (store.activity.isEmpty ? "正在检测环境；点击取消本轮检测。" : store.activity + "；点击取消本轮检测。")
                      : "重新读取系统、检测出口并核对环境。")
            } else if section == .protection {
                Button { Task { await store.refreshBackground() } } label: { Label("读取保护状态", systemImage: "arrow.clockwise") }.disabled(store.busy)
            }
        }
    }
    private var environmentContent: some View {
        Group {
            auditPanel
            Surface(p) {
                DisclosureGroup("系统地区、时区与环境对齐修复", isExpanded: $showEnvironmentAdjustment) {
                    environmentAdjustment.padding(.top, 14)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
        }
    }
    private var auditPanel: some View {
        Group {
            VStack(alignment: .leading, spacing: 12) {
                if !store.detectionError.isEmpty {
                    InlineNotice(title: "本轮检测未完成", detail: store.detectionError, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                }
                if !store.sourceNotices.isEmpty {
                    InlineNotice(title: "数据源状态", detail: store.sourceNotices.map { $0.title + "：" + $0.detail }.joined(separator: "\n"),
                                 symbol: "antenna.radiowaves.left.and.right", tint: sourceNoticeTint(store.sourceNotices), p: p)
                }
                if let result = store.currentEnvironment {
                    if let recommendation = EnvironmentModeRecommendation.evaluate(result.display_facts?.local?.rules) {
                        InlineNotice(title: recommendation.title, detail: recommendation.detail,
                                     symbol: "lightbulb", tint: p.blue, p: p)
                    }
                    if let facts = result.facts, facts.state == "fail" {
                        InlineNotice(title: "当前环境风险", detail: facts.risks?.compactMap { $0.reason ?? $0.id }.joined(separator: "\n") ?? "本轮环境检测发现风险。",
                                     symbol: "exclamationmark.shield", tint: p.red, p: p)
                    }
                    if let transition = result.context_transition, transition.state != "stable" {
                        InlineNotice(title: transition.state == "changed" ? "检测期间环境已变化" : "环境采样暂不可用",
                                     detail: contextTransitionDetail(transition),
                                     symbol: "arrow.triangle.2.circlepath", tint: p.amber, p: p)
                    }
                    if result.candidates.count > 1 {
                        InlineNotice(title: "检测到多个运行中的代理候选", detail: result.candidates.joined(separator: "、") + "。请核对实际监听入口与路由后重新检测；当前保持未确认。", symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                    }
                    TimelineView(.explicit(evidenceDisplayDates(until: result.expires_at))) { context in
                        let expired = result.expires_at < context.date.timeIntervalSince1970
                        let historical = expired || store.currentEnvironmentIsHistorical
                        VStack(alignment: .leading, spacing: 10) {
                            EnvironmentAtlasPlate(result: result, p: p, historical: historical,
                                                  previousObserved: store.previousEnvironment?.observed_at)
                            HStack {
                                if historical {
                                    Label(expired ? "历史样本 · 请重新检测" :
                                          store.detectionError.isEmpty ? "上下文已变化 · 上次样本仅供参考" : "本轮检测未完成 · 上次样本仅供参考",
                                          systemImage: "clock.badge.exclamationmark").foregroundStyle(p.amber)
                                }
                            }.font(WatchTypography.small).foregroundStyle(p.secondary)
                            let previousRows = Dictionary(store.previousEnvironment.map { $0.rows.map { ($0.id, $0) } } ?? [],
                                                          uniquingKeysWith: { first, _ in first })
                            let checks = AtlasCheckGroups(rows: result.rows, historical: historical)
                            if !checks.attention.isEmpty {
                                VStack(alignment: .leading, spacing: 8) {
                                    AtlasCaption(text: "本轮待核对 · \(checks.attention.count) 项", tint: p.amber)
                                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 265), alignment: .top)], spacing: 8) {
                                        ForEach(checks.attention) { row in
                                            environmentTile(row, historical: false, previous: previousRows[row.id])
                                        }
                                    }
                                }
                            }
                            ViewThatFits(in: .horizontal) {
                                HStack(alignment: .top, spacing: 14) {
                                    ledger(result, checks: checks, historical: historical, previous: previousRows).frame(minWidth: 380, maxWidth: .infinity)
                                    sessionInspector.frame(width: 252)
                                }
                                VStack(spacing: 14) {
                                    ledger(result, checks: checks, historical: historical, previous: previousRows)
                                    sessionInspector
                                }
                            }
                        }
                    }
                    if !store.webRTCReceiptError.isEmpty {
                        InlineNotice(title: "WebRTC 保护判定未提交", detail: store.webRTCReceiptError,
                                     symbol: "exclamationmark.shield", tint: p.amber, p: p)
                    }
                    Label("悬停查看完整依据 · 点击固定 · Esc 关闭", systemImage: "cursorarrow").font(WatchTypography.small).foregroundStyle(p.secondary)
                    DisclosureGroup("检测范围与数据来源") {
                        Text(result.message).padding(.top, 6)
                        Text("本次检测会请求出口、DNS、STUN 与服务响应，不携带账号凭据，也不保存候选为目标。受控启动的联网预检有独立开关。")
                        Text("DNS 与 UDP/STUN 为受控启动必检；国家相同不能替代实际出口与代理路径校验。WebRTC 检测只覆盖应用内 WebView，不能用来替其他应用作出无泄漏保证。")
                    }.font(WatchTypography.caption).foregroundStyle(p.secondary)
                    if !store.dnsReceiptError.isEmpty {
                        InlineNotice(title: "DNS 结果尚未同步到启动预检", detail: store.dnsReceiptError, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                    }
                    if let netCoffee { EnvironmentIPQualitySummary(store: netCoffee, environment: result, p: p, openIPScore: openIPScore) }
                } else {
                    Label(store.busy ? "正在读取系统与检测出口…" : "尚无本轮样本。点击「检测环境」。", systemImage: "network").font(WatchTypography.body).foregroundStyle(p.secondary)
                    sessionInspector
                }
            }
        }
    }
    private func environmentTile(_ row: EnvironmentCheckRow, historical: Bool, previous: EnvironmentCheckRow?) -> some View {
        EnvironmentCheckTile(row: row, p: p, stale: historical, previous: previous,
                             flags: row.id == "dns" ? dnsRecursiveFlags(leakChecks) : nil,
                             onConfirmBaseline: row.id == "ip_history" ? { Task { _ = await store.confirmBaseline() } } : nil)
    }
    private func ledger(_ result: CurrentEnvironmentReceipt, checks: AtlasCheckGroups, historical: Bool, previous: [String: EnvironmentCheckRow]) -> some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 11) {
                SectionHeading(title: "检测明细", p: p)
                let subjects = AtlasSubject.allCases.filter { subject in
                    checks.sections[subject] != nil ||
                        (subject == .exit && result.display_facts?.local != nil) ||
                        (subject == .leaks && leakChecks != nil)
                }
                ForEach(subjects) { subject in
                    let rows = checks.sections[subject] ?? []
                    Divider()
                    DisclosureGroup {
                        VStack(spacing: 6) {
                            ForEach(rows) { row in
                                environmentTile(row, historical: historical, previous: previous[row.id])
                            }
                            if subject == .exit, let local = result.display_facts?.local {
                                EnvironmentModeTile(local: local, p: p, stale: historical)
                            }
                            if subject == .leaks, let leakChecks {
                                EnvironmentWebRTCTile(state: leakChecks.rtc, p: p, stale: historical, open: { openLeakCheck(.webrtc) })
                            }
                        }.padding(.top, 6)
                    } label: {
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text(subject.index).font(WatchTypography.mono).foregroundStyle(p.secondary)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(subject.rawValue).font(WatchTypography.bodyStrong)
                                Text(subject.summary(rows, historical: historical, rtc: leakChecks?.rtc))
                                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                }
            }.foregroundStyle(p.text)
        }
    }
    private var sessionInspector: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 11) {
                Text("双 AI 会话与通道").font(WatchTypography.title)
                ForEach(MonitoredProduct.allCases) { product in
                    let session = store.sessionPresentation(for: product)
                    let channel = channelState(product)
                    let tint = sessionGuardTint(session)
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 6) {
                            BrandLogo(brand: product == .claude ? .claude : .chatgpt, size: 14)
                            Text(product.title).font(WatchTypography.captionStrong)
                            Spacer(minLength: 4)
                            Badge(text: channel?.protectionScopeLabel ?? session.title, color: tint)
                        }
                        Text(session.title + " · " + session.detail)
                            .font(WatchTypography.small)
                            .foregroundStyle(session.tone == "danger" ? p.red : session.tone == "warning" ? p.amber : p.secondary)
                            .lineLimit(3)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(9)
                    .background(p.elevated.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
                }
                Text("受控启动时按各应用已保存策略独立核验，不使用此处状态直接放行。")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
                HStack(spacing: 12) {
                    Button { navigate(.accounts) } label: { Label("启动与账号", systemImage: "arrow.right") }.buttonStyle(.borderless)
                    Button { navigate(.protection) } label: { Label("后台保护", systemImage: "shield.lefthalf.filled") }.buttonStyle(.borderless)
                }.font(WatchTypography.caption)
            }.foregroundStyle(p.text).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    /// Recursive-resolver countries from the latest DNS probe, de-duplicated
    /// in observation order; nil when nothing is on record.
    private func dnsRecursiveFlags(_ leakChecks: LeakCheckStore?) -> [String]? {
        guard let observations = leakChecks?.dns.result?.observations else { return nil }
        var seen = Set<String>()
        var order: [String] = []
        for item in observations where item.kind == "resolver" {
            if let country = item.country, !country.isEmpty, seen.insert(country).inserted { order.append(country) }
        }
        return order.isEmpty ? nil : order
    }
    private func sourceNoticeTint(_ notices: [EnvironmentSourceNotice]) -> Color {
        notices.contains { $0.severity == "fail" || $0.severity == "error" } ? p.red : notices.contains { $0.severity == "warn" } ? p.amber : p.secondary
    }
    private func contextTransitionDetail(_ value: EnvironmentContextTransition) -> String {
        if value.state == "changed" {
            let fields = value.changed_fields?.joined(separator: "、") ?? "代理或网络上下文"
            return "本轮开始后 \(fields) 已变化；结果不会作为当前启动许可。"
        }
        let unavailable = value.unavailable?.joined(separator: "、") ?? "代理上下文"
        return "\(unavailable) 暂未稳定；自动刷新会等待有效上下文后重试。"
    }
    private var environmentAdjustment: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("当系统时区、地区格式或 IPv6 与本轮出口不一致时，可在此生成具体的系统环境对齐预览并一键应用；VPN 与代理预期请前往「后台保护 → 01 · 公用底座」管理。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            HStack {
                Button { Task { await store.detectEnvironment() } } label: { Label("自动检测并生成修复建议", systemImage: "wand.and.stars") }
                    .disabled(store.busy || store.hasUnsavedSettings || store.setupRecoveryRequired)
                Button { Task { await store.inspectEnvironment() } } label: { Label("读取本机与已接受参考", systemImage: "desktopcomputer") }.disabled(store.busy)
                Button("按已接受参考生成修复预览") {
                    Task { await store.preview("repair"); showReview = store.plan != nil }
                }.disabled(store.busy || store.hasUnsavedSettings)
            }
            if let observation = store.environment {
                environmentValues(store.candidate?.rows ?? observation.rows)
            }
            if let candidate = store.candidate {
                Text("候选采样于 \(timeLabel(candidate.observed_at)) · 有效至 \(timeLabel(candidate.expires_at))").font(WatchTypography.caption).foregroundStyle(p.blue)
                Toggle("应用候选的地区、日期、时区及所需 IPv6 设置；Claude 保持英文", isOn: $store.setupApplyEnvironment).disabled(store.busy)
                Button("预览具体变更") { Task { await store.previewEnvironment() } }.disabled(store.busy || store.hasUnsavedSettings || store.setupRecoveryRequired)
                if let plan = store.setupPlan {
                    ForEach(plan.actions) { action in changeRow(action) }
                    Button("应用所列系统变更") {
                        pendingTitle = "应用环境修复"
                        pendingMessage = plan.rows.filter { !$0.proposed.isEmpty }.map { $0.title + "：" + $0.target + " → " + $0.proposed }.joined(separator: "\n")
                            + "\n\n" + plan.actions.map { $0.title + "：" + ($0.detail ?? "请核对权限范围") }.joined(separator: "\n")
                        pendingAction = "应用所列变更"; pendingDestructive = false; pendingArguments = []; applyingSetup = true; confirmation = true
                    }.buttonStyle(.borderedProminent).disabled(!store.setupCanConfirm)
                }
            }
        }
    }
    private func environmentValues(_ rows: [EnvironmentValueRow]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(rows) { row in
                VStack(alignment: .leading, spacing: 7) {
                    Text(row.title).font(WatchTypography.bodyStrong)
                    Text("实测：" + row.current).foregroundStyle(p.text)
                    Text("已接受参考：" + row.target).foregroundStyle(p.secondary)
                    if !row.proposed.isEmpty { Text("本次候选：" + row.proposed).foregroundStyle(p.blue) }
                    DisclosureGroup("来源与确认记录") {
                        Text("实测来源：" + row.source)
                        Text("参考来源：" + row.target_source)
                        if !row.proposed_source.isEmpty { Text("候选来源：" + row.proposed_source) }
                    }.font(WatchTypography.small).foregroundStyle(p.secondary)
                }.font(WatchTypography.caption).textSelection(.enabled).padding(.vertical, 10)
                Divider()
            }
        }
    }
    private var accountsContent: some View {
        Group {
            Surface(p) {
                VStack(alignment: .leading, spacing: 14) {
                    DesktopAccountControls(store: store, monitor: monitor, product: .claude,
                                           caption: claudeAccountCaption, p: p)
                    if let conflict = store.accounts?.legacy_conflict {
                        VStack(alignment: .leading, spacing: 8) {
                            InlineNotice(title: conflict.title, detail: conflict.summaryDetail,
                                         symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                            Button("重新核对账号状态") { Task { await store.load() } }
                                .disabled(store.busy)
                        }
                    }
                    if let accounts = store.accounts, !accounts.accounts.isEmpty {
                        HStack(spacing: 12) {
                            ForEach(accounts.accounts) { account in
                                if account.current {
                                    accountCard(account)
                                } else {
                                    Button {
                                        let slot = SwitcherStore.accountSlotPresentation(account, current: accounts.current)
                                        confirm(slot.confirmationTitle, slot.confirmationDetail,
                                                ["account", "switch", account.id, "--apply", "--ack-unverified-version"],
                                                action: slot.actionTitle, destructive: true)
                                    } label: {
                                        accountCard(account)
                                    }.buttonStyle(.plain).disabled(store.busy || store.hasUnsavedSettings || accounts.recovery_required == true || accounts.legacy_conflict != nil)
                                        .accessibilityLabel("切换到账号 \(account.id)，当前账号是 \(accounts.current ?? "未知")，切换会自动保存与恢复资料")
                                }
                            }
                        }
                        HStack {
                            Text("切换时会保存当前资料，再重新打开 Claude 载入所选槽位。")
                                .font(WatchTypography.caption).foregroundStyle(p.secondary)
                            Spacer()
                            Toggle("切换完成后返回环境状态", isOn: $returnToOverviewAfterSwitch)
                                .font(WatchTypography.caption)
                                .controlSize(.small)
                        }
                    } else {
                        Text(store.loaded ? "尚未取得 Claude 账号槽位资料。" : "正在读取 Claude 账号…")
                            .font(WatchTypography.caption).foregroundStyle(p.secondary)
                    }
                    if store.accounts?.recovery_required == true {
                        Button("恢复未完成账号切换") { confirm("恢复账号资料", "将按事务记录找回原目录，保留可能产生的新资料供核对。", ["account", "recover", "--apply"], action: "恢复账号资料") }.disabled(store.busy)
                    }
                    if let claudeVersions = store.aiVersions?.claude {
                        ProductVersionsSection(
                            product: .claude,
                            info: claudeVersions,
                            pruneMessage: store.pruneCLIMessages[.claude] ?? "",
                            disabled: store.busy || store.hasUnsavedSettings || store.accounts?.recovery_required == true,
                            p: p,
                            onConfirmPrune: { info in
                                confirm("清理 Claude 旧版 CLI",
                                        "将删除 Watch 管理的 Claude 内置 CLI 与独立 CLI 旧版本目录（\(info.prunable_versions.joined(separator: "、"))，约 \(info.prunableMBText)），保留各来源当前最新版本。清理前需确保 Claude 桌面端与 CLI 已退出；不会触碰原版切换器目录。",
                                        ["account", "prune-cli", "--product", "claude", "--apply"],
                                        action: "清理旧版本",
                                        destructive: true)
                            }
                        )
                    }
                }
            }
            ChatGPTAccountPanel(
                store: store,
                monitor: monitor,
                presence: desktopPresence,
                p: p,
                onConfirmPrune: { info in
                    confirm("清理 ChatGPT / Codex 旧版 CLI",
                            "将删除已检测到的 Codex CLI 旧版本目录（\(info.prunable_versions.joined(separator: "、"))，约 \(info.prunableMBText)），保留当前最新版本。清理前需确保 ChatGPT 桌面端与 Codex CLI 已退出。",
                            ["account", "prune-cli", "--product", "chatgpt", "--apply"],
                            action: "清理旧版本",
                            destructive: true)
                }
            )
            launchConditions
            Surface(p) {
                DisclosureGroup("原版切换器资料迁移", isExpanded: $showMigration) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("迁移是独立维护操作；原版保镖继续并行。工具操作日志已归口至「事件记录 › 日志操作」。")
                        HStack {
                            Button("查看原版可导入资料") {
                                Task {
                                    await store.perform(["account", "import"], refresh: false)
                                    importPreview = store.failure ? nil : store.message
                                }
                            }
                            Button("导入原版资料…") {
                                confirm("导入原版资料", "将导入原版 A/B 存档与工具设置，原版资料及原版保镖保留。请先核对预览。", ["account", "import", "--apply"], action: "导入资料")
                            }
                        }.disabled(store.busy || store.hasUnsavedSettings)
                        if let importPreview { Text(importPreview).textSelection(.enabled) }
                    }.font(WatchTypography.caption).padding(.top, 12)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
        }
    }
    private var claudeAccountCaption: String {
        if let id = store.accounts?.current {
            return "本地 A / B 资料槽位 · 当前使用槽位 \(id)"
        }
        return "本地 A / B 资料槽位 · 当前槽位尚未核实"
    }
    private func accountCard(_ account: SwitcherAccountSlot) -> some View {
        let presentation = SwitcherStore.accountSlotPresentation(account, current: store.accounts?.current)
        return AccountSlotCard(account: account, summary: presentation.summary, p: p,
                               actionTitle: account.stored ? "切换到 " + account.id : "使用 " + account.id)
    }
    private var selectedPolicyPreview: EnvironmentPolicyEvaluation? {
        if launchProduct == .claude { return store.currentPolicyEvaluation }
        guard let env = store.currentEnvironment,
              let preview = env.chatgpt_policy_evaluation,
              SwitcherStore.acceptsDisplayPolicy(preview, for: env, hasUnsavedSettings: store.hasUnsavedSettings) else {
            return nil
        }
        return preview
    }
    private var launchConditions: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    SectionHeading(title: "启动条件与会话核验", p: p)
                    HStack(spacing: 4) {
                        ForEach(MonitoredProduct.allCases) { product in
                            let selected = launchProduct == product
                            Button {
                                withAnimation(.easeInOut(duration: 0.15)) { launchProduct = product }
                            } label: {
                                HStack(spacing: 6) {
                                    BrandLogo(brand: product == .claude ? .claude : .chatgpt, size: 13)
                                    Text(product.title)
                                        .font(selected ? WatchTypography.captionStrong : WatchTypography.caption)
                                }
                                .foregroundStyle(selected ? p.text : p.secondary)
                                .padding(.horizontal, 10).padding(.vertical, 4)
                                .background(selected ? p.surface : Color.clear, in: RoundedRectangle(cornerRadius: 6))
                                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(selected ? p.border.opacity(0.85) : Color.clear, lineWidth: 1))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(3)
                    .background(p.elevated, in: RoundedRectangle(cornerRadius: 8))
                    Spacer()
                    Button { Task { await store.checkLaunchConditions() } } label: { Label("重新核验条件", systemImage: "checklist") }
                        .disabled(store.busy || store.hasUnsavedSettings)
                }
                let session = store.sessionPresentation(for: launchProduct)
                if let result = selectedPolicyPreview {
                    TimelineView(.explicit(evidenceDisplayDates(until: result.expires_at))) { context in
                        let expired = result.expires_at < context.date.timeIntervalSince1970
                        VStack(alignment: .leading, spacing: 9) {
                            launchSummary(session, product: launchProduct) {
                                Label(expired ? "启动要求预览已过期" : result.ready ? "同轮启动要求已满足" : "同轮启动要求尚未满足",
                                      systemImage: expired ? "clock" : result.ready ? "checkmark.circle.fill" : "exclamationmark.triangle")
                                    .foregroundStyle(expired ? p.secondary : result.ready ? p.mint : p.amber)
                            }
                            Text("环境采样于 " + timeLabel(result.observed_at) + " · 受控启动时将独立重新核验")
                                .font(WatchTypography.small).foregroundStyle(p.secondary)
                            ForEach(result.rows.filter { result.blocked.contains($0.id) }) { row in
                                VStack(alignment: .leading, spacing: 4) {
                                    Label(row.name + " · " + row.statusLabel, systemImage: row.statusSymbol).font(WatchTypography.bodyStrong)
                                    Text(row.detail).font(WatchTypography.caption)
                                    if row.id == "ip_history" {
                                        HStack(spacing: 8) {
                                            Button {
                                                Task {
                                                    _ = await store.confirmBaseline()
                                                }
                                            } label: {
                                                Label("核准此 IP 为新基准", systemImage: "checkmark.seal.fill")
                                            }
                                            .buttonStyle(.borderedProminent)
                                            .controlSize(.small)
                                            .disabled(store.busy)
                                            Text("确认后将更新基准并重新核验启动条件").font(WatchTypography.small).foregroundStyle(p.secondary)
                                        }.padding(.top, 4)
                                    }
                                }.foregroundStyle(expired ? p.secondary : p.amber)
                            }
                        }
                    }
                    if let facts = result.facts, facts.state == "fail" {
                        InlineNotice(title: "同轮阻断原因", detail: facts.risks?.compactMap { $0.reason ?? $0.id }.joined(separator: "\n") ?? "当前保护事实未满足。",
                                     symbol: "exclamationmark.shield", tint: p.red, p: p)
                    }
                } else {
                    launchSummary(session, product: launchProduct) {
                        Label("启动要求待检查", systemImage: "clock").foregroundStyle(p.secondary)
                    }
                    Text("尚未取得与当前环境同轮的 \(launchProduct.title) 启动要求预览。点击右上角「重新核验条件」或直接启动时将独立检查。")
                        .font(WatchTypography.body).foregroundStyle(p.secondary)
                    if !store.detectionError.isEmpty {
                        Text("本轮采样未完成：" + store.detectionError).font(WatchTypography.caption).foregroundStyle(p.amber)
                    }
                }
                if session.tone == "danger" || session.tone == "warning" {
                    Text(session.detail).font(WatchTypography.caption).foregroundStyle(session.tone == "danger" ? p.red : p.amber)
                }
                if !store.webRTCReceiptError.isEmpty {
                    InlineNotice(title: "WebRTC 当前保护判定未提交", detail: store.webRTCReceiptError,
                                 symbol: "exclamationmark.shield", tint: p.amber, p: p)
                }
                DisclosureGroup("上次实际启动预检（历史）", isExpanded: $showAuditHistory) {
                    VStack(alignment: .leading, spacing: 8) {
                        if let result = store.audit {
                            TimelineView(.explicit(evidenceDisplayDates(until: result.expires_at))) { context in
                                let expired = result.expires_at < context.date.timeIntervalSince1970
                                VStack(alignment: .leading, spacing: 6) {
                                    Label(expired ? "历史预检已过期，不代表当前环境" : "历史预检记录", systemImage: expired ? "clock.badge.exclamationmark" : "clock")
                                        .foregroundStyle(expired ? p.secondary : p.amber)
                                    Text("采样于 " + timeLabel(result.observed_at)).font(WatchTypography.small).foregroundStyle(p.secondary)
                                    Text(result.message).font(WatchTypography.caption).foregroundStyle(p.secondary)
                                }
                            }
                        } else {
                            Text("暂无实际启动预检记录。").font(WatchTypography.caption).foregroundStyle(p.secondary)
                        }
                        if !store.auditOperationMessage.isEmpty {
                            Text("本次启动预检结果：" + store.auditOperationMessage)
                                .font(WatchTypography.caption).foregroundStyle(store.failure ? p.amber : p.secondary)
                        }
                    }.padding(.top, 8)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                ForEach(store.background?.policy_issues ?? []) { issue in
                    VStack(alignment: .leading, spacing: 4) {
                        Label(issue.title, systemImage: "info.circle").font(WatchTypography.bodyStrong)
                        Text(issue.detail).font(WatchTypography.caption)
                    }.foregroundStyle(p.amber)
                }
            }
        }
    }
    private func launchSummary<Readiness: View>(_ session: SessionProtectionPresentation,
                                                 product: MonitoredProduct,
                                                 @ViewBuilder readiness: () -> Readiness) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            readiness()
            Divider().frame(height: 14)
            Label(session.title, systemImage: session.symbol)
                .help(session.detail).accessibilityHint(session.detail)
            Spacer(minLength: 4)
            PageLink(title: "查看代理与连接", p: p) { openNetwork(product) }.fixedSize()
        }.font(WatchTypography.bodyStrong)
    }

    /// Per-criterion actions for a running Claude session. The backend
    /// records a baseline at session start (HTTP exit, DNS recursive exit
    /// countries, WebRTC public candidates) and compares each round; a drift
    /// triggers the configured action, a missing or stale sample only warns.
    /// Each AI service declares its own policy, so the panel renders the
    /// catalog instead of one shape copied per service.
    private var protectionPolicyPanel: some View {
        let policy = AIPolicyCatalog.service(for: policyProduct)
        let gates = PrelaunchGateDescriptor.descriptors(for: policyProduct)
        let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
        return Surface(p) {
            VStack(alignment: .leading, spacing: 14) {
                // Header: 02 · AI 应用专属配置 + Brand Pill Switcher + Live Channel Badge
                HStack(alignment: .center, spacing: 10) {
                    Text("02 · AI 应用配置")
                        .font(WatchTypography.small.weight(.semibold))
                        .foregroundStyle(p.secondary)
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(p.elevated, in: RoundedRectangle(cornerRadius: 5))
                    HStack(spacing: 4) {
                        ForEach(MonitoredProduct.allCases) { product in
                            let selected = policyProduct == product
                            Button {
                                withAnimation(.easeInOut(duration: 0.15)) { policyProduct = product }
                            } label: {
                                HStack(spacing: 6) {
                                    BrandLogo(brand: product == .claude ? .claude : .chatgpt, size: 14)
                                    Text(product.title)
                                        .font(selected ? WatchTypography.captionStrong : WatchTypography.caption)
                                }
                                .foregroundStyle(selected ? p.text : p.secondary)
                                .padding(.horizontal, 11).padding(.vertical, 5)
                                .background(
                                    selected ? p.surface : Color.clear,
                                    in: RoundedRectangle(cornerRadius: 6)
                                )
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .strokeBorder(selected ? p.border.opacity(0.85) : Color.clear, lineWidth: 1)
                                )
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(3)
                    .background(p.elevated, in: RoundedRectangle(cornerRadius: 8))
                    Spacer(minLength: 8)
                    Badge(
                        text: channelState(policyProduct)?.protectionScopeLabel ?? "通道回执待读取",
                        color: p.mint
                    )
                    PageLink(title: "查看连接路径", p: p) { openNetwork(policyProduct) }
                }

                Divider()

                // Sub-panel A: 受控桌面入口 (Opt-in) & 当前所选应用会话详情
                VStack(alignment: .leading, spacing: 10) {
                    if let entryControl = managedEntryControl {
                        ManagedEntryPanel(control: entryControl, product: policyProduct, p: p)
                            .clipShape(RoundedRectangle(cornerRadius: 9))
                            .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
                    }
                    if let evidence = store.sessionEvidence(for: policyProduct) {
                        DisclosureGroup("\(policyProduct.title) 当前会话基线详情") {
                            sessionGuardCard(evidence, product: policyProduct).padding(.top, 8)
                        }
                        .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                    }
                }

                Divider()

                // Sub-panel B: 启动前门禁要求（按当前所选 AI 应用独立配置）
                VStack(alignment: .leading, spacing: 10) {
                    HStack(alignment: .firstTextBaseline) {
                        Label("\(policyProduct.title) 启动前门禁要求", systemImage: "checkmark.shield")
                            .font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                        Spacer()
                        Text("开启项未通过时将阻止受控启动；未开启项仅检测提示")
                            .font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                    LazyVGrid(columns: columns, spacing: 10) {
                        ForEach(gates) { gate in
                            prelaunchGateCard(gate)
                        }
                    }
                    ForEach(store.policyWarnings, id: \.self) {
                        Text($0).font(WatchTypography.small).foregroundStyle(p.amber)
                    }
                }
                .disabled(store.busy || !store.loaded)

                Divider()

                // Sub-panel C: 运行中异常处置策略（按当前所选 AI 应用独立配置）
                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .firstTextBaseline) {
                        Label(policy.title, systemImage: "bolt.shield")
                            .font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                        Spacer()
                    }
                    Text(policy.subtitle)
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    VStack(spacing: 0) {
                        ForEach(Array(policy.criteria.enumerated()), id: \.element.id) { index, criterion in
                            if index > 0 { Divider() }
                            policyCell(criterion, in: policy)
                                .padding(.horizontal, 12).padding(.vertical, 8)
                        }
                    }
                    .background(p.elevated.opacity(0.35), in: RoundedRectangle(cornerRadius: 9))
                    .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
                }
                .disabled(store.busy || !store.loaded)

                Divider()

                // Sub-panel D: 当前 AI 应用卡片底部一体化保存栏
                HStack(alignment: .center, spacing: 12) {
                    Label(
                        store.hasUnsavedSettings
                            ? "当前有未保存的 \(policyProduct.title) 保护策略修改"
                            : (channelState(policyProduct)?.policy_sync_label_zh ?? "当前应用保护策略已同步"),
                        systemImage: store.hasUnsavedSettings ? "pencil.circle.fill" : "checkmark.circle"
                    )
                    .font(WatchTypography.caption)
                    .foregroundStyle(store.hasUnsavedSettings ? p.amber : p.secondary)
                    Spacer()
                    if store.hasUnsavedSettings {
                        Button("撤销未保存修改") { store.discardChanges() }
                            .disabled(store.busy)
                    }
                    Button("保存 \(policyProduct.title) 设置") {
                        Task { await store.save(); await store.refreshBackground() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!store.hasUnsavedSettings || store.busy)
                }
            }
        }
    }

    private func prelaunchGateCard(_ gate: PrelaunchGateDescriptor) -> some View {
        let isEnabled = store.isOn(gate.setting, fallback: gate.fallback)
        return HStack(alignment: .center, spacing: 10) {
            Image(systemName: gate.symbol)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(isEnabled ? p.blue : p.secondary)
                .frame(width: 26, height: 26)
                .background(p.elevated, in: RoundedRectangle(cornerRadius: 6))
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(gate.title).font(WatchTypography.captionStrong).foregroundStyle(p.text)
                    if let badge = gate.badge {
                        Text(badge)
                            .font(WatchTypography.small)
                            .foregroundStyle(p.blue)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(p.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 4))
                    }
                }
                Text(gate.detail)
                    .font(WatchTypography.small)
                    .foregroundStyle(p.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 6)
            Toggle(gate.title, isOn: store.flag(gate.setting, fallback: gate.fallback))
                .toggleStyle(.switch)
                .controlSize(.small)
                .labelsHidden()
        }
        .padding(10)
        .background(
            isEnabled ? p.blue.opacity(0.05) : p.elevated.opacity(0.35),
            in: RoundedRectangle(cornerRadius: 9)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 9)
                .strokeBorder(isEnabled ? p.blue.opacity(0.35) : p.border.opacity(0.6), lineWidth: 1)
        )
    }

    private func policyCell(_ criterion: PolicyCriterion, in policy: AIServicePolicy) -> some View {
        let selected = store.choice(policy.setting(criterion)).wrappedValue
        let actionTint: Color = selected == "force" ? p.red : selected == "close" ? p.amber : p.blue
        return HStack(spacing: 12) {
            Circle().fill(actionTint).frame(width: 6, height: 6)
            Text(criterion.title).font(WatchTypography.body)
            Spacer(minLength: 8)
            Picker(criterion.title, selection: store.choice(policy.setting(criterion))) {
                ForEach(policy.actions) { Text($0.title).tag($0.id) }
            }
            .labelsHidden()
            .frame(width: 150)
            .disabled(policy.actions.count < 2)
            .help("选择此应用遇到该项风险时的处置")
        }
    }

    private var draftActions: some View {
        HStack(spacing: 10) {
            Button("保存设置") { Task { await store.save(); await store.refreshBackground() } }
                .buttonStyle(.borderedProminent).disabled(!store.hasUnsavedSettings || store.busy)
            if store.hasUnsavedSettings {
                Button("撤销未保存修改") { store.discardChanges() }.disabled(store.busy)
                Text("未保存").font(WatchTypography.small).foregroundStyle(p.amber)
            }
        }
    }

    private var globalInfrastructurePanel: some View {
        let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
        return Surface(p) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .center, spacing: 10) {
                    Text("01 · 公用底座")
                        .font(WatchTypography.small.weight(.semibold))
                        .foregroundStyle(p.secondary)
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(p.elevated, in: RoundedRectangle(cornerRadius: 5))
                    SectionHeading(title: "全局守护服务与 VPN 监督基线", p: p)
                    Spacer(minLength: 8)
                    if let result = store.background {
                        Text(result.evidenceSummary + " · " + timeLabel(result.observed_at))
                            .font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                }

                if let result = store.background {
                    TimelineView(.explicit(evidenceDisplayDates(until: result.observed_at + 35))) { context in
                        let stale = !store.backgroundError.isEmpty || context.date.timeIntervalSince1970 - result.observed_at > 35
                        LazyVGrid(columns: columns, spacing: 10) {
                            ForEach(result.services) { service in
                                serviceCard(service, stale: stale)
                            }
                        }
                    }
                } else {
                    Text(store.busy ? "正在读取后台…" : "尚无后台状态，请刷新。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary).padding(.vertical, 6)
                }

                Divider()

                vpnExpectationSection
            }
        }
    }

    private func serviceCard(_ service: BackgroundServiceRow, stale: Bool) -> some View {
        let descriptor = BackgroundServiceCatalog.descriptor(service.id)
        let tint = stale ? p.secondary : service.healthy ? p.mint : service.state == "inactive" ? p.secondary : p.amber
        return DisclosureGroup {
            VStack(alignment: .leading, spacing: 7) {
                if let summary = service.evidenceSummary {
                    Text(summary).font(WatchTypography.small).foregroundStyle(p.secondary)
                }
                if let desired = service.desired {
                    Text("保存设置：" + (desired ? "开启" : "关闭") + " · 实际状态见回读结果")
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                }
                if let successful = service.last_success_at {
                    Text("最近有效巡检：" + timeLabel(successful)).font(WatchTypography.small).foregroundStyle(p.secondary)
                }
                if let checked = service.last_checked {
                    Text("最近检查：" + timeLabel(checked)).font(WatchTypography.small).foregroundStyle(p.secondary)
                }
                HStack {
                    serviceControls(service, descriptor)
                }
                .controlSize(.small)
                .disabled(store.busy || store.hasUnsavedSettings)
                Text("来源：" + service.source).font(WatchTypography.small).foregroundStyle(p.secondary)
            }
            .padding(.top, 8)
        } label: {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: descriptor.symbol)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(p.blue)
                        .frame(width: 24, height: 24)
                        .background(p.elevated, in: RoundedRectangle(cornerRadius: 6))
                    Text(service.title).font(WatchTypography.bodyStrong).lineLimit(1)
                    Spacer(minLength: 4)
                    Badge(text: stale ? "上次状态" : service.statusLabel, color: tint)
                }
                Text(service.detail)
                    .font(WatchTypography.small)
                    .foregroundStyle(p.secondary)
                    .lineLimit(1)
            }
        }
        .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
        .padding(10)
        .background(p.elevated.opacity(0.35), in: RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
    }

    private var protectionContent: some View {
        Group {
            if !store.backgroundError.isEmpty {
                InlineNotice(title: "后台状态读取未完成", detail: store.backgroundError, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
            }
            if let facts = store.background?.facts, facts.state == "fail" {
                InlineNotice(title: "当前保护风险", detail: facts.risks?.compactMap { $0.reason ?? $0.id }.joined(separator: "\n") ?? "后端已报告当前风险。",
                             symbol: "exclamationmark.shield", tint: p.red, p: p)
            }
            globalInfrastructurePanel
            protectionPolicyPanel
            Surface(p) {
                DisclosureGroup("底层发布源与系统辅助维护", isExpanded: $showSettings) {
                    settingsPanel.padding(.top, 12)
                }
                .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
        }
    }

    /// What a service offers is read from its descriptor — which setting its
    /// switch owns, how the action reads and what it requires first — instead
    /// of comparing the service id against a list of known names.
    @ViewBuilder
    private func serviceControls(_ service: BackgroundServiceRow,
                                 _ descriptor: BackgroundServiceCatalog.Descriptor) -> some View {
        if let toggle = descriptor.toggle {
            if descriptor.requiresSource && !store.updateSourceReady {
                Button("配置本项目发布源…") { showSettings = true; showSource = true }
                if service.desired == true { serviceButton("预览关闭更新设置", toggle, enable: false) }
            } else {
                let outOfSync = service.state == "mismatch"
                    || (descriptor.requiresEnabled && service.desired == true && !store.isOn(Setting.enabled))
                if outOfSync { serviceButton(descriptor.syncTitle, toggle, enable: service.desired ?? true) }
                serviceButton(service.desired == true ? descriptor.disableTitle : descriptor.enableTitle,
                              toggle, enable: service.desired != true)
            }
        } else {
            Label(descriptor.note ?? "此服务由本工具单独管理。", systemImage: "link")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
        }
    }
    private func serviceButton(_ title: String, _ setting: FlagSetting, enable: Bool) -> some View {
        Button(title) { Task { await store.previewProtection(setting.key, enable: enable); showReview = store.plan != nil } }
    }
    private func sessionGuardCard(_ evidence: SessionProtectionEvidence, product: MonitoredProduct = .claude) -> some View {
        let session = evidence.session
        let value = evidence.presentation(at: store.loginClock.timeIntervalSince1970)
        return VStack(alignment: .leading, spacing: 10) {
            SessionProtectionStatusView(value: value, p: p)
            if session.baseline != nil || session.current != nil || (session.reason != nil && session.state != "idle") || session.locked_at != nil {
                Surface(p) {
                    VStack(alignment: .leading, spacing: 9) {
                        if let baseline = session.baseline {
                            Text("会话基准：" + egressText(baseline)).font(WatchTypography.caption)
                        }
                        if let current = session.current {
                            Text((session.state == "locked" ? "阻断时出口：" : "最近核验出口：") + egressText(current)).font(WatchTypography.caption)
                        }
                        if let reason = session.reason, session.state != "idle" {
                            Text((session.state == "locked" ? "触发原因：" : "检测情况：") + reason.detail).font(WatchTypography.caption).foregroundStyle(sessionGuardTint(value))
                            if let observed = reason.observed_at {
                                Text("原因时间：" + timeLabel(observed)).font(WatchTypography.small).foregroundStyle(p.secondary)
                            }
                        }
                        if let locked = session.locked_at {
                            Text("锁存时间：" + timeLabel(locked)).font(WatchTypography.small).foregroundStyle(p.secondary)
                        }
                        Text("明确风险时按 \(product.title) 已配置策略立即处置；未知状态不会宣称已完成检测。").font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                }
            }
        }
    }
    private func egressText(_ value: EgressReference) -> String {
        [value.ip, value.country].compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: " / ")
    }
    private func sessionGuardTint(_ value: SessionProtectionPresentation) -> Color {
        value.tone == "danger" ? p.red : value.tone == "warning" ? p.amber : value.tone == "success" ? p.mint : p.secondary
    }
    private var settingsPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(store.updateSourceIsBuiltin
                 ? "已内置官方 GitHub 发布源（anyun-hy/agent-watch），日常检查更新请直接使用左下角「检查更新」；下方仅在需要自定义测试源或维护系统辅助组件时使用。"
                 : "此处供本项目发布维护使用。未内置公钥且未手动填写发布源与固定公钥时，自动更新显示尚不可用。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            TextField("本项目 HTTPS 发布清单（留空则使用内置源）", text: store.text(Setting.updateURL)).textFieldStyle(.roundedBorder)
            Text("固定 RSA 公钥（PEM，留空则使用内置公钥）").font(WatchTypography.caption)
            TextEditor(text: store.text(Setting.updatePublicKey)).font(WatchTypography.mono).frame(height: 84)
            HStack(spacing: 10) {
                if store.hasUnsavedSettings {
                    Button("保存发布源设置") { Task { await store.save(); await store.refreshBackground() } }
                        .buttonStyle(.borderedProminent).disabled(store.busy)
                    Button("撤销修改") { store.discardChanges() }.disabled(store.busy)
                }
                Button("更新系统辅助组件…") {
                    confirm("更新系统辅助组件", "需要管理员认证，更新本工具固定辅助程序；不会切换时区、语言或原版保镖。", ["services", "refresh-admin", "--apply"], action: "更新辅助组件")
                }.disabled(store.hasUnsavedSettings)
            }
            if let updateResult { Text(updateResult).textSelection(.enabled) }
        }
        .font(WatchTypography.caption)
        .disabled(store.busy || !store.loaded)
    }

    private var vpnExpectationSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .center, spacing: 10) {
                Image(systemName: "network.badge.shield.half.filled")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(p.blue)
                    .frame(width: 24, height: 24)
                    .background(p.elevated, in: RoundedRectangle(cornerRadius: 6))
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text("只读 VPN 监督预期").font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                        if let syncState = store.policySyncState {
                            Badge(
                                text: syncState.labelZh,
                                color: syncState == .applyFailed ? p.red : syncState == .applied ? p.mint : p.amber
                            )
                        }
                    }
                    Text(store.savedVpnExpectationSummary)
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                }
                Spacer(minLength: 8)
                Button(showVpnEditor ? "收起修改" : "修改 VPN 预期…") {
                    withAnimation(.easeInOut(duration: 0.15)) { showVpnEditor.toggle() }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
            if showVpnEditor {
                Divider()
                HStack(spacing: 8) {
                    TextField("预期运行模式（如 rule / global）", text: Binding(
                        get: { store.vpnExpectationDraft.running_mode ?? "" },
                        set: { store.updateVpnExpectationDraft(runningMode: $0) }
                    )).textFieldStyle(.roundedBorder)
                    TextField("预期代理组", text: Binding(
                        get: { store.vpnExpectationDraft.proxy_group },
                        set: { store.updateVpnExpectationDraft(proxyGroup: $0) }
                    )).textFieldStyle(.roundedBorder)
                    TextField("预期节点", text: Binding(
                        get: { store.vpnExpectationDraft.expected_node ?? "" },
                        set: { store.updateVpnExpectationDraft(expectedNode: $0) }
                    )).textFieldStyle(.roundedBorder)
                    Button("确认保存 VPN 预期") {
                        Task {
                            await store.confirmAndSaveVpnExpectation()
                            showVpnEditor = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(store.busy)
                }
                Text("仅写入 Watch 本地只读比对基线，不修改外部 VPN / TAG 客户端设置。")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
            }
        }
        .padding(10)
        .background(p.elevated.opacity(0.35), in: RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
    }

    private var changeReview: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("确认具体变更").font(WatchTypography.pageTitle)
            Text("每项列出修改前后的值和权限范围。Agent Watch 与原版保镖独立管理。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(store.plan?.actions ?? []) { action in changeRow(action) }
                    if store.plan?.actions.isEmpty == true { Text("没有待应用的变更。").foregroundStyle(p.secondary) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(maxHeight: 330)
            if !store.message.isEmpty { Text(store.message).font(WatchTypography.caption).foregroundStyle(store.failure ? p.amber : p.secondary).textSelection(.enabled) }
            HStack {
                Button("取消") { showReview = false }.disabled(store.busy)
                Spacer()
                Button("应用 \(store.plan?.actions.count ?? 0) 项变更") {
                    Task { await store.applyPreview(); if !store.failure { showReview = false } }
                }.buttonStyle(.borderedProminent).disabled(store.busy || store.hasUnsavedSettings || store.plan?.actions.isEmpty != false)
            }
        }.padding(24).frame(width: 590).foregroundStyle(p.text).background(p.surface).interactiveDismissDisabled(store.busy)
    }
    private func changeRow(_ action: SwitcherRepairAction) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text(action.title).font(WatchTypography.bodyStrong)
                Spacer()
                Badge(text: action.scope == "administrator" ? "管理员" : action.scope == "preferences" ? "系统偏好" : action.scope == "application" ? "应用" : "本工具", color: action.scope == "administrator" ? p.amber : p.blue)
            }
            Text(action.detail ?? "具体值未返回，请重新生成预览。").font(WatchTypography.caption).foregroundStyle(p.secondary).textSelection(.enabled)
        }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(p.elevated, in: RoundedRectangle(cornerRadius: 9))
    }
    private func timeLabel(_ epoch: Double) -> String { Date(timeIntervalSince1970: epoch).formatted(date: .numeric, time: .shortened) }
}

struct EnvironmentCheckTile: View {
    let row: EnvironmentCheckRow
    let p: Palette
    var stale = false
    /// Same row from the previous detection receipt; when its value or state
    /// differs, the tile shows what this refresh actually changed.
    var previous: EnvironmentCheckRow?
    /// Recursive-resolver country codes for the DNS row; displayed as small
    /// flag chips under the value.
    var flags: [String]? = nil
    var onConfirmBaseline: (() -> Void)? = nil
    @State private var presentation = EnvironmentDetailPresentation()
    @State private var previewTask: Task<Void, Never>?
    @State private var closeTask: Task<Void, Never>?
    private var tint: Color {
        if stale || row.state == "info" || row.state == "cached" { return p.secondary }
        return row.state == "ok" ? p.mint : row.state == "fail" ? p.red : p.amber
    }
    private var value: String {
        guard let current = row.current, !current.isEmpty else { return row.detail }
        return current == "unknown" ? "尚未取得验证依据" : current
    }
    /// Only live, current samples carry the diff; a historical badge already
    /// tells the whole "not current" story without mixing in a change marker.
    private var changeNote: String? {
        guard row.id != "guard", !stale, let previous, previous.current != row.current || previous.state != row.state else { return nil }
        if let old = previous.current, !old.isEmpty, old != row.current { return "上一轮：" + old }
        return "上一轮：" + previous.statusLabel
    }
    private var showReference: Bool { row.id == "timezone" || row.id == "locale" || row.state == "fail" || row.state == "cached" }

    var body: some View {
        card
            .accessibilityLabel(row.name + "，" + row.statusLabel + "，" + value)
            .accessibilityHint("按空格键固定检测依据与来源，再次激活或按 Esc 关闭")
            .accessibilityValue(presentation.isPinned ? "详情已固定" : "")
            .onHover { inside in
                presentation.hoverCard(inside)
                updateHover()
            }
            .popover(isPresented: popoverBinding, arrowEdge: .trailing) { popoverDetails }
            .onExitCommand(perform: dismiss)
            .onDisappear(perform: dismiss)
    }
    private var popoverBinding: Binding<Bool> {
        Binding(get: { presentation.isPresented }, set: { if !$0 { dismiss() } })
    }
    private var popoverDetails: some View {
        EnvironmentCheckDetails(row: row, p: p, pinned: presentation.isPinned,
            togglePin: { presentation.togglePin(); updateHover() }, close: dismiss, stale: stale,
            onConfirmBaseline: onConfirmBaseline)
            .onHover { inside in
                presentation.hoverDetails(inside)
                updateHover()
            }
            .onExitCommand(perform: dismiss)
    }
    private var card: some View {
        Button {
            cancelTasks()
            presentation.activate()
        } label: {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: row.categorySymbol).font(.system(size: 16, weight: .medium))
                        .foregroundStyle(tint).frame(width: 30, height: 30)
                        .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 6) {
                            Text(row.name).font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                            Spacer(minLength: 0)
                            Label(stale ? "历史样本" : row.statusLabel, systemImage: stale ? "clock" : row.statusSymbol)
                                .font(WatchTypography.small).foregroundStyle(tint)
                                .padding(.horizontal, 6).padding(.vertical, 3)
                                .background(tint.opacity(0.10), in: Capsule())
                            Image(systemName: presentation.isPinned ? "pin.fill" : "info.circle")
                                .font(.system(size: 11, weight: .medium)).foregroundStyle(p.secondary)
                                .accessibilityHidden(true)
                        }
                        Text(value).font(WatchTypography.caption).foregroundStyle(p.text)
                            .lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                        if let note = changeNote {
                            Label(note, systemImage: "arrow.triangle.2.circlepath")
                                .font(WatchTypography.small).foregroundStyle(p.blue)
                                .lineLimit(1)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(p.blue.opacity(0.10), in: Capsule())
                                .accessibilityLabel("与上一轮相比有变化，" + note)
                        }
                        if !stale, let flags, !flags.isEmpty {
                            HStack(spacing: 6) {
                                Text("递归出口").font(WatchTypography.small).foregroundStyle(p.secondary)
                                ForEach(flags, id: \.self) { code in
                                    Text(countryFlag(code) + " " + code)
                                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                                        .monospacedDigit()
                                }
                            }.accessibilityElement(children: .combine)
                                .accessibilityLabel("DNS 递归出口国家：" + flags.joined(separator: "、"))
                        }
                        if showReference, let reference = row.reference {
                            Text("要求：" + reference).font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(2)
                        }
                        if row.id == "ip_history" && (row.state == "warn" || row.state == "fail") {
                            VStack(alignment: .leading, spacing: 4) {
                                if let changedAt = row.changed_detected_at {
                                    Label("变更为当前 IP：" + environmentTimelineStamp(changedAt), systemImage: "clock.arrow.circlepath")
                                        .font(WatchTypography.small).foregroundStyle(p.amber)
                                } else {
                                    Label("与基准不一致，已拦截启动", systemImage: "hand.raised.fill")
                                        .font(WatchTypography.small).foregroundStyle(p.amber)
                                }
                                if let confirmedIP = row.confirmed_ip, !confirmedIP.isEmpty {
                                    let baselineNote: String = {
                                        if let lastSeen = row.last_baseline_seen_at {
                                            return "原基准 \(confirmedIP) · 最后在线 \(environmentTimelineStamp(lastSeen))"
                                        }
                                        if let confirmedAt = row.confirmed_at {
                                            return "原基准 \(confirmedIP) · 核准于 \(environmentTimelineStamp(confirmedAt))"
                                        }
                                        return "原基准 \(confirmedIP)"
                                    }()
                                    Text(baselineNote)
                                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                                        .lineLimit(1)
                                }
                            }
                        }
                        if let sampled = row.sampled_at {
                            Text((row.state == "cached" ? "上次有效采样：" : (row.sample_reused == true ? "复用采样：" : "采样时间：")) + environmentSummaryTime(sampled))
                                .font(WatchTypography.small).foregroundStyle(p.secondary)
                        }
                        if !stale, row.id == "ip_history", row.state == "warn", let onConfirmBaseline {
                            HStack(spacing: 8) {
                                Button {
                                    onConfirmBaseline()
                                } label: {
                                    Label("核准为新基准", systemImage: "checkmark.seal.fill")
                                }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.small)
                                Text("点击卡片查看完整轨迹")
                                    .font(WatchTypography.small).foregroundStyle(p.secondary)
                            }
                            .padding(.top, 2)
                        }
                    }
                }.frame(maxWidth: .infinity, minHeight: 48, alignment: .topLeading)
            .padding(10)
            .background(p.elevated.opacity(0.65), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(
                !stale && row.state == "fail" ? p.red.opacity(0.4) : p.border.opacity(0.65), lineWidth: 1))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private func dismiss() { cancelTasks(); presentation.dismiss() }
    private func cancelTasks() {
        previewTask?.cancel(); previewTask = nil
        closeTask?.cancel(); closeTask = nil
    }
    private func updateHover() {
        cancelTasks()
        if presentation.shouldPreview {
            previewTask = Task { @MainActor in
                try? await Task.sleep(nanoseconds: 350_000_000)
                guard !Task.isCancelled else { return }
                presentation.previewIfNeeded()
            }
        } else if presentation.shouldClose {
            closeTask = Task { @MainActor in
                try? await Task.sleep(nanoseconds: 200_000_000)
                guard !Task.isCancelled else { return }
                presentation.closeIfNeeded()
            }
        }
    }
}

/// Synthetic grid card (same pattern as the WebRTC tile): names the proxy
/// routing mode the audit actually observed — 全局 or 规则 — plus the exit
/// node and rule-table coverage. Evidence-only display; never gates.
private struct EnvironmentModeTile: View {
    let local: EnvironmentLocalFacts
    let p: Palette
    let stale: Bool
    private var api: EnvironmentTagAPI? { local.tag?.api }
    private var rules: EnvironmentRulesEvidence? { local.rules }
    private var mode: String { api?.mode ?? rules?.actual_mode ?? "" }
    private var status: (label: String, symbol: String, tint: Color, value: String) {
        if stale { return ("历史样本", "clock", p.secondary, "环境采样已过期；重新检测后显示当前模式。") }
        if mode.isEmpty {
            let reason = api?.reason ?? rules?.detail ?? ""
            return ("未取得", "questionmark.circle.fill", p.amber,
                    "未能读取代理路由模式" + (reason.isEmpty ? "；请确认代理客户端控制接口可用。" : "；" + reason))
        }
        if mode == "global" {
            let node = api?.global_node ?? api?.selected_node ?? ""
            return ("全局模式", "arrow.triangle.branch", p.mint,
                    "全部流量统一走单一出口节点，规则表不参与匹配。" + (node.isEmpty ? "" : "出口节点：" + node))
        }
        if mode == "rule" {
            let missing = rules?.missing_domains?.count ?? 0
            let covered = rules?.covered_domains?.count ?? 0
            let coverage = missing > 0 ? "规则表缺失 \(missing) 项域名覆盖。" : (covered > 0 ? "规则表覆盖 \(covered) 项域名。" : "")
            return ("规则模式", "list.bullet.rectangle", p.blue,
                    "流量按规则表逐条匹配，未覆盖的域名可能绕过代理直连。" + coverage)
        }
        return ("未识别模式", "questionmark.circle.fill", p.amber, "代理运行在 \(mode) 模式；实际流量走向见连接页。")
    }
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: status.symbol)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(status.tint).frame(width: 30, height: 30)
                .background(status.tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Text("代理模式").font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                    Spacer(minLength: 0)
                    Label(status.label, systemImage: status.symbol).font(WatchTypography.small).foregroundStyle(status.tint)
                        .padding(.horizontal, 6).padding(.vertical, 3).background(status.tint.opacity(0.10), in: Capsule())
                }
                Text(status.value).font(WatchTypography.caption).foregroundStyle(p.text)
                    .lineLimit(3).frame(maxWidth: .infinity, alignment: .leading)
                if let detail = rules?.detail, !detail.isEmpty, !stale, !mode.isEmpty {
                    Text(detail).font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(2)
                }
            }
        }.frame(maxWidth: .infinity, minHeight: 48, alignment: .topLeading).padding(10)
            .background(p.elevated.opacity(0.65), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(
                !stale && mode == "rule" && (rules?.missing_domains?.count ?? 0) > 0 ? p.amber.opacity(0.4) : p.border.opacity(0.65), lineWidth: 1))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("代理模式，" + status.label + "，" + status.value)
    }
}

private struct EnvironmentWebRTCTile: View {
    let state: LeakCheckState
    let p: Palette
    let stale: Bool
    let open: () -> Void
    private var status: (label: String, symbol: String, tint: Color, value: String) {
        if stale { return ("历史样本", "clock", p.secondary, "环境采样已过期；WebRTC 最近结果见详情") }
        if state.running { return ("更新中", "arrow.triangle.2.circlepath", p.blue, state.result == nil ? "正在采集当前 WebView 的 ICE/STUN 候选" : "正在更新；保留上次检测结果") }
        switch state.verdict.state {
        case .matched: return ("已核对", "checkmark.circle.fill", p.mint, state.verdict.title)
        case .difference: return ("出口差异", "exclamationmark.triangle", p.amber, state.verdict.title)
        case .incomplete, .unconfigured: return ("检测未完成", "exclamationmark.triangle.fill", p.amber, state.verdict.detail)
        case .cancelled: return ("已取消", "stop.circle", p.amber, state.verdict.detail)
        case .idle: return ("尚未检测", "clock", p.secondary, "等待自动检测或打开详情立即检测")
        case .running: return ("更新中", "arrow.triangle.2.circlepath", p.blue, "正在采集当前 WebView 的 ICE/STUN 候选")
        }
    }
    var body: some View {
        Button(action: open) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "antenna.radiowaves.left.and.right").font(.system(size: 16, weight: .medium))
                    .foregroundStyle(status.tint).frame(width: 30, height: 30)
                    .background(status.tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 6) {
                        Text("WebRTC 泄漏检测").font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                        Spacer(minLength: 0)
                        Label(status.label, systemImage: status.symbol).font(WatchTypography.small).foregroundStyle(status.tint)
                            .padding(.horizontal, 6).padding(.vertical, 3).background(status.tint.opacity(0.10), in: Capsule())
                    }
                    Text(status.value).font(WatchTypography.caption).foregroundStyle(p.text).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                    if let result = state.result { Text("采样于 " + environmentSummaryTime(result.finishedAt)).font(WatchTypography.small).foregroundStyle(p.secondary) }
                }
            }.frame(maxWidth: .infinity, minHeight: 48, alignment: .topLeading).padding(10)
                .background(p.elevated.opacity(0.65), in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(status.tint.opacity(0.35), lineWidth: 1))
        }.buttonStyle(.plain).accessibilityLabel("WebRTC 泄漏检测，" + status.label)
    }
}

private struct EnvironmentIPQualitySummary: View {
    @ObservedObject var store: NetCoffeeStore
    let environment: CurrentEnvironmentReceipt
    let p: Palette
    let openIPScore: (String) -> Void
    private var egressRow: EnvironmentCheckRow? {
        environment.rows.first(where: { $0.id == "egress" })
    }
    private var ip: String? {
        guard let raw = egressRow?.current else { return nil }
        return raw.components(separatedBy: " / ").first.flatMap { LeakIPAddress($0.trimmingCharacters(in: .whitespacesAndNewlines))?.canonical }
    }
    var body: some View {
        guard let ip else { return AnyView(EmptyView()) }
        let receipt = store.report(ip)
        let fresh = store.isFreshLookup(ip)
        let isp = receipt?.field("isp").replacingOccurrences(of: "未提供", with: "") ?? egressRow?.isp ?? ""
        let company = receipt?.field("company_name").replacingOccurrences(of: "未提供", with: "") ?? egressRow?.company_name ?? ""
        let org = receipt?.field("asOrganization").replacingOccurrences(of: "未提供", with: "") ?? egressRow?.as_org ?? ""
        let effectiveCompany = !company.isEmpty ? company : org
        let nature = egressRow?.nature ?? ""
        let isResidential = receipt?.data?["isResidential"]?.flag ?? egressRow?.is_residential
        let isDatacenter = receipt?.data?["is_datacenter"]?.flag ?? egressRow?.is_datacenter
        let typeBadge = isResidential == true ? "家庭住宅 IP (原生)" : (isDatacenter == true ? "机房/数据中心" : (!nature.isEmpty ? nature : ""))
        let rdns = receipt?.field("rdns").replacingOccurrences(of: "未提供", with: "") ?? egressRow?.rdns ?? ""
        let city = receipt?.field("city").replacingOccurrences(of: "未提供", with: "") ?? ""
        let region = receipt?.field("region").replacingOccurrences(of: "未提供", with: "") ?? ""
        let location = !region.isEmpty && !city.isEmpty ? "\(region) \(city)" : (egressRow?.location ?? "")

        return AnyView(Surface(p, padding: 12) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("IP 质量与运营商归属", systemImage: "gauge.with.dots.needle.50percent").font(WatchTypography.bodyStrong)
                    if !typeBadge.isEmpty {
                        Text(typeBadge)
                            .font(WatchTypography.small)
                            .foregroundStyle(isResidential == true ? p.mint : p.amber)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background((isResidential == true ? p.mint : p.amber).opacity(0.12), in: Capsule())
                    }
                    Spacer()
                    Text(store.running.contains(ip) ? "更新中" : receipt == nil ? "未取得" : fresh && receipt?.cache_state != "last_good" ? "本轮实测" : "历史资料")
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                    PageLink(title: "查看 IP 评分", p: p) { openIPScore(ip) }
                }
                if let receipt {
                    HStack(alignment: .top, spacing: 18) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(receipt.score.map(String.init) ?? "—")
                                .font(.system(size: 26, weight: .bold, design: .monospaced))
                                .foregroundStyle((receipt.score ?? 0) >= 80 ? p.mint : p.text)
                            Text("Net.Coffee 信任分").font(WatchTypography.small).foregroundStyle(p.secondary)
                        }.frame(minWidth: 80, alignment: .leading)

                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 8) {
                                Text("AS\(receipt.field("asn")) · \(effectiveCompany)")
                                    .font(WatchTypography.captionStrong)
                                    .lineLimit(1)
                                if !isp.isEmpty && isp != effectiveCompany {
                                    Text("(\(isp))")
                                        .font(WatchTypography.caption)
                                        .foregroundStyle(p.secondary)
                                        .lineLimit(1)
                                }
                            }
                            HStack(spacing: 12) {
                                if !location.isEmpty {
                                    Label("IP 归属地区：" + location, systemImage: "mappin.and.ellipse")
                                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                                }
                                if !rdns.isEmpty {
                                    Text("rDNS: \(rdns)")
                                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                                        .lineLimit(1)
                                }
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Text((fresh && receipt.cache_state != "last_good" ? "资料时间：" : "历史资料时间：") + environmentSummaryTime(receipt.queriedAt) + " · 数据来自 Net.Coffee 原站")
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                } else {
                    Text("正在按本轮公网出口 IP 读取 Net.Coffee 运营商与网络资料；未返回时保持未取得。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
            }
        })
    }
}

func environmentSummaryTime(_ epoch: Double) -> String {
    Date(timeIntervalSince1970: epoch).formatted(date: .numeric, time: .shortened)
}

func environmentTimelineStamp(_ epoch: Double) -> String {
    Date(timeIntervalSince1970: epoch).formatted(
        .dateTime.month(.twoDigits).day(.twoDigits).hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits)
    )
}

/// Any ISO 3166-1 alpha-2 code renders as its regional flag via Unicode
/// regional indicators (same mechanism the backend uses for egress cards).
/// Non-2-letter input degrades to the plain text instead of garbage.
func countryFlag(_ code: String) -> String {
    let upper = code.uppercased()
    guard upper.count == 2, upper.unicodeScalars.allSatisfy({ ("A"..."Z").contains(String($0)) }) else { return code }
    let scalars = upper.unicodeScalars.map { Unicode.Scalar(0x1F1E6 + ($0.value - 65)) }.compactMap { $0 }
    return scalars.count == 2 ? String(String.UnicodeScalarView(scalars)) : code
}


struct EnvironmentCheckDetails: View {
    let row: EnvironmentCheckRow
    let p: Palette
    let pinned: Bool
    let togglePin: () -> Void
    let close: () -> Void
    var stale = false
    var onConfirmBaseline: (() -> Void)? = nil
    @State private var contentHeight: CGFloat = 240

    private var tint: Color {
        if stale || row.state == "info" || row.state == "cached" { return p.secondary }
        return row.state == "ok" ? p.mint : row.state == "fail" ? p.red : p.amber
    }
    private var value: String {
        guard let current = row.current, !current.isEmpty, current != "unknown" else { return "尚未取得验证依据" }
        return current
    }
    private var copyText: String {
        let stamp = row.state == "cached" ? "上次有效采样：" : (row.sample_reused == true ? "复用采样：" : "采样时间：")
        var lines = [
            row.name + " · " + (stale ? "历史样本" : row.statusLabel),
            "实测：" + value,
            "判定依据：" + (row.reference ?? "无独立参考值"),
            "说明：" + row.detail
        ]
        if let asn = row.asn_num, !asn.isEmpty { lines.append("ASN: AS\(asn)") }
        if let isp = row.isp, !isp.isEmpty { lines.append("服务商/ISP: \(isp)") }
        if let company = row.company_name ?? row.as_org, !company.isEmpty { lines.append("企业/归属: \(company)") }
        if let rdns = row.rdns, !rdns.isEmpty { lines.append("反向DNS: \(rdns)") }
        if let loc = row.location, !loc.isEmpty { lines.append("定位: \(loc)") }
        lines.append("来源：" + (row.source ?? row.scope))
        if let sampled = row.sampled_at { lines.append(stamp + environmentSummaryTime(sampled)) }
        if let error = row.query_error, !error.isEmpty { lines.append("本次查询失败：" + error) }
        return lines.filter { !$0.isEmpty }.joined(separator: "\n")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 9) {
                Image(systemName: row.categorySymbol).foregroundStyle(tint)
                Text(row.name).font(WatchTypography.bodyStrong)
                Spacer(minLength: 4)
                Button(action: togglePin) {
                    Image(systemName: pinned ? "pin.fill" : "pin")
                }.help(pinned ? "取消固定" : "固定详情，移开鼠标后保留")
                    .accessibilityLabel(pinned ? "取消固定详情" : "固定详情")
                Button(action: close) { Image(systemName: "xmark") }
                    .help("关闭详情（Esc）").accessibilityLabel("关闭详情")
            }.buttonStyle(.plain)
            Label(stale ? "历史样本 · 请重新检测" : row.statusLabel, systemImage: stale ? "clock" : row.statusSymbol)
                .font(WatchTypography.caption).foregroundStyle(tint)
            ScrollView {
                details.background(GeometryReader { geometry in
                    Color.clear.preference(key: EnvironmentDetailHeight.self, value: geometry.size.height)
                })
            }.frame(height: min(320, max(60, contentHeight)))
                .onPreferenceChange(EnvironmentDetailHeight.self) { height in
                    if height > 0 { contentHeight = height }
                }
            Divider().overlay(p.border)
            HStack {
                Text(pinned ? "已固定 · 可选择并复制文字" : "点击卡片或图钉可固定")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(copyText, forType: .string)
                } label: { Label("复制", systemImage: "doc.on.doc") }
                    .buttonStyle(.borderless).font(WatchTypography.caption)
                    .accessibilityLabel("复制本项完整检测依据")
            }
        }.padding(16).frame(width: 436, alignment: .leading)
            .foregroundStyle(p.text).background(p.surface)
            .environment(\.colorScheme, p.dark ? .dark : .light)
    }
    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            detail("实测", value)
            if let reference = row.reference { detail("判定依据", reference) }
            detail("说明", row.detail)

            if row.id == "egress" || row.id == "asn" || row.isp != nil || row.as_org != nil || row.company_name != nil {
                asnAndOperatorSection
            }

            if row.id == "ip_history" || row.confirmed_ip != nil {
                ipHistorySection
                if let onConfirm = onConfirmBaseline, row.id == "ip_history", row.state == "warn" {
                    HStack(spacing: 8) {
                        Button {
                            onConfirm()
                            close()
                        } label: {
                            Label("核准实测 IP 为新基准", systemImage: "checkmark.seal.fill")
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                        Text("核准后重新核验并解除拦截").font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                    .padding(8)
                    .background(p.elevated.opacity(0.85), in: RoundedRectangle(cornerRadius: 6))
                }
            }

            detail("来源", row.source ?? row.scope)
            if let sampled = row.sampled_at {
                detail(row.state == "cached" ? "上次有效采样" : (row.sample_reused == true ? "复用采样" : "采样时间"), environmentSummaryTime(sampled))
            }
            if let error = row.query_error, !error.isEmpty { detail("本次查询失败", error) }
        }.frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
    }

    @ViewBuilder
    private var asnAndOperatorSection: some View {
        let asn = row.asn_num ?? ""
        let isp = row.isp ?? ""
        let company = row.company_name ?? row.as_org ?? ""
        let kind = row.asn_kind ?? ""
        let rdns = row.rdns ?? ""
        let loc = row.location ?? ""
        let res = row.is_residential
        let nature = row.nature ?? ""

        if !asn.isEmpty || !isp.isEmpty || !company.isEmpty || !rdns.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text("ASN / 运营商详细归属").font(WatchTypography.captionStrong).foregroundStyle(p.secondary)
                VStack(alignment: .leading, spacing: 5) {
                    if !asn.isEmpty {
                        attributeRow("ASN", "AS\(asn)")
                    }
                    if !isp.isEmpty {
                        attributeRow("服务商 / ISP", isp)
                    }
                    if !company.isEmpty {
                        attributeRow("ASN 归属 / 企业", company)
                    }
                    if !nature.isEmpty {
                        attributeRow("使用场景 / 评估", nature)
                    } else if let res {
                        attributeRow("标记类型", res ? "家庭住宅 IP (原生)" : "数据中心 / 机房")
                    }
                    if !kind.isEmpty {
                        attributeRow("ASN 自报类型", kind == "backbone" ? "backbone (骨干网)" : kind)
                    }
                    if let count = row.asn_ipv4_count {
                        attributeRow("ASN IPv4 总量", String(count))
                    }
                    if let tbps = row.asn_tbps, !tbps.isEmpty {
                        attributeRow("预估带宽", tbps)
                    }
                    if let alloc = row.asn_allocated, !alloc.isEmpty {
                        attributeRow("ASN 注册日期", alloc)
                    }
                    if !rdns.isEmpty {
                        attributeRow("反向 DNS (rDNS)", rdns)
                    }
                    if !loc.isEmpty {
                        attributeRow("地区定位", loc)
                    }
                }
                .padding(8)
                .background(p.elevated.opacity(0.7), in: RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    @ViewBuilder
    private var ipHistorySection: some View {
        if let entries = row.history_entries, !entries.isEmpty {
            VStack(alignment: .leading, spacing: 7) {
                Text("出口变迁时间轴与基准对比").font(WatchTypography.captionStrong).foregroundStyle(p.secondary)
                if row.changed_detected_at != nil || row.last_baseline_seen_at != nil {
                    HStack(spacing: 12) {
                        if let lastSeen = row.last_baseline_seen_at {
                            Text("原基准最后在线：" + environmentTimelineStamp(lastSeen))
                        }
                        if let changedAt = row.changed_detected_at {
                            Text("新出口首次发现：" + environmentTimelineStamp(changedAt))
                                .foregroundStyle(p.amber)
                        }
                    }
                    .font(WatchTypography.small)
                    .foregroundStyle(p.secondary)
                }
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(entries) { entry in
                        let isCurrent = entry.role == "current"
                        let isBaseline = entry.role == "confirmed_baseline"
                        let roleColor: Color = isCurrent ? (row.state == "ok" ? p.mint : p.amber) : isBaseline ? p.blue : p.secondary
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(alignment: .center, spacing: 8) {
                                Text(entry.label ?? entry.role ?? "记录")
                                    .font(WatchTypography.small.weight(.medium))
                                    .foregroundStyle(roleColor)
                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                    .background(roleColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 4))
                                Text(entry.ip)
                                    .font(WatchTypography.captionStrong)
                                    .monospaced()
                                    .lineLimit(1)
                                    .fixedSize(horizontal: true, vertical: false)
                                Spacer(minLength: 4)
                                if let node = entry.node, !node.isEmpty {
                                    Text(node)
                                        .font(WatchTypography.small)
                                        .foregroundStyle(p.secondary)
                                        .lineLimit(1)
                                }
                            }
                            if let stampLine = historyEntryTimeSummary(entry) {
                                Text(stampLine)
                                    .font(WatchTypography.small)
                                    .foregroundStyle(p.secondary)
                                    .monospacedDigit()
                            }
                        }
                        .padding(.horizontal, 8).padding(.vertical, 6)
                        .background(p.surface.opacity(0.65), in: RoundedRectangle(cornerRadius: 5))
                    }
                }
                .padding(8)
                .background(p.elevated.opacity(0.7), in: RoundedRectangle(cornerRadius: 6))
            }
        } else if let confirmed = row.confirmed_ip, !confirmed.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("已确认基准 IP").font(WatchTypography.small).foregroundStyle(p.secondary)
                Text(confirmed).font(WatchTypography.caption).monospaced().lineLimit(1)
            }
        }
    }

    private func historyEntryTimeSummary(_ entry: HistoryEntry) -> String? {
        var parts: [String] = []
        if let confirmed = entry.confirmed_at {
            parts.append("基准核准 " + environmentTimelineStamp(confirmed))
        }
        if let first = entry.first_seen, let last = entry.last_seen {
            if abs(last - first) < 5 {
                parts.append("观测于 " + environmentTimelineStamp(last))
            } else {
                parts.append("首次 " + environmentTimelineStamp(first) + " · 最后 " + environmentTimelineStamp(last))
            }
        } else if let last = entry.last_seen {
            parts.append("最后观测 " + environmentTimelineStamp(last))
        }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private func attributeRow(_ label: String, _ val: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).font(WatchTypography.small).foregroundStyle(p.secondary).frame(width: 110, alignment: .leading)
            Text(val).font(WatchTypography.caption).fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
    }
    private func detail(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(WatchTypography.small).foregroundStyle(p.secondary)
            Text(text).font(WatchTypography.caption).fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct EnvironmentDetailHeight: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
}

private func evidenceDisplayDates(until timestamp: Double) -> [Date] {
    let now = Date()
    let expiry = Date(timeIntervalSince1970: timestamp.nextUp)
    return timestamp.isFinite && expiry > now ? [now, expiry] : [now]
}
