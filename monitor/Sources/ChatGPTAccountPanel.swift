import AppKit
import SwiftUI

struct AccountSlotCard: View {
    let account: SwitcherAccountSlot
    let summary: String
    let p: Palette
    var lastSelected = false
    var actionTitle: String?

    var body: some View {
        let tint = account.current ? p.mint : p.blue
        HStack(spacing: 11) {
            Text(verbatim: account.id)
                .font(WatchTypography.title).foregroundStyle(tint)
                .frame(width: 32, height: 36)
                .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 7))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text("账号 \(account.id)").font(WatchTypography.bodyStrong)
                    if lastSelected && !account.current { Text("上次选用").font(WatchTypography.small).foregroundStyle(p.secondary) }
                }
                if let name = account.account_label, !name.isEmpty {
                    Text(name).font(WatchTypography.bodyStrong).lineLimit(2)
                        .help("保存时的账号：" + name)
                }
                Text(summary).font(WatchTypography.caption).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 4)
            if account.current {
                Badge(text: "当前", color: tint)
            } else {
                HStack(spacing: 4) {
                    if let actionTitle { Text(actionTitle).font(WatchTypography.captionStrong) }
                    Image(systemName: "arrow.right").accessibilityHidden(true)
                }.foregroundStyle(tint)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 38, alignment: .leading).padding(12)
        .background(account.current ? p.mint.opacity(0.07) : p.elevated.opacity(0.55), in: RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(account.current ? tint.opacity(0.40) : p.border))
        .contentShape(RoundedRectangle(cornerRadius: 9))
        .accessibilityElement(children: .combine)
    }
}

struct ChatGPTAccountPanel: View {
    @ObservedObject var store: SwitcherStore
    var monitor: MonitorStore? = nil
    let presence: WorkspaceDesktopPresence?
    let p: Palette
    var onConfirmPrune: ((AIProductVersionsInfo) -> Void)? = nil
    @State private var activation = 0

    private struct StatusRequest: Equatable {
        let presence: WorkspaceDesktopPresence?
        let loaded: Bool
        let activation: Int
    }

    var body: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 14) {
                DesktopAccountControls(store: store, monitor: monitor, product: .openAI, caption: selectionSummary, p: p)
                if let state = store.chatGPTAccounts {
                    HStack(spacing: 12) {
                        ForEach(state.accounts) { slot in
                            if slot.current {
                                AccountSlotCard(account: slot, summary: slotSummary(slot), p: p)
                            } else {
                                Button {
                                    Task { await store.switchChatGPTAccount(to: slot.id) }
                                } label: {
                                    AccountSlotCard(account: slot, summary: slotSummary(slot), p: p,
                                                    lastSelected: state.selected == slot.id, actionTitle: actionTitle(slot, state))
                                }
                                .buttonStyle(.plain)
                                .disabled(store.busy || store.hasUnsavedSettings || store.switchingChatGPTSlot != nil)
                                .accessibilityLabel(actionTitle(slot, state) + "，" + slotSummary(slot))
                                .help("用账号 \(slot.id) 的资料打开 ChatGPT")
                            }
                        }
                    }
                    Text("切换时会用所选槽位的资料重新打开 ChatGPT。空槽需要先在桌面端登录。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                } else {
                    Text(store.chatGPTAccountsError ?? (store.loaded ? "当前后台未提供 ChatGPT 桌面账号切换。" : "正在读取桌面账号…"))
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
                if let info = store.aiVersions?.chatgpt {
                    ProductVersionsSection(
                        product: .openAI,
                        info: info,
                        pruneMessage: store.pruneCLIMessages[.openAI] ?? "",
                        disabled: store.busy || store.hasUnsavedSettings || store.switchingChatGPTSlot != nil,
                        p: p,
                        onConfirmPrune: onConfirmPrune
                    )
                }
            }
        }.task(id: StatusRequest(presence: presence, loaded: store.loaded, activation: activation)) {
            await store.refreshChatGPTAccounts()
        }.onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            activation += 1
        }
    }

    private var selectionSummary: String {
        if let id = store.switchingChatGPTSlot {
            return "本地 A / B 资料槽位 · 正在切换到槽位 \(id)…"
        } else if let id = store.chatGPTAccounts?.current {
            return "本地 A / B 资料槽位 · 桌面正在使用槽位 \(id)"
        } else if let id = store.chatGPTAccounts?.selected {
            return "本地 A / B 资料槽位 · 上次选用槽位 \(id)（当前桌面未运行）"
        } else {
            return "本地 A / B 资料槽位 · 当前槽位尚未核实"
        }
    }

    private func slotSummary(_ slot: SwitcherAccountSlot) -> String {
        switch slot.login_state {
        case "logged_in": return "本地已登录 ChatGPT"
        case "signed_out": return "未登录 ChatGPT"
        case "uninitialized": return "空槽 · 尚未建立资料"
        default:
            switch slot.profile_state {
            case "present": return "已有本地资料 · 登录未核实"
            case "absent": return "未发现本地资料 · 登录未核实"
            default: return "登录状态未核实"
            }
        }
    }

    private func actionTitle(_ slot: SwitcherAccountSlot, _ state: SwitcherAccountState) -> String {
        if ["signed_out", "uninitialized"].contains(slot.login_state ?? "") { return "打开 \(slot.id) 登录" }
        return state.current == nil ? "打开 \(slot.id)" : "切换到 \(slot.id)"
    }
}

struct DesktopAccountControls: View {
    @ObservedObject var store: SwitcherStore
    var monitor: MonitorStore? = nil
    let product: MonitoredProduct
    let caption: String
    let p: Palette
    @State private var saveChoice: DesktopAccountCapture?

    private var capture: DesktopAccountCapture? { store.manualAccounts[product] }
    private var name: String { product == .claude ? "Claude" : "ChatGPT" }
    private var moduleTitle: String { product == .claude ? "Claude" : "ChatGPT / Codex" }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                BrandLogo(brand: product == .claude ? .claude : .chatgpt, size: 18)
                SectionHeading(title: moduleTitle, caption: caption, p: p)
                Spacer(minLength: 6)
                if let monitor {
                    GraphLaunchButton(product: product, monitor: monitor, switcher: store,
                                      processControl: monitor.processControl, p: p).fixedSize()
                    AIProcessCloseButton(product: product, store: monitor, control: monitor.processControl,
                                         switcher: store, p: p).fixedSize()
                }
                Button {
                    Task {
                        if let reading = await store.loadManualAccount(product), reading.canSave {
                            saveChoice = reading
                        }
                    }
                } label: {
                    Label(store.readingAccount == product ? "读取中…" : "加载当前账号信息", systemImage: "person.text.rectangle")
                }
                .disabled(store.busy).fixedSize()
            }
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("当前桌面账号").font(WatchTypography.caption).foregroundStyle(p.secondary)
                Text(accountText).font(WatchTypography.bodyStrong).textSelection(.enabled)
                if let capture, capture.canSave {
                    Text("读取于 " + capture.observedAt.formatted(date: .omitted, time: .standard))
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                }
            }
            if let capture, !capture.canSave, capture.state != "app_closed" {
                Text(capture.detail).font(WatchTypography.caption).foregroundStyle(p.secondary)
                if product == .claude, capture.state == "access_required" {
                    Button("打开辅助功能设置") { store.openClaudeWatchAccessibilitySettings() }.buttonStyle(.borderless)
                }
            }
            if let feedback = store.accountFeedback[product] {
                Text(feedback).font(WatchTypography.caption).textSelection(.enabled)
            }
        }
        .alert("将 " + name + " 账号保存到哪个槽位？", isPresented: Binding(
            get: { saveChoice != nil && saveChoice?.source_token == capture?.source_token },
            set: { if !$0 { saveChoice = nil } }
        ), presenting: saveChoice) { reading in
            saveButton("A", reading: reading)
            saveButton("B", reading: reading)
            Button("取消", role: .cancel) {}
        } message: { reading in
            let label = reading.label ?? name
            if store.hasUnsavedSettings {
                Text("已读取「" + label + "」。请先保存或撤销工具设置，再加载账号。")
            } else if product == .claude && store.accounts?.recovery_required == true {
                Text("已读取「" + label + "」。请先恢复未完成的账号切换，再加载账号。")
            } else if product == .claude, let conflict = store.accounts?.legacy_conflict {
                Text("已读取「" + label + "」。" + conflict.message + "，请先核对资料冲突后再保存。")
            } else if product == .openAI, let slot = reading.slot {
                Text("「" + label + "」正在使用槽位 " + slot + "。选另一个空槽会把这份资料改存到那里。")
            } else {
                Text("当前账号为「" + label + "」。已有其他账号的槽位会保留原资料。")
            }
        }
    }

    private func saveButton(_ slot: String, reading: DesktopAccountCapture) -> some View {
        Button("保存到 " + slot) {
            guard let token = reading.source_token else { return }
            Task { await store.saveManualAccount(product, to: slot, expectedToken: token) }
        }
        .disabled(store.busy || store.hasUnsavedSettings ||
                  (product == .claude && (store.accounts?.recovery_required == true || store.accounts?.legacy_conflict != nil)))
    }

    private var accountText: String {
        guard let capture else { return "尚未加载" }
        if let label = capture.label {
            if let slot = capture.slot { return label + " · 槽位 " + slot }
            return label
        }
        switch capture.state {
        case "signed_out", "logged_out": return "未登录"
        case "app_closed": return name + " 未运行"
        case "access_required": return "需要辅助功能权限"
        default: return "未能核实当前账号"
        }
    }
}

struct ProductVersionsSection: View {
    let product: MonitoredProduct
    let info: AIProductVersionsInfo
    let pruneMessage: String
    let disabled: Bool
    let p: Palette
    var onConfirmPrune: ((AIProductVersionsInfo) -> Void)? = nil

    private var desktopTitle: String { product == .claude ? "Claude Desktop" : "ChatGPT Desktop" }
    private var embeddedTitle: String { product == .claude ? "Claude 内置 CLI" : "ChatGPT 随包 CLI" }
    private var standaloneTitle: String { product == .claude ? "Claude Code CLI（独立安装）" : "Codex CLI（独立安装）" }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            HStack(spacing: 8) {
                Text("桌面端与 CLI 版本管理").font(WatchTypography.captionStrong).foregroundStyle(p.secondary)
                Spacer(minLength: 4)
                Badge(text: info.has_warnings ? "发现多版本 / 旧版" : "版本正常",
                      color: info.has_warnings ? p.amber : p.mint)
            }
            desktopRow
            embeddedCLIRow
            standaloneCLIRow
            if !info.prunable_versions.isEmpty {
                HStack(alignment: .center, spacing: 10) {
                    Text("可清理旧版本：\(info.prunable_versions.joined(separator: "、"))（约 \(info.prunableMBText)）")
                        .font(WatchTypography.small).foregroundStyle(p.amber)
                    Spacer(minLength: 4)
                    if let onConfirmPrune {
                        Button("清理旧版本…") {
                            onConfirmPrune(info)
                        }
                        .controlSize(.small)
                        .disabled(disabled)
                    }
                }
            }
            if !pruneMessage.isEmpty {
                Text(pruneMessage).font(WatchTypography.caption).foregroundStyle(p.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    private var desktopRow: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Text(desktopTitle).font(WatchTypography.bodyStrong)
                let versionText = SwitcherStore.formattedVersion(info.desktop.selected_version, build: info.desktop.selected_build)
                Text(versionText.isEmpty ? (info.desktop.installs.isEmpty ? "未检测到安装" : "版本未确认") : versionText)
                    .font(WatchTypography.mono).foregroundStyle(p.secondary)
                Spacer(minLength: 4)
                if info.desktop.multiple_versions {
                    Badge(text: "\(info.desktop.installs.count) 个副本", color: p.amber)
                } else if !info.desktop.installs.isEmpty {
                    Text("单版本").font(WatchTypography.small).foregroundStyle(p.secondary)
                }
            }
            if info.desktop.multiple_versions {
                ForEach(info.desktop.installs) { install in
                    let ver = SwitcherStore.formattedVersion(install.version, build: install.build_version)
                    Text("\(install.selected ? "当前" : "副本") · \(ver.isEmpty ? "版本未知" : ver) · \(install.path)")
                        .font(WatchTypography.small).foregroundStyle(p.amber).textSelection(.enabled)
                }
            } else if !info.desktop.selected_path.isEmpty {
                Text(info.desktop.selected_path).font(WatchTypography.small).foregroundStyle(p.secondary).textSelection(.enabled)
            }
            if info.desktop.sandbox_compat_mode {
                Text("受控网络沙盒兼容模式：检测到 Aperitif 组件，受控启动将自动启用外层网络沙盒 + 钥匙串放行 + 高敏目录隔离 + --no-sandbox。")
                    .font(WatchTypography.small).foregroundStyle(p.blue)
            }
        }
    }

    private var embeddedCLIRow: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Text(embeddedTitle).font(WatchTypography.bodyStrong)
                if info.embedded_cli.present {
                    Text(info.embedded_cli.latest.isEmpty ? "已内置" : info.embedded_cli.latest)
                        .font(WatchTypography.mono).foregroundStyle(p.secondary)
                    if !info.embedded_cli.source_label.isEmpty {
                        Text("· " + info.embedded_cli.source_label)
                            .font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                } else {
                    Text("未检测到").font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
                Spacer(minLength: 4)
                if !info.embedded_cli.redundant_versions.isEmpty {
                    Badge(text: "\(info.embedded_cli.redundant_versions.count) 个旧版 · \(info.embedded_cli.redundantMBText)", color: p.amber)
                } else if info.embedded_cli.bundled_in_app && info.embedded_cli.present {
                    Text("随应用包").font(WatchTypography.small).foregroundStyle(p.secondary)
                } else if info.embedded_cli.present {
                    Text("无冗余旧版").font(WatchTypography.small).foregroundStyle(p.secondary)
                }
            }
            if !info.embedded_cli.path.isEmpty {
                Text(info.embedded_cli.path).font(WatchTypography.small).foregroundStyle(p.secondary).textSelection(.enabled)
            }
            if !info.embedded_cli.legacy_redundant_versions.isEmpty {
                Text("原版切换器目录另检测到旧版：\(info.embedded_cli.legacy_redundant_versions.joined(separator: "、"))（只读提示，本工具不修改原版目录）")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
            }
        }
    }

    private var standaloneCLIRow: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Text(standaloneTitle).font(WatchTypography.bodyStrong)
                if !info.standalone_cli.selected_version.isEmpty {
                    Text(info.standalone_cli.selected_version).font(WatchTypography.mono).foregroundStyle(p.secondary)
                    if !info.standalone_cli.selected_source_label.isEmpty {
                        Text("· " + info.standalone_cli.selected_source_label)
                            .font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                } else if info.standalone_cli.installs.isEmpty {
                    Text("未检测到独立安装").font(WatchTypography.caption).foregroundStyle(p.secondary)
                } else {
                    Text("已安装").font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
                Spacer(minLength: 4)
                if info.standalone_cli.multiple_versions {
                    Badge(text: "\(info.standalone_cli.installs.count) 个安装来源", color: p.amber)
                } else if !info.standalone_cli.installs.isEmpty {
                    Text("单来源").font(WatchTypography.small).foregroundStyle(p.secondary)
                }
            }
            if info.standalone_cli.multiple_versions {
                ForEach(info.standalone_cli.installs) { install in
                    let label = install.source_label.isEmpty ? install.source_kind : install.source_label
                    let ver = install.version.isEmpty ? label : "\(install.version)（\(label)）"
                    Text("\(install.selected ? "当前" : "其他来源") · \(ver) · \(install.path)")
                        .font(WatchTypography.small).foregroundStyle(p.amber).textSelection(.enabled)
                }
            } else if !info.standalone_cli.selected_path.isEmpty {
                Text(info.standalone_cli.selected_path).font(WatchTypography.small).foregroundStyle(p.secondary).textSelection(.enabled)
            }
        }
    }
}
