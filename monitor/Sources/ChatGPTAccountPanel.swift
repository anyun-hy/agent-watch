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
    let presence: WorkspaceDesktopPresence?
    let p: Palette
    @State private var activation = 0

    private struct StatusRequest: Equatable {
        let presence: WorkspaceDesktopPresence?
        let loaded: Bool
        let activation: Int
    }

    var body: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 14) {
                DesktopAccountControls(store: store, product: .openAI, caption: selectionSummary, p: p)
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
                if store.aiVersions?.chatgpt_desktop.seatbelt_incompatible == true {
                    InlineNotice(title: "当前 ChatGPT 构建暂不兼容受控 Seatbelt 启动",
                                 detail: "已检测到包内包含 Aperitif 辅助进程组件，从「代理与连接」受控启动时会自动拦截以防止崩溃。",
                                 symbol: "exclamationmark.shield", tint: p.amber, p: p)
                }
            }
        }.task(id: StatusRequest(presence: presence, loaded: store.loaded, activation: activation)) {
            await store.refreshChatGPTAccounts()
        }.onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            activation += 1
        }
    }

    private var selectionSummary: String {
        let base: String
        if let id = store.switchingChatGPTSlot { base = "正在打开账号 \(id) 并核对桌面状态…" }
        else if let id = store.chatGPTAccounts?.current { base = "桌面正在使用槽位 \(id)" }
        else if let id = store.chatGPTAccounts?.selected { base = "上次选用槽位 \(id)，当前桌面实例尚未核实" }
        else { base = "当前桌面使用的账号槽位尚未核实" }
        let versionText = SwitcherStore.formattedVersion(store.chatgptVersion, build: store.chatgptBuild)
        return versionText.isEmpty ? base : "\(base) · ChatGPT \(versionText)"
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
    let product: MonitoredProduct
    let caption: String
    let p: Palette
    @State private var saveChoice: DesktopAccountCapture?

    private var capture: DesktopAccountCapture? { store.manualAccounts[product] }
    private var name: String { product == .claude ? "Claude" : "ChatGPT" }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                BrandLogo(brand: product == .claude ? .claude : .chatgpt, size: 18)
                SectionHeading(title: name + " 账号", caption: caption, p: p)
                Spacer(minLength: 6)
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
            if let capture, !capture.canSave {
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
