import AppKit
import SwiftUI

/// Pure vector emblem for Agent Watch ("Hex Agent Core"): a geometric hexagon
/// sandbox enclosing a four-point AI spark. Shared by the menu bar popover and
/// main sidebar so brand identity stays consistent without colliding with
/// generic shield icons.
struct HexAgentCoreMark: View {
    var size: CGFloat = 18
    var color: Color = .primary
    var lineWidth: CGFloat = 1.6

    var body: some View {
        Canvas { context, canvasSize in
            let s = min(canvasSize.width, canvasSize.height)
            let scale = s / 18.0
            let ox = (canvasSize.width - s) / 2.0
            let oy = (canvasSize.height - s) / 2.0
            let pt: (CGFloat, CGFloat) -> CGPoint = { x, y in
                CGPoint(x: ox + x * scale, y: oy + y * scale)
            }

            var hex = Path()
            hex.move(to: pt(9.0, 1.8))
            hex.addLine(to: pt(15.2, 5.4))
            hex.addLine(to: pt(15.2, 12.6))
            hex.addLine(to: pt(9.0, 16.2))
            hex.addLine(to: pt(2.8, 12.6))
            hex.addLine(to: pt(2.8, 5.4))
            hex.closeSubpath()
            context.stroke(
                hex,
                with: .color(color),
                style: StrokeStyle(lineWidth: lineWidth * scale, lineCap: .round, lineJoin: .round)
            )

            var star = Path()
            star.move(to: pt(9.0, 5.3))
            star.addLine(to: pt(10.0, 8.0))
            star.addLine(to: pt(12.7, 9.0))
            star.addLine(to: pt(10.0, 10.0))
            star.addLine(to: pt(9.0, 12.7))
            star.addLine(to: pt(8.0, 10.0))
            star.addLine(to: pt(5.3, 9.0))
            star.addLine(to: pt(8.0, 8.0))
            star.closeSubpath()
            context.fill(star, with: .color(color))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// Read-only menu bar popover summarizing authoritative protection, egress,
/// proxy, and AI client status from `MonitorStore` and `SwitcherStore`.
/// Never introduces separate policy decisions or polling loops.
struct StatusBarPopoverView: View {
    @ObservedObject var store: MonitorStore
    @ObservedObject var switcher: SwitcherStore
    @ObservedObject var initialization: FirstRunInitialization
    @AppStorage("darkAppearance") private var dark = false

    let isMainWindowVisible: () -> Bool
    let onOpenPage: (Page) -> Void
    let onOpenProductConnections: (MonitoredProduct) -> Void
    let onToggleWindow: () -> Void
    let onRefresh: () -> Void
    let onQuit: () -> Void

    private var p: Palette { Palette(dark: dark) }

    private var appVersionLabel: String {
        let info = Bundle.main.infoDictionary
        let short = (info?["CFBundleShortVersionString"] as? String) ?? ""
        let build = (info?["CFBundleVersion"] as? String) ?? ""
        if !short.isEmpty && !build.isEmpty {
            return "v\(short) · #\(build)"
        }
        return short.isEmpty ? "" : "v\(short)"
    }

    private var session: SessionProtectionPresentation {
        switcher.sessionDisplay
    }

    private var sessionColor: Color {
        if session.tone == "danger" { return p.red }
        if session.tone == "warning" { return p.amber }
        if session.tone == "success" || session.title == SessionProtectionPresentation.idleTitle {
            return p.mint
        }
        return p.secondary
    }

    private var activeEgress: EgressReference? {
        StatusBarController.resolveActiveEgress(switcher)
    }

    private var proxySummaryText: String {
        guard let proxy = store.proxy else {
            return store.proxyError ?? "等待后台代理采样"
        }
        let mode = modeName(proxy.mode)
        let rawNode = proxy.mode == "global" ? proxy.globalNode : proxy.selectedNode
        let activeNode = rawNode.isEmpty ? nil : rawNode
        if proxy.selectionDiffers {
            return "\(mode) · 节点与预期不一致"
        }
        if let activeNode {
            return "\(mode) · \(activeNode)"
        }
        let endpoint = proxy.endpoint
            .replacingOccurrences(of: "http://", with: "")
            .replacingOccurrences(of: "https://", with: "")
        return "\(endpoint) · \(mode) · \(store.entryTitle)"
    }

    private var proxyStatusColor: Color {
        guard let proxy = store.proxy else { return p.amber }
        if proxy.selectionDiffers || proxy.entryState == "mismatch" { return p.amber }
        return proxy.entryState == "verified" ? p.mint : p.secondary
    }

    private var isRefreshing: Bool {
        store.refreshing || switcher.refreshingBackground
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            headerSection
            if let available = switcher.updateStatus, available.isAvailable {
                updateBanner(available)
            }
            if !initialization.entered {
                firstRunBanner
            } else {
                networkCard
                productsCard
                quickActionsGrid
            }
            Divider().overlay(p.border.opacity(0.6))
            footerSection
        }
        .padding(14)
        .frame(width: 368)
        .background(p.background)
        .foregroundStyle(p.text)
        .font(WatchTypography.caption)
        .preferredColorScheme(dark ? .dark : .light)
    }

    private var headerSection: some View {
        HStack(alignment: .center, spacing: 10) {
            HexAgentCoreMark(size: 22, color: sessionColor, lineWidth: 1.7)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("Agent Watch")
                        .font(WatchTypography.section)
                        .lineLimit(1)
                    if !appVersionLabel.isEmpty {
                        Text(appVersionLabel)
                            .font(WatchTypography.small)
                            .foregroundStyle(p.secondary)
                            .lineLimit(1)
                    }
                }
                HStack(spacing: 5) {
                    Circle().fill(sessionColor).frame(width: 6, height: 6)
                    Text(session.title)
                        .font(WatchTypography.small.weight(.medium))
                        .foregroundStyle(sessionColor)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            Button(action: onRefresh) {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 12, weight: .medium))
                    .frame(width: 26, height: 26)
                    .background(p.elevated, in: RoundedRectangle(cornerRadius: 7))
            }
            .buttonStyle(.plain)
            .disabled(isRefreshing)
            .opacity(isRefreshing ? 0.5 : 1)
            .help("立即刷新后台与网络状态")
            .accessibilityLabel("刷新状态")
        }
    }

    private func updateBanner(_ available: UpdateStatusReceipt) -> some View {
        Button {
            onOpenPage(.protection)
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "arrow.down.circle.fill")
                    .font(.system(size: 13))
                    .foregroundStyle(p.blue)
                Text("发现新版本 \(available.versionLabel)，前往安装")
                    .font(WatchTypography.small.weight(.medium))
                    .foregroundStyle(p.text)
                    .lineLimit(1)
                Spacer(minLength: 4)
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(p.secondary)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(p.blue.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(p.blue.opacity(0.35), lineWidth: 1))
        }
        .buttonStyle(.plain)
    }

    private var firstRunBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("首次初始化尚未完成")
                .font(WatchTypography.captionStrong)
            Text("请打开主窗口完成环境与权限核对后启用完整守护。")
                .font(WatchTypography.small)
                .foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                onToggleWindow()
            } label: {
                Text("打开初始化向导")
                    .font(WatchTypography.small.weight(.medium))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .background(p.blue.opacity(0.18), in: RoundedRectangle(cornerRadius: 7))
                    .foregroundStyle(p.blue)
            }
            .buttonStyle(.plain)
        }
        .padding(10)
        .background(p.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
    }

    private var networkCard: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Image(systemName: "globe.asia.australia")
                    .font(.system(size: 11))
                    .foregroundStyle(p.secondary)
                    .frame(width: 15)
                Text("当前出口")
                    .font(WatchTypography.small)
                    .foregroundStyle(p.secondary)
                Spacer(minLength: 6)
                if let egress = activeEgress, let ip = egress.ip {
                    HStack(spacing: 5) {
                        if let code = CountryIdentity.code(egress.country, country: egress.country) {
                            CountryFlag(code: code, width: 14)
                            Text("\(ip) · \(code)")
                                .font(WatchTypography.small.weight(.medium))
                                .monospacedDigit()
                                .lineLimit(1)
                        } else {
                            Text(ip)
                                .font(WatchTypography.small.weight(.medium))
                                .monospacedDigit()
                                .lineLimit(1)
                        }
                    }
                    .fixedSize(horizontal: true, vertical: false)
                } else {
                    Text(isRefreshing ? "正在读取…" : "等待采样")
                        .font(WatchTypography.small)
                        .foregroundStyle(p.secondary)
                }
            }

            HStack(spacing: 6) {
                Image(systemName: "cable.connector")
                    .font(.system(size: 11))
                    .foregroundStyle(proxyStatusColor)
                    .frame(width: 15)
                Text("本机代理")
                    .font(WatchTypography.small)
                    .foregroundStyle(p.secondary)
                Spacer(minLength: 6)
                Text(proxySummaryText)
                    .font(WatchTypography.small)
                    .foregroundStyle(proxyStatusColor == p.amber ? p.amber : p.text)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            HStack(spacing: 6) {
                Image(systemName: "waveform.path.ecg")
                    .font(.system(size: 11))
                    .foregroundStyle(store.live ? p.mint : p.amber)
                    .frame(width: 15)
                Text("采集心跳")
                    .font(WatchTypography.small)
                    .foregroundStyle(p.secondary)
                Spacer(minLength: 6)
                Text(heartbeatSummaryText)
                    .font(WatchTypography.small)
                    .foregroundStyle(store.live ? p.secondary : p.amber)
                    .monospacedDigit()
                    .lineLimit(1)
            }
        }
        .padding(10)
        .background(p.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
    }

    private var heartbeatSummaryText: String {
        if store.error != nil { return "读取异常" }
        if !store.automatic { return "已暂停自动刷新" }
        guard let snapshot = store.snapshot else { return "等待首次采样" }
        let stamp = timeText(snapshot.capturedAt)
        return store.live ? "正常 · \(stamp)" : "待核对 · \(stamp)"
    }

    private var productsCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(MonitoredProduct.allCases) { product in
                productRow(product)
            }
        }
        .padding(10)
        .background(p.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
    }

    private func productRow(_ product: MonitoredProduct) -> some View {
        let processes = store.snapshot?.processes.filter { $0.product == product } ?? []
        let count = processes.count
        let channel = store.channelState(for: product)
        let status = productStatus(count: count, channel: channel)

        return Button {
            onOpenProductConnections(product)
        } label: {
            HStack(spacing: 8) {
                BrandLogo(brand: product == .claude ? .claude : .chatgpt, size: 16)
                Text(product.title)
                    .font(WatchTypography.small.weight(.medium))
                    .foregroundStyle(p.text)
                    .lineLimit(1)
                Spacer(minLength: 6)
                HStack(spacing: 5) {
                    Circle().fill(status.color).frame(width: 5, height: 5)
                    Text(status.label)
                        .font(WatchTypography.small)
                        .foregroundStyle(status.color)
                        .lineLimit(1)
                }
                .fixedSize(horizontal: true, vertical: false)
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(p.secondary.opacity(0.7))
            }
            .padding(.vertical, 3)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func productStatus(count: Int, channel: FamilyChannelMonitorState?) -> (label: String, color: Color) {
        if let channel {
            let hasActiveSession = channel.session_id?.isEmpty == false
            if count == 0 && (!hasActiveSession || channel.reason_code == "idle_no_process") {
                return ("未运行 · 网关待命", p.secondary)
            }
            switch channel.display_state {
            case .forwarding:
                return (count > 0 ? "受控守护 · \(count) 进程" : "通道获准转发", p.mint)
            case .blocked:
                return ("已阻断断流", p.red)
            case .disconnecting:
                return ("正在断开连接", p.amber)
            case .failed:
                return ("执行异常", p.red)
            case .pendingVerification:
                if count > 0 { return ("待核验 · \(count) 进程", p.amber) }
            }
        }
        if count > 0 {
            return ("运行中 · \(count) 进程", p.blue)
        }
        return ("未运行", p.secondary)
    }

    private var quickActionsGrid: some View {
        let items: [(String, String, Page)] = [
            ("环境状态", Page.environment.symbol, .environment),
            ("启动与账号", Page.switcher.symbol, .switcher),
            ("保护与设置", Page.protection.symbol, .protection),
            ("网络全景诊断", Page.panorama.symbol, .panorama),
        ]
        return LazyVGrid(columns: [GridItem(.flexible(), spacing: 6), GridItem(.flexible(), spacing: 6)], spacing: 6) {
            ForEach(items, id: \.0) { title, symbol, destination in
                Button {
                    onOpenPage(destination)
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: symbol)
                            .font(.system(size: 11))
                            .foregroundStyle(p.blue)
                            .frame(width: 14)
                        Text(title)
                            .font(WatchTypography.small)
                            .foregroundStyle(p.text)
                            .lineLimit(1)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 9)
                    .padding(.vertical, 7)
                    .background(p.surface, in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(p.border.opacity(0.6), lineWidth: 1))
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var footerSection: some View {
        HStack(spacing: 8) {
            Button(action: onToggleWindow) {
                HStack(spacing: 5) {
                    Image(systemName: isMainWindowVisible() ? "macwindow.badge.minus" : "macwindow")
                        .font(.system(size: 11))
                    Text(isMainWindowVisible() ? "隐藏主窗口" : "打开主窗口")
                        .font(WatchTypography.small.weight(.medium))
                }
                .padding(.horizontal, 9)
                .padding(.vertical, 5)
                .background(p.elevated, in: RoundedRectangle(cornerRadius: 7))
            }
            .buttonStyle(.plain)

            if switcher.updateSourceReady {
                Button {
                    Task { await store.checkForUpdates() }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: switcher.updateStatus?.isAvailable == true
                              ? "arrow.down.circle.fill" : "arrow.triangle.2.circlepath")
                            .font(.system(size: 10))
                        Text(store.checkingForUpdate ? "检查中…"
                             : switcher.updateStatus?.isAvailable == true ? "有新版本" : "检查更新")
                            .font(WatchTypography.small)
                    }
                    .foregroundStyle(switcher.updateStatus?.isAvailable == true ? p.blue : p.secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(p.elevated.opacity(0.6), in: RoundedRectangle(cornerRadius: 7))
                }
                .buttonStyle(.plain)
                .disabled(store.checkingForUpdate || switcher.busy || switcher.hasUnsavedSettings || switcher.isFixture)
            }

            Spacer(minLength: 4)

            Button(action: onQuit) {
                HStack(spacing: 4) {
                    Image(systemName: "power")
                        .font(.system(size: 10))
                    Text("退出")
                        .font(WatchTypography.small)
                }
                .foregroundStyle(p.secondary)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
            }
            .buttonStyle(.plain)
        }
    }
}
