import AppKit
import SwiftUI
import UserNotifications

struct MonitorView: View {
    @ObservedObject var store: MonitorStore
    let startMonitoring: Bool
    let restoresNavigation: Bool
    let refreshAction: (() -> Void)?
    @AppStorage("darkAppearance") private var dark = false
    @AppStorage("selectedPage") private var savedPage = Page.environment.rawValue
    @FocusState private var focusedPage: Page?
    @State private var sidebarVisibility: NavigationSplitViewVisibility = .all
    @State private var showProxyDetails = false

    init(store: MonitorStore, startMonitoring: Bool = true, restoresNavigation: Bool = true, refreshAction: (() -> Void)? = nil) {
        self.store = store
        self.startMonitoring = startMonitoring
        self.restoresNavigation = restoresNavigation
        self.refreshAction = refreshAction
    }

    private var p: Palette { Palette(dark: dark) }
    private var statusTint: Color { store.error != nil ? p.amber : !store.automatic ? p.secondary : store.live ? p.mint : p.amber }
    private var statusTitle: String {
        if store.error != nil { return "本次同步未完成" }
        return !store.automatic && store.snapshot != nil ? "界面同步已暂停" : store.heroTitle
    }
    private var statusDetail: String {
        if store.error != nil { return "当前状态未能确认，可手动刷新重试。已有记录保留为上次采样。" }
        if !store.automatic { return "后台监控独立运行。手动刷新可更新当前显示。" }
        guard let snapshot = store.snapshot else { return "正在读取后台状态与网络快照。" }
        if !store.live { return snapshot.health.detail }
        return snapshot.health.mode == "ACTIVE"
            ? "正在观察当前会话及关联进程的活动。"
            : "正在观察 AI 应用进程、后台活动与代理入口。"
    }

    var body: some View {
        NavigationSplitView(columnVisibility: $sidebarVisibility) {
            sidebar.navigationSplitViewColumnWidth(min: 172, ideal: 188, max: 228)
        } detail: {
            VStack(spacing: 0) {
                if !store.page.isManualCheck { pageHeader }
                if let mismatch = store.runtimeVersionMismatch {
                    HStack(alignment: .center, spacing: 12) {
                        Image(systemName: "arrow.triangle.2.circlepath.circle.fill")
                            .font(.system(size: 16, weight: .medium))
                            .foregroundStyle(p.blue)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("检测到新版本应用，需同步升级后台运行组件")
                                .font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                            Text(store.runtimeSyncError ?? "\(mismatch.summary) 仅需一次管理员授权即可完成同步，原有账号与策略全部保留。")
                                .font(WatchTypography.caption)
                                .foregroundStyle(store.runtimeSyncError == nil ? p.secondary : p.amber)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 8)
                        Button {
                            Task { await store.syncRuntimeFromBundle() }
                        } label: {
                            HStack(spacing: 6) {
                                if store.syncingRuntime {
                                    ProgressView().controlSize(.small)
                                }
                                Text(store.syncingRuntime ? "正在同步…" : "同步升级后台与网关")
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(store.syncingRuntime)
                    }
                    .padding(12)
                    .background(p.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
                    .overlay(RoundedRectangle(cornerRadius: 9).stroke(p.blue.opacity(0.25), lineWidth: 1))
                    .padding(.horizontal, 20).padding(.bottom, 12)
                }
                if let error = store.error {
                    InlineNotice(title: "暂时无法同步检测数据", detail: error,
                                 symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                        .padding(.horizontal, 20).padding(.bottom, 12)
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        switch store.page {
                        case .overview: overview
                        case .network: network
                        case .processes: ProcessActivityPage(store: store, p: p)
                        case .events: EventTimelinePage(store: store, p: p)
                        case .dns: DNSLeakPage(store: store.leakChecks, p: p)
                        case .webrtc: WebRTCLeakPage(store: store.leakChecks, p: p)
                        case .claudeAI: AIInspectorPage(service: .claude, store: store, probes: store.aiChecks, p: p)
                        case .ipScore: NetCoffeeScorePage(store: store.netCoffee, p: p)
                        case .gptAI: AIInspectorPage(service: .gpt, store: store, probes: store.aiChecks, p: p)
                        case .environment: taskPage(.environment)
                        case .switcher: taskPage(.accounts)
                        case .protection: taskPage(.protection)
                        }
                        if store.page.isLeakCheck || store.page == .ipScore {
                            PageLink(title: "返回环境状态", p: p) { store.page = .environment }
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: 1280).frame(maxWidth: .infinity)
                        .padding(.horizontal, 20).padding(.bottom, 20)
                }
                footer
            }.background(p.background)
        }
        .navigationSplitViewStyle(.balanced)
        .navigationTitle("Agent Watch")
        .toolbar {
            MonitorRefreshToolbar(automatic: $store.automatic, refreshing: store.refreshing, p: p) {
                if let refreshAction { refreshAction() }
                else { store.refresh(manual: true) }
            }
        }
        .foregroundStyle(p.text)
        .font(WatchTypography.body)
        .fontDesign(.monospaced)
        .preferredColorScheme(dark ? .dark : .light)
        .onChange(of: dark) { _, value in
            // Keep window chrome, sheets and alerts in step with the palette;
            // preferredColorScheme alone leaves them on the system appearance.
            NSApp.appearance = NSAppearance(named: value ? .darkAqua : .aqua)
        }
        .frame(minWidth: 1000, minHeight: 680)
        .onAppear {
            if restoresNavigation { store.page = Page.restored(savedPage) }
            if startMonitoring { store.start() }
            Task { await store.refreshNotificationAccess() }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            store.refreshRuntimeVersionSync()
            Task { await store.refreshNotificationAccess() }
        }
        .onReceive(NotificationCenter.default.publisher(for: .watchNotificationPermissionChanged)) { _ in
            Task { await store.refreshNotificationAccess() }
        }
        .onChange(of: store.page) { _, page in if restoresNavigation { savedPage = page.rawValue } }
    }

    private func taskPage(_ section: SwitcherSection) -> some View {
        SwitcherPage(store: store.switcher, p: p, desktopPresence: store.desktopPresence,
                     section: section, navigate: { target in
            store.page = target == .environment ? .environment : target == .accounts ? .switcher : .protection
        }, openLeakCheck: { kind in store.page = kind == .dns ? .dns : .webrtc },
        openNetwork: store.showConnections, openIPScore: { ip in
            store.netCoffee.selectedForPage(ip)
            store.netCoffee.query = ip
            store.page = .ipScore
        }, channelState: store.channelState(for:), leakChecks: store.leakChecks,
        netCoffee: store.netCoffee, finished: { store.page = .environment })
    }

    private func navRow(_ page: Page) -> some View {
        let selected = store.page == page
        return Button { store.page = page } label: {
            HStack(spacing: 8) {
                Group {
                    if page == .claudeAI || page == .gptAI {
                        BrandLogo(brand: page == .claudeAI ? .claude : .chatgpt, size: 14)
                    } else {
                        Image(systemName: page.symbol)
                            .font(.system(size: 14, weight: .medium)).foregroundStyle(p.blue)
                    }
                }.frame(width: 18, height: 18).accessibilityHidden(true)
                Text(page.rawValue).font(selected ? WatchTypography.bodyStrong : WatchTypography.body)
                    .lineLimit(1).minimumScaleFactor(0.85)
            }
            .foregroundStyle(p.text)
            .padding(.horizontal, 6).frame(maxWidth: .infinity, minHeight: 31, alignment: .leading)
            .background(selected ? p.color(0x3D5164, 0xE8EFF5) : .clear, in: RoundedRectangle(cornerRadius: 7))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).focused($focusedPage, equals: page)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .listRowInsets(EdgeInsets(top: 0, leading: 0, bottom: 0, trailing: 0))
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    HexAgentCoreMark(size: 19, color: p.mint, lineWidth: 1.7)
                    Text("Agent Watch").font(WatchTypography.section).lineLimit(1)
                    Spacer(minLength: 0)
                }
                Text("Claude · ChatGPT / Codex").font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(1).minimumScaleFactor(0.82)
            }.padding(.horizontal, 15).padding(.top, 16).padding(.bottom, 15)
            List {
                Section {
                    ForEach(Page.primaryPages, id: \.self) { page in navRow(page) }
                } header: {
                    Text("日常使用").foregroundStyle(p.secondary)
                }
                Section {
                    ForEach(Page.monitorPages, id: \.self) { page in navRow(page) }
                } header: {
                    Text("监控与记录").foregroundStyle(p.secondary)
                }
                Section {
                    ForEach(Page.diagnosticPages, id: \.self) { page in navRow(page) }
                } header: {
                    Text("网络检测").foregroundStyle(p.secondary)
                }
            }.listStyle(.sidebar).scrollContentBackground(.hidden)
            .onMoveCommand { direction in
                let pages = Page.orderedPages
                guard direction == .up || direction == .down,
                      let index = pages.firstIndex(of: focusedPage ?? store.page) else { return }
                let next = index + (direction == .down ? 1 : -1)
                guard pages.indices.contains(next) else { return }
                focusedPage = pages[next]
                store.page = pages[next]
            }
            VStack(alignment: .leading, spacing: 12) {
                Divider()
                HStack(spacing: 7) {
                    Circle().fill(store.live ? p.mint : p.amber).frame(width: 6, height: 6)
                    Text(store.live ? (store.automatic ? "采集后台心跳正常" : "上次后台心跳正常") : store.snapshot == nil ? "等待后台心跳" : "后台心跳待核对")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
                HStack {
                    Text(dark ? "深色外观" : "浅色外观").font(WatchTypography.caption).foregroundStyle(p.secondary)
                    Spacer()
                    Button { dark.toggle() } label: {
                        Image(systemName: dark ? "sun.max" : "moon").font(.system(size: 14)).frame(width: 25, height: 24)
                    }.buttonStyle(.borderless).help("切换浅色与深色外观")
                        .accessibilityLabel("切换外观")
                }
            }.padding(.horizontal, 15).padding(.bottom, 15)
        }
        .background(p.sidebar)
    }

    private var pageHeader: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text(store.page.rawValue).font(WatchTypography.pageTitle)
                Text(pageCaption).font(WatchTypography.body).foregroundStyle(p.secondary)
            }
            Spacer(minLength: 12)
        }.padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 18)
    }
    private var pageCaption: String {
        switch store.page {
        case .overview: return "后台状态、当前检测结果与需要关注的事项"
        case .network: return "查看已观测的连接路径，区分实际证据与配置参考"
        case .processes: return "最近采样到的 AI 应用及关联进程"
        case .events: return "检索最近的监控事件与原始记录"
        case .dns: return "采集递归出口，按预期解析器核对；无结果保持未完成"
        case .webrtc: return "比较当前检测 WebView 的 ICE/STUN 候选与 HTTP 出口"
        case .claudeAI: return "核对 Claude 域名的代理诊断、入口响应与现有连接"
        case .ipScore: return "读取 Net.Coffee 评分与原始 IP 资料"
        case .gptAI: return "核对 ChatGPT 与 API 入口响应，并查看现有连接证据"
        case .switcher: return Page.switcher.caption
        case .environment: return Page.environment.caption
        case .protection: return Page.protection.caption
        }
    }
    private var footer: some View {
        HStack(spacing: 7) {
            if store.error != nil {
                Label("本次同步未完成", systemImage: "exclamationmark.triangle").foregroundStyle(p.amber)
            } else if !store.automatic {
                Label("自动检测与刷新已暂停", systemImage: "pause.circle")
            }
            Spacer()
            pageSampleTime.monospacedDigit()
        }.font(WatchTypography.small).foregroundStyle(p.secondary)
            .padding(.horizontal, 20).frame(height: 31)
            .background(p.surface.opacity(0.5))
            .overlay(alignment: .top) { Rectangle().fill(p.border.opacity(0.55)).frame(height: 1) }
    }
    @ViewBuilder private var pageSampleTime: some View {
        switch store.page {
        case .environment:
            SampleTimestamp(source: store.switcher, label: "环境采样") { $0.currentEnvironment?.observed_at }
        case .switcher:
            SampleTimestamp(source: store.switcher, label: "启动条件采样") { $0.currentPolicyEvaluation?.observed_at }
        case .protection:
            SampleTimestamp(source: store.switcher, label: "后台状态读取") { $0.background?.observed_at }
        case .claudeAI, .gptAI:
            let service: AIService = store.page == .claudeAI ? .claude : .gpt
            SampleTimestamp(source: store.aiChecks, label: "服务检测") { $0.state(service).result?.finishedAt }
        case .dns, .webrtc:
            let dns = store.page == .dns
            SampleTimestamp(source: store.leakChecks, label: "最近检测") { (dns ? $0.dns : $0.rtc).result?.finishedAt }
        case .ipScore:
            SampleTimestamp(source: store.netCoffee, label: "IP 资料查询") { $0.report($0.selectedIP)?.queriedAt }
        case .network:
            let display = store.graphDisplay(for: store.networkSelection.product)
            Text(display.sample.map { (display.isHistorical ? "历史连接采样于 " : "连接采样于 ") + timeText($0.observedAt) } ?? "等待连接采样")
        case .processes, .events, .overview:
            Text(store.snapshot.map { "后台快照 " + timeText($0.capturedAt) } ?? "等待后台快照")
        }
    }

    private var overview: some View {
        let baseline = SessionBaselinePresentation.make(evidence: store.switcher.sessionDisplayEvidence,
                                                        now: store.now.timeIntervalSince1970)
        let baselineNeedsAttention = ["danger", "warning"].contains(baseline.tone)
        return Group {
            Surface(p, padding: 18) {
                HStack(spacing: 15) {
                    Image(systemName: "server.rack")
                        .font(.system(size: 26, weight: .regular)).foregroundStyle(statusTint)
                        .frame(width: 48, height: 48).background(statusTint.opacity(0.08), in: RoundedRectangle(cornerRadius: 13))
                    VStack(alignment: .leading, spacing: 6) {
                        Text("采集后台 · " + statusTitle).font(WatchTypography.title)
                        Text(statusDetail).font(WatchTypography.body).foregroundStyle(p.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 16)
                    VStack(alignment: .trailing, spacing: 7) {
                        Badge(text: store.error != nil ? "读取失败" : !store.automatic ? "界面刷新暂停" : store.live ? "心跳正常" : "待核对", color: statusTint)
                        PageLink(title: "查看后台保护", p: p) { store.page = .protection }
                    }
                }
                VStack(alignment: .leading, spacing: 7) {
                    if store.error == nil && store.automatic {
                        if store.proxy == nil {
                            InlineNotice(title: "代理快照尚未就绪", detail: store.proxyError ?? "等待后台提供有效采样。",
                                         symbol: "clock", tint: p.amber, p: p)
                        } else if store.proxy?.selectionDiffers == true {
                            InlineNotice(title: "当前选择与参照节点不同", detail: "请在代理与连接页核对实际路径。",
                                         symbol: "arrow.triangle.branch", tint: p.amber, p: p)
                        } else if store.proxy?.coversProxy != true {
                            InlineNotice(title: "入口与控制器尚未关联", detail: "当前控制器数据不能证明该入口的流量路径。",
                                         symbol: "link", tint: p.amber, p: p)
                        }
                    }
                    if baselineNeedsAttention { baselineNotice(baseline) }
                    if store.snapshot?.monitoredApps?.isEmpty == false && !multiProductCoverageDeclared {
                        InlineNotice(title: "Codex 与 ChatGPT 需要更新后台", detail: "当前后台没有声明 Codex 与 ChatGPT 的采集能力；界面不会把未采样到的 0 个进程显示为已覆盖。",
                                     symbol: "arrow.down.app", tint: p.amber, p: p)
                    }
                    if let notice = store.notificationAccess.notice {
                        HStack(alignment: .top, spacing: 8) {
                            Text(notice).font(WatchTypography.caption).foregroundStyle(p.amber)
                            Button("打开通知设置") {
                                if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") { NSWorkspace.shared.open(url) }
                            }.buttonStyle(.borderless).font(WatchTypography.caption)
                        }
                    }
                }
            }
            Surface(p, padding: 12) {
                HStack(spacing: 12) {
                    metric("AI 应用进程", value: store.snapshot.map { String($0.processes.count) } ?? "—",
                           detail: store.snapshot == nil ? "等待首次采样" : "最近采样的进程数量", symbol: Page.processes.symbol, tint: p.blue, destination: .processes)
                    Divider()
                    metric("本机代理入口", value: store.entryTitle,
                           detail: store.proxy?.endpoint.replacingOccurrences(of: "http://", with: "") ?? "等待代理快照",
                           symbol: "cable.connector", tint: store.proxy?.entryState == "verified" ? p.mint : p.amber, destination: .network)
                    Divider()
                    metric("实际代理链", value: store.chainTitle,
                           detail: store.proxy?.flows.isEmpty == false ? "以选中连接的证据为准" : "使用受监控应用后产生连接样本",
                           symbol: Page.network.symbol, tint: store.chainTitle == "样本匹配" ? p.mint : p.blue, destination: .network)
                }.fixedSize(horizontal: false, vertical: true)
            }
            Surface(p) {
                HStack {
                    SectionHeading(title: "最近事件", p: p)
                    Spacer()
                    Button("查看全部") { store.page = .events }.buttonStyle(.borderless)
                        .font(WatchTypography.caption).foregroundStyle(p.blue)
                }.padding(.bottom, 8)
                if let error = store.snapshot?.eventError {
                    Text(error).font(WatchTypography.caption).foregroundStyle(p.amber).padding(.vertical, 8)
                }
                if let events = store.snapshot?.events, !events.isEmpty {
                    ForEach(Array(events.prefix(4))) { EventTimelineRow(event: $0, p: p, compact: true) }
                } else {
                    Text(store.snapshot == nil ? "正在读取事件记录…" : "暂无可显示的事件记录。")
                        .font(WatchTypography.body).foregroundStyle(p.secondary).padding(.vertical, 16)
                }
            }
            Surface(p) {
                SectionHeading(title: "应用与会话", p: p)
                ForEach(MonitoredProduct.allCases) { product in
                    let count = store.snapshot?.processes.filter { $0.product == product }.count
                    Button { store.showConnections(product) } label: {
                        HStack(spacing: 9) {
                            BrandLogo(brand: product == .claude ? .claude : .chatgpt, size: 17)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(product.title).font(WatchTypography.bodyStrong)
                                Text(store.channelState(for: product)?.protectionScopeLabel ?? "通道回执待读取")
                                    .font(WatchTypography.small).foregroundStyle(p.secondary)
                            }
                            Spacer(minLength: 4)
                            Text(count.map { "采样 \($0) 个进程" } ?? "等待采样")
                                .font(WatchTypography.small).foregroundStyle(p.secondary)
                            Image(systemName: "chevron.right").imageScale(.small).foregroundStyle(p.blue)
                        }.padding(.vertical, 9).contentShape(Rectangle())
                    }.buttonStyle(.plain)
                    Divider()
                }
                if !baselineNeedsAttention { baselineNotice(baseline) }
                Button { store.page = .network } label: { Label("查看连接证据", systemImage: "arrow.right") }
                    .buttonStyle(.borderless).font(WatchTypography.caption).foregroundStyle(p.blue).padding(.top, 13)
            }
            Surface(p) {
                DisclosureGroup("服务详情") {
                    VStack(alignment: .leading, spacing: 6) {
                        DetailRow(title: "服务 PID", value: store.snapshot?.health.pid.map(String.init) ?? "待确认", p: p, monospaced: true)
                        DetailRow(title: "最近心跳", value: heartbeatValue, p: p, monospaced: true)
                        DetailRow(title: "登录自启", value: store.snapshot.map { $0.autoStart ? "已配置" : "未配置" } ?? "读取中", p: p)
                        DetailRow(title: "异常退出恢复", value: store.snapshot.map { $0.keepAlive ? "已配置" : "未配置" } ?? "读取中", p: p)
                        DetailRow(title: "系统提醒", value: WatchNotificationAccess.summary(mode: store.snapshot?.health.alerts, access: store.notificationAccess), p: p,
                                  tint: store.notificationAccess.notice == nil ? nil : p.amber)
                    }.padding(.top, 8)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
        }
    }

    private func baselineNotice(_ value: SessionBaselinePresentation) -> some View {
        InlineNotice(title: value.title, detail: value.detail, symbol: value.symbol,
                     tint: value.tone == "danger" ? p.red : value.tone == "warning" ? p.amber : value.tone == "success" ? p.mint : p.blue, p: p)
    }

    private var heartbeatValue: String {
        guard let snapshot = store.snapshot, let age = snapshot.health.heartbeatAge else { return "待确认" }
        return "\(Int(max(0, age + store.now.timeIntervalSince1970 - snapshot.capturedAt))) 秒前"
    }
    private var multiProductCoverageDeclared: Bool {
        let apps = Set(store.snapshot?.monitoredApps ?? [])
        return apps.contains("codex") && apps.contains("chatgpt")
    }
    private func metric(_ title: String, value: String, detail: String, symbol: String, tint: Color, destination: Page) -> some View {
        Button { store.page = destination } label: {
            VStack(alignment: .leading, spacing: 5) {
                Label(title, systemImage: symbol).font(WatchTypography.captionStrong).foregroundStyle(tint)
                Text(value).font(WatchTypography.title)
                Text(detail).font(WatchTypography.small).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }.frame(maxWidth: .infinity, alignment: .topLeading).contentShape(Rectangle())
        }.buttonStyle(.plain).help("查看" + destination.rawValue)
    }

    private var network: some View {
        Group {
            ConnectionGraphView(store: store, p: p)
            ConnectionInventoryView(store: store, p: p)
            Surface(p) {
                DisclosureGroup(isExpanded: $showProxyDetails) {
                    VStack(alignment: .leading, spacing: 0) {
                        if let proxy = store.proxy {
                            DetailRow(title: "本机入口", value: proxy.endpoint, p: p, monospaced: true)
                            DetailRow(title: "监听进程", value: proxy.listenerPID.map { "PID \($0)" } ?? "待确认", p: p, monospaced: true)
                            DetailRow(title: "程序路径", value: proxy.listenerPath, p: p, monospaced: true)
                            DetailRow(title: "核对结果", value: proxy.entryReason, p: p)
                            Divider().padding(.vertical, 8)
                            DetailRow(title: "采样控制器模式", value: modeName(proxy.mode), p: p)
                            DetailRow(title: "海外AI 分组配置", value: proxy.selectedNode, p: p)
                            DetailRow(title: "GLOBAL 配置", value: proxy.globalNode, p: p)
                            DetailRow(title: "参照节点", value: proxy.expectedNode, p: p)
                            DetailRow(title: "参照方式", value: proxy.pinned ? "已保存到环境基线" : "随 TAG 分组选择，尚未固定", p: p)
                            DetailRow(title: "入口覆盖", value: proxy.coversProxy ? "控制器已关联此入口" : "尚未确认", p: p)
                            DetailRow(title: "网络采样", value: timeText(proxy.observedAt, date: true), p: p, monospaced: true)
                        } else {
                            Text(store.proxyError ?? "等待有效的后台代理快照。").font(WatchTypography.body)
                                .foregroundStyle(p.secondary).padding(.vertical, 12)
                        }
                    }.padding(.top, 12)
                } label: {
                    SectionHeading(title: "代理详情", caption: "查看监听者、控制器和配置参考", p: p)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
            Label("入口验证和节点配置不能单独证明 DNS 出口；未采集的信息保持待确认。", systemImage: "info.circle")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true).padding(.horizontal, 3)
        }
    }

}

func modeName(_ mode: String) -> String {
    switch mode {
    case "global": return "全局模式"
    case "rule": return "规则模式"
    case "direct": return "直连模式"
    default: return "待确认"
    }
}

private struct SampleTimestamp<Source: ObservableObject>: View {
    @ObservedObject var source: Source
    let label: String
    let timestamp: (Source) -> Double?

    var body: some View {
        Text(timestamp(source).flatMap { $0.isFinite && $0 > 0 ? label + " " + timeText($0) : nil } ?? "等待" + label)
    }
}

func timeText(_ epoch: Double, date: Bool = false) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "zh_CN")
    formatter.dateFormat = date ? "MM-dd HH:mm:ss" : "HH:mm:ss"
    return formatter.string(from: Date(timeIntervalSince1970: epoch))
}

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate, ObservableObject {
    @Published var notificationTarget: String?
    private var statusBarController: StatusBarController?
    private weak var boundStore: MonitorStore?
    private weak var boundInitialization: FirstRunInitialization?
    static func notificationPage(_ target: String?) -> Page? {
        let pages: [String: Page] = ["events": .events, "environment": .environment, "protection": .protection]
        guard let target else { return nil }
        return pages[target]
    }
    @MainActor func attachStatusBar(store: MonitorStore, initialization: FirstRunInitialization) {
        boundStore = store
        boundInitialization = initialization
        statusBarController?.bind(store: store, initialization: initialization)
    }
    func applicationWillFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
    }
    /// A fresh install starts light; a stored choice still wins. Setting the
    /// application appearance keeps the window chrome in step with the palette.
    private func applyAppearance() {
        let dark = UserDefaults.standard.object(forKey: "darkAppearance") as? Bool ?? false
        NSApp.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
           let icon = NSImage(contentsOf: url) {
            NSApp.applicationIconImage = icon
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        applyAppearance()
        let controller = StatusBarController()
        if let boundStore, let boundInitialization {
            controller.bind(store: boundStore, initialization: boundInitialization)
        }
        statusBarController = controller
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            if settings.authorizationStatus == .notDetermined {
                center.requestAuthorization(options: [.alert, .sound]) { _, _ in
                    DispatchQueue.main.async {
                        NotificationCenter.default.post(name: .watchNotificationPermissionChanged, object: nil)
                    }
                }
            }
        }
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        guard response.actionIdentifier == UNNotificationDefaultActionIdentifier,
              let target = response.notification.request.content.userInfo["destination"] as? String,
              Self.notificationPage(target) != nil else {
            completionHandler(); return
        }
        DispatchQueue.main.async {
            self.notificationTarget = target
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first(where: { $0.canBecomeKey })?.makeKeyAndOrderFront(nil)
            completionHandler()
        }
    }
    // The monitor lives in the menu bar: closing or miniaturizing the window
    // collapses it into the status item instead of terminating the app.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !StatusBarController.mainWindowVisible() {
            statusBarController?.showMainWindow()
        }
        return true
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        statusBarController?.prepareToQuit()
        return .terminateNow
    }
}

#if !UI_REVIEW
struct ClaudeWatchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var store: MonitorStore
    @StateObject private var initialization: FirstRunInitialization
    @MainActor init() {
        let store = MonitorStore()
        let storage = InitializationStorage()
        _store = StateObject(wrappedValue: store)
        _initialization = StateObject(wrappedValue: FirstRunInitialization(checks: FirstRunChecks(store: store),
            completed: storage.isComplete(), diagnosticLog: BoundedDiagnosticLog(component: "initialization_flow"),
            saveCompletion: { try storage.complete() }))
    }
    var body: some Scene {
        WindowGroup("Agent Watch") {
            MonitorEntryView(store: store, initialization: initialization)
                .onAppear {
                    delegate.attachStatusBar(store: store, initialization: initialization)
                }
                .onReceive(delegate.$notificationTarget) { target in
                    guard let page = AppDelegate.notificationPage(target) else { return }
                    UserDefaults.standard.set(page.rawValue, forKey: "selectedPage")
                    store.page = page
                }
        }
            .defaultSize(width: 1240, height: 820)
            .windowStyle(.titleBar)
            .windowToolbarStyle(.unifiedCompact)
            .commands {
                CommandGroup(replacing: .newItem) {}
                CommandMenu("页面") {
                    ForEach(Array(Page.orderedPages.enumerated()), id: \.element) { index, page in
                        if index < 10 {
                            Button(page.rawValue) { store.page = page }
                                .keyboardShortcut(KeyEquivalent(Character(index == 9 ? "0" : String(index + 1))), modifiers: .command)
                        } else { Button(page.rawValue) { store.page = page } }
                    }.disabled(!initialization.entered)
                }
            }
    }
}

@main
enum ClaudeWatchMain {
    @MainActor static func main() {
        if CommandLine.arguments.dropFirst().first == "--notification-deliver" {
            WatchNotificationWorker.run(arguments: CommandLine.arguments)
        }
        ClaudeWatchApp.main()
    }
}
#endif
