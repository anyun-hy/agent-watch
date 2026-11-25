import AppKit
import Combine
import SwiftUI

/// Visual badge tone projected strictly from authoritative store state.
enum TrayIconStatus: Equatable {
    case idle
    case safe
    case warning
    case danger

    var dotColor: NSColor? {
        switch self {
        case .idle: return nil
        case .safe: return NSColor(srgbRed: 0.133, green: 0.773, blue: 0.369, alpha: 1.0)
        case .warning: return NSColor(srgbRed: 0.961, green: 0.620, blue: 0.043, alpha: 1.0)
        case .danger: return NSColor(srgbRed: 0.937, green: 0.267, blue: 0.267, alpha: 1.0)
        }
    }
}

/// CoreGraphics renderer for the custom "Hex Agent Core" macOS menu bar icon
/// (18x18 pt Retina vector: hexagonal Seatbelt boundary + four-point AI core,
/// with an optional status indicator dot cut cleanly into the bottom-right).
///
/// Relies on AppKit's native `NSImage(size:flipped:drawingHandler:)` appearance
/// resolution rather than KVO-observing `button.effectiveAppearance`, which
/// triggers an infinite `_updateReplicants` redraw loop on multi-display macOS.
enum StatusBarIconRenderer {
    static func render(status: TrayIconStatus) -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: true) { _ in
            let strokeColor: NSColor = (status == .idle) ? .black : .labelColor
            let hex = NSBezierPath()
            hex.move(to: NSPoint(x: 9.0, y: 1.8))
            hex.line(to: NSPoint(x: 15.2, y: 5.4))
            hex.line(to: NSPoint(x: 15.2, y: 12.6))
            hex.line(to: NSPoint(x: 9.0, y: 16.2))
            hex.line(to: NSPoint(x: 2.8, y: 12.6))
            hex.line(to: NSPoint(x: 2.8, y: 5.4))
            hex.close()
            hex.lineWidth = 1.65
            hex.lineJoinStyle = .round
            hex.lineCapStyle = .round
            strokeColor.setStroke()
            hex.stroke()

            let star = NSBezierPath()
            star.move(to: NSPoint(x: 9.0, y: 5.3))
            star.line(to: NSPoint(x: 10.0, y: 8.0))
            star.line(to: NSPoint(x: 12.7, y: 9.0))
            star.line(to: NSPoint(x: 10.0, y: 10.0))
            star.line(to: NSPoint(x: 9.0, y: 12.7))
            star.line(to: NSPoint(x: 8.0, y: 10.0))
            star.line(to: NSPoint(x: 5.3, y: 9.0))
            star.line(to: NSPoint(x: 8.0, y: 8.0))
            star.close()
            strokeColor.setFill()
            star.fill()

            if let dot = status.dotColor, let ctx = NSGraphicsContext.current?.cgContext {
                // Punch a crisp transparent halo so the status dot never muddies
                // against the hexagon corner on either light or dark menu bars.
                ctx.saveGState()
                ctx.setBlendMode(.clear)
                ctx.fillEllipse(in: CGRect(x: 11.7, y: 11.7, width: 6.2, height: 6.2))
                ctx.restoreGState()

                dot.setFill()
                NSBezierPath(ovalIn: NSRect(x: 12.6, y: 12.6, width: 4.4, height: 4.4)).fill()
            }
            return true
        }
        // Monochrome standby uses native macOS template tinting; colored badges
        // resolve `NSColor.labelColor` per-display inside `drawingHandler`.
        image.isTemplate = (status == .idle)
        image.accessibilityDescription = "Agent Watch"
        return image
    }
}

/// Menu-bar presence for Agent Watch. Left-click opens a live SwiftUI status
/// popover; right-click opens a compact native menu. Closing the main window
/// folds it into the menu bar while background supervision continues.
@MainActor
final class StatusBarController: NSObject, NSWindowDelegate, NSPopoverDelegate {
    private let item: NSStatusItem
    private let popover = NSPopover()
    private var quitting = false
    private weak var store: MonitorStore?
    private weak var initialization: FirstRunInitialization?
    private var subscriptions = Set<AnyCancellable>()
    private var currentIconStatus: TrayIconStatus = .idle
    private var globalClickMonitor: Any?
    private var localEventMonitor: Any?

    override init() {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        super.init()
        popover.behavior = .transient
        popover.animates = true
        popover.delegate = self
        if let button = item.button {
            button.image = StatusBarIconRenderer.render(status: .idle)
            button.toolTip = "Agent Watch · 正在读取后台状态（左键详情卡片，右键菜单）"
            button.target = self
            button.action = #selector(statusItemClicked)
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
        NotificationCenter.default.addObserver(
            self, selector: #selector(handleWindowKey(_:)),
            name: NSWindow.didBecomeKeyNotification, object: nil)
        NotificationCenter.default.addObserver(
            self, selector: #selector(handleAppResignActive(_:)),
            name: NSApplication.didResignActiveNotification, object: nil)
        adoptWindows()
    }

    deinit {
        if let globalClickMonitor { NSEvent.removeMonitor(globalClickMonitor) }
        if let localEventMonitor { NSEvent.removeMonitor(localEventMonitor) }
        NotificationCenter.default.removeObserver(self)
    }

    /// Connects the tray icon and popover to the single authoritative SwiftUI stores.
    func bind(store: MonitorStore, initialization: FirstRunInitialization) {
        self.store = store
        self.initialization = initialization
        subscriptions.removeAll()

        let content = StatusBarPopoverView(
            store: store,
            switcher: store.switcher,
            initialization: initialization,
            isMainWindowVisible: { Self.mainWindowVisible() },
            onOpenPage: { [weak self] page in self?.openPage(page) },
            onOpenProductConnections: { [weak self] product in self?.openProductConnections(product) },
            onToggleWindow: { [weak self] in self?.toggleMainWindowFromPopover() },
            onRefresh: { [weak self] in self?.refreshNow() },
            onQuit: { [weak self] in self?.quitFromMenu() }
        )
        let hosting = NSHostingController(rootView: content)
        hosting.sizingOptions = .preferredContentSize
        popover.contentViewController = hosting

        // Re-evaluate tray badge & tooltip whenever authoritative store facts change.
        store.$snapshot.sink { [weak self] _ in self?.syncTrayStatus() }.store(in: &subscriptions)
        store.$error.sink { [weak self] _ in self?.syncTrayStatus() }.store(in: &subscriptions)
        store.switcher.$background.sink { [weak self] _ in self?.syncTrayStatus() }.store(in: &subscriptions)
        store.switcher.$currentEnvironment.sink { [weak self] _ in self?.syncTrayStatus() }.store(in: &subscriptions)
        store.switcher.$backgroundError.sink { [weak self] _ in self?.syncTrayStatus() }.store(in: &subscriptions)
        store.switcher.$updateStatus.sink { [weak self] _ in self?.syncTrayStatus() }.store(in: &subscriptions)
        store.$channelSubscription.sink { [weak self] _ in self?.syncTrayStatus() }.store(in: &subscriptions)

        syncTrayStatus()
    }

    static func resolveActiveEgress(_ switcher: SwitcherStore) -> EgressReference? {
        let candidates: [EgressReference?] = [
            switcher.currentEnvironment?.egress_reference,
            switcher.audit?.egress_reference,
            switcher.background?.session_guard?.current,
            switcher.background?.egress_reference,
        ]
        for candidate in candidates {
            if let ref = candidate, let ip = ref.ip, !ip.isEmpty {
                return ref
            }
        }
        return nil
    }

    private func computeIconStatus() -> (TrayIconStatus, String) {
        guard let store else {
            return (.idle, "Agent Watch（左键详情卡片，右键菜单）")
        }
        let session = store.switcher.sessionDisplay
        let anyBlockedOrFailed = MonitoredProduct.allCases.contains { product in
            guard let channel = store.channelState(for: product) else { return false }
            let procCount = store.snapshot?.processes.filter { $0.product == product }.count ?? 0
            let hasActiveSession = channel.session_id?.isEmpty == false
            guard procCount > 0 || hasActiveSession else { return false }
            if channel.reason_code == "idle_no_process" { return false }
            return channel.display_state == .blocked || channel.display_state == .failed
        }
        let anyForwarding = MonitoredProduct.allCases.contains { product in
            let procCount = store.snapshot?.processes.filter { $0.product == product }.count ?? 0
            return procCount > 0 && store.channelState(for: product)?.display_state == .forwarding
        }
        let updateAvailable = store.switcher.updateStatus?.isAvailable == true

        let badge: TrayIconStatus
        if session.tone == "danger" || anyBlockedOrFailed {
            badge = .danger
        } else if session.tone == "warning"
            || store.error != nil
            || (!store.live && store.snapshot != nil)
            || store.proxy?.selectionDiffers == true
            || updateAvailable {
            badge = .warning
        } else if session.tone == "success" || (store.live && anyForwarding) {
            badge = .safe
        } else {
            badge = .idle
        }

        var parts = ["Agent Watch · \(session.title)"]
        if let ip = Self.resolveActiveEgress(store.switcher)?.ip {
            parts.append("出口 \(ip)")
        }
        if updateAvailable, let label = store.switcher.updateStatus?.versionLabel, !label.isEmpty {
            parts.append("有新版 \(label)")
        }
        parts.append("左键详情 / 右键菜单")
        return (badge, parts.joined(separator: " · "))
    }

    private func syncTrayStatus() {
        let (status, tooltip) = computeIconStatus()
        item.button?.toolTip = tooltip
        if status != currentIconStatus {
            currentIconStatus = status
            redrawIcon()
        }
    }

    private func redrawIcon() {
        guard let button = item.button else { return }
        button.image = StatusBarIconRenderer.render(status: currentIconStatus)
    }

    // MARK: window adoption

    /// The main SwiftUI window is titled and far larger than the 1x1 offscreen
    /// sampling hosts and transient menu bar popover windows.
    static func isMainWindow(_ window: NSWindow) -> Bool {
        guard !(window is NSPanel) else { return false }
        let typeName = NSStringFromClass(type(of: window))
        if typeName.contains("Popover") || typeName.contains("StatusBar") { return false }
        return window.canBecomeMain && window.frame.width > 100
    }

    static func mainWindowVisible() -> Bool {
        NSApp.windows.contains { Self.isMainWindow($0) && $0.isVisible && !$0.isMiniaturized }
    }

    @objc private func handleWindowKey(_ note: Notification) {
        guard let window = note.object as? NSWindow else { return }
        adopt(window)
    }

    private func adoptWindows() {
        for window in NSApp.windows { adopt(window) }
    }

    private func adopt(_ window: NSWindow) {
        guard Self.isMainWindow(window) else { return }
        window.delegate = self
        if window.isMiniaturized {
            window.deminiaturize(nil)
            window.orderOut(nil)
        }
    }

    // MARK: status item interactions

    @objc private func statusItemClicked() {
        guard let event = NSApp.currentEvent else { return }
        let isSecondary = event.type == .rightMouseUp
            || (event.type == .leftMouseUp && event.modifierFlags.contains(.control))
        if isSecondary {
            closePopover()
            buildMenu().popUp(positioning: nil, at: .zero, in: item.button)
        } else {
            togglePopover()
        }
    }

    private func togglePopover() {
        guard let button = item.button else { return }
        if popover.isShown {
            closePopover()
            return
        }
        guard popover.contentViewController != nil else {
            if Self.mainWindowVisible() { hideMainWindow() } else { showMainWindow() }
            return
        }
        if let switcher = store?.switcher, switcher.background == nil && !switcher.refreshingBackground {
            Task { await switcher.refreshBackground() }
        }
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        popover.contentViewController?.view.window?.makeKey()
        installDismissMonitors()
    }

    private func closePopover() {
        removeDismissMonitors()
        if popover.isShown {
            popover.performClose(nil)
        }
    }

    func popoverDidClose(_ notification: Notification) {
        removeDismissMonitors()
    }

    @objc private func handleAppResignActive(_ note: Notification) {
        closePopover()
    }

    private func installDismissMonitors() {
        removeDismissMonitors()
        globalClickMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.closePopover()
            }
        }
        localEventMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown, .keyDown]
        ) { [weak self] event in
            guard let self, self.popover.isShown else { return event }
            if event.type == .keyDown, event.keyCode == 53 {
                self.closePopover()
                return nil
            }
            if event.type != .keyDown {
                let popoverWindow = self.popover.contentViewController?.view.window
                let statusButtonWindow = self.item.button?.window
                if event.window !== popoverWindow && event.window !== statusButtonWindow {
                    self.closePopover()
                }
            }
            return event
        }
    }

    private func removeDismissMonitors() {
        if let globalClickMonitor {
            NSEvent.removeMonitor(globalClickMonitor)
            self.globalClickMonitor = nil
        }
        if let localEventMonitor {
            NSEvent.removeMonitor(localEventMonitor)
            self.localEventMonitor = nil
        }
    }

    private func openPage(_ page: Page) {
        closePopover()
        if let store, initialization?.entered == true {
            UserDefaults.standard.set(page.rawValue, forKey: "selectedPage")
            store.page = page
        }
        showMainWindow()
    }

    private func openProductConnections(_ product: MonitoredProduct) {
        closePopover()
        if let store, initialization?.entered == true {
            store.showConnections(product)
        }
        showMainWindow()
    }

    private func toggleMainWindowFromPopover() {
        closePopover()
        if Self.mainWindowVisible() { hideMainWindow() } else { showMainWindow() }
    }

    @objc private func refreshNow() {
        store?.refresh(manual: true)
    }

    private func buildMenu() -> NSMenu {
        let menu = NSMenu()
        let titleText = store.map { "Agent Watch · \($0.switcher.sessionDisplay.title)" }
            ?? "Agent Watch 正在后台守护"
        let status = NSMenuItem(title: titleText, action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)

        if let store, let ip = Self.resolveActiveEgress(store.switcher)?.ip {
            let egressItem = NSMenuItem(title: "当前出口：\(ip)", action: nil, keyEquivalent: "")
            egressItem.isEnabled = false
            menu.addItem(egressItem)
        }

        menu.addItem(.separator())

        let refresh = NSMenuItem(title: "立即刷新状态", action: #selector(refreshNow), keyEquivalent: "r")
        refresh.target = self
        menu.addItem(refresh)

        if Self.mainWindowVisible() {
            let hide = NSMenuItem(title: "隐藏主窗口", action: #selector(hideMainWindow), keyEquivalent: "")
            hide.target = self
            menu.addItem(hide)
        } else {
            let show = NSMenuItem(title: "打开主窗口", action: #selector(showMainWindow), keyEquivalent: "")
            show.target = self
            menu.addItem(show)
        }

        menu.addItem(.separator())
        let quit = NSMenuItem(title: "退出 Agent Watch", action: #selector(quitFromMenu), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        return menu
    }

    @objc func showMainWindow() {
        closePopover()
        guard let window = NSApp.windows.first(where: { Self.isMainWindow($0) }) else { return }
        NSApp.activate(ignoringOtherApps: true)
        if window.isMiniaturized { window.deminiaturize(nil) }
        window.makeKeyAndOrderFront(nil)
    }

    @objc func hideMainWindow() {
        closePopover()
        for window in NSApp.windows where Self.isMainWindow(window) && !window.isMiniaturized {
            window.orderOut(nil)
        }
    }

    @objc private func quitFromMenu() {
        closePopover()
        prepareToQuit()
        NSApp.terminate(nil)
    }

    func prepareToQuit() {
        quitting = true
    }

    // MARK: NSWindowDelegate — close collapses to the menu bar

    func windowShouldClose(_ window: NSWindow) -> Bool {
        guard Self.isMainWindow(window), !quitting else { return true }
        window.orderOut(nil)
        return false
    }
}
