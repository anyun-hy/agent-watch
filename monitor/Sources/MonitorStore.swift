import Foundation
import Combine
import UserNotifications
import AppKit

@MainActor
final class MonitorStore: ObservableObject {
    private let connectionEvidenceUpdated = PassthroughSubject<Void, Never>()
    let historyUpdated = PassthroughSubject<Void, Never>()
    let leakChecks: LeakCheckStore
    let aiChecks: AIProbeStore
    let netCoffee = NetCoffeeStore()
    let processControl = AIProcessControl()
    let managedEntryControl: ManagedEntryControl
    let managedVpn: ManagedVpnStore
    let switcher: SwitcherStore
    /// First-run owns diagnostic/mutation sequencing; publication events request readback.
    @Published private(set) var initializing = false
    @Published var snapshot: MonitorSnapshot?
    @Published var error: String?
    @Published var refreshing = false
    @Published var automatic = true {
        didSet {
            if automatic && !oldValue && started {
                refreshBackgroundIfNeeded(at: Date(), force: true)
                refresh()
                historyUpdated.send()
            }
        }
    }
    @Published private(set) var notificationAccess = WatchNotificationAccess.unknown
    /// Native desktop presence is a display fact, not protection evidence.
    @Published private(set) var desktopPresence: WorkspaceDesktopPresence?
    @Published var page: Page = .environment
    @Published var now = Date()
    @Published var networkSelection = NetworkGraphSelection()
    @Published private(set) var graphContinuity = GraphContinuityStore()
    @Published private(set) var serverReferences: [String: ServerReference] = [:]
    @Published private(set) var channelSubscription = ChannelMonitorSubscriptionStore()
    @Published private(set) var runtimeVersionMismatch: RuntimeVersionMismatch?
    @Published private(set) var syncingRuntime = false
    @Published private(set) var runtimeSyncError: String?
    @Published private(set) var checkingForUpdate = false
    @Published private(set) var updateCheckNote: String?
    @Published private(set) var updateCheckFailed = false
    private var referenceQueryRunning = false
    private var referenceQueriesEnabled = false
    private var started = false
    private var publications: MonitorPublicationObserver?
    private var expiryTask: DispatchWorkItem?
    private var rereadExpiredSnapshot: Double?
    private var lastAcceptedFreshSnapshotAt: Double?
    private var wakeToken: NSObjectProtocol?
    private var workspaceObserver: WorkspaceAppObserver?
    private var lastBackgroundRead: Date = .distantPast
    private var backgroundReadRunning = false
    private var pendingBackgroundRead = false
    private var backgroundRetry: DispatchWorkItem?
    private var switcherReady: AnyCancellable?
    private var environmentRefreshScheduler = EnvironmentRefreshScheduler()
    private var diagnosticContext = DiagnosticContextTracker()
    private var refreshGate = MonitorRefreshGate()
    private var notificationRequestGeneration = 0
    init(leakChecks: LeakCheckStore? = nil, aiChecks: AIProbeStore? = nil, switcher: SwitcherStore? = nil) {
        self.leakChecks = leakChecks ?? LeakCheckStore()
        self.aiChecks = aiChecks ?? AIProbeStore()
        self.switcher = switcher ?? SwitcherStore()
        self.managedEntryControl = ManagedEntryControl(isFixture: self.switcher.isFixture)
        self.managedVpn = ManagedVpnStore(isFixture: self.switcher.isFixture)
        switcherReady = self.switcher.$busy.combineLatest(self.switcher.$readingEnvironment)
            .filter { busy, _ in !busy }.receive(on: DispatchQueue.main)
            .sink { [weak self] _, readingEnvironment in
                guard let self else { return }
                self.drainPendingBackgroundRead()
                if !readingEnvironment && self.started && self.automatic && !self.initializing {
                    self.refreshEnvironmentIfNeeded()
                }
            }
        let bindingContext: () -> String? = { [weak self] in self?.retainedDiagnosticContext() }
        let currentContext: () -> String? = { [weak self] in self?.currentDiagnosticContext() }
        self.leakChecks.contextProvider = bindingContext
        self.leakChecks.automaticContextProvider = currentContext
        self.switcher.diagnosticContextProvider = bindingContext
        self.leakChecks.onEvidenceReceived = { [weak self] kind, reply, item in
            self?.switcher.acceptEvidence(kind, reply: reply, item: item)
            self?.scheduleEvidenceExpiry()
        }
        self.leakChecks.onEvidenceFailed = { [weak self] kind, detail in
            self?.switcher.acceptEvidenceFailure(kind, detail: detail)
        }
        self.switcher.onDNSReceiptRecorded = { [weak self] in
            self?.requestEnvironmentRefreshAfterDNS()
        }
        self.switcher.onWebRTCRiskRecorded = { [weak self] in
            guard let self, !self.initializing else { return }
            self.refreshBackgroundIfNeeded(at: Date())
        }
        self.switcher.onBackgroundUpdated = { [weak self] in
            self?.connectionEvidenceUpdated.send()
            self?.scheduleEvidenceExpiry()
        }
        self.switcher.onConfigUpdated = { [weak self] in
            guard let self else { return }
            self.channelSubscription.markReconnected()
            self.refresh(manual: true)
        }
        self.aiChecks.contextProvider = bindingContext
        self.aiChecks.onResult = { [weak self] result in
            self?.scheduleEvidenceExpiry()
            let ip = result.exitIP
            guard !ip.isEmpty else { return }
            self?.netCoffee.fetchAI(ip)
        }
        self.switcher.onCurrentEnvironment = { [weak self] result in
            self?.leakChecks.acceptEnvironment(result)
            self?.refreshEnvironmentQuality(result)
        }
        // Fixture snapshots have an explicit producer. Live daemon events
        // must not replace them with reads from a different runtime.
        guard !self.switcher.isFixture else { return }
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let name = "io.local.watchpanel.channel_update" as CFString
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let store = Unmanaged<MonitorStore>.fromOpaque(observer).takeUnretainedValue()
                DispatchQueue.main.async {
                    store.handleChannelUpdate()
                }
            },
            name,
            nil,
            .deliverImmediately
        )
    }
    deinit {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterRemoveEveryObserver(center, observer)
        expiryTask?.cancel()
        backgroundRetry?.cancel()
        if let wakeToken { NSWorkspace.shared.notificationCenter.removeObserver(wakeToken) }
    }
    func start() {
        guard !started else { return }
        started = true
        if !switcher.isFixture {
            observePublications()
            wakeToken = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification,
                object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in
                    guard let self else { return }
                    self.advanceClock(at: Date())
                    if self.automatic || self.initializing {
                        self.refreshBackgroundIfNeeded(at: Date(), force: true)
                        self.refresh()
                        self.historyUpdated.send()
                    }
                }
            }
        }
        refreshRuntimeVersionSync()
        refreshBackgroundIfNeeded(at: Date())
        referenceQueriesEnabled = !initializing
        refresh()
        if workspaceObserver == nil && !switcher.isFixture {
            let observer = WorkspaceAppObserver { [weak self] presence in
                guard let self else { return }
                for product in MonitoredProduct.allCases where self.desktopPresence?.processIDs(for: product) != presence.processIDs(for: product) {
                    self.switcher.forgetManualAccount(product)
                }
                self.desktopPresence = presence
                self.refresh(manual: true)
            }
            workspaceObserver = observer
            desktopPresence = observer.start()
        }
        scheduleEvidenceExpiry()
    }
    private func observePublications() {
        guard publications == nil && !switcher.isFixture else { return }
        let root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/ClaudeWatch")
        let observer = MonitorPublicationObserver(root: root) { [weak self] changes in self?.publicationsDidChange(changes) }
        if observer.start() { publications = observer }
    }
    func refreshNotificationAccess() async {
        guard !switcher.isFixture else { return }
        await readNotificationAccess {
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            return .classify(settings.authorizationStatus, alert: settings.alertSetting, style: settings.alertStyle)
        }
    }
    func refreshRuntimeVersionSync() {
        guard !switcher.isFixture else {
            runtimeVersionMismatch = nil
            return
        }
        runtimeVersionMismatch = RuntimeVersionSync.currentMismatch()
        if runtimeVersionMismatch == nil {
            runtimeSyncError = nil
        }
    }
    func syncRuntimeFromBundle() async {
        guard !switcher.isFixture, !syncingRuntime else { return }
        syncingRuntime = true
        runtimeSyncError = nil
        defer { syncingRuntime = false }
        do {
            let data = try await Task.detached(priority: .userInitiated) {
                try SwitcherCommandRunner.run(["install-runtime", "--apply"])
            }.value
            let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            guard parsed?["status"] as? String == "ok" else {
                runtimeSyncError = (parsed?["error"] as? [String: Any])?["message"] as? String
                    ?? (parsed?["message"] as? String)
                    ?? "后台采集与 Seatbelt 网关同步升级未确认，请重试。"
                return
            }
            refreshRuntimeVersionSync()
            refresh(manual: true)
            await switcher.refreshBackground(maximumAge: 0)
        } catch {
            runtimeSyncError = error.localizedDescription
        }
    }
    func checkForUpdates() async {
        guard !switcher.isFixture, !checkingForUpdate else { return }
        checkingForUpdate = true
        updateCheckNote = nil
        updateCheckFailed = false
        defer { checkingForUpdate = false }
        await switcher.perform(["update"], refresh: false)
        if switcher.failure {
            updateCheckFailed = true
            updateCheckNote = switcher.message.isEmpty ? "检查更新失败，请稍后重试。" : switcher.message
        } else if let available = switcher.updateStatus, available.isAvailable {
            updateCheckNote = "发现新版本 \(available.versionLabel)"
        } else {
            updateCheckNote = switcher.message.isEmpty ? "当前已是最新版本。" : switcher.message
        }
    }
    func installAvailableUpdate() async {
        guard !switcher.isFixture else { return }
        updateCheckFailed = false
        await switcher.perform(["update", "--apply", "--detach", "--relaunch"], refresh: false)
        if switcher.failure {
            updateCheckFailed = true
            updateCheckNote = switcher.message.isEmpty ? "下载或安装更新未完成，请重试。" : switcher.message
        }
    }
    private func readNotificationAccess(_ reader: () async -> WatchNotificationAccess) async {
        notificationRequestGeneration += 1
        let generation = notificationRequestGeneration
        let value = await reader()
        guard generation == notificationRequestGeneration else { return }
        notificationAccess = value
    }
    #if UI_REVIEW
    func refreshNotificationAccessForFixture(_ reader: () async -> WatchNotificationAccess) async {
        guard switcher.isFixture else { return }
        await readNotificationAccess(reader)
    }
    #endif
    func advanceClock(at date: Date) {
        now = date
        leakChecks.now = date
        aiChecks.now = date
        switcher.advanceLoginClock(date)
        connectionEvidenceUpdated.send()
        scheduleEvidenceExpiry()
    }

    private func scheduleEvidenceExpiry() {
        expiryTask?.cancel()
        guard started else { return }
        let time = Date().timeIntervalSince1970
        var deadlines = leakChecks.evidenceDeadlines
        if automatic && !initializing, let due = environmentRefreshScheduler.nextCheck {
            deadlines.append(due.timeIntervalSince1970)
        }
        if let last = diagnosticContext.lastVerifiedAt {
            deadlines.append(last.timeIntervalSince1970 + DiagnosticContextTracker.grace)
        }
        if let value = snapshot {
            if let age = value.health.heartbeatAge { deadlines.append(value.capturedAt + 30 - age) }
            deadlines.append(value.capturedAt + MonitorSnapshotTiming.snapshotMaximumAge)
            if let proxy = value.proxy { deadlines.append(proxy.observedAt + MonitorSnapshotTiming.proxyMaximumAge) }
            for state in value.channelSupervision?.families.values ?? [:].values {
                deadlines += [state.valid_until, state.blocked_evidence_valid_until,
                              state.process_disposition_receipt.map { $0.observed_at + 15 }].compactMap { $0 }
                deadlines += (state.previous_process_disposition_receipts ?? []).map { $0.observed_at + 15 }
            }
            deadlines += value.processes.compactMap { $0.protection?.valid_until }
        }
        if let background = switcher.background { deadlines += [background.observed_at + 30, background.observed_at + 35] }
        if let session = switcher.sessionDisplayEvidence {
            deadlines.append(session.observedAt + 35)
            if let until = session.session.valid_until { deadlines.append(until) }
        }
        deadlines += AIService.allCases.compactMap { aiChecks.state($0).result.map { $0.finishedAt + AIProbePolicy.maximumAge } }
        deadlines += serverReferences.values.map(\.expiresAt)
        // A failed watcher can recover on the next evidence check.
        if publications == nil && !switcher.isFixture { deadlines.append(time + MonitorSnapshotTiming.snapshotMaximumAge) }
        guard let next = deadlines.filter({ $0.isFinite && $0 > time }).min() else { return }
        let task = DispatchWorkItem { [weak self] in
            guard let self else { return }
            let date = Date()
            self.observePublications()
            self.advanceClock(at: date)
            guard self.automatic || self.initializing else { return }
            let expired = self.snapshot.flatMap { value in
                value.health.state == "running" && value.capturedAt + MonitorSnapshotTiming.snapshotMaximumAge <= date.timeIntervalSince1970
                    ? value.capturedAt : nil
            }
            if self.publications == nil || (expired != nil && expired != self.rereadExpiredSnapshot) {
                self.rereadExpiredSnapshot = expired
                self.refresh()
            }
            if self.publications == nil || self.switcher.background.map({ date.timeIntervalSince1970 >= $0.observed_at + 30 }) == true {
                self.refreshBackgroundIfNeeded(at: date)
            }
            self.refreshServerReference()
            if self.automatic, self.environmentRefreshScheduler.nextCheck.map({ $0 <= date }) == true {
                self.refreshEnvironmentIfNeeded()
            }
        }
        expiryTask = task
        DispatchQueue.main.asyncAfter(deadline: .now() + max(0, next - time), execute: task)
    }

    func publicationsDidChange(_ changes: MonitorPublications, at date: Date = Date()) {
        guard automatic || initializing else { return }
        if changes.contains(.service) { refreshBackgroundIfNeeded(at: date) }
        if changes.contains(.snapshot) { refresh() }
        if changes.contains(.history) { historyUpdated.send() }
    }

    func handleChannelUpdate() {
        if automatic || initializing { refresh() }
    }
    func refresh(manual: Bool = false) {
        guard !switcher.isFixture else { return }
        if manual { refreshBackgroundIfNeeded(at: Date(), force: true) }
        let shouldRead = refreshGate.request(manual: manual)
        if refreshing != refreshGate.manualVisible { refreshing = refreshGate.manualVisible }
        guard shouldRead else { return }
        Task {
            let result = await Task.detached(priority: .utility) {
                SnapshotRunner.run()
            }.value
            // Advance the display clock before deriving `live` through
            // `proxy` or starting any context-bound diagnostic.
            let completedAt = Date()
            switch result {
            case .success(let value):
                acceptSnapshot(value, receivedAt: completedAt)
            case .failure(let message):
                if case .rustCandidate? = BundledBackendVariant.current() { LeakDiagnosticTrace.shared.schedule(kind: "all", event: "snapshot_failed") }
                error = message
                channelSubscription.markReconnected()
                advanceClock(at: completedAt)
            }
            synchronizeNetworkSelection()
            let followUp = refreshGate.complete()
            if refreshing != refreshGate.manualVisible { refreshing = refreshGate.manualVisible }
            if followUp && (refreshGate.manualVisible || automatic || initializing) { refresh(manual: refreshGate.manualVisible) }
        }
    }
    func acceptSnapshot(_ value: MonitorSnapshot, receivedAt: Date) {
        // First-run and normal observation share this publication path.
        // Backend capture time remains authoritative; rereads cannot renew it.
        now = max(receivedAt, Date(timeIntervalSince1970: value.capturedAt))
        error = nil
        if MonitorSnapshotTiming.isCurrent(capturedAt: value.capturedAt, now: now.timeIntervalSince1970) {
            lastAcceptedFreshSnapshotAt = value.capturedAt
        } else {
            lastAcceptedFreshSnapshotAt = nil
        }
        let transition = observeDiagnosticContext(from: value, at: receivedAt)
        snapshot = value
        if let channel = value.channelSupervision { channelSubscription.applySnapshot(channel) }
        else { channelSubscription.markReconnected() }
        // The UI observes authoritative receipts; it never reissues permits.
        // Re-evaluate only after both the tracker and snapshot describe this
        // observation. Otherwise a recovered sampler can leave a fresh
        // receipt marked incomplete until an unrelated later clock tick.
        advanceClock(at: now)
        if automatic && transition == .changed { switcher.invalidateCurrentEnvironmentRequest() }
        if automatic && !initializing {
            refreshEnvironmentIfNeeded()
        }
    }
    /// A read completion is not itself new evidence. Observe the same main-actor
    /// store the check just evaluated, without requesting any reads from it.
    func waitForConnectionChange(until deadline: Date, changed: @escaping () -> Bool) async {
        guard !Task.isCancelled, !changed(), deadline.timeIntervalSinceNow > 0 else { return }
        let (stream, continuation) = AsyncStream<Void>.makeStream()
        let subscription = connectionEvidenceUpdated.first { changed() }.sink { continuation.finish() }
        // No periodic wake: expiry is the check's original evidence boundary.
        let expiry = DispatchWorkItem { continuation.finish() }
        DispatchQueue.main.asyncAfter(deadline: .now() + max(0, deadline.timeIntervalSinceNow), execute: expiry)
        defer { subscription.cancel(); expiry.cancel() }
        var iterator = stream.makeAsyncIterator()
        _ = await iterator.next()  // also returns immediately on task cancellation
    }
    func channelState(for product: MonitoredProduct) -> FamilyChannelMonitorState? {
        let family = product == .claude ? "claude" : "openai"
        return channelSubscription.effectiveState(
            for: family,
            now: now.timeIntervalSince1970,
            live: live
        )
    }
    func unmanagedPids(for product: MonitoredProduct) -> [UInt32] {
        channelState(for: product)?.unmanagedPids ?? []
    }
    func isProcessUnmanaged(_ process: WatchedProcess) -> Bool {
        guard let state = channelState(for: process.product) else { return true }
        return state.isUnmanagedProcess(process)
    }
    func processEvidenceText(_ process: WatchedProcess) -> String {
        "发现依据：\(process.discoveryExplanation)\n" + process.protectionExplanation(
            state: channelState(for: process.product), executorBootId: snapshot?.channelSupervision?.executor_boot_id,
            now: now.timeIntervalSince1970, live: live)
    }
    var vpnSupervision: VpnSupervisionSnapshotModel? {
        guard live else { return nil }
        return snapshot?.vpnSupervision
    }
    var vpnExpectationDifferences: [VpnFieldDiffModel] {
        vpnSupervision?.differences ?? []
    }
    var vpnUnknownOrStaleReasons: [String] {
        guard let sup = snapshot?.vpnSupervision else {
            return live ? ["vpn_supervision_unavailable"] : ["monitor_snapshot_stale_or_offline"]
        }
        return sup.unknownOrStaleReasons
    }
    func isConfirmedFlowBlocked(for product: MonitoredProduct) -> Bool {
        guard let state = channelState(for: product) else { return false }
        return state.isConfirmedFlowBlocked(at: now.timeIntervalSince1970)
    }
    private func refreshBackgroundIfNeeded(at date: Date, force: Bool = false) {
        pendingBackgroundRead = true
        guard !backgroundReadRunning, !switcher.busy else { return }
        backgroundRetry?.cancel()
        let remaining = lastBackgroundRead.addingTimeInterval(5).timeIntervalSince(date)
        if !force && remaining > 0 {
            let retry = DispatchWorkItem { [weak self] in self?.drainPendingBackgroundRead() }
            backgroundRetry = retry
            DispatchQueue.main.asyncAfter(deadline: .now() + remaining, execute: retry)
            return
        }
        pendingBackgroundRead = false
        backgroundReadRunning = true
        lastBackgroundRead = date
        Task { @MainActor in
            await switcher.refreshBackground()
            backgroundReadRunning = false
            drainPendingBackgroundRead()
            scheduleEvidenceExpiry()
        }
    }
    private func drainPendingBackgroundRead() {
        guard pendingBackgroundRead else { return }
        guard automatic || initializing else { pendingBackgroundRead = false; return }
        refreshBackgroundIfNeeded(at: Date())
    }
    private func refreshEnvironmentIfNeeded() {
        guard !initializing else { return }
        let usableContext = currentDiagnosticContext()
        let busy = switcher.readingEnvironment || switcher.busy
        guard environmentRefreshScheduler.claim(context: usableContext, now: Date(), switcherBusy: busy,
              observedAt: snapshot?.proxy.map { Date(timeIntervalSince1970: $0.observedAt) }) != nil else {
            if usableContext == nil, case .rustCandidate? = BundledBackendVariant.current() {
                LeakDiagnosticTrace.shared.schedule(kind: "dns", event: "schedule_context_missing")
            }
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            defer { self.scheduleEvidenceExpiry() }
            guard self.currentDiagnosticContext() == usableContext else {
                self.environmentRefreshScheduler.complete(context: usableContext, accepted: false, now: Date())
                return
            }
            let accepted = await self.switcher.detectCurrentEnvironment()
            // Do not let a read begun on an older proxy identity publish a
            // complete environment/launch-preview pair after a new identity
            // was confirmed while it was running.
            guard self.currentDiagnosticContext() == usableContext else {
                self.environmentRefreshScheduler.complete(context: usableContext, accepted: false, now: Date())
                return
            }
            self.environmentRefreshScheduler.complete(context: usableContext, accepted: accepted, now: Date(),
                validUntil: self.switcher.currentEnvironment?.expires_at)
        }
    }
    private func context(from value: ProxySnapshot?) -> String? {
        guard let value, value.entryState == "verified", value.apiState == "available",
              value.coversProxy else { return nil }
        // Must exactly match receipts::tag_signature: DNS/WebRTC receipts bind
        // themselves to both selected and global node values, not a collapsed
        // mode-dependent display node.
        return tagReceiptContext(endpoint: value.endpoint, mode: value.mode,
                                 selectedNode: value.selectedNode, globalNode: value.globalNode)
    }
    private func observeDiagnosticContext(from value: MonitorSnapshot, at date: Date) -> DiagnosticContextTracker.Transition {
        let proxy = freshProxy(in: value, at: date)
        let sourceTime = proxy.map { Date(timeIntervalSince1970: $0.observedAt) } ?? date
        return diagnosticContext.observe(context(from: proxy), observedAt: sourceTime)
    }
    /// Only a directly verified identity can start a new environment round.
    /// A short sampler gap can retain its predecessor for an in-flight probe,
    /// but cannot create a new green environment receipt.
    private func currentDiagnosticContext() -> String? {
        context(from: freshProxy(in: snapshot, at: now))
    }
    var initializationContext: String? {
        context(from: freshInitializationProxy(in: snapshot, at: now))
    }
    private func freshInitializationProxy(in snapshot: MonitorSnapshot?, at date: Date) -> ProxySnapshot? {
        guard error == nil, let snapshot, snapshot.proxyError == nil,
              lastAcceptedFreshSnapshotAt == snapshot.capturedAt,
              MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: date.timeIntervalSince1970,
                                              maximumAge: MonitorSnapshotTiming.proxyMaximumAge),
              let value = snapshot.proxy else { return nil }
        let age = date.timeIntervalSince1970 - value.observedAt
        return (0...MonitorSnapshotTiming.proxyMaximumAge).contains(age) ? value : nil
    }
    func beginInitialization(startSnapshotPolling: Bool = true) {
        initializing = true
        if startSnapshotPolling { start() }
    }
    func finishInitialization() {
        // Preserve the exact receipts just checked; normal polling adopts them
        // instead of clearing or immediately recollecting all page data.
        environmentRefreshScheduler.complete(context: currentDiagnosticContext(), accepted: true, now: Date(),
            validUntil: switcher.currentEnvironment?.expires_at)
        initializing = false
        referenceQueriesEnabled = true
    }
    private func retainedDiagnosticContext() -> String? {
        guard !hasExplicitProxyFailure else { return nil }
        // A directly verified, still-current snapshot is stronger than the
        // short grace used only when an observation is unavailable. Do not
        // discard its identity merely because the producer's next sample has
        // not arrived within that grace window.
        return currentDiagnosticContext() ?? diagnosticContext.retained(at: now)
    }
    private var hasExplicitProxyFailure: Bool {
        guard let value = freshRawProxy(in: snapshot, at: now) else { return false }
        return value.entryState == "mismatch" || value.apiState == "mismatch" || value.selectionChanged
    }
    private func freshRawProxy(in snapshot: MonitorSnapshot?, at date: Date) -> ProxySnapshot? {
        guard error == nil, let snapshot,
              MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: date.timeIntervalSince1970),
              let value = snapshot.proxy else { return nil }
        let age = date.timeIntervalSince1970 - value.observedAt
        return (0...MonitorSnapshotTiming.proxyMaximumAge).contains(age) ? value : nil
    }
    private func freshProxy(in snapshot: MonitorSnapshot?, at date: Date) -> ProxySnapshot? {
        guard snapshot?.proxyError == nil else { return nil }
        return freshRawProxy(in: snapshot, at: date)
    }
    private func requestEnvironmentRefreshAfterDNS() {
        // Do not merge a DNS-only receipt into a prior observation.  The next
        // stable full observation atomically refreshes both environment and
        // display-only launch-preview rows.
        guard automatic else { return }
        guard !environmentRefreshScheduler.isInFlight else { return }
        environmentRefreshScheduler.requestRefresh()
        refreshEnvironmentIfNeeded()
    }
    private func refreshEnvironmentQuality(_ result: CurrentEnvironmentReceipt) {
        if let receipt = result.netcoffee_lookup { netCoffee.ingest(receipt) }
        if let raw = result.rows.first(where: { $0.id == "egress" })?.current,
           let candidate = raw.components(separatedBy: " / ").first,
           let ip = LeakIPAddress(candidate.trimmingCharacters(in: .whitespacesAndNewlines)),
           ip.isPublic {
            if netCoffee.selectedIP.isEmpty {
                netCoffee.selectedForPage(ip.canonical)
                if netCoffee.query.isEmpty { netCoffee.query = ip.canonical }
            }
            if !switcher.isFixture && netCoffee.report(ip.canonical) == nil {
                netCoffee.fetch(ip.canonical)
            }
        }
    }
    func showConnections(_ product: MonitoredProduct) {
        networkSelection.product = product
        page = .network
    }
    func synchronizeNetworkSelection() {
        var selection = networkSelection
        selection.reconcile(proxy: proxy, processes: snapshot?.processes ?? [],
                            fresh: proxyFresh && proxy?.connectionObservationIsComplete == true)
        if selection != networkSelection { networkSelection = selection }
        rememberGraphPath()
        refreshServerReference()
    }
    func selectNetworkFlow(_ flow: Flow, product: MonitoredProduct) {
        networkSelection.select(flowID: flow.id, product: product)
        rememberGraphPath()
        refreshServerReference()
    }
    private var graphEgress: (ip: String?, time: Double?) {
        guard let background = switcher.background,
              0 <= now.timeIntervalSince1970 - background.observed_at,
              now.timeIntervalSince1970 - background.observed_at <= 30,
              let reference = background.session_guard?.current,
              let at = reference.observed_at ?? reference.checked_at,
              0 <= now.timeIntervalSince1970 - at, now.timeIntervalSince1970 - at <= 30,
              let ip = reference.ip, !ip.isEmpty else { return (nil, nil) }
        return (ip, at)
    }
    private func rememberGraphPath() {
        graphContinuity.observe(snapshot: snapshot, selection: networkSelection, now: now.timeIntervalSince1970,
            error: error, automatic: automatic, claudeEgressIP: graphEgress.ip,
            egressObservedAt: graphEgress.time, blockedProducts: Set(MonitoredProduct.allCases.filter { isConfirmedFlowBlocked(for: $0) }),
            references: serverReferences)
    }
    func graphDisplay(for product: MonitoredProduct) -> GraphDisplayState {
        graphContinuity.display(product: product, snapshot: snapshot, selection: networkSelection,
            now: now.timeIntervalSince1970, error: error, automatic: automatic,
            claudeEgressIP: graphEgress.ip, egressObservedAt: graphEgress.time, safetyBlocked: isConfirmedFlowBlocked(for: product))
    }
    func reference(for flow: Flow?) -> ServerReference? {
        guard let request = ServerReferenceRequest(flow: flow), let value = serverReferences[request.key],
              value.applies(to: request, now: now.timeIntervalSince1970) else { return nil }
        return value
    }
    func acceptServerReference(_ result: ServerReference?, for request: ServerReferenceRequest, at date: Date) {
        let epoch = date.timeIntervalSince1970
        let value = result.flatMap { $0.applies(to: request, now: epoch) ? $0 : nil }
            ?? ServerReference.unavailable(for: request, now: epoch)
        if serverReferences[request.key] == nil, serverReferences.count >= 64,
           let oldest = serverReferences.min(by: { $0.value.queriedAt < $1.value.queriedAt })?.key {
            serverReferences.removeValue(forKey: oldest)
        }
        serverReferences[request.key] = value
        scheduleEvidenceExpiry()
        // Only a still-current selected connection may capture this reference.
        // Late answers never mutate a historical path from an ended connection.
        rememberGraphPath()
    }
    private func refreshServerReference() {
        guard referenceQueriesEnabled, automatic, page == .network, !referenceQueryRunning,
              graphDisplay(for: networkSelection.product).phase == .live,
              let selectedID = networkSelection.selectedFlowID(for: networkSelection.product),
              let flow = proxy?.flows.first(where: { $0.id == selectedID }),
              let request = ServerReferenceRequest(flow: flow), reference(for: flow) == nil else { return }
        referenceQueryRunning = true
        Task {
            let result = await Task.detached(priority: .utility) { ServerReferenceRunner.run(request) }.value
            referenceQueryRunning = false
            acceptServerReference(result, for: request, at: Date())
        }
    }
    var proxy: ProxySnapshot? {
        guard live else { return nil }
        return freshProxy(in: snapshot, at: now)
    }
    var proxyError: String? {
        if let error { return error }
        if let message = snapshot?.proxyError { return message }
        if let value = snapshot?.proxy, now.timeIntervalSince1970 - value.observedAt > 30 {
            return "网络样本已过期，等待后台更新"
        }
        return nil
    }
    var live: Bool {
        guard let s = snapshot else { return false }
        let elapsed = now.timeIntervalSince1970 - s.capturedAt
        return error == nil && s.health.state == "running" && MonitorSnapshotTiming.isCurrent(capturedAt: s.capturedAt, now: now.timeIntervalSince1970)
            && (s.health.heartbeatAge ?? 99) + elapsed <= 30
    }
    var proxyFresh: Bool {
        proxy != nil
    }
    var heroTitle: String {
        guard snapshot != nil else { return error == nil ? "正在连接监控" : "暂时无法读取" }
        guard live else { return "监控状态待检查" }
        switch snapshot?.health.mode {
        case "ACTIVE": return "授权会话监控中"
        case "GUARD": return "后台警戒中"
        default: return "运行模式待确认"
        }
    }
    var entryTitle: String {
        guard let p = proxy else { return "等待采样" }
        guard proxyFresh else { return "待刷新" }
        switch p.entryState {
        case "verified": return "已确认"
        case "mismatch": return "身份不符"
        case "unavailable": return "不可用"
        default: return "待确认"
        }
    }
    var chainTitle: String {
        guard let p = proxy else { return "等待采样" }
        guard !p.flows.isEmpty else { return "暂无样本" }
        guard proxyFresh else { return "待刷新" }
        if p.flows.contains(where: { $0.policy == "mismatch" }) { return "发现差异" }
        if p.flows.allSatisfy({ $0.association == "correlated" && $0.policy == "match" }) { return "样本匹配" }
        return "部分待确认"
    }
}

