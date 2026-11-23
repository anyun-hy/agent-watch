import AppKit
import Foundation

/// Native presence only; process membership and protection are backend facts.
struct WorkspaceDesktopPresence: Equatable {
    static let supervisedBundleIDs: Set<String> = ["com.anthropic.claudefordesktop", "com.openai.codex", "com.openai.chat"]
    private struct Entry: Equatable {
        let bundle: String
        let bundleName: String?
    }
    private var processes: [pid_t: Entry] = [:]

    mutating func record(pid: pid_t, bundle: String, bundleName: String? = nil, launched: Bool) -> Bool {
        guard Self.supervisedBundleIDs.contains(bundle) else { return false }
        if launched {
            let entry = Entry(bundle: bundle, bundleName: bundleName)
            guard processes[pid] != entry else { return false }
            processes[pid] = entry
        } else {
            guard processes[pid]?.bundle == bundle else { return false }
            processes.removeValue(forKey: pid)
        }
        return true
    }

    func processIDs(for product: MonitoredProduct) -> Set<pid_t> {
        let bundles = product == .claude ? ["com.anthropic.claudefordesktop"] : ["com.openai.codex", "com.openai.chat"]
        return Set(processes.compactMap { bundles.contains($0.value.bundle) ? $0.key : nil })
    }

    func contains(bundle: String) -> Bool { processes.values.contains { $0.bundle == bundle } }

    func containsChatGPT() -> Bool {
        processes.values.contains { entry in
            entry.bundle == "com.openai.chat" ||
                (entry.bundle == "com.openai.codex" && entry.bundleName?.lowercased() == "chatgpt.app")
        }
    }

}

/// Subscribe before seeding the initial inventory. Launch/termination changes
/// are deduplicated by process identity, not by an arbitrary delay.
final class WorkspaceAppObserver {
    private var presence = WorkspaceDesktopPresence()
    private var tokens: [NSObjectProtocol] = []
    private let onChange: (WorkspaceDesktopPresence) -> Void
    init(onChange: @escaping (WorkspaceDesktopPresence) -> Void) { self.onChange = onChange }

    func start() -> WorkspaceDesktopPresence {
        guard tokens.isEmpty else { return presence }
        let workspace = NSWorkspace.shared
        for (name, launched) in [(NSWorkspace.didLaunchApplicationNotification, true),
                                 (NSWorkspace.didTerminateApplicationNotification, false)] {
            tokens.append(workspace.notificationCenter.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in
                guard let self, let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                      let bundle = app.bundleIdentifier,
                      self.presence.record(pid: app.processIdentifier, bundle: bundle, bundleName: app.bundleURL?.lastPathComponent, launched: launched) else { return }
                self.onChange(self.presence)
            })
        }
        for app in workspace.runningApplications {
            guard let bundle = app.bundleIdentifier else { continue }
            _ = presence.record(pid: app.processIdentifier, bundle: bundle, bundleName: app.bundleURL?.lastPathComponent, launched: true)
        }
        return presence
    }
    deinit { for token in tokens { NSWorkspace.shared.notificationCenter.removeObserver(token) } }
}
