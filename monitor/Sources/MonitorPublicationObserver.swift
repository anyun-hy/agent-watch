import Darwin
import Foundation

struct MonitorPublications: OptionSet {
    let rawValue: UInt8
    static let snapshot = Self(rawValue: 1)
    static let service = Self(rawValue: 2)
    static let history = Self(rawValue: 4)
    static let managedInstance = Self(rawValue: 8)

    static let files: [String: Self] = [
        "state/runtime-snapshot.json": .snapshot,
        "state/channel-supervision.json": .snapshot,
        "state/guard-service-heartbeat.json": .service,
        "switcher/guard-heartbeat.json": .service,
        "switcher/config.json": .service,
        "switcher/events.jsonl": .history, "switcher/events.previous.jsonl": .history,
        "switcher/traffic-events.jsonl": .history, "switcher/traffic-events.previous.jsonl": .history,
        "switcher/diagnostic-events.jsonl": .history, "switcher/diagnostic-events.previous.jsonl": .history
    ]
}

/// Directory events rebind names after atomic replacement or rotation. Events
/// on the files themselves also catch appends. Only Rust readback supplies data.
final class MonitorPublicationObserver {
    private struct Contents: Equatable {
        let size: off_t
        let modified: Int
        let nanoseconds: Int
        init(_ info: stat) {
            size = info.st_size
            modified = info.st_mtimespec.tv_sec
            nanoseconds = info.st_mtimespec.tv_nsec
        }
    }
    private struct Watch {
        let device: dev_t
        let inode: ino_t
        var contents: Contents
        let source: DispatchSourceFileSystemObject
    }
    private let root: URL
    private let files: [String: MonitorPublications]
    private let directories: [URL]
    private let onChange: (MonitorPublications) -> Void
    private var watches: [URL: Watch] = [:]

    init(root: URL, files: [String: MonitorPublications] = MonitorPublications.files,
         onChange: @escaping (MonitorPublications) -> Void) {
        self.root = root
        self.files = files
        var parents = Set([root.deletingLastPathComponent(), root])
        for name in files.keys {
            var directory = root
            for component in name.split(separator: "/").dropLast() {
                directory.appendPathComponent(String(component))
                parents.insert(directory)
            }
        }
        directories = parents.sorted { $0.pathComponents.count < $1.pathComponents.count }
        self.onChange = onChange
    }

    func start() -> Bool {
        reconcile()
        return watches[root.deletingLastPathComponent()] != nil
    }

    private func reconcile(_ hint: MonitorPublications = []) {
        var changed = hint
        // Install the parent before inspecting children. The registration
        // callback covers changes between the initial stat and kernel setup.
        for directory in directories {
            _ = bind(directory, publication: [])
        }
        for (name, publication) in files {
            if bind(root.appendingPathComponent(name), publication: publication) {
                changed.formUnion(publication)
            }
        }
        if !changed.isEmpty { onChange(changed) }
    }

    private func bind(_ url: URL, publication: MonitorPublications) -> Bool {
        let old = watches[url]
        var info = stat()
        guard stat(url.path, &info) == 0 else {
            watches.removeValue(forKey: url)?.source.cancel()
            return old != nil
        }
        if let old, old.device == info.st_dev && old.inode == info.st_ino {
            guard !publication.isEmpty, old.contents != Contents(info) else { return false }
            watches[url]?.contents = Contents(info)
            return true
        }
        watches.removeValue(forKey: url)?.source.cancel()
        let fd = open(url.path, O_EVTONLY | O_CLOEXEC)
        guard fd >= 0 else { return old != nil }
        guard fstat(fd, &info) == 0 else { close(fd); return old != nil }
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .revoke], queue: .main)
        watches[url] = Watch(device: info.st_dev, inode: info.st_ino, contents: Contents(info), source: source)
        source.setCancelHandler { close(fd) }
        source.setRegistrationHandler { [weak self] in self?.reconcile() }
        source.setEventHandler { [weak self] in
            guard let self, self.watches[url]?.source.handle == fd else { return }
            self.reconcile(publication)
        }
        source.activate()
        return true
    }

    deinit { for watch in watches.values { watch.source.cancel() } }
}
