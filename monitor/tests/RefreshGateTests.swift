import Foundation

@main
struct RefreshGateTests {
    @MainActor
    static func main() async throws {
        var checks = 0
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            checks += 1
        }
        var gate = MonitorRefreshGate()
        expect(gate.request(manual: false), "automatic read starts")
        expect(!gate.manualVisible, "automatic read never activates manual indicator")
        expect(!gate.request(manual: false), "automatic ticks cannot overlap")
        expect(!gate.request(manual: true), "manual request waits for active read")
        expect(gate.manualVisible, "explicit request gets feedback")
        expect(!gate.request(manual: true), "repeated requests coalesce")
        expect(gate.complete(), "queued manual read must execute")
        expect(gate.manualVisible, "feedback persists across queued read")
        expect(gate.request(manual: true), "queued read starts")
        expect(!gate.request(manual: false), "background cannot interrupt manual read")
        expect(gate.complete(), "publication during a manual read schedules a silent follow-up")
        expect(!gate.manualVisible && !gate.reading, "manual state clears after completion")
        expect(gate.request(manual: false), "automatic synchronization resumes")
        expect(!gate.manualVisible, "resumed polling stays silent")
        expect(!gate.complete(), "ordinary completion has no extra work")
        let files = FileManager.default
        let parent = files.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let root = parent.appendingPathComponent("ClaudeWatch")
        let state = root.appendingPathComponent("state")
        let logs = root.appendingPathComponent("switcher")
        try files.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? files.removeItem(at: parent) }
        expect(MonitorPublications.files["state/unrelated.json"] == nil,
               "unrelated file writes do not request a read")
        let (events, sink) = AsyncStream<MonitorPublications>.makeStream()
        let observer = MonitorPublicationObserver(root: root) { sink.yield($0) }
        expect(observer.start(), "owned publication observer starts")
        let deadline = Task { try await Task.sleep(for: .seconds(5)); sink.finish() }
        defer { deadline.cancel(); sink.finish() }
        try files.createDirectory(at: state, withIntermediateDirectories: true)
        try files.createDirectory(at: logs, withIntermediateDirectories: true)
        let snapshot = state.appendingPathComponent("runtime-snapshot.json")
        let history = logs.appendingPathComponent("events.jsonl")
        try Data("initial".utf8).write(to: snapshot, options: .atomic)
        var iterator = events.makeAsyncIterator()
        func waitFor(_ wanted: MonitorPublications) async -> Bool {
            while let event = await iterator.next() { if event.contains(wanted) { return true } }
            return false
        }
        let initial = await waitFor(.snapshot)
        expect(initial, "real snapshot publication wakes reader")
        try Data("replacement".utf8).write(to: snapshot, options: .atomic)
        let replaced = await waitFor(.snapshot)
        expect(replaced, "atomic replacement remains observable")
        try Data().write(to: history)
        let created = await waitFor(.history)
        expect(created, "creating the active log wakes history")
        let writer = try FileHandle(forWritingTo: history)
        try writer.write(contentsOf: Data("event".utf8))
        try writer.close()
        let appended = await waitFor(.history)
        expect(appended, "appending to the existing inode wakes history")
        try files.moveItem(at: history, to: logs.appendingPathComponent("events.previous.jsonl"))
        let rotated = await waitFor(.history)
        expect(rotated, "log rotation wakes history reader")
        withExtendedLifetime(observer) {}
        print("RefreshGateTests: \(checks) assertions passed")
    }
}
