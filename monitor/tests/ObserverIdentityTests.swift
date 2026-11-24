import Foundation

@main
struct ObserverIdentityTests {
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
            exit(1)
        }
    }

    static func child() throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        return process
    }

    static func stop(_ process: Process) {
        if process.isRunning { process.terminate(); process.waitUntilExit() }
    }

    static func main() throws {
        let live = try child()
        defer { stop(live) }
        let pid = live.processIdentifier

        observerIdentityMisses[pid] = 1
        let recovered = try inventory()
        let recoveredRows = recovered["processes"] as! [[String: Any]]
        let recoveredMissing = recovered["unavailable"] as! [[String: Any]]
        expect(recoveredRows.contains { ($0["pid"] as? NSNumber)?.int32Value == pid }, "transient inventory failure is rechecked")
        expect(!recoveredMissing.contains { ($0["pid"] as? NSNumber)?.int32Value == pid }, "recovered identity is not left unavailable")

        observerIdentityMisses[pid] = 2
        let unreadable = try inventory()
        let unreadableRows = unreadable["unavailable"] as! [[String: Any]]
        expect(unreadableRows.contains { ($0["pid"] as? NSNumber)?.int32Value == pid && $0["code"] as? String == "identity_unavailable" }, "unreadable live process stays unavailable")
        expect(!(unreadable["exited"] as! [Int32]).contains(pid), "unreadable live process is not treated as exited")
        observerIdentityMisses.removeValue(forKey: pid)

        let ending = try child()
        defer { stop(ending) }
        let endingPID = ending.processIdentifier
        observerIdentityMisses[endingPID] = 1
        observerAfterInventoryScan = { stop(ending) }
        let exitedInventory = try inventory()
        observerAfterInventoryScan = nil
        expect((exitedInventory["exited"] as! [Int32]).contains(endingPID), "confirmed exit during inventory is not reported as a read failure")

        guard let identity = currentIdentity(pid) else { fatalError("test child identity unavailable") }
        let request = Request(schema: 1, round_id: UUID().uuidString, targets: [identity])
        observerBeforeSocketRecheck = { target in
            if target == pid { observerIdentityMisses[pid] = 1 }
        }
        let unknown = try sockets(request)
        observerBeforeSocketRecheck = nil
        let unknownRow = (unknown["socket_samples"] as! [[String: Any]])[0]
        expect(unknownRow["code"] as? String == "identity_unavailable", "live target with unreadable identity remains unknown")
        expect(live.isRunning, "identity failure does not terminate the target")

        let wrong = Identity(pid: identity.pid, parent: identity.parent, uid: identity.uid,
                             executable: identity.executable, start_seconds: identity.start_seconds + 1,
                             start_microseconds: identity.start_microseconds, start_stamp: identity.start_stamp)
        let reused = try sockets(Request(schema: 1, round_id: UUID().uuidString, targets: [wrong]))
        expect((reused["socket_samples"] as! [[String: Any]])[0]["code"] as? String == "identity_changed", "mismatched process identity remains unconfirmed")

        observerBeforeSocketRecheck = { target in if target == pid { stop(live) } }
        let exitedSockets = try sockets(request)
        observerBeforeSocketRecheck = nil
        let exitedRow = (exitedSockets["socket_samples"] as! [[String: Any]])[0]
        expect(exitedRow["code"] as? String == "process_exited", "confirmed exit during socket scan is not misreported as identity change")
        expect(exitedRow["sockets"] == nil, "no stale sockets survive an exited target")

        // A live process whose executable was unlinked/replaced on disk (e.g. an auto-updated
        // unrelated app) makes proc_pidpath return ENOENT. inventory() must recover its kernel
        // exec_path via KERN_PROCARGS2 instead of poisoning the whole machine inventory, while
        // strict identity checks (sockets/identities) remain fail-closed.
        let unlinkedDir = "/private/tmp/cw-unlinked-observer-\(UUID().uuidString)"
        let unlinkedBin = unlinkedDir + "/sleep-copy"
        try FileManager.default.createDirectory(atPath: unlinkedDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: unlinkedDir) }
        try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: unlinkedBin)
        let sign = Process()
        sign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        sign.arguments = ["--force", "--sign", "-", unlinkedBin]
        sign.standardOutput = FileHandle.nullDevice
        sign.standardError = FileHandle.nullDevice
        try sign.run()
        sign.waitUntilExit()
        expect(sign.terminationStatus == 0, "ad-hoc codesign succeeded for temporary sleep copy")
        let unlinkedProc = Process()
        unlinkedProc.executableURL = URL(fileURLWithPath: unlinkedBin)
        unlinkedProc.arguments = ["30"]
        try unlinkedProc.run()
        defer { stop(unlinkedProc) }
        let unlinkedPID = unlinkedProc.processIdentifier
        guard let beforeUnlink = currentIdentity(unlinkedPID) else { fatalError("unlinked fixture missing initial identity") }
        try FileManager.default.removeItem(atPath: unlinkedBin)
        try FileManager.default.removeItem(atPath: unlinkedDir)
        expect(unlinkedProc.isRunning, "unlinked fixture process remains alive")
        expect(currentIdentity(unlinkedPID) == nil, "strict currentIdentity still rejects unlinked executable")
        let afterUnlink = try inventory()
        let afterRows = afterUnlink["processes"] as! [[String: Any]]
        let afterUnavailable = afterUnlink["unavailable"] as! [[String: Any]]
        let expectedExecs: Set<String> = [unlinkedBin, unlinkedBin.replacingOccurrences(of: "/private/tmp/", with: "/tmp/")]
        let foundRow = afterRows.first { ($0["pid"] as? NSNumber)?.int32Value == unlinkedPID }
        let foundUnavailable = afterUnavailable.first { ($0["pid"] as? NSNumber)?.int32Value == unlinkedPID }
        let foundExec = foundRow?["executable"] as? String
        expect(foundExec.map { expectedExecs.contains($0) } == true,
               "inventory recovers kernel exec_path for unlinked executable (expected=\(expectedExecs), row=\(String(describing: foundRow)), unavailable=\(String(describing: foundUnavailable)))")
        expect(!afterUnavailable.contains { ($0["pid"] as? NSNumber)?.int32Value == unlinkedPID },
               "unlinked unrelated executable does not poison inventory unavailable list")
        let unlinkedSockets = try sockets(Request(schema: 1, round_id: UUID().uuidString, targets: [beforeUnlink]))
        let unlinkedSocketRow = (unlinkedSockets["socket_samples"] as! [[String: Any]])[0]
        expect(unlinkedSocketRow["code"] as? String == "identity_unavailable",
               "socket sampling remains fail-closed when target executable vnode is unlinked")
        print("ObserverIdentityTests: temporary owned processes only")
    }
}
