import Foundation
#if !PROCESS_POLICY_TESTS
import AppKit
import Combine
import Darwin
#endif

/// Native identity binding only; target selection and exit confirmation are Rust services.
struct AIProcessIdentity: Codable, Equatable, Sendable {
    let pid, parent: Int32
    let uid: UInt32
    let startSeconds, startMicroseconds: UInt64
    let executable: String
    var auditToken: [UInt32]? = nil
    enum CodingKeys: String, CodingKey {
        case pid, uid
        case parent = "ppid", startSeconds = "start_seconds", startMicroseconds = "start_microseconds"
        case executable = "executable_path", auditToken = "audit_token"
    }
    func sameProcess(as other: Self) -> Bool {
        pid == other.pid && uid == other.uid && startSeconds == other.startSeconds
            && startMicroseconds == other.startMicroseconds && executable == other.executable
            && auditToken == other.auditToken
    }
}
enum AIProcessInventoryFailure: Error {
    case malformed, engineUnavailable, timeout, outputTooLarge, readFailed, commandFailed
}
struct AIProcessClosePlan: Sendable {
    let product: MonitoredProduct
    let targets: [AIProcessIdentity]
    let requestID: String
    let payload: Data
    let force: Bool

    private struct Wire: Decodable {
        struct Target: Decodable { let process: AIProcessIdentity; let desktop_main: Bool }
        let schema: Int
        let force: Bool?
        let request_id, family: String
        let targets: [Target]
    }
    static func decode(_ data: Data, product: MonitoredProduct) throws -> Self {
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        guard wire.schema == 1, wire.family == family(product), UUID(uuidString: wire.request_id) != nil else {
            throw AIProcessInventoryFailure.malformed
        }
        return .init(product: product, targets: wire.targets.map(\.process), requestID: wire.request_id, payload: data, force: wire.force ?? false)
    }
    static func family(_ product: MonitoredProduct) -> String { product == .claude ? "claude" : "openai" }
}
struct AIProcessExitReceipt: Decodable {
    let schema: Int
    let request_id, family, code, message: String
    let complete: Bool
    static func decode(_ data: Data, plan: AIProcessClosePlan) throws -> Self {
        let receipt = try JSONDecoder().decode(Self.self, from: data)
        guard receipt.schema == 1, receipt.request_id == plan.requestID,
              receipt.family == AIProcessClosePlan.family(plan.product) else { throw AIProcessInventoryFailure.malformed }
        return receipt
    }
}
/// Immediate recheck at the AppKit effect boundary; no selection, waiting or fallback.
enum AIProcessNativeAction {
    static func applyToMatchingIdentity(_ expected: AIProcessIdentity,
        lookup: (Int32) -> AIProcessIdentity?, effect: (Int32) -> Bool) -> Bool {
        guard expected.pid > 1, expected.auditToken?.count == 8,
              let current = lookup(expected.pid), expected.sameProcess(as: current) else { return false }
        return effect(expected.pid)
    }
}

#if !PROCESS_POLICY_TESTS
enum AIProcessInventory {
    private static func rawAuditToken(_ pid: Int32) -> audit_token_t? {
        guard pid > 1 else { return nil }
        var name: mach_port_name_t = 0
        guard task_name_for_pid(mach_task_self_, pid, &name) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, name) }
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &token) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(name, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }
        return token
    }
    private static func tokenWords(_ token: audit_token_t) -> [UInt32] {
        let v = token.val
        return [v.0, v.1, v.2, v.3, v.4, v.5, v.6, v.7]
    }
    static func identity(_ pid: Int32) -> AIProcessIdentity? {
        guard pid > 1 else { return nil }
        var info = proc_bsdinfo()
        let expected = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, expected) == expected else { return nil }
        let beforeToken = rawAuditToken(pid)
        // PROC_PIDPATHINFO_MAXSIZE is a C expression macro unavailable in Swift.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        if var token = beforeToken {
            guard proc_pidpath_audittoken(&token, &path, UInt32(path.count)) > 0 else { return nil }
        } else {
            guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        }
        var confirm = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &confirm, expected) == expected,
              info.pbi_uid == confirm.pbi_uid,
              info.pbi_start_tvsec == confirm.pbi_start_tvsec,
              info.pbi_start_tvusec == confirm.pbi_start_tvusec else { return nil }
        let beforeWords = beforeToken.map(tokenWords)
        let afterWords = rawAuditToken(pid).map(tokenWords)
        guard beforeWords == afterWords else { return nil }
        return .init(pid: pid, parent: Int32(confirm.pbi_ppid), uid: confirm.pbi_uid,
                     startSeconds: confirm.pbi_start_tvsec, startMicroseconds: confirm.pbi_start_tvusec,
                     executable: String(cString: path), auditToken: beforeWords)
    }
    /// One bounded subprocess boundary. No reader or timer thread survives it.
    static func command(_ executable: URL, arguments: [String], deadline: TimeInterval,
                        maxBytes: Int = 4_000_000, input: Data? = nil) throws -> Data {
        let task = Process(), pipe = Pipe()
        task.executableURL = executable; task.arguments = arguments
        task.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        let inputPipe = input.map { _ in Pipe() }
        if let inputPipe { task.standardInput = inputPipe }
        else { task.standardInput = FileHandle.nullDevice }
        task.standardOutput = pipe; task.standardError = FileHandle.nullDevice
        let handle = pipe.fileHandleForReading
        let descriptor = handle.fileDescriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw AIProcessInventoryFailure.readFailed
        }
        try task.run()
        try? pipe.fileHandleForWriting.close()
        defer {
            // This is only the Process instance created above, never a monitored target.
            if task.isRunning { _ = Darwin.kill(task.processIdentifier, SIGKILL) }
            task.waitUntilExit()
            try? handle.close()
        }
        if let input, let inputPipe {
            let writer = inputPipe.fileHandleForWriting
            defer { try? writer.close() }
            let fd = writer.fileDescriptor
            guard fcntl(fd, F_SETFL, O_NONBLOCK) >= 0, fcntl(fd, F_SETNOSIGPIPE, 1) >= 0 else {
                throw AIProcessInventoryFailure.readFailed
            }
            var sent = 0
            while sent < input.count {
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw AIProcessInventoryFailure.timeout }
                let count = input.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: sent), input.count - sent) }
                if count > 0 { sent += count; continue }
                guard count < 0 && (errno == EAGAIN || errno == EINTR) else { throw AIProcessInventoryFailure.readFailed }
                var writable = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                _ = poll(&writable, 1, 20)
            }
        }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 65_536)
        var eof = false
        while !eof || task.isRunning {
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                throw AIProcessInventoryFailure.timeout
            }
            if !eof {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
                if count > 0 {
                    guard data.count + count <= maxBytes else { throw AIProcessInventoryFailure.outputTooLarge }
                    data.append(contentsOf: buffer.prefix(count))
                    continue
                }
                if count == 0 { eof = true }
                else if errno != EAGAIN && errno != EINTR { throw AIProcessInventoryFailure.readFailed }
            }
            if eof && !task.isRunning { break }
            var pollfd = pollfd(fd: eof ? -1 : descriptor, events: Int16(POLLIN), revents: 0)
            let remaining = max(1, min(100, Int((deadline - ProcessInfo.processInfo.systemUptime) * 1_000)))
            if poll(&pollfd, 1, Int32(remaining)) < 0 && errno != EINTR {
                throw AIProcessInventoryFailure.readFailed
            }
        }
        task.waitUntilExit()
        guard task.terminationStatus == 0 else { throw AIProcessInventoryFailure.commandFailed }
        return data
    }

    static func runEngine(_ args: [String], input: Data? = nil, timeout: TimeInterval) throws -> Data {
        guard let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil),
              FileManager.default.isExecutableFile(atPath: engine.path) else { throw AIProcessInventoryFailure.engineUnavailable }
        return try command(engine, arguments: args, deadline: ProcessInfo.processInfo.systemUptime + timeout, input: input)
    }
}

#if !PROCESS_HELPER
@MainActor
final class AIProcessControl: ObservableObject {
    typealias Command = @Sendable ([String], Data?, TimeInterval) throws -> Data
    @Published private(set) var busy = false
    let isFixture: Bool
    private let command: Command
    init(isFixture: Bool = false, command: @escaping Command = { args, input, timeout in
        try AIProcessInventory.runEngine(args, input: input, timeout: timeout)
    }) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
        self.command = command
    }
    func prepare(_ product: MonitoredProduct, sampled: [WatchedProcess], backendPID: Int?) async throws -> AIProcessClosePlan {
        guard !busy else { throw CancellationError() }
        busy = true; defer { busy = false }
        if isFixture {
            return .init(product: product, targets: sampled.filter { $0.product == product }.map {
                .init(pid: Int32($0.pid), parent: 1, uid: getuid(), startSeconds: 1, startMicroseconds: 0, executable: "/mock/" + $0.name)
            }, requestID: UUID().uuidString, payload: Data(), force: true)
        }
        var args = ["process-exit", "prepare", "--force", "--family", AIProcessClosePlan.family(product)]
        if let pid = backendPID, pid > 1 { args += ["--protect-pid", String(pid)] }
        let run = command, arguments = args
        let data = try await Task.detached(priority: .userInitiated) { try run(arguments, nil, 20) }.value
        let plan = try AIProcessClosePlan.decode(data, product: product)
        guard plan.force else { throw AIProcessInventoryFailure.malformed }
        return plan
    }
    func execute(_ plan: AIProcessClosePlan) async -> String {
        guard plan.force else { return "退出方式未确认：此按钮需要后台生成的强制结束计划。" }
        guard !busy else { return "已有关闭操作正在进行。" }
        busy = true; defer { busy = false }
        if isFixture { return "模拟强制结束 \(plan.targets.count) 个 \(plan.product.title) 进程；未向任何系统进程发送信号。" }
        do {
            let run = command
            let data = try await Task.detached(priority: .userInitiated) {
                try run(["process-exit", "apply", "--apply", "--force"], plan.payload, 45)
            }.value
            return try AIProcessExitReceipt.decode(data, plan: plan).message
        } catch { return "退出结果未确认：\(error.localizedDescription)" }
    }
}
#endif
#endif
