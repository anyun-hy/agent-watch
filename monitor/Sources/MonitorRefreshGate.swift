import Foundation

/// Coalesces reads while keeping automatic synchronization visually silent.
struct MonitorRefreshGate {
    private(set) var reading = false
    private(set) var manualVisible = false
    private var queued = false
    private var manualQueued = false

    mutating func request(manual: Bool) -> Bool {
        if reading {
            queued = true
            if manual {
                manualQueued = true
                manualVisible = true
            }
            return false
        }
        reading = true
        manualVisible = manual
        return true
    }

    /// An event during a read needs one trailing read, even without a manual request.
    mutating func complete() -> Bool {
        reading = false
        manualVisible = manualQueued
        manualQueued = false
        defer { queued = false }
        return queued
    }
}
