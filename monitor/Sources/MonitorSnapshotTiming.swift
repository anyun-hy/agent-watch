import Foundation

/// Evaluate the original capture time on publication and at its deadline.
enum MonitorSnapshotTiming {
    static let snapshotMaximumAge: TimeInterval = 8
    static let proxyMaximumAge: TimeInterval = 30
    static func isCurrent(capturedAt: Double, now: Double, maximumAge: Double = snapshotMaximumAge) -> Bool {
        let elapsed = now - capturedAt
        return elapsed >= 0 && elapsed < maximumAge
    }
}
