import Foundation

/// Debounces snapshot-derived proxy context before starting a costly
/// environment observation. Empty/transient contexts never count as a change.
struct EnvironmentRefreshScheduler {
    static let interval: TimeInterval = 60
    enum Trigger: Equatable { case initial, changed, interval, retry }
    private(set) var stableContext: String?
    private var candidateContext: String?
    private var consecutiveCandidateCount = 0
    private var candidateSample: Date?
    private var expiresAt: Date?
    var nextCheck: Date? { inFlight ? nil : retryAfter ?? expiresAt }
    private var retryAfter: Date?
    private var failures = 0
    private(set) var inFlight = false
    var isInFlight: Bool { inFlight }

    mutating func requestRefresh() {
        expiresAt = nil
    }

    mutating func claim(context: String?, now: Date, switcherBusy: Bool, observedAt: Date? = nil) -> Trigger? {
        guard !inFlight, !switcherBusy else { return nil }
        guard let context, !context.isEmpty else {
            candidateContext = nil; candidateSample = nil; consecutiveCandidateCount = 0
            return nil
        }
        let sample = observedAt ?? now
        if context != candidateContext {
            candidateContext = context; candidateSample = sample; consecutiveCandidateCount = 1
        } else if candidateSample.map({ sample > $0 }) ?? true {
            candidateSample = sample; consecutiveCandidateCount = 2
        }
        guard consecutiveCandidateCount >= 2 else { return nil }
        let trigger: Trigger
        if let retryAfter {
            guard now >= retryAfter else { return nil }
            trigger = .retry
        } else if stableContext == nil { trigger = .initial }
        else if stableContext != context { trigger = .changed }
        else if expiresAt.map({ now >= $0 }) ?? true { trigger = .interval }
        else { return nil }
        inFlight = true
        return trigger
    }

    mutating func complete(context: String?, accepted: Bool, now: Date, validUntil: Double? = nil) {
        inFlight = false
        guard accepted, let context, !context.isEmpty else {
            failures += 1
            retryAfter = now.addingTimeInterval(min(30, Double(5 * (1 << min(failures - 1, 2)))))
            return
        }
        stableContext = context
        candidateContext = context
        consecutiveCandidateCount = max(consecutiveCandidateCount, 2)
        expiresAt = validUntil.flatMap { $0.isFinite ? Date(timeIntervalSince1970: $0) : nil } ?? now.addingTimeInterval(Self.interval)
        retryAfter = nil
        failures = 0
    }
}
