import Foundation
import Combine
import SwiftUI

/// Manages opt-in controlled entry wrappers for AI desktop applications.
/// Original apps in /Applications remain untouched.
@MainActor
final class ManagedEntryControl: ObservableObject {
    @Published private(set) var isGenerated: Bool = false
    @Published private(set) var isConfigured: Bool = false
    @Published private(set) var statusLabel: String = "未配置"
    @Published private(set) var entryPath: String = ""
    @Published private(set) var candidateSources: [String] = []
    @Published private(set) var busy: Bool = false
    @Published private(set) var errorMessage: String? = nil
    
    var hasMultipleSources: Bool { candidateSources.count > 1 }
    
    let isFixture: Bool

    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
    }
    
    static func target(for product: MonitoredProduct) -> String {
        product == .claude ? "claude-desktop" : "chatgpt-desktop"
    }

    func refresh(for product: MonitoredProduct) async {
        if isFixture {
            isGenerated = false
            statusLabel = "受控入口未生成"
            entryPath = "/mock/Applications/\(product.title) (Controlled).app"
            return
        }
        let t = Self.target(for: product)
        do {
            let data = try await Task.detached(priority: .utility) {
                try AIProcessInventory.runEngine(["entry", "status", "--target", t], timeout: 10)
            }.value
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                if let report = json["status_report"] as? [String: Any] {
                    self.isGenerated = report["entry_generated"] as? Bool ?? false
                    self.isConfigured = report["activation_configured"] as? Bool ?? false
                    self.statusLabel = report["status_label"] as? String ?? "状态未知"
                    self.entryPath = report["entry_path"] as? String ?? ""
                    self.errorMessage = nil
                }
                if let sources = json["candidate_sources"] as? [String] {
                    self.candidateSources = sources
                }
            }
        } catch {
            self.errorMessage = error.localizedDescription
        }
    }

    func setEnabled(_ enable: Bool, for product: MonitoredProduct) async -> Bool {
        guard !busy else { return false }
        busy = true
        defer { busy = false }
        let t = Self.target(for: product)
        let action = enable ? "activate" : "deactivate"
        let args = ["entry", action, "--target", t, "--apply"]
        if isFixture {
            try? await Task.sleep(nanoseconds: 300_000_000)
            isGenerated = enable
            isConfigured = enable
            statusLabel = enable ? "入口已生成，等待实际调用" : "受控入口未生成"
            return true
        }
        do {
            let data = try await Task.detached(priority: .userInitiated) {
                try AIProcessInventory.runEngine(args, timeout: 25)
            }.value
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                if let status = json["status"] as? String, status == "ok" {
                    await refresh(for: product)
                    return true
                } else if let msg = json["message"] as? String {
                    self.errorMessage = msg
                    await refresh(for: product)
                    return false
                }
            }
            await refresh(for: product)
            return true
        } catch {
            self.errorMessage = "操作未完成：\(error.localizedDescription)"
            await refresh(for: product)
            return false
        }
    }
}
