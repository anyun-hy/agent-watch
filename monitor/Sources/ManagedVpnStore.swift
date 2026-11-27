import Foundation
import Combine

enum ManagedVpnMode: String, Codable, CaseIterable, Identifiable {
    case external
    case managed

    var id: String { rawValue }

    var title: String {
        switch self {
        case .external: return "复用本机 VPN"
        case .managed: return "独立内置 VPN（不影响本机）"
        }
    }
}

struct ManagedVpnCoreStatus: Codable, Equatable {
    let available: Bool
    let source: String?
    let sha256_prefix: String?
    let error_code: String?
    let message: String?
}

struct ManagedVpnRuntimeInfo: Codable, Equatable {
    let schema: Int?
    let mode: String
    let state: String
    let pid: UInt32?
    let node_id: String?
    let node_name: String?
    let protocol_label: String?
    let upstream_endpoint: String?
    let started_at: Double?
    let updated_at: Double?
    let error_code: String?
    let error_message: String?
}

struct ManagedVpnServiceSummary: Codable, Equatable {
    let configured: Bool
    let label: String
    let host: String
    let has_token: Bool
    let last_synced_at: UInt64?
    let last_error: String?
    let notice: String?
}

struct ManagedVpnNodeProbe: Codable, Equatable {
    let latency_ms: UInt64?
    let egress_ip: String?
    let country: String?
    let region: String?
    let isp: String?
    let checked_at: Double?
    let error: String?
}

struct ManagedVpnNode: Codable, Equatable, Identifiable {
    let id: String
    let name: String
    let provider_kind: String
    let source_id: String?
    let `protocol`: String
    let protocol_label: String
    let server_masked: String
    let port: UInt16
    let sni: String?
    let fingerprint: String?
    let flow: String?
    let reality: Bool
    let protocol_note: String?
    let probe: ManagedVpnNodeProbe?

    var isBuiltinService: Bool { provider_kind == "builtin_service" }
}

struct ManagedVpnStatusPayload: Codable, Equatable {
    let status: String
    let mode: String
    let runtime: ManagedVpnRuntimeInfo
    let core: ManagedVpnCoreStatus
    let service: ManagedVpnServiceSummary
    let selected_node: ManagedVpnNode?
    let node_count: Int
    let nodes: [ManagedVpnNode]
}

struct ManagedVpnImportPreviewPayload: Codable, Equatable {
    let status: String
    let preview: Bool?
    let count: Int
    let nodes: [ManagedVpnNode]
}

struct ManagedVpnProbeResponse: Codable, Equatable {
    let status: String
    let id: String
    let name: String
    let probe: ManagedVpnNodeProbe
}

/// Thin UI state adapter for `watch-engine vpn ...`.
/// Never parses credentials, never spawns `watch-vpn-core`, and never stores secrets.
@MainActor
final class ManagedVpnStore: ObservableObject {
    let isFixture: Bool

    @Published private(set) var mode: ManagedVpnMode = .external
    @Published private(set) var runtime: ManagedVpnRuntimeInfo?
    @Published private(set) var core: ManagedVpnCoreStatus?
    @Published private(set) var service: ManagedVpnServiceSummary?
    @Published private(set) var selectedNode: ManagedVpnNode?
    @Published private(set) var nodes: [ManagedVpnNode] = []
    @Published private(set) var busy = false
    @Published private(set) var probingNodeIDs: Set<String> = []
    @Published private(set) var message: String = ""
    @Published private(set) var errorMessage: String?

    init(isFixture: Bool = false) {
        self.isFixture = isFixture
        if isFixture {
            self.mode = .external
            self.core = ManagedVpnCoreStatus(available: true, source: "fixture", sha256_prefix: "fixture00000", error_code: nil, message: nil)
            self.service = ManagedVpnServiceSummary(configured: false, label: "", host: "", has_token: false, last_synced_at: nil, last_error: nil, notice: nil)
            self.runtime = ManagedVpnRuntimeInfo(schema: 1, mode: "external", state: "inactive", pid: nil, node_id: nil, node_name: nil, protocol_label: nil, upstream_endpoint: nil, started_at: nil, updated_at: nil, error_code: nil, error_message: nil)
        }
    }

    var selectedNodeID: String? { selectedNode?.id }
    var builtinNodes: [ManagedVpnNode] { nodes.filter(\.isBuiltinService) }
    var customNodes: [ManagedVpnNode] { nodes.filter { !$0.isBuiltinService } }

    func refresh() async {
        guard !isFixture else { return }
        do {
            let data = try await runCommand(["vpn", "status"])
            let decoded = try JSONDecoder().decode(ManagedVpnStatusPayload.self, from: data)
            applyStatus(decoded)
            errorMessage = nil
        } catch {
            errorMessage = extractErrorMessage(error)
        }
    }

    func setMode(_ target: ManagedVpnMode) async {
        guard !isFixture else {
            mode = target
            message = target == .managed ? "已切换为独立内置 VPN 模式（示例）" : "已切换为复用本机 VPN 模式（示例）"
            return
        }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            let data = try await runCommand(["vpn", "mode", "--mode", target.rawValue, "--apply"])
            message = extractMessage(from: data) ?? (target == .managed ? "已切换为独立内置 VPN 模式" : "已切换为复用本机 VPN 模式")
            await refresh()
        } catch {
            errorMessage = extractErrorMessage(error)
        }
    }

    func previewImport(text: String, provider: String = "custom") async -> Result<[ManagedVpnNode], Error> {
        guard !isFixture else { return .success([]) }
        do {
            let body = try JSONSerialization.data(withJSONObject: ["text": text])
            let data = try await runCommand(["vpn", "import", "--preview", "--provider", provider], input: body)
            let decoded = try JSONDecoder().decode(ManagedVpnImportPreviewPayload.self, from: data)
            return .success(decoded.nodes)
        } catch {
            return .failure(error)
        }
    }

    func commitImport(text: String?, url: String?, provider: String = "custom") async -> Bool {
        guard !isFixture else { return true }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            var payload: [String: Any] = [:]
            if let text, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                payload["text"] = text
            }
            if let url, !url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                payload["url"] = url
            }
            let body = try JSONSerialization.data(withJSONObject: payload)
            let data = try await runCommand(["vpn", "import", "--apply", "--provider", provider], input: body)
            message = extractMessage(from: data) ?? "节点导入完成"
            await refresh()
            return true
        } catch {
            errorMessage = extractErrorMessage(error)
            return false
        }
    }

    func selectNode(id: String) async {
        guard !isFixture else { return }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            let data = try await runCommand(["vpn", "select", "--id", id, "--apply"])
            message = extractMessage(from: data) ?? "已切换独立节点"
            await refresh()
        } catch {
            errorMessage = extractErrorMessage(error)
        }
    }

    func deleteNode(id: String) async {
        guard !isFixture else { return }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            let data = try await runCommand(["vpn", "delete", "--id", id, "--apply"])
            message = extractMessage(from: data) ?? "已删除节点"
            await refresh()
        } catch {
            errorMessage = extractErrorMessage(error)
        }
    }

    func probeNode(id: String) async {
        guard !isFixture else { return }
        probingNodeIDs.insert(id)
        errorMessage = nil
        defer { probingNodeIDs.remove(id) }
        do {
            let data = try await runCommand(["vpn", "probe", "--id", id])
            _ = try? JSONDecoder().decode(ManagedVpnProbeResponse.self, from: data)
            await refresh()
        } catch {
            errorMessage = extractErrorMessage(error)
        }
    }

    func saveAndSyncBuiltinService(url: String, token: String, label: String) async -> Bool {
        guard !isFixture else { return true }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            var payload: [String: Any] = ["url": url.trimmingCharacters(in: .whitespacesAndNewlines)]
            if !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                payload["token"] = token.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            if !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                payload["label"] = label.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            let body = try JSONSerialization.data(withJSONObject: payload)
            _ = try await runCommand(["vpn", "service-set", "--apply"], input: body)
            let syncData = try await runCommand(["vpn", "service-sync", "--apply"])
            if let obj = try? JSONSerialization.jsonObject(with: syncData) as? [String: Any],
               let count = obj["count"] as? Int {
                message = "自带 VPN 服务已同步，共获取 \(count) 个节点"
            } else {
                message = "自带 VPN 服务已保存并同步"
            }
            await refresh()
            return true
        } catch {
            errorMessage = extractErrorMessage(error)
            await refresh()
            return false
        }
    }

    func syncBuiltinService() async {
        guard !isFixture else { return }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            let syncData = try await runCommand(["vpn", "service-sync", "--apply"])
            if let obj = try? JSONSerialization.jsonObject(with: syncData) as? [String: Any],
               let count = obj["count"] as? Int {
                message = "自带 VPN 服务同步完成（共 \(count) 个节点）"
            } else {
                message = "自带 VPN 服务同步完成"
            }
            await refresh()
        } catch {
            errorMessage = extractErrorMessage(error)
            await refresh()
        }
    }

    func clearBuiltinService() async {
        guard !isFixture else { return }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            let data = try await runCommand(["vpn", "service-clear", "--apply"])
            message = extractMessage(from: data) ?? "已清除自带 VPN 服务配置"
            await refresh()
        } catch {
            errorMessage = extractErrorMessage(error)
        }
    }

    private func applyStatus(_ payload: ManagedVpnStatusPayload) {
        mode = ManagedVpnMode(rawValue: payload.mode) ?? .external
        runtime = payload.runtime
        core = payload.core
        service = payload.service
        selectedNode = payload.selected_node
        nodes = payload.nodes
    }

    private func runCommand(_ args: [String], input: Data? = nil) async throws -> Data {
        try await Task.detached(priority: .userInitiated) {
            try SwitcherCommandRunner.run(args, input: input)
        }.value
    }

    private func extractMessage(from data: Data) -> String? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj["message"] as? String
    }

    private func extractErrorMessage(_ error: Error) -> String {
        let raw = error.localizedDescription
        if let data = raw.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let msg = obj["message"] as? String, !msg.isEmpty {
            return msg
        }
        return raw
    }
}
