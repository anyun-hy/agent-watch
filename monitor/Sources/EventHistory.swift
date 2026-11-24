import AppKit
import Foundation

struct EventHistoryRequest: Encodable, Sendable {
    let filter, query: String
    let offset: Int
}

struct EventHistoryResponse: Decodable, Sendable {
    let status: String
    let events: [Event]
    let total, nextOffset: Int
    let hasMore: Bool
    let invalidRecords: Int
}

enum EventHistoryRead: Sendable {
    case success(EventHistoryResponse)
    case failure
}

enum EventHistoryRunner {
    static func read(_ request: EventHistoryRequest) -> EventHistoryRead {
        do {
            let input = try JSONEncoder().encode(request)
            // Search text goes through stdin, not process arguments or a log.
            let data = try SwitcherCommandRunner.run(["event-history"], input: input)
            let response = try JSONDecoder().decode(EventHistoryResponse.self, from: data)
            guard response.status == "ok" else { return .failure }
            return .success(response)
        } catch {
            return .failure
        }
    }
}

enum DiagnosticExportResult: Sendable {
    case success(url: URL, message: String)
    case failure(message: String)
}

enum DiagnosticExportRunner {
    static func write(to url: URL) -> DiagnosticExportResult {
        do {
            let data = try SwitcherCommandRunner.run(["diagnostic-export", "--export", url.path])
            let response = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let status = response?["status"] as? String
            let message = (response?["message"] as? String)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if status == "ok" {
                return .success(
                    url: url,
                    message: (message?.isEmpty == false ? message! : "诊断包已导出；缺失和截断证据已单独标明")
                )
            }
            return .failure(
                message: (message?.isEmpty == false ? message! : "诊断导出失败。请检查保存位置权限，并使用一个不存在的新文件名。")
            )
        } catch {
            let detail = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
            return .failure(
                message: detail.isEmpty
                    ? "诊断导出失败。请检查保存位置权限，并使用一个不存在的新文件名。"
                    : "诊断导出失败：\(detail)"
            )
        }
    }

    @MainActor static func pickDestinationURL() -> URL? {
        let panel = NSSavePanel()
        panel.title = "导出排障诊断包"
        panel.message = "仅导出经过脱敏筛选的本地运行与状态记录；不会重新检测网络。请选择新文件，已有文件不会被覆盖。"
        panel.nameFieldStringValue = "AgentWatch-diagnostics-\(Int(Date().timeIntervalSince1970)).json"
        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    @MainActor static func revealInFinder(_ url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}
