import Foundation

enum PanoramaFocusSection: String, CaseIterable, Identifiable {
    case all = "全景总览"
    case ipIntel = "IP 深度画像"
    case aiEndpoints = "AI 端点与协议栈"
    case leaks = "DNS / WebRTC 泄漏取证"
    var id: String { rawValue }
}

enum Page: String, CaseIterable {
    case overview = "监控概览", network = "代理与连接", processes = "进程活动", events = "事件记录"
    case panorama = "网络全景诊断"
    case dns = "DNS 泄漏检测", webrtc = "WebRTC 泄漏检测"
    case ipScore = "IP 评分"
    case claudeAI = "Claude AI 检测", gptAI = "GPT / Codex 检测"
    case switcher = "启动与账号", environment = "环境状态", protection = "保护与设置"

    static let primaryPages: [Page] = [.environment, .switcher, .protection]
    static let monitorPages: [Page] = [.network, .processes, .events]
    static let diagnosticPages: [Page] = [.panorama]
    static var orderedPages: [Page] { primaryPages + monitorPages + diagnosticPages }

    static func restored(_ value: String) -> Page {
        switch value {
        case "安全启动与账号", "监控概览": return .environment
        case "后台保护", "保护与设置": return .protection
        case "网络全景诊断", "AI 连通检测", "Claude AI 检测", "GPT / Codex 检测", "泄漏检测", "DNS 泄漏检测", "WebRTC 泄漏检测", "IP 评分":
            return .panorama
        default:
            return Page(rawValue: value) ?? .environment
        }
    }

    var isPrimary: Bool { Self.primaryPages.contains(self) }
    var isLeakCheck: Bool { self == .dns || self == .webrtc }
    var isDiagnosticWorkbench: Bool {
        switch self {
        case .panorama, .dns, .webrtc, .ipScore, .claudeAI, .gptAI: return true
        default: return false
        }
    }
    var isManualCheck: Bool { isDiagnosticWorkbench || isPrimary }

    var sidebarTitle: String {
        if isDiagnosticWorkbench { return "网络全景诊断" }
        return rawValue
    }

    func matchesSidebarItem(_ item: Page) -> Bool {
        if item == .panorama { return isDiagnosticWorkbench }
        return self == item
    }

    var symbol: String {
        switch self {
        case .overview: return "square.grid.2x2"
        case .network: return "point.3.connected.trianglepath.dotted"
        case .processes: return "waveform.path"
        case .events: return "clock.arrow.circlepath"
        case .panorama: return "waveform.badge.magnifyingglass"
        case .dns: return "server.rack"
        case .webrtc: return "antenna.radiowaves.left.and.right"
        case .switcher: return "person.text.rectangle"
        case .environment: return "globe.asia.australia"
        case .protection: return "slider.horizontal.3"
        case .claudeAI: return "sparkles"
        case .ipScore: return "gauge.with.dots.needle.50percent"
        case .gptAI: return "terminal"
        }
    }

    var caption: String {
        switch self {
        case .overview: return "后台状态、入口与当前检测结果"
        case .network: return "区分代理设置与实际连接证据"
        case .processes: return "Claude 及关联进程的最近一次采样"
        case .events: return "查看和筛选本地保留的事件与检测记录"
        case .panorama, .dns, .webrtc, .ipScore, .claudeAI, .gptAI:
            return "一键并发核验权威 IP 纯净度画像、AI 全端点协议栈及 DNS / WebRTC 全栈防泄漏证据"
        case .switcher: return "Claude 与 ChatGPT 账号、Claude 启动条件"
        case .environment: return "自动识别代理，核对本轮实测环境"
        case .protection: return "统一管理守护底座、AI 专属 VPN 双模式、启动门禁与风控策略"
        }
    }
}
