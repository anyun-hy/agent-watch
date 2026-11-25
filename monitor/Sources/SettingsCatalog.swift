import Foundation

/// A typed handle for one configuration key.
///
/// A key is declared once here and referenced by handle everywhere else, so a
/// call site cannot misspell a name and a rename cannot leave a stale literal
/// behind. Reading is a table lookup, never a chain of comparisons on an id.
struct FlagSetting: Hashable {
    let key: String
}

struct TextSetting: Hashable {
    let key: String
}

/// A three-state action. The fallback is the value assumed when the key is
/// absent, and it belongs to the service the key belongs to.
struct ChoiceSetting: Hashable {
    let key: String
    let fallback: String
}

enum Setting {
    static let enabled = FlagSetting(key: "enabled")
    static let guardEnabled = FlagSetting(key: "guard_enabled")
    static let timezoneWatchdog = FlagSetting(key: "timezone_watchdog")
    static let autoUpdate = FlagSetting(key: "auto_update")
    static let returnToOverview = FlagSetting(key: "return_to_overview_after_launch")
    static let requireIPv6Off = FlagSetting(key: "require_ipv6_off")
    static let requireEnglish = FlagSetting(key: "require_english")
    static let requireDNS = FlagSetting(key: "require_dns")
    static let requireStun = FlagSetting(key: "require_stun")
    static let requirePinnedRules = FlagSetting(key: "require_pinned_rules")
    static let gptRequireIPv6Off = FlagSetting(key: "gpt_require_ipv6_off")
    static let gptRequireDNS = FlagSetting(key: "gpt_require_dns")
    static let gptRequireStun = FlagSetting(key: "gpt_require_stun")
    static let gptRequirePinnedRules = FlagSetting(key: "gpt_require_pinned_rules")
    static let updateURL = TextSetting(key: "update_url")
    static let updatePublicKey = TextSetting(key: "update_public_key")
    static let country = TextSetting(key: "country")
    static let locale = TextSetting(key: "locale")
    static let networkBackend = ChoiceSetting(key: "network_backend", fallback: "seatbelt")
}

/// How one background service is presented and which setting its switch owns.
///
/// The services differ, and the difference is declared here: a lookup by id
/// replaces comparisons against `service.id` scattered through the view.
enum BackgroundServiceCatalog {
    struct Descriptor {
        let symbol: String
        /// The setting this service's switch writes. `nil` marks a service
        /// that is only reported on and has no switch of its own.
        let toggle: FlagSetting?
        let enableTitle: String
        let disableTitle: String
        let syncTitle: String
        /// Shown instead of a switch when the service has none.
        let note: String?
        /// A service whose switch only makes sense once the watch itself is
        /// enabled.
        let requiresEnabled: Bool
        /// A service that cannot be switched on before its release source is
        /// configured.
        let requiresSource: Bool
    }
    static let byID: [String: Descriptor] = [
        "guard": .init(
            symbol: "shield.lefthalf.filled", toggle: Setting.guardEnabled,
            enableTitle: "启用保护", disableTitle: "预览停用保护", syncTitle: "预览同步后台状态",
            note: nil, requiresEnabled: true, requiresSource: false),
        "watchdog": .init(
            symbol: "clock.badge.checkmark", toggle: Setting.timezoneWatchdog,
            enableTitle: "预览启用", disableTitle: "预览停用", syncTitle: "预览同步后台状态",
            note: nil, requiresEnabled: false, requiresSource: false),
        "updater": .init(
            symbol: "arrow.down.circle", toggle: Setting.autoUpdate,
            enableTitle: "预览启用", disableTitle: "预览停用", syncTitle: "预览同步后台状态",
            note: nil, requiresEnabled: false, requiresSource: true),
        "original": .init(
            symbol: "link", toggle: nil,
            enableTitle: "", disableTitle: "", syncTitle: "",
            note: "原版独立管理，与 Agent Watch 保持并行", requiresEnabled: false, requiresSource: false),
    ]
    /// Unknown ids keep the generic shield and get no switch rather than
    /// falling back to a guessed key.
    static func descriptor(_ id: String) -> Descriptor {
        byID[id] ?? .init(symbol: "shield.lefthalf.filled", toggle: nil,
                          enableTitle: "", disableTitle: "", syncTitle: "",
                          note: nil, requiresEnabled: false, requiresSource: false)
    }
}

struct PrelaunchGateDescriptor: Identifiable {
    let id: String
    let title: String
    let detail: String
    let symbol: String
    let setting: FlagSetting
    let fallback: FlagSetting?
    let badge: String?

    static func descriptors(for product: MonitoredProduct) -> [PrelaunchGateDescriptor] {
        switch product {
        case .claude:
            return [
                .init(id: "claude_ipv6", title: "要求 IPv6 已关闭",
                      detail: "防止双栈网络下 IPv6 旁路直连", symbol: "network.slash",
                      setting: Setting.requireIPv6Off, fallback: nil, badge: nil),
                .init(id: "claude_english", title: "要求客户端使用英文",
                      detail: "核对客户端首选语言为 en-US", symbol: "character.bubble",
                      setting: Setting.requireEnglish, fallback: nil, badge: "Claude 专属"),
                .init(id: "claude_rules", title: "要求代理规则覆盖通过",
                      detail: "核验 TAG 规则表命中 Claude 域名", symbol: "arrow.triangle.branch",
                      setting: Setting.requirePinnedRules, fallback: nil, badge: nil),
                .init(id: "claude_dns", title: "要求 DNS 递归出口无泄漏",
                      detail: "启动前要求 DNS 探针递归出口通过", symbol: "server.rack",
                      setting: Setting.requireDNS, fallback: nil, badge: nil),
                .init(id: "claude_stun", title: "要求 UDP / STUN 出口一致",
                      detail: "启动前要求 STUN 探针无真实 IP 暴露", symbol: "waveform.path.ecg",
                      setting: Setting.requireStun, fallback: nil, badge: nil)
            ]
        case .openAI:
            return [
                .init(id: "gpt_ipv6", title: "要求 IPv6 已关闭",
                      detail: "防止双栈网络下 IPv6 旁路直连", symbol: "network.slash",
                      setting: Setting.gptRequireIPv6Off, fallback: Setting.requireIPv6Off, badge: nil),
                .init(id: "gpt_rules", title: "要求代理规则覆盖通过",
                      detail: "核验 TAG 规则表覆盖 ChatGPT / Codex", symbol: "arrow.triangle.branch",
                      setting: Setting.gptRequirePinnedRules, fallback: Setting.requirePinnedRules, badge: nil),
                .init(id: "gpt_dns", title: "要求 DNS 递归出口无泄漏",
                      detail: "启动前要求 DNS 探针递归出口通过", symbol: "server.rack",
                      setting: Setting.gptRequireDNS, fallback: Setting.requireDNS, badge: nil),
                .init(id: "gpt_stun", title: "要求 UDP / STUN 出口一致",
                      detail: "启动前要求 STUN 探针无真实 IP 暴露", symbol: "waveform.path.ecg",
                      setting: Setting.gptRequireStun, fallback: Setting.requireStun, badge: nil)
            ]
        }
    }
}
