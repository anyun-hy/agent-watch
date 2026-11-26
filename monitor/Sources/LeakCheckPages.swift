import SwiftUI

struct DNSLeakPage: View {
    @ObservedObject var store: LeakCheckStore
    let p: Palette
    var switchKind: ((LeakKind) -> Void)? = nil
    var body: some View { LeakInspectorPage(kind: .dns, store: store, p: p, switchKind: switchKind) }
}
struct WebRTCLeakPage: View {
    @ObservedObject var store: LeakCheckStore
    let p: Palette
    var switchKind: ((LeakKind) -> Void)? = nil
    var body: some View { LeakInspectorPage(kind: .webrtc, store: store, p: p, switchKind: switchKind) }
}

/// Displays daemon-owned evidence and submits user detection requests.
private struct LeakInspectorPage: View {
    let kind: LeakKind
    @ObservedObject var store: LeakCheckStore
    let p: Palette
    var switchKind: ((LeakKind) -> Void)? = nil
    @ObservedObject private var diagnosticLog = DiagnosticLogStatus.shared
    @State private var detailsExpanded = false
    @State private var localExpanded = false
    private var isDNS: Bool { kind == .dns }
    private var isIPLeak: Bool { isDNS }
    private var state: LeakCheckState { isDNS ? store.dns : store.rtc }
    private var currentProgress: String? { store.progress[kind] }
    // The latest result remains authoritative for the verdict and backend record.
    // The display result may be the previous good sample after a collector failure.
    private var latestResult: LeakProbeResult? { state.result }
    private var result: LeakProbeResult? { state.displayResult }
    private var showingPreviousSuccessfulResult: Bool { state.displaysPreviousSuccessfulResult }
    private var style: InspectorStyle { .init(p: p) }
    private var title: String { isDNS ? "DNS 泄漏检测" : "WebRTC 泄漏检测" }
    private var expected: Binding<String> { Binding(get: { store.rtcExpected }, set: { store.rtcExpected = $0 }) }
    private var countryCodes: [String:String] { CountryIdentity.geoCodes(result?.externalJSON) }
    private var observations: [LeakObservation] { result?.observations ?? [] }
    private var reference: [LeakObservation] { observations.filter { $0.kind.lowercased() == "http" } }
    private var detected: [LeakObservation] { observations.filter { $0.kind.lowercased() != "http" } }
    private var local: [LeakObservation] { detected.filter(isLocal) }
    private var principal: [LeakObservation] { detected.filter { !isLocal($0) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let switchKind {
                HStack(spacing: 4) {
                    ForEach([LeakKind.dns, LeakKind.webrtc], id: \.self) { candidate in
                        let selected = candidate == kind
                        Button {
                            switchKind(candidate)
                        } label: {
                            HStack(spacing: 6) {
                                Image(systemName: candidate == .dns ? Page.dns.symbol : Page.webrtc.symbol)
                                    .font(.system(size: 12, weight: .medium))
                                Text(candidate == .dns ? "DNS 递归出口" : "WebRTC 候选")
                                    .font(selected ? WatchTypography.captionStrong : WatchTypography.caption)
                            }
                            .foregroundStyle(selected ? p.text : p.secondary)
                            .padding(.horizontal, 12).padding(.vertical, 6)
                            .background(selected ? p.surface : Color.clear, in: RoundedRectangle(cornerRadius: 7))
                            .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(selected ? p.border.opacity(0.85) : Color.clear, lineWidth: 1))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                    Spacer()
                }
                .padding(3)
                .background(p.elevated, in: RoundedRectangle(cornerRadius: 9))
            }
            InspectorHeading(title: title,
                subtitle: isDNS ? "递归解析出口 · 与同轮公网出口国家核对" : "当前检测 WebView · ICE / STUN 与 HTTP 出口核对",
                p: p) {
                    Button {
                        state.running ? store.cancel(kind) : store.start(kind)
                    } label: {
                        Label(state.running ? "取消检测" : isDNS ? "检测 DNS" : "检测 WebRTC",
                              systemImage: state.running ? "stop.fill" : "play.fill").font(WatchTypography.bodyStrong)
                    }.buttonStyle(.borderedProminent).tint(style.action)
                        .accessibilityLabel(state.running ? "取消\(title)" : latestResult == nil ? "开始\(title)" : "重新运行\(title)")
                }
            if state.running, let progress = currentProgress { Label(progress,systemImage:"arrow.triangle.2.circlepath").font(.callout).foregroundStyle(style.network) }
            InspectorStatus(verdict: state.verdict, running: state.running,
                            source: isDNS ? "DNS · 递归解析器" : "WebRTC · ICE / STUN",
                            symbol: isDNS ? Page.dns.symbol : Page.webrtc.symbol, p: p)
            SamplingEvidence(source: isDNS ? "IPLeak · 本机 WebView 查询" : "本机 WebView · ICE 候选",
                             timeLabel: showingPreviousSuccessfulResult ? "上次有效样本" : state.running ? "上次完成" : "完成于",
                             timestamp: result?.finishedAt, p: p)
            if let error = diagnosticLog.error ?? LeakDiagnosticTrace.shared.error {
                Label(error, systemImage: "exclamationmark.triangle").font(WatchTypography.caption).foregroundStyle(p.amber)
            }
            if showingPreviousSuccessfulResult, let previous = result {
                let latestSuffix = latestResult.map { "（\(probeTime($0.finishedAt))）" } ?? ""
                let previousTime = probeTime(previous.finishedAt)
                Label("本轮查询\(latestSuffix)未完成。下方显示上次有效样本（\(previousTime)），启动预检采用本轮结果。", systemImage: "clock.arrow.circlepath")
                    .font(.callout).foregroundStyle(p.amber).fixedSize(horizontal: false, vertical: true)
            }
            if latestResult?.contextChanged == true {
                Label("检测期间网络环境发生变化，本轮结果需重新核对。", systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(p.amber)
            }
            if let diagnostic = store.diagnostics[kind] {
                Text(diagnostic).font(.callout).foregroundStyle(p.secondary)
            }
            addressComparison
            if !local.isEmpty {
                DisclosureGroup(isExpanded: $localExpanded) {
                    observationList(local).padding(.top, 8)
                } label: {
                    Label("本地与 mDNS 候选（\(local.count)）", systemImage: "desktopcomputer")
                        .font(.callout.weight(.medium)).foregroundStyle(style.location)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
            if !isDNS { settings }
            details
            Label(isDNS ? "本机 WebView 发起查询，IPLeak 返回 DNS 观测；不代表所有 AI 应用。"
                  : "仅代表当前检测 WebView，不代表 AI 应用或其他浏览器。", systemImage: "info.circle")
                .font(.caption).foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }.font(WatchTypography.body).foregroundStyle(p.text)
            .frame(maxWidth: 1120, alignment: .leading).padding(.top, 24)
    }

    private var addressComparison: some View {
        Surface(p) {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 20) {
                    addresses.frame(minWidth: 282, maxWidth: .infinity, alignment: .leading)
                    Divider()
                    referenceSummary.frame(minWidth: 230, maxWidth: .infinity, alignment: .leading)
                }.fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 14) { addresses; Divider(); referenceSummary }
            }
        }
    }

    private var referenceSummary: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeading("HTTP 出口参考", icon: "globe", color: style.transport)
            if reference.isEmpty {
                Text(state.running ? "等待本轮 HTTP 出口参考" : result == nil ? "等待首次检测" : "未取得 HTTP 出口参考")
                    .font(WatchTypography.body).foregroundStyle(p.secondary)
            } else {
                observationList(reference)
            }
        }
    }

    private var settings: some View {
        VStack(alignment: .leading, spacing: 12) {
            if isDNS {
                Text("自动比较同一轮 DNS 递归出口与 HTTP 公网出口的国家：同国通过；异国显示泄漏风险；任一国家缺失则本轮未完成。无需填写或确认 DNS IP 名单。")
                    .font(.caption).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
            } else {
                Text("自动比较当前检测 WebView 的公网 ICE / STUN 候选与同轮 HTTP 公网出口；无需手动填写预期出口 IP。")
                    .font(.caption).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if let error = state.inputError, !error.isEmpty {
                Label(error, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(p.amber)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
    private var addresses: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeading(isDNS ? "DNS 递归出口" : "公网与中继候选",
                           icon: isDNS ? "network" : "antenna.radiowaves.left.and.right", color: style.network)
            if principal.isEmpty {
                Text(state.running ? "正在收集地址" : result == nil ? "等待首次检测" : "本轮未取得可对照的地址")
                    .font(WatchTypography.body).foregroundStyle(p.secondary)
            } else if isDNS {
                observationList(principal)
            } else {
                ForEach(LeakCandidateGroup.group(principal)) { group in
                    if group.observations.count > 1 {
                        DisclosureGroup {
                            observationList(group.observations).padding(.top, 6)
                        } label: {
                            VStack(alignment: .leading, spacing: 5) {
                                Text(group.id.address).font(WatchTypography.mono).textSelection(.enabled)
                                let countries = group.countries
                                if countries.count == 1, let country = countries.first, country != "地区未取得" {
                                    CountryLine(code: countryCodes[group.id.address], country: country, p: p)
                                } else {
                                    Text(countries.joined(separator: " / ")).font(WatchTypography.caption)
                                        .foregroundStyle(p.secondary)
                                }
                                Text([observationKind(group.id.kind), group.id.family.map { "IPv\($0)" },
                                      "\(group.sourceCount) 个来源"].compactMap { $0 }.joined(separator: " · "))
                                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                            }
                        }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                    } else if let item = group.observations.first {
                        observationRow(item)
                    }
                }
            }
        }
    }

    private func observationList(_ rows: [LeakObservation]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, item in
                if index > 0 { Divider() }
                observationRow(item)
            }
        }
    }

    private func observationRow(_ item: LeakObservation) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(item.address).font(WatchTypography.mono.weight(.semibold)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            CountryLine(code: countryCodes[item.address], country: item.country, region: item.region,
                        city: item.city, organization: item.isp, p: p)
            Text([item.kind == "http" ? "HTTP 参考" : observationKind(item.kind),
                  item.family.map { "IPv\($0)" }, item.source].compactMap { $0 }.joined(separator: " · "))
                .font(WatchTypography.caption).foregroundStyle(p.secondary).textSelection(.enabled)
            if let source = item.geoSource {
                Text(source + (item.geoQueriedAt.map { " · " + probeTime($0) } ?? ""))
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let latestResult, !latestResult.errors.isEmpty {
                Label("本轮查询失败：\(latestResult.errors[0].message)", systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(p.amber).fixedSize(horizontal: false, vertical: true)
            }
            DisclosureGroup(isExpanded: $detailsExpanded) {
                VStack(alignment: .leading, spacing: 12) {
                    if isDNS { settings }
                    Text(isDNS ? "IPLeak DNS 和 HTTP 均通过当前 WebView 采样。" : "Net.Coffee 提供归属，Cloudflare 提供 HTTP 参考。UDP 按系统路由检测。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                    if let result {
                        if showingPreviousSuccessfulResult {
                            DetailRow(title: "展示样本", value: "上次有效结果；当前判词见页面顶部", p: p)
                        }
                        DetailRow(title: "检测范围", value: result.scope, p: p)
                        DetailRow(title: "开始时间", value: probeTime(result.startedAt), p: p, monospaced: true)
                        DetailRow(title: "完成时间", value: probeTime(result.finishedAt), p: p, monospaced: true)
                        ForEach(Array(result.errors.enumerated()), id: \.offset) { _, error in
                            Text("\(error.stage) · \(error.code)：\(error.message)").font(.callout)
                                .foregroundStyle(p.amber).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        }
                        if let raw = result.externalJSON {
                            Text(isIPLeak ? "IPLeak 回执（DNS 地址、计数与归属摘要）" : "Net.Coffee 原始 API 回执（含来源、时间、HTTP 状态与未裁剪 JSON）").font(.callout.weight(.medium))
                            Text(raw).font(.system(.caption,design:.monospaced)).textSelection(.enabled).fixedSize(horizontal:false,vertical:true)
                        }
                        ForEach(Array(result.details.enumerated()), id: \.offset) { _, detail in
                            Text(detail).font(.callout).foregroundStyle(p.secondary).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Text(isDNS ? "结果仅覆盖所选检测来源；DNS 与 HTTP 地址不要求相同，比较的是同轮实测国家。"
                         : "仅在当前检测 WebView 内采集候选；未访问摄像头或麦克风，不覆盖其他应用的 WebRTC 行为。")
                        .font(.callout).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                }.padding(.top, 16)
            } label: {
                Label("检测范围与原始证据", systemImage: "doc.text.magnifyingglass")
                    .font(.callout.weight(.medium)).foregroundStyle(p.secondary)
            }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
        }.padding(.horizontal, 4)
    }
    private func sectionHeading(_ title: String, icon: String, color: Color) -> some View {
        HStack(spacing: 8) { InspectorIcon(name: icon, color: color); Text(title).font(.headline) }
    }
    private func isLocal(_ observation: LeakObservation) -> Bool {
        guard !isDNS else { return false }
        return observation.kind == "mdns" || (observation.kind == "host" && LeakIPAddress(observation.address)?.isPublic != true)
    }
    private func observationKind(_ value: String) -> String {
        switch value {
        case "resolver": return "递归解析器"
        case "srflx": return "STUN 候选"
        case "prflx": return "对端反射候选"
        case "relay": return "TURN 中继"
        case "host": return "主机候选"
        case "mdns": return "mDNS"
        default: return value
        }
    }
    private func probeTime(_ epoch: Double) -> String {
        epoch.isFinite && epoch > 0 ? timeText(epoch, date: true) : "未取得"
    }
}

/// Presentation groups retain every original observation, including its source and location.
struct LeakCandidateGroup: Identifiable {
    struct Key: Hashable {
        let address, kind: String
        let family: Int?
    }
    let id: Key
    var observations: [LeakObservation]
    var sourceCount: Int { Set(observations.map(\.source)).count }
    var countries: [String] {
        var seen: Set<String> = []
        return observations.compactMap {
            let country = $0.country?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let label = country.isEmpty ? "地区未取得" : country
            return seen.insert(label).inserted ? label : nil
        }
    }

    static func group(_ observations: [LeakObservation]) -> [Self] {
        var result: [Self] = []
        var indices: [Key: Int] = [:]
        for item in observations {
            let key = Key(address: LeakIPAddress(item.address)?.canonical ?? item.address,
                          kind: item.kind, family: item.family)
            if let index = indices[key] {
                result[index].observations.append(item)
            } else {
                indices[key] = result.count
                result.append(Self(id: key, observations: [item]))
            }
        }
        return result
    }
}
