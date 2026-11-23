import SwiftUI

/// Evidence-only atlas from the same receipt. A country silhouette never
/// identifies an IP location; the footer counts the returned check rows.
struct EnvironmentAtlasPlate: View {
    let result: CurrentEnvironmentReceipt
    let p: Palette
    let historical: Bool
    let previousObserved: Double?

    private var egress: EnvironmentCheckRow? { result.rows.first { $0.id == "egress" } }
    private var egressValue: String? {
        guard let raw = egress?.current, !raw.isEmpty, raw != "unknown" else { return nil }
        return raw
    }
    private var place: String {
        // Use the country label already formatted by the producer, not the
        // timezone city or the IP registrant's administrative address.
        guard let raw = egressValue else { return "出口未取得" }
        let parts = raw.components(separatedBy: " / ")
        guard parts.count == 2, let country = parts[1].components(separatedBy: " · ").first,
              !country.isEmpty else { return raw }
        return country
    }
    private var modeAndNode: String? {
        let local = result.display_facts?.local
        let api = local?.tag?.api
        guard let mode = api?.mode ?? local?.rules?.actual_mode, !mode.isEmpty else { return nil }
        let node = mode == "global" ? api?.global_node ?? api?.selected_node : api?.selected_node
        let title = mode == "global" ? "全局模式" : mode == "rule" ? "规则模式" : mode
        return [title, node].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
    }
    private var accent: Color { p.color(0x9CDACB, 0x216C64) }
    private var note: String {
        if historical { return "历史样本" }
        if egress?.state == "cached" { return "上次有效采样" }
        if egress?.sample_reused == true { return "复用采样" }
        return "本轮观测"
    }

    private var countryCode: String? {
        // Country already supplied by the egress receipt; no city lookup.
        let raw = result.display_facts?.online?.geo?.country ?? result.egress_reference?.country
        return CountryIdentity.code(raw, country: raw)
    }
    var body: some View {
        VStack(spacing: 0) {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 0) {
                    exitPlate.frame(minWidth: 265, maxWidth: .infinity)
                    AtlasRegionPlate(code: countryCode, historical: historical, p: p).frame(width: 272)
                }
                VStack(spacing: 0) { exitPlate; AtlasRegionPlate(code: countryCode, historical: historical, p: p) }
            }
            Divider()
            plot
        }
        .background(p.color(0x303F47, 0xFAF8F1))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(p.border))
    }

    private var exitPlate: some View {
        VStack(alignment: .leading, spacing: 8) {
            AtlasCaption(text: "图 01   /   观测出口", tint: accent)
            Text(place).font(.system(size: 34, weight: .semibold, design: .monospaced))
                .foregroundStyle(p.text).textSelection(.enabled)
            if let value = egressValue, place != value {
                Text(value).font(WatchTypography.mono).foregroundStyle(p.text).textSelection(.enabled)
            }
            Text(note + " · " + (egress?.statusLabel ?? "未取得"))
                .font(WatchTypography.captionStrong).foregroundStyle(historical ? p.secondary : accent)
            Divider().padding(.vertical, 2)
            if let modeAndNode { Label(modeAndNode, systemImage: "arrow.triangle.branch") }
            if let zone = result.display_facts?.online?.geo?.timezone.flatMap(TimeZone.init(identifier:)) {
                TimelineView(.everyMinute) { clock in
                    Label(exitClock(zone, clock.date), systemImage: "clock")
                }
            }
            Text("采样于 " + environmentSummaryTime(result.observed_at))
            if let previousObserved, previousObserved > 0 { Text("上一轮 " + environmentSummaryTime(previousObserved)) }
        }.font(WatchTypography.caption).foregroundStyle(p.secondary)
            .padding(20).frame(maxWidth: .infinity, alignment: .leading)
    }

    private var plot: some View {
        VStack(alignment: .leading, spacing: 7) {
            AtlasCaption(text: "检测分布   /   \(result.rows.count) 项原始检测" + (historical ? " · 历史样本" : ""), tint: p.secondary)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 82), spacing: 10)], alignment: .leading, spacing: 6) {
                ForEach(series, id: \.key) { item in
                    HStack(spacing: 4) {
                        Circle().fill(historical ? p.secondary : item.tint).frame(width: 5, height: 5)
                        Text(item.label)
                        Text("\(result.count(item.key))").monospacedDigit().bold()
                    }.font(WatchTypography.caption).foregroundStyle(p.text)
                        .accessibilityElement(children: .combine)
                }
            }
        }.padding(.horizontal, 18).padding(.vertical, 10)
    }
    /// Live exit-local time plus the offset against this Mac, e.g.
    /// "出口 18:52 · 与本机差 +1h" or "+30m" for half-hour zones.
    private func exitClock(_ tz: TimeZone, _ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.timeZone = tz
        formatter.dateFormat = "HH:mm"
        let offset = (tz.secondsFromGMT(for: date) - TimeZone.current.secondsFromGMT(for: date)) / 60
        let diff: String
        if offset == 0 {
            diff = "与本机同"
        } else {
            var text = offset > 0 ? "+" : "-"
            let hours = abs(offset) / 60, minutes = abs(offset) % 60
            if hours > 0 { text += "\(hours)h" }
            if minutes > 0 { text += "\(minutes)m" }
            diff = "与本机差 \(text)"
        }
        return "出口 \(formatter.string(from: date)) · \(diff)"
    }
    private var series: [(key: String, label: String, tint: Color)] {
        [("ok", "核对", accent), ("fail", "需处理", p.red), ("unknown", "未取得", p.amber),
         ("warn", "提示", p.amber), ("info", "已读取", p.blue), ("cached", "上次有效", p.secondary)]
    }

}

/// The approved outline is a country illustration, never an IP point or path.
private struct AtlasRegionPlate: View {
    let code: String?
    let historical: Bool
    let p: Palette
    private var ink: Color { p.color(0xAFD4C7, 0x3C685D) }
    private var name: String {
        code.flatMap { Locale(identifier: "zh_Hans").localizedString(forRegionCode: $0) } ?? code ?? "地区未取得"
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            AtlasCaption(text: "区域图版   /   " + (code ?? "—"), tint: ink)
            Canvas { context, size in
                var shape = Path()
                if code == "JP" {
                    let scale = min(size.width / 510, size.height / 354)
                    let dx = (size.width - 510 * scale) / 2, dy = (size.height - 354 * scale) / 2
                    for island in Self.islands {
                        for i in stride(from: 0, to: island.count, by: 2) {
                            let pt = CGPoint(x: (CGFloat(island[i]) - 778) * scale + dx,
                                             y: (CGFloat(island[i + 1]) - 111) * scale + dy)
                            if i == 0 { shape.move(to: pt) } else { shape.addLine(to: pt) }
                        }
                        shape.closeSubpath()
                    }
                    context.fill(shape, with: .color(p.color(0x57776A, 0xB8CDBE)))
                } else {
                    // Generic graticule: no inferred continent, route or pin.
                    let d = min(size.width, size.height) - 4
                    guard d > 0 else { return }
                    let rect = CGRect(x: (size.width - d) / 2, y: (size.height - d) / 2, width: d, height: d)
                    shape.addEllipse(in: rect)
                    for inset in [0.14, 0.33] { shape.addEllipse(in: rect.insetBy(dx: d * inset, dy: 0)) }
                    for ratio in [0.25, 0.5, 0.75] {
                        let y = d * ratio, half = sqrt(max(0, d*d/4 - pow(y-d/2,2)))
                        shape.move(to: CGPoint(x: rect.midX - half, y: rect.minY + y)); shape.addLine(to: CGPoint(x: rect.midX + half, y: rect.minY + y))
                    }
                }
                context.stroke(shape, with: .color(ink.opacity(0.8)), lineWidth: 1)
            }.frame(height: 120).accessibilityHidden(true)
            HStack(alignment: .lastTextBaseline) {
                Text(name).font(WatchTypography.title)
                Spacer(minLength: 4)
                Text(code == "JP" ? "国家示意 · 非路径" : "经纬网示意 · 非定位")
                    .font(WatchTypography.small)
            }.foregroundStyle(ink)
            if historical { Text("历史样本").font(WatchTypography.small).foregroundStyle(p.secondary) }
        }.padding(16).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
            .background {
                ZStack {
                    p.color(0x283E40, 0xE4ECE7)
                    Canvas { context, size in
                        var grid = Path()
                        for x in stride(from: CGFloat.zero, through: size.width, by: 32) {
                            grid.move(to: CGPoint(x: x, y: 0)); grid.addLine(to: CGPoint(x: x, y: size.height))
                        }
                        for y in stride(from: CGFloat.zero, through: size.height, by: 32) {
                            grid.move(to: CGPoint(x: 0, y: y)); grid.addLine(to: CGPoint(x: size.width, y: y))
                        }
                        context.stroke(grid, with: .color(ink.opacity(0.13)), lineWidth: 0.6)
                    }.accessibilityHidden(true)
                }
            }
    }
    // Four unmodified island outlines from the approved V2 vector plate.
    private static let islands: [[Int]] = [
        [797, 417, 785, 408, 806, 396, 828, 393, 847, 401, 837, 413, 853, 417, 841, 432, 837, 451, 822, 463, 813, 449, 803, 458, 797, 449, 806, 437, 813, 425],
        [856, 405, 881, 391, 890, 393, 909, 386, 924, 383, 940, 386, 935, 393, 924, 396, 921, 408, 909, 402, 893, 408, 878, 420, 872, 410],
        [820, 391, 831, 380, 856, 375, 875, 365, 890, 354, 906, 355, 930, 351, 952, 350, 958, 355, 974, 355, 985, 351, 983, 339, 1000, 326, 1005, 313, 1020, 307, 1013, 319, 1013, 324, 1030, 320, 1048, 315, 1069, 300, 1079, 295, 1087, 290, 1090, 278, 1098, 265, 1104, 252, 1098, 245, 1104, 233, 1113, 218, 1123, 218, 1126, 225, 1137, 222, 1130, 212, 1147, 213, 1149, 230, 1160, 242, 1168, 258, 1158, 270, 1155, 279, 1151, 287, 1139, 287, 1134, 293, 1133, 309, 1134, 320, 1122, 331, 1120, 343, 1131, 350, 1119, 354, 1114, 363, 1100, 369, 1098, 359, 1106, 352, 1098, 354, 1093, 362, 1083, 359, 1077, 365, 1073, 376, 1066, 373, 1065, 364, 1048, 377, 1014, 376, 1008, 372, 1005, 367, 999, 375, 1007, 383, 991, 388, 972, 404, 960, 401, 951, 388, 957, 380, 961, 375, 941, 372, 921, 377, 899, 380, 876, 386, 869, 384, 859, 393, 845, 390],
        [1107, 212, 1120, 204, 1137, 205, 1126, 197, 1115, 192, 1129, 186, 1154, 185, 1186, 199, 1204, 182, 1226, 177, 1240, 176, 1262, 171, 1278, 166, 1261, 165, 1268, 147, 1239, 153, 1217, 148, 1186, 134, 1164, 116, 1153, 116, 1158, 138, 1147, 156, 1144, 168, 1129, 171, 1116, 167, 1112, 176, 1100, 184, 1103, 197]
    ]
}

/// Editorial grouping only. No cross-row verdict or newly inferred location.
enum AtlasSubject: String, CaseIterable, Identifiable {
    case exit = "出口与代理", time = "地区、时区与系统语言", leaks = "DNS、UDP 与 WebRTC", services = "服务与后台"
    case other = "其他检测"
    var id: Self { self }
    var index: String {
        switch self { case .exit: "01"; case .time: "02"; case .leaks: "03"; case .services: "04"; case .other: "05" }
    }
    var ids: [String] {
        switch self {
        case .exit: ["egress", "ip_history", "asn", "proxy", "tun", "routing"]
        case .time: ["timezone", "locale", "language"]
        case .leaks: ["dns", "stun", "ipv6"]
        case .services: ["reachability", "chatgpt_reachability", "guard"]
        case .other: []
        }
    }
    func summary(_ rows: [EnvironmentCheckRow], historical: Bool, rtc: LeakCheckState?) -> String {
        // Surface exceptions; do not duplicate every tile in a collapsed group's label.
        var lines: [String] = rows.isEmpty ? [] : ["\(rows.count) 项" + (historical ? " · 历史样本" : "")]
        if !historical {
            lines += rows.filter { ["warn", "fail", "unknown", "cached"].contains($0.state) }
                .map { $0.name + "：" + $0.statusLabel }
        }
        if self == .leaks, let rtc {
            lines.append("WebRTC：" + (historical ? "最近结果见详情" : (rtc.running ? "更新中" : rtc.verdict.title)))
        }
        return lines.isEmpty ? "暂无该组检测回执" : lines.joined(separator: "　")
    }
}

struct AtlasCheckGroups {
    var attention: [EnvironmentCheckRow] = []
    var sections: [AtlasSubject: [EnvironmentCheckRow]] = [:]

    init(rows: [EnvironmentCheckRow], historical: Bool) {
        for row in rows {
            if !historical && (row.state == "warn" || row.state == "fail") {
                attention.append(row)
            } else {
                let subject = AtlasSubject.allCases.first { $0.ids.contains(row.id) } ?? .other
                sections[subject, default: []].append(row)
            }
        }
    }
}

struct AtlasCaption: View {
    let text: String
    let tint: Color
    var body: some View {
        Text(text).font(.system(size: 11, weight: .semibold, design: .monospaced))
            .tracking(1.1).foregroundStyle(tint)
    }
}
