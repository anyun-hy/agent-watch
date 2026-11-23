import SwiftUI

/// Shared by the diagnostic pages. Icon colors describe
/// content; verdict colors retain their independent success/warning meaning.
struct InspectorStyle {
    let p: Palette
    var action: Color { p.blue }
    var service: Color { p.color(0xE5B591, 0x945A35) }
    var network: Color { p.blue }
    var proxy: Color { p.mint }
    var location: Color { p.color(0xC9B8ED, 0x75519B) }
    var transport: Color { p.color(0x8BD5D7, 0x197A80) }
    var border: Color { p.border.opacity(p.dark ? 0.55 : 0.65) }
    func pageIcon(_ page: Page) -> Color {
        switch page {
        case .ipScore: return service
        case .claudeAI: return service
        case .gptAI: return proxy
        case .dns: return network
        case .webrtc: return location
        default: return p.secondary
        }
    }
    func verdictColor(_ state: LeakVerdictState) -> Color {
        switch state {
        case .matched: return p.mint
        case .difference, .incomplete: return p.amber
        case .running, .unconfigured: return p.blue
        case .idle, .cancelled: return p.secondary
        }
    }
    func verdictSymbol(_ state: LeakVerdictState) -> String {
        switch state {
        case .matched: return "checkmark.circle"
        case .difference: return "exclamationmark.triangle"
        case .incomplete: return "clock.badge.exclamationmark"
        case .running: return "arrow.triangle.2.circlepath"
        case .cancelled: return "xmark.circle"
        case .unconfigured: return "info.circle"
        case .idle: return "circle.dotted"
        }
    }
}

struct InspectorIcon: View {
    let name: String
    let color: Color
    var size: CGFloat = 15
    var body: some View {
        Image(systemName: name).font(.system(size: size, weight: .regular))
            .symbolRenderingMode(.hierarchical).foregroundStyle(color).accessibilityHidden(true)
    }
}

struct InspectorHeading<Actions: View>: View {
    let title, subtitle: String
    let p: Palette
    @ViewBuilder let actions: Actions
    var body: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(WatchTypography.pageTitle).accessibilityAddTraits(.isHeader)
                Text(subtitle).font(WatchTypography.body).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            actions
        }
    }
}

struct InspectorStatus: View {
    let verdict: LeakVerdict
    let running: Bool
    let source: String
    var brand: ServiceBrand?
    var symbol: String?
    var tint: Color?
    let p: Palette
    var body: some View {
        let style = InspectorStyle(p: p)
        let color = tint ?? style.verdictColor(verdict.state)
        HStack(spacing: 14) {
            Group {
                if running { ProgressView().controlSize(.small) }
                else if let brand { BrandLogo(brand: brand, size: 24) }
                else { InspectorIcon(name: symbol ?? style.verdictSymbol(verdict.state), color: color, size: 22) }
            }.frame(width: 40, height: 40)
                .background(color.opacity(0.09), in: RoundedRectangle(cornerRadius: 9))
            VStack(alignment: .leading, spacing: 5) {
                Text(source).font(WatchTypography.small).foregroundStyle(p.secondary)
                Text(verdict.title).font(WatchTypography.title).foregroundStyle(p.text)
                Text(verdict.detail).font(WatchTypography.caption).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            InspectorIcon(name: style.verdictSymbol(verdict.state), color: color, size: 18)
        }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(p.surface, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(color.opacity(0.36)))
    }
}

struct SamplingEvidence: View {
    let source: String
    let timeLabel: String
    let timestamp: Double?
    let p: Palette

    var body: some View {
        let time = timestamp.flatMap { $0.isFinite && $0 > 0 ? timeText($0, date: true) : nil }
        Label(source + "　·　" + (time.map { timeLabel + " " + $0 } ?? "等待采样"), systemImage: "clock")
            .font(WatchTypography.caption).foregroundStyle(p.secondary).textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true).accessibilityElement(children: .combine)
    }
}

struct InspectorPanel<Content: View>: View {
    let p: Palette
    @ViewBuilder let content: Content
    var body: some View {
        content.frame(maxWidth: .infinity, alignment: .leading)
            .background(p.surface, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(p.border.opacity(0.65)))
    }
}
