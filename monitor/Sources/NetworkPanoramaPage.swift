import AppKit
import SwiftUI

/// Unified, high-density Network & Risk Intelligence Workbench ("网络全景诊断").
/// Consolidates pure-Rust multi-source IP risk intelligence (`ipapi.is` + `RIPEstat` + `DoH PTR` + `ipinfo.io`),
/// dual-platform AI endpoint & Cloudflare edge protocol telemetry (`Claude` + `ChatGPT/OpenAI`),
/// and daemon-authoritative DNS / WebRTC / dual-stack interface leak forensics on a single screen.
struct NetworkPanoramaPage: View {
    @ObservedObject var store: MonitorStore
    @ObservedObject var ipIntel: IpIntelStore
    @ObservedObject var aiChecks: AIProbeStore
    @ObservedObject var leakChecks: LeakCheckStore
    let p: Palette

    @State private var rawEvidenceExpanded = false
    @State private var localInterfacesExpanded = false
    @State private var txtFallbackExpanded = false
    @State private var copiedTag: String?

    private var style: InspectorStyle { InspectorStyle(p: p) }
    private var anyRunning: Bool {
        ipIntel.isRunning || aiChecks.all.running || leakChecks.dns.running || leakChecks.rtc.running
    }

    private var effectiveAIState: AIProbeState {
        if aiChecks.all.result != nil || aiChecks.all.running {
            return aiChecks.all
        }
        if aiChecks.claude.result != nil { return aiChecks.claude }
        return aiChecks.gpt
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            topControlWorkbench
            claudeSafetyVerdictBanner
            executiveKpiStrip

            if store.panoramaFocus == .all || store.panoramaFocus == .ipIntel {
                ipIntelligenceModule
            }
            if store.panoramaFocus == .all || store.panoramaFocus == .aiEndpoints {
                aiEndpointsModule
            }
            if store.panoramaFocus == .all || store.panoramaFocus == .leaks {
                leakForensicsModule
            }

            auditReceiptFooter
        }
        .foregroundStyle(p.text)
        .frame(maxWidth: 1220, alignment: .leading)
        .padding(.top, 16)
        .task {
            if !store.switcher.isFixture {
                if ipIntel.currentReport == nil && !ipIntel.isRunning {
                    ipIntel.queryCurrentExit(force: false)
                }
                if aiChecks.all.result == nil && !aiChecks.all.running {
                    aiChecks.start(.all)
                }
                leakChecks.autoLoadIfNeeded(.dns)
                leakChecks.autoLoadIfNeeded(.webrtc)
            } else {
                ipIntel.loadFixture()
                if aiChecks.all.result == nil { aiChecks.loadFixture(.ready) }
            }
        }
    }

    private func runFullPanoramaScan() {
        ipIntel.queryCurrentExit(force: true)
        aiChecks.start(.all)
        leakChecks.start(.dns)
        leakChecks.start(.webrtc)
    }

    private func cancelAllScans() {
        ipIntel.cancel()
        aiChecks.cancel(.all)
        if leakChecks.dns.running { leakChecks.cancel(.dns) }
        if leakChecks.rtc.running { leakChecks.cancel(.webrtc) }
    }

    private func copyToPasteboard(_ text: String, tag: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copiedTag = tag
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            if copiedTag == tag { copiedTag = nil }
        }
    }

    // MARK: - Top Control & Focus Bar

    private var topControlWorkbench: some View {
        Surface(p, padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .center, spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text("全景风控与链路诊断台").font(WatchTypography.title)
                            Badge(
                                text: store.managedVpn.mode == .managed ? "独立内置 VPN 通道" : "复用本机外部 VPN",
                                color: store.managedVpn.mode == .managed ? p.mint : p.blue
                            )
                        }
                        Text("纯 Rust 并发核验：api.ipapi.is + RIPEstat RPKI + DoH 逆向 PTR + AI 全端点边缘协议栈 + 双权威 DNS / STUN 防泄漏。")
                            .font(WatchTypography.caption)
                            .foregroundStyle(p.secondary)
                    }
                    Spacer(minLength: 12)
                    Button {
                        anyRunning ? cancelAllScans() : runFullPanoramaScan()
                    } label: {
                        Label(
                            anyRunning ? "停止扫描" : "一键全景深度扫描",
                            systemImage: anyRunning ? "stop.fill" : "bolt.horizontal.circle.fill"
                        )
                        .font(WatchTypography.bodyStrong)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(anyRunning ? p.secondary : p.blue)
                }

                Divider()

                HStack(spacing: 10) {
                    HStack(spacing: 4) {
                        ForEach(PanoramaFocusSection.allCases) { sec in
                            let selected = store.panoramaFocus == sec
                            Button {
                                withAnimation(.easeInOut(duration: 0.14)) {
                                    store.panoramaFocus = sec
                                }
                            } label: {
                                Text(sec.rawValue)
                                    .font(selected ? WatchTypography.captionStrong : WatchTypography.caption)
                                    .foregroundStyle(selected ? p.text : p.secondary)
                                    .padding(.horizontal, 11)
                                    .padding(.vertical, 5)
                                    .background(selected ? p.surface : Color.clear, in: RoundedRectangle(cornerRadius: 7))
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 7)
                                            .strokeBorder(selected ? p.border.opacity(0.85) : Color.clear, lineWidth: 1)
                                    )
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(3)
                    .background(p.elevated, in: RoundedRectangle(cornerRadius: 9))

                    Spacer(minLength: 8)

                    HStack(spacing: 8) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 12))
                            .foregroundStyle(p.secondary)
                        TextField("输入任意公网 IP 单独查画像（留空查当前通道出口）", text: $ipIntel.queryInput)
                            .textFieldStyle(.roundedBorder)
                            .font(WatchTypography.mono)
                            .frame(minWidth: 260, maxWidth: 320)
                            .onSubmit {
                                store.panoramaFocus = store.panoramaFocus == .all ? .all : .ipIntel
                                ipIntel.submitCustomOrCurrent()
                            }
                        Button(ipIntel.queryInput.trimmingCharacters(in: .whitespaces).isEmpty ? "查当前出口" : "查此 IP") {
                            ipIntel.submitCustomOrCurrent()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .disabled(ipIntel.isRunning)

                        if !ipIntel.currentExitIP.isEmpty && !ipIntel.selectedIP.isEmpty && ipIntel.selectedIP != ipIntel.currentExitIP {
                            Button("切回当前出口") {
                                ipIntel.focusAndQuery(ipIntel.currentExitIP)
                            }
                            .buttonStyle(.borderless)
                            .font(WatchTypography.small)
                            .foregroundStyle(p.blue)
                        }
                    }
                }

                if let err = ipIntel.errorMessage, !err.isEmpty {
                    InlineNotice(title: "IP 情报查询提示", detail: err, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                }
            }
        }
    }

    // MARK: - Claude / AI Readiness Safety Verdict Banner

    private struct SafetyPillar: Identifiable {
        let id: String
        let title: String
        let state: String // "pass" | "warn" | "fail" | "pending"
        let detail: String
    }

    private var claudeSafetyVerdictBanner: some View {
        let report = ipIntel.currentReport
        let aiResult = effectiveAIState.result
        let dnsVerdict = leakChecks.dns.verdict
        let rtcVerdict = leakChecks.rtc.verdict

        let blockedRegions: Set<String> = ["CN", "HK", "MO", "RU", "BY", "IR", "KP"]
        let exitCountry = (report?.countryCode ?? aiResult?.countryCode ?? "").uppercased()
        let regCountry = (report?.registered_country_code ?? "").uppercased()

        let regionPillar: SafetyPillar = {
            if exitCountry.isEmpty {
                return SafetyPillar(id: "region", title: "地区合规", state: "pending", detail: "等待识别落地国家")
            }
            if blockedRegions.contains(exitCountry) || regCountry == "CN" {
                return SafetyPillar(id: "region", title: "地区合规", state: "fail", detail: "命中封锁区或中国注册 ASN（\(exitCountry)/\(regCountry)）")
            }
            return SafetyPillar(id: "region", title: "地区合规", state: "pass", detail: "安全海外区（\(exitCountry)）")
        }()

        let purityPillar: SafetyPillar = {
            guard let r = report, let s = r.score else {
                return SafetyPillar(id: "purity", title: "IP 纯净度", state: "pending", detail: "等待评估")
            }
            if r.is_tor == true || r.is_abuser == true || s.value < 45 {
                return SafetyPillar(id: "purity", title: "IP 纯净度", state: "fail", detail: "\(s.value) 分 · 高危滥用或黑名单")
            }
            if s.value >= 78 {
                return SafetyPillar(id: "purity", title: "IP 纯净度", state: "pass", detail: "\(s.value) 分 · \(r.is_residential == true ? "家宽级" : s.label)")
            }
            return SafetyPillar(id: "purity", title: "IP 纯净度", state: "warn", detail: "\(s.value) 分 · 机房或广播特征")
        }()

        let endpointPillar: SafetyPillar = {
            let eps = aiResult?.endpoints ?? []
            if eps.isEmpty {
                return SafetyPillar(id: "endpoints", title: "AI 连通性", state: "pending", detail: "等待端点探测")
            }
            let claudeBlocked = eps.contains { $0.family == "claude" && $0.httpStatus == 403 && $0.cfChallenge != true }
            if claudeBlocked {
                return SafetyPillar(id: "endpoints", title: "AI 连通性", state: "fail", detail: "Claude 端点返回 403 拒绝访问")
            }
            let ok = eps.filter { $0.status == "responded" && ($0.httpStatus == 200 || $0.httpStatus == 401) }.count
            return SafetyPillar(id: "endpoints", title: "AI 连通性", state: ok == eps.count ? "pass" : "warn", detail: "\(ok)/\(eps.count) 端点正常")
        }()

        let dnsPillar: SafetyPillar = {
            switch dnsVerdict.state {
            case .matched: return SafetyPillar(id: "dns", title: "DNS 零泄漏", state: "pass", detail: "AI 域名解析无国内泄漏")
            case .difference: return SafetyPillar(id: "dns", title: "DNS 零泄漏", state: "fail", detail: "检测到异国/国内 DNS 泄漏")
            default: return SafetyPillar(id: "dns", title: "DNS 零泄漏", state: "pending", detail: dnsVerdict.title)
            }
        }()

        let rtcPillar: SafetyPillar = {
            switch rtcVerdict.state {
            case .matched: return SafetyPillar(id: "rtc", title: "WebRTC 防护", state: "pass", detail: "无公网 UDP 反射泄漏")
            case .difference: return SafetyPillar(id: "rtc", title: "WebRTC 防护", state: "fail", detail: "检测到公网候选与出口不一致")
            default: return SafetyPillar(id: "rtc", title: "WebRTC 防护", state: "pending", detail: rtcVerdict.title)
            }
        }()

        let tzPillar: SafetyPillar = {
            guard let aligned = report?.usage?.timezone_aligned else {
                return SafetyPillar(id: "tz", title: "时区指纹", state: "pending", detail: "待核对本机时区")
            }
            if aligned {
                return SafetyPillar(id: "tz", title: "时区指纹", state: "pass", detail: "与出口时区一致 (\(report?.timezone ?? ""))")
            }
            return SafetyPillar(id: "tz", title: "时区指纹", state: "warn", detail: "出口 \(report?.timezone ?? "") ≠ 本机 \(report?.usage?.system_timezone ?? "")")
        }()

        let pillars = [regionPillar, purityPillar, endpointPillar, dnsPillar, rtcPillar, tzPillar]
        let hasFail = pillars.contains { $0.state == "fail" }
        let hasWarn = pillars.contains { $0.state == "warn" }
        let hasPending = pillars.contains { $0.state == "pending" }

        let (headline, summary, symbol, tint): (String, String, String, Color) = {
            if hasFail {
                let firstFail = pillars.first { $0.state == "fail" }?.detail ?? "存在高危封号风险项"
                return ("严禁启动 Claude · 检测到高危风险", "首要阻断项：\(firstFail)。请更换纯净海外节点并排除泄漏后再登录或启动。", "xmark.shield.fill", p.red)
            }
            if hasWarn {
                let firstWarn = pillars.first { $0.state == "warn" }?.detail ?? "存在可优化项"
                return ("基本可用 · 建议对齐配置后再启动 Claude", "待优化项：\(firstWarn)。对齐本机时区或切至原生家宽节点可显著降低风控概率。", "exclamationmark.shield.fill", p.amber)
            }
            if hasPending {
                return ("正在核验 Claude 6 项防封安全指标…", "等待全部探针回执完成后给出最终安全就绪判定。", "shield.lefthalf.filled", p.blue)
            }
            return ("Claude / ChatGPT 当前可安全运行（6 项防封指标全部通过）", "出口地区合规、IP 纯净度达标、AI 域名与 WebRTC 零泄漏且本机时区已对齐；运行期间请勿跨国切换当前通道节点。", "checkmark.shield.fill", p.mint)
        }()

        return VStack(alignment: .leading, spacing: 11) {
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: symbol)
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(tint)
                VStack(alignment: .leading, spacing: 3) {
                    Text(headline)
                        .font(WatchTypography.section)
                        .foregroundStyle(p.text)
                    Text(summary)
                        .font(WatchTypography.caption)
                        .foregroundStyle(p.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                if tzPillar.state == "warn" {
                    Button("前往环境状态对齐时区 ↗") {
                        store.page = .environment
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 175), spacing: 8)], spacing: 8) {
                ForEach(pillars) { item in
                    let c: Color = item.state == "pass" ? p.mint : item.state == "fail" ? p.red : item.state == "warn" ? p.amber : p.secondary
                    let icon = item.state == "pass" ? "checkmark.circle.fill" : item.state == "fail" ? "xmark.circle.fill" : item.state == "warn" ? "exclamationmark.triangle.fill" : "clock"
                    HStack(spacing: 6) {
                        Image(systemName: icon).font(.system(size: 11)).foregroundStyle(c)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(item.title).font(WatchTypography.small.weight(.semibold)).foregroundStyle(p.text)
                            Text(item.detail).font(.system(size: 10)).foregroundStyle(p.secondary).lineLimit(1)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 8).padding(.vertical, 6)
                    .background(p.surface.opacity(0.85), in: RoundedRectangle(cornerRadius: 7))
                }
            }
        }
        .padding(14)
        .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(tint.opacity(0.32), lineWidth: 1))
    }

    // MARK: - 4-Card Executive Summary KPI Strip

    private var executiveKpiStrip: some View {
        let columns = [
            GridItem(.flexible(minimum: 220), spacing: 12),
            GridItem(.flexible(minimum: 220), spacing: 12),
            GridItem(.flexible(minimum: 220), spacing: 12),
            GridItem(.flexible(minimum: 220), spacing: 12)
        ]
        let report = ipIntel.currentReport
        let scoreVal = report?.score?.value
        let scoreColor = scoreTint(scoreVal)

        let aiVerdict = effectiveAIState.verdict
        let aiColor = style.verdictColor(aiVerdict.state)

        let dnsVerdict = leakChecks.dns.verdict
        let dnsColor = style.verdictColor(dnsVerdict.state)

        let rtcVerdict = leakChecks.rtc.verdict
        let rtcColor = style.verdictColor(rtcVerdict.state)

        return LazyVGrid(columns: columns, spacing: 12) {
            Button { store.panoramaFocus = .ipIntel } label: {
                kpiCard(
                    index: "01 · 出口纯净度",
                    title: scoreVal.map { "\($0) / 100 · \(report?.score?.label ?? "")" } ?? (ipIntel.isRunning ? "正在评估…" : "待扫描"),
                    subtitle: report.map { "\($0.usage?.native_label ?? "待核验") · \($0.usage?.label ?? $0.ip ?? "")" } ?? "多源风控与滥用率评估",
                    symbol: "shield.lefthalf.filled.badge.checkmark",
                    tint: scoreColor
                )
            }
            .buttonStyle(.plain)

            Button { store.panoramaFocus = .aiEndpoints } label: {
                let endpoints = effectiveAIState.result?.endpoints ?? []
                let okCount = endpoints.filter { $0.status == "responded" && ($0.httpStatus == 200 || $0.httpStatus == 401) }.count
                let colo = endpoints.compactMap(\.colo).first(where: { !$0.isEmpty }) ?? report?.edge_trace?.colo ?? ""
                kpiCard(
                    index: "02 · AI 全端点连通",
                    title: effectiveAIState.running ? "正在并发探测…" : (endpoints.isEmpty ? aiVerdict.title : "\(okCount)/\(endpoints.count) 端点正常响应"),
                    subtitle: !colo.isEmpty ? "Cloudflare 落地 \(colo) · \(effectiveAIState.result?.exitIP ?? "已响应")" : aiVerdict.detail,
                    symbol: "sparkles.rectangle.stack",
                    tint: aiColor
                )
            }
            .buttonStyle(.plain)

            Button { store.panoramaFocus = .leaks } label: {
                let resolvers = (leakChecks.dns.displayResult?.observations ?? []).filter { $0.kind == "resolver" }
                let countries = Array(Set(resolvers.compactMap(\.country))).sorted().joined(separator: "/")
                kpiCard(
                    index: "03 · DNS 递归防泄漏",
                    title: leakChecks.dns.running ? "正在检测…" : dnsVerdict.title,
                    subtitle: resolvers.isEmpty ? dnsVerdict.detail : "观测 \(resolvers.count) 个递归出口\(countries.isEmpty ? "" : " [\(countries)]") · 含 ECS 核验",
                    symbol: "server.rack",
                    tint: dnsColor
                )
            }
            .buttonStyle(.plain)

            Button { store.panoramaFocus = .leaks } label: {
                let obs = leakChecks.rtc.displayResult?.observations ?? []
                let srflx = obs.filter { $0.kind == "srflx" }
                kpiCard(
                    index: "04 · WebRTC 与双栈网卡",
                    title: leakChecks.rtc.running ? "正在检测…" : rtcVerdict.title,
                    subtitle: srflx.isEmpty ? rtcVerdict.detail : "STUN 公网候选 \(Set(srflx.map(\.address)).count) 个 · 含本机双栈路由核对",
                    symbol: "antenna.radiowaves.left.and.right",
                    tint: rtcColor
                )
            }
            .buttonStyle(.plain)
        }
    }

    private func kpiCard(index: String, title: String, subtitle: String, symbol: String, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Image(systemName: symbol)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(tint)
                Text(index)
                    .font(WatchTypography.small.weight(.semibold))
                    .foregroundStyle(p.secondary)
                Spacer(minLength: 0)
            }
            Text(title)
                .font(WatchTypography.bodyStrong)
                .foregroundStyle(p.text)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
            Text(subtitle)
                .font(WatchTypography.small)
                .foregroundStyle(p.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(13)
        .frame(maxWidth: .infinity, minHeight: 84, alignment: .topLeading)
        .background(p.surface, in: RoundedRectangle(cornerRadius: 11))
        .overlay(RoundedRectangle(cornerRadius: 11).strokeBorder(tint.opacity(0.32), lineWidth: 1))
    }

    // MARK: - Module 01: Pure-Rust Authoritative IP Intelligence

    private var ipIntelligenceModule: some View {
        VStack(alignment: .leading, spacing: 12) {
            moduleSectionBanner(
                code: "MODULE 01",
                title: "权威出口 IP 深度风控与路由画像",
                subtitle: "聚合 api.ipapi.is 定量滥用率、RIPEstat 官方 RPKI/RIR、DoH 逆向 PTR 与多源地理漂移",
                trailing: {
                    if ipIntel.isRunning {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("正在并发取证…").font(WatchTypography.small).foregroundStyle(p.secondary)
                        }
                    } else if let r = ipIntel.currentReport, let ts = r.finishedAt {
                        Text("采样于 \(timeText(ts, date: true))")
                            .font(WatchTypography.small.monospacedDigit())
                            .foregroundStyle(p.secondary)
                    }
                }
            )

            if let report = ipIntel.currentReport, report.isComplete {
                ipHeroScoreBanner(report)
                ipScoreFactorsStrip(report)

                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 12) {
                        ipUsageAndScenariosCard(report)
                            .frame(minWidth: 380, maxWidth: .infinity, alignment: .topLeading)
                        ipAsnAndCompanyCard(report)
                            .frame(minWidth: 380, maxWidth: .infinity, alignment: .topLeading)
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        ipUsageAndScenariosCard(report)
                        ipAsnAndCompanyCard(report)
                    }
                }

                ipTenDimensionThreatMatrix(report)
                ipGeoConsistencyCard(report)
            } else {
                Surface(p, padding: 20) {
                    HStack(spacing: 12) {
                        if ipIntel.isRunning {
                            ProgressView()
                            Text("正在通过受控代理并发请求 api.ipapi.is、RIPEstat RPKI、ipinfo.io 与 DoH PTR…")
                                .font(WatchTypography.body)
                                .foregroundStyle(p.secondary)
                        } else {
                            Image(systemName: "globe.badge.chevron.backward")
                                .font(.system(size: 20))
                                .foregroundStyle(p.secondary)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("尚未载入 IP 风控画像").font(WatchTypography.bodyStrong)
                                Text("点击右上角「一键全景深度扫描」或在输入框填入任意公网 IP 即可获取完整十维风控分析。")
                                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                            }
                        }
                        Spacer()
                    }
                }
            }
        }
    }

    private func ipHeroScoreBanner(_ r: IpIntelReport) -> some View {
        let ipText = r.ip ?? r.query ?? "—"
        let scoreVal = r.score?.value ?? 0
        let tint = scoreTint(scoreVal)
        let isCustomIP = !ipIntel.currentExitIP.isEmpty && ipText != ipIntel.currentExitIP

        return Surface(p, padding: 18) {
            VStack(alignment: .leading, spacing: 14) {
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .center, spacing: 20) {
                        ipHeroIdentityBlock(r, ipText: ipText, isCustomIP: isCustomIP)
                        Spacer(minLength: 12)
                        ipGradientMeterBlock(score: scoreVal, label: r.score?.label ?? "已评估", tint: tint)
                    }
                    VStack(alignment: .leading, spacing: 14) {
                        ipHeroIdentityBlock(r, ipText: ipText, isCustomIP: isCustomIP)
                        ipGradientMeterBlock(score: scoreVal, label: r.score?.label ?? "已评估", tint: tint)
                    }
                }
            }
        }
    }

    private func ipHeroIdentityBlock(_ r: IpIntelReport, ipText: String, isCustomIP: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Text(ipText)
                    .font(.system(size: 26, weight: .bold, design: .monospaced))
                    .textSelection(.enabled)
                Button {
                    copyToPasteboard(ipText, tag: "hero_ip")
                } label: {
                    Image(systemName: copiedTag == "hero_ip" ? "checkmark" : "doc.on.doc")
                        .font(.system(size: 11, weight: .medium))
                }
                .buttonStyle(.borderless)
                .foregroundStyle(copiedTag == "hero_ip" ? p.mint : p.secondary)
                .help("复制 IP 地址")

                if isCustomIP {
                    Badge(text: "指定 IP 查询（非当前通道出口）", color: p.amber)
                } else {
                    Badge(text: "当前受控通道实测出口", color: p.blue)
                }
            }
            HStack(spacing: 8) {
                CountryFlag(code: r.countryCode)
                let place = [r.country, r.region, r.city]
                    .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
                Text(place.isEmpty ? "归属地待确认" : place.joined(separator: " · "))
                    .font(WatchTypography.bodyStrong)
                if let org = r.company_name ?? r.asOrganization, !org.isEmpty {
                    Text("· \(org)")
                        .font(WatchTypography.body)
                        .foregroundStyle(p.secondary)
                        .lineLimit(1)
                }
            }
            if let tr = r.edge_trace, !tr.colo.isEmpty {
                HStack(spacing: 8) {
                    Badge(text: "CF Edge: \(tr.colo) \(tr.colo_city)", color: p.blue)
                    if !tr.tls.isEmpty { Badge(text: tr.tls, color: p.secondary) }
                    if !tr.http.isEmpty { Badge(text: tr.http, color: p.secondary) }
                    if !tr.kex.isEmpty { Badge(text: tr.kex, color: p.secondary) }
                }
            }
        }
    }

    private func ipGradientMeterBlock(score: Int, label: String, tint: Color) -> some View {
        HStack(spacing: 16) {
            VStack(alignment: .trailing, spacing: 6) {
                GeometryReader { geo in
                    let clamped = CGFloat(min(max(score, 0), 100)) / 100.0
                    let xPos = max(6, min(geo.size.width - 6, geo.size.width * clamped))
                    ZStack(alignment: .leading) {
                        Capsule()
                            .fill(
                                LinearGradient(
                                    colors: [p.red, p.amber, p.mint],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .frame(height: 9)
                        Circle()
                            .fill(p.surface)
                            .frame(width: 15, height: 15)
                            .overlay(Circle().strokeBorder(tint, lineWidth: 3))
                            .offset(x: xPos - 7.5)
                    }
                }
                .frame(width: 210, height: 16)

                HStack {
                    Text("0 高危")
                    Spacer()
                    Text("25")
                    Spacer()
                    Text("50")
                    Spacer()
                    Text("75")
                    Spacer()
                    Text("100 纯净")
                }
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(p.secondary)
                .frame(width: 210)
            }

            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text("\(score)")
                    .font(.system(size: 28, weight: .bold, design: .monospaced))
                Text(label)
                    .font(WatchTypography.captionStrong)
            }
            .foregroundStyle(tint)
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(tint.opacity(0.32), lineWidth: 1))
        }
    }

    private func ipScoreFactorsStrip(_ r: IpIntelReport) -> some View {
        let factors = r.score?.factors ?? []
        return Surface(p, padding: 14) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("纯 Rust 可解释评分明细（满分 100 基准逐项核算）", systemImage: "function")
                        .font(WatchTypography.captionStrong)
                        .foregroundStyle(p.secondary)
                    Spacer()
                    Text("非第三方黑盒分数 · 每项加减分可独立核查")
                        .font(WatchTypography.small)
                        .foregroundStyle(p.secondary)
                }
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 250), spacing: 10)], spacing: 8) {
                    ForEach(factors) { f in
                        let c = factorColor(f.status)
                        HStack(alignment: .top, spacing: 8) {
                            Text(f.delta == 0 ? "基准" : (f.delta > 0 ? "+\(f.delta)" : "\(f.delta)"))
                                .font(WatchTypography.small.monospaced().weight(.semibold))
                                .foregroundStyle(c)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(c.opacity(0.12), in: RoundedRectangle(cornerRadius: 5))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(f.label)
                                    .font(WatchTypography.captionStrong)
                                    .foregroundStyle(p.text)
                                Text(f.detail)
                                    .font(WatchTypography.small)
                                    .foregroundStyle(p.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                        }
                        .padding(9)
                        .background(p.elevated.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
        }
    }

    private func ipUsageAndScenariosCard(_ r: IpIntelReport) -> some View {
        let usage = r.usage
        let nativeColor: Color = usage?.native_status == "native" ? p.mint : usage?.native_status == "broadcast" ? p.amber : p.red
        let hostIsGood = r.is_residential == true
        let tzAligned = usage?.timezone_aligned

        return Surface(p, padding: 16) {
            VStack(alignment: .leading, spacing: 11) {
                SectionHeading(title: "使用场景、原生性与环境指纹", p: p)

                kvBadgeRow(
                    key: "IP 原生性",
                    text: [r.country, usage?.registered_country_code.isEmpty == false ? "(RIR: \(usage!.registered_country_code))" : nil]
                        .compactMap { $0 }.joined(separator: " "),
                    badge: usage?.native_label ?? "待核验",
                    badgeColor: nativeColor
                )
                kvBadgeRow(
                    key: "宿主网络标记",
                    text: nonEmpty(r.datacenter_name) ?? nonEmpty(r.company_type?.uppercased()) ?? "公网单播",
                    badge: usage?.label ?? (hostIsGood ? "家庭住宅宽带 (ISP)" : "常规网络"),
                    badgeColor: hostIsGood ? p.mint : (r.is_hosting == true ? p.amber : p.blue)
                )
                kvBadgeRow(
                    key: "运营商类型",
                    text: nonEmpty(r.company_name) ?? nonEmpty(r.asOrganization) ?? "未披露",
                    badge: (nonEmpty(r.company_type) ?? nonEmpty(r.asn_kind) ?? "ISP").uppercased(),
                    badgeColor: (r.company_type == "isp") ? p.mint : p.blue
                )
                kvBadgeRow(
                    key: "时区指纹对齐",
                    text: "出口 \(nonEmpty(r.timezone) ?? "未知") vs 本机 \(nonEmpty(usage?.system_timezone) ?? "未知")",
                    badge: tzAligned == true ? "时区一致" : tzAligned == false ? "时区偏移" : "待比对",
                    badgeColor: tzAligned == true ? p.mint : tzAligned == false ? p.amber : p.secondary
                )

                Divider()
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("逆向主机名 (DoH PTR)").font(WatchTypography.small).foregroundStyle(p.secondary)
                        Spacer()
                        Text(nonEmpty(r.rdns) ?? "未配置反向 PTR 记录")
                            .font(WatchTypography.small.monospaced())
                            .foregroundStyle(p.text)
                            .textSelection(.enabled)
                            .lineLimit(1)
                    }
                    if let note = nonEmpty(r.rdns_note) {
                        Text(note)
                            .font(WatchTypography.small)
                            .foregroundStyle(r.rdns_class == "residential_dialup" ? p.mint : r.rdns_class == "cloud_hosting" ? p.amber : p.secondary)
                    }
                }

                if let scenarios = r.ai_scenarios {
                    Divider()
                    Text("AI 业务场景风控适配评估").font(WatchTypography.captionStrong).foregroundStyle(p.secondary)
                    scenarioRow(brand: .claude, name: "Claude Desktop / Web", verdict: scenarios.claude)
                    scenarioRow(brand: .chatgpt, name: "ChatGPT / Codex", verdict: scenarios.chatgpt)
                    scenarioRow(brand: nil, name: "Anthropic / OpenAI API", verdict: scenarios.api)
                }
            }
        }
    }

    private func scenarioRow(brand: ServiceBrand?, name: String, verdict: IpScenarioVerdict) -> some View {
        let c = factorColor(verdict.status)
        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 7) {
                if let brand {
                    BrandLogo(brand: brand, size: 13)
                } else {
                    Image(systemName: "terminal").font(.system(size: 11)).foregroundStyle(p.blue)
                }
                Text(name).font(WatchTypography.captionStrong)
                Spacer()
                Badge(text: verdict.grade, color: c)
            }
            Text(verdict.detail)
                .font(WatchTypography.small)
                .foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(8)
        .background(p.elevated.opacity(0.38), in: RoundedRectangle(cornerRadius: 7))
    }

    private func ipAsnAndCompanyCard(_ r: IpIntelReport) -> some View {
        let compAbuse = r.abuser?.company
        let asnAbuse = r.abuser?.asn

        return Surface(p, padding: 16) {
            VStack(alignment: .leading, spacing: 11) {
                SectionHeading(title: "ASN 自治系统与企业主体档案", p: p)

                HStack {
                    Text("自治系统编号 (ASN)").font(WatchTypography.caption).foregroundStyle(p.secondary)
                    Spacer()
                    let asnText = r.asn.map { "AS\($0)" } ?? "未提供"
                    Text(asnText).font(WatchTypography.bodyStrong.monospaced()).textSelection(.enabled)
                    if r.asn != nil {
                        Button {
                            copyToPasteboard(asnText, tag: "asn")
                        } label: {
                            Image(systemName: copiedTag == "asn" ? "checkmark" : "doc.on.doc")
                                .font(.system(size: 11))
                        }
                        .buttonStyle(.borderless)
                        .foregroundStyle(copiedTag == "asn" ? p.mint : p.secondary)
                    }
                    if let rir = nonEmpty(r.rir) {
                        Badge(text: rir, color: p.blue)
                    }
                }
                DetailRow(title: "ASN 归属机构", value: nonEmpty(r.asOrganization) ?? "未披露", p: p)
                DetailRow(title: "ASN 自报类型", value: formatAsnKind(r.asn_kind), p: p)
                DetailRow(title: "BGP 路由前缀 (CIDR)", value: nonEmpty(r.cidr) ?? "未提供", p: p, monospaced: true)
                DetailRow(title: "企业分配网段", value: nonEmpty(r.company_network) ?? "未提供", p: p, monospaced: true)
                DetailRow(title: "RIR 分配注册国", value: nonEmpty(r.registered_country_code).map { "\($0)（来源：\(r.usage?.registered_country_source ?? "RIR")）" } ?? "未提供", p: p)
                if let allocated = nonEmpty(r.asn_allocated) {
                    DetailRow(title: "ASN 注册日期", value: allocated, p: p, monospaced: true)
                }

                Divider()
                Text("ipapi.is 定量历史滥用率（越低越纯净）").font(WatchTypography.captionStrong).foregroundStyle(p.secondary)

                kvBadgeRow(
                    key: "企业网段滥用度",
                    text: nonEmpty(compAbuse?.raw) ?? "未披露",
                    badge: compAbuse?.tier_zh ?? "未知",
                    badgeColor: abuserTierColor(compAbuse?.tier)
                )
                kvBadgeRow(
                    key: "ASN 整体滥用度",
                    text: nonEmpty(asnAbuse?.raw) ?? "未披露",
                    badge: asnAbuse?.tier_zh ?? "未知",
                    badgeColor: abuserTierColor(asnAbuse?.tier)
                )

                Divider()
                DetailRow(title: "运营企业主体", value: nonEmpty(r.company_name) ?? "未披露", p: p)
                if let dom = nonEmpty(r.company_domain) {
                    DetailRow(title: "企业官方域名", value: dom, p: p, monospaced: true)
                }
                if let email = nonEmpty(r.abuse_email) {
                    DetailRow(title: "网络滥用投诉信箱", value: email, p: p, monospaced: true)
                }
            }
        }
    }

    private func ipTenDimensionThreatMatrix(_ r: IpIntelReport) -> some View {
        let cols = [
            GridItem(.flexible(minimum: 260), spacing: 12),
            GridItem(.flexible(minimum: 260), spacing: 12),
            GridItem(.flexible(minimum: 260), spacing: 12)
        ]
        return LazyVGrid(columns: cols, spacing: 12) {
            Surface(p, padding: 15) {
                VStack(alignment: .leading, spacing: 10) {
                    Label("风险深度检测（匿名与代理）", systemImage: "eye.trianglebadge.exclamationmark")
                        .font(WatchTypography.bodyStrong)
                    threatPillRow("商业 VPN 出口", detected: r.is_vpn == true, detail: nonEmpty(r.vpn_service))
                    threatPillRow("公开 / 共享代理 (Proxy)", detected: r.is_proxy == true)
                    threatPillRow("Tor 匿名洋葱节点", detected: r.is_tor == true)
                    threatPillRow("数据中心 / 云主机 (IDC)", detected: r.is_datacenter == true, detail: nonEmpty(r.datacenter_name), warnOnly: true)
                }
            }

            Surface(p, padding: 15) {
                VStack(alignment: .leading, spacing: 10) {
                    Label("技术与异常行为指标", systemImage: "cpu")
                        .font(WatchTypography.bodyStrong)
                    threatPillRow("单 IP 恶意滥用记录", detected: r.is_abuser == true)
                    threatPillRow("搜索引擎 / 自动化爬虫", detected: r.is_crawler == true, warnOnly: true)
                    threatPillRow("Bogon / 保留非公网段", detected: r.is_bogon == true, cleanLabel: "否 (公网可达)")
                    HStack {
                        Text("特殊接入属性").font(WatchTypography.caption).foregroundStyle(p.secondary)
                        Spacer()
                        let tags = [
                            r.is_mobile == true ? "蜂窝移动网" : nil,
                            r.is_anycast == true ? "Anycast 任播" : nil,
                            r.is_satellite == true ? "卫星链路" : nil
                        ].compactMap { $0 }
                        Badge(text: tags.isEmpty ? "标准陆基单播" : tags.joined(separator: " · "), color: tags.isEmpty ? p.mint : p.blue)
                    }
                }
            }

            Surface(p, padding: 15) {
                VStack(alignment: .leading, spacing: 10) {
                    Label("BGP 路由签名与反向域名", systemImage: "point.3.filled.connected.trianglepath.dotted")
                        .font(WatchTypography.bodyStrong)
                    let rpkiStatus = r.rpki?.status ?? "unknown"
                    let rpkiColor: Color = rpkiStatus == "valid" ? p.mint : rpkiStatus.hasPrefix("invalid") ? p.red : p.secondary
                    HStack {
                        Text("RIPE RPKI 状态").font(WatchTypography.caption).foregroundStyle(p.secondary)
                        Spacer()
                        Badge(text: r.rpki?.label ?? "Unknown", color: rpkiColor)
                    }
                    if let roa = r.rpki?.roas.first {
                        Text("ROA 授权：\(roa.origin) · \(roa.prefix)\(roa.max_length.map { " (max /\($0))" } ?? "")")
                            .font(WatchTypography.small.monospaced())
                            .foregroundStyle(p.secondary)
                    }
                    Divider()
                    Text("关联反向域名 (PTR)").font(WatchTypography.caption).foregroundStyle(p.secondary)
                    if let domains = r.related_domains, !domains.isEmpty {
                        ForEach(domains.prefix(3)) { item in
                            HStack {
                                Text(item.domain)
                                    .font(WatchTypography.small.monospaced())
                                    .lineLimit(1)
                                    .textSelection(.enabled)
                                Spacer()
                                Text(item.via).font(WatchTypography.small).foregroundStyle(p.secondary)
                            }
                        }
                    } else {
                        Text("未检出 PTR 关联域名").font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                }
            }
        }
    }

    private func threatPillRow(_ label: String, detected: Bool, detail: String? = nil, cleanLabel: String = "未检测到", warnOnly: Bool = false) -> some View {
        let tint: Color = detected ? (warnOnly ? p.amber : p.red) : p.mint
        let badgeText = detected ? (detail.map { "已命中 · \($0)" } ?? "已检测到") : cleanLabel
        return HStack(spacing: 8) {
            Text(label).font(WatchTypography.caption).foregroundStyle(p.secondary)
            Spacer(minLength: 6)
            Badge(text: badgeText, color: tint)
        }
    }

    private func ipGeoConsistencyCard(_ r: IpIntelReport) -> some View {
        guard let geo = r.geo_consistency, !geo.sources.isEmpty else { return AnyView(EmptyView()) }
        return AnyView(Surface(p, padding: 15) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("多源地理位置交叉核验（防广播漂移与错配）", systemImage: "map")
                        .font(WatchTypography.bodyStrong)
                    Spacer()
                    Badge(
                        text: geo.consistent ? "多源国家一致" : "国家归属冲突 (\(geo.countries.joined(separator: "/")))",
                        color: geo.consistent ? p.mint : p.red
                    )
                    if let drift = geo.max_drift_km {
                        Badge(
                            text: String(format: "最大坐标偏移 %.1f km", drift),
                            color: drift < 80 ? p.blue : p.amber
                        )
                    }
                }
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 10)], spacing: 8) {
                    ForEach(geo.sources) { src in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(src.source).font(WatchTypography.captionStrong).foregroundStyle(p.blue)
                                Spacer()
                                CountryFlag(code: src.country_code)
                                Text(src.country_code).font(WatchTypography.small.monospaced().weight(.semibold))
                            }
                            let locText = [src.country, src.region, src.city].filter { !$0.isEmpty }.joined(separator: " / ")
                            Text(locText.isEmpty ? "—" : locText)
                                .font(WatchTypography.caption)
                                .lineLimit(1)
                            HStack(spacing: 8) {
                                if let lat = src.latitude, let lon = src.longitude {
                                    Text(String(format: "%.3f, %.3f", lat, lon))
                                        .font(WatchTypography.small.monospaced())
                                        .foregroundStyle(p.secondary)
                                }
                                if !src.timezone.isEmpty {
                                    Text(src.timezone)
                                        .font(WatchTypography.small)
                                        .foregroundStyle(p.secondary)
                                }
                            }
                        }
                        .padding(10)
                        .background(p.elevated.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
        })
    }

    // MARK: - Module 02: AI Endpoints, Edge Protocol Stack & Live Socket Correlation

    private var aiEndpointsModule: some View {
        let state = effectiveAIState
        let result = state.result

        return VStack(alignment: .leading, spacing: 12) {
            moduleSectionBanner(
                code: "MODULE 02",
                title: "AI 平台全端点连通、边缘协议栈与进程连接对照",
                subtitle: "并发实测 Claude / Anthropic API / ChatGPT / OpenAI API 响应耗时、Cloudflare 落地机房 (Colo)、TLS 密钥交换与应用实际代理链",
                trailing: {
                    Button {
                        state.running ? aiChecks.cancel(.all) : aiChecks.start(.all)
                    } label: {
                        Label(state.running ? "停止探测" : "重测全部端点", systemImage: state.running ? "stop.fill" : "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            )

            Surface(p, padding: 16) {
                VStack(alignment: .leading, spacing: 12) {
                    if let endpoints = result?.endpoints, !endpoints.isEmpty {
                        ForEach(Array(endpoints.enumerated()), id: \.element.id) { idx, ep in
                            if idx > 0 { Divider() }
                            aiEndpointRow(ep)
                        }
                        if let refEp = result?.referenceEndpoint {
                            Divider()
                            aiEndpointRow(refEp, isReference: true)
                        }
                    } else {
                        Text(state.running ? "正在通过受控代理并发请求 Claude 与 OpenAI 全部诊断端点…" : "尚未执行端点连通探测。")
                            .font(WatchTypography.body)
                            .foregroundStyle(p.secondary)
                            .padding(.vertical, 6)
                    }

                    Divider()
                    liveAppSocketCorrelationStrip(probeResult: result)
                }
            }
        }
    }

    private func aiEndpointRow(_ ep: AIEndpointResult, isReference: Bool = false) -> some View {
        let code = ep.httpStatus ?? 0
        let healthy = ep.status == "responded" && (code == 200 || code == 401)
        let tint: Color = healthy ? p.mint : (code == 403 || code == 429) ? p.amber : p.red
        let brand: ServiceBrand = isReference ? .cloudflare : (ep.family == "gpt" ? .chatgpt : .claude)

        return HStack(alignment: .center, spacing: 12) {
            BrandLogo(brand: brand, size: 18)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(ep.label ?? ep.url)
                        .font(WatchTypography.bodyStrong)
                    if let colo = nonEmpty(ep.colo) {
                        Badge(text: "POP: \(colo)\(nonEmpty(ep.coloCity).map { " · \($0)" } ?? "")", color: p.blue)
                    }
                    if ep.cfChallenge == true {
                        Badge(text: "CF Turnstile 质询", color: p.amber)
                    }
                }
                HStack(spacing: 10) {
                    Text(ep.url)
                        .font(WatchTypography.small.monospaced())
                        .foregroundStyle(p.secondary)
                        .textSelection(.enabled)
                    if let ip = nonEmpty(ep.exitIP) {
                        Text("出口 \(ip)")
                            .font(WatchTypography.small.monospaced())
                            .foregroundStyle(p.text)
                    }
                }
            }

            Spacer(minLength: 8)

            HStack(spacing: 6) {
                if let tls = nonEmpty(ep.tls) {
                    Badge(text: tls, color: p.secondary)
                }
                if let proto = nonEmpty(ep.httpProtocol) {
                    Badge(text: proto, color: p.secondary)
                }
                if let kex = nonEmpty(ep.kex) {
                    Badge(text: kex, color: p.secondary)
                }
                if let warp = nonEmpty(ep.warp), warp != "off" {
                    Badge(text: "WARP: \(warp)", color: p.amber)
                }
            }

            VStack(alignment: .trailing, spacing: 2) {
                Badge(
                    text: code > 0 ? "HTTP \(code)" : (ep.status == "timeout" ? "超时" : "异常"),
                    color: tint
                )
                Text(ep.elapsedMs.map { String(format: "%.0f ms", $0) } ?? ep.message)
                    .font(WatchTypography.small.monospacedDigit())
                    .foregroundStyle(p.secondary)
            }
            .frame(minWidth: 88, alignment: .trailing)
        }
        .padding(.vertical, 3)
    }

    private func liveAppSocketCorrelationStrip(probeResult: AIProbeResult?) -> some View {
        let claudeScope = ConnectionGraphScope(
            product: .claude,
            processes: store.snapshot?.processes ?? [],
            flows: store.proxy?.flows ?? []
        )
        let gptScope = ConnectionGraphScope(
            product: .openAI,
            processes: store.snapshot?.processes ?? [],
            flows: store.proxy?.flows ?? []
        )
        let claudeNodes = Array(Set(claudeScope.platformFlows.filter { $0.association == "correlated" }.compactMap { $0.chains.last })).sorted()
        let gptNodes = Array(Set(gptScope.platformFlows.filter { $0.association == "correlated" }.compactMap { $0.chains.last })).sorted()

        return HStack(alignment: .center, spacing: 14) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .foregroundStyle(p.mint)
            VStack(alignment: .leading, spacing: 3) {
                Text("本机运行中 AI 进程实时连接印证（区分诊断请求与应用实际流量）")
                    .font(WatchTypography.captionStrong)
                HStack(spacing: 16) {
                    Text("Claude：\(claudeScope.processes.count) 进程 / \(claudeScope.platformFlows.count) 连接 · 节点：\(claudeNodes.isEmpty ? "暂无活跃连接" : claudeNodes.joined(separator: "、"))")
                        .font(WatchTypography.small)
                        .foregroundStyle(p.secondary)
                    Text("ChatGPT / Codex：\(gptScope.processes.count) 进程 / \(gptScope.platformFlows.count) 连接 · 节点：\(gptNodes.isEmpty ? "暂无活跃连接" : gptNodes.joined(separator: "、"))")
                        .font(WatchTypography.small)
                        .foregroundStyle(p.secondary)
                }
            }
            Spacer()
            PageLink(title: "查看连接拓扑图", p: p) {
                store.page = .network
            }
        }
        .padding(10)
        .background(p.elevated.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Module 03: Authoritative DNS & WebRTC / Interface Leak Forensics

    private var leakForensicsModule: some View {
        VStack(alignment: .leading, spacing: 12) {
            moduleSectionBanner(
                code: "MODULE 03",
                title: "DNS 权威递归与 WebRTC / 本机全网卡泄漏取证",
                subtitle: "与受控启动门禁共享同一守护进程权威证据链（通过即自动满足启动预检）",
                trailing: {
                    HStack(spacing: 8) {
                        Button(leakChecks.dns.running ? "取消 DNS" : "重测 DNS") {
                            leakChecks.dns.running ? leakChecks.cancel(.dns) : leakChecks.start(.dns)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)

                        Button(leakChecks.rtc.running ? "取消 WebRTC" : "重测 WebRTC") {
                            leakChecks.rtc.running ? leakChecks.cancel(.webrtc) : leakChecks.start(.webrtc)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
            )

            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 12) {
                    dnsForensicsCard
                        .frame(minWidth: 380, maxWidth: .infinity, alignment: .topLeading)
                    webrtcForensicsCard
                        .frame(minWidth: 380, maxWidth: .infinity, alignment: .topLeading)
                }
                VStack(alignment: .leading, spacing: 12) {
                    dnsForensicsCard
                    webrtcForensicsCard
                }
            }
        }
    }

    private func cleanVerdictDetail(_ raw: String, finishedAt: Double?) -> String {
        guard let finishedAt, finishedAt.isFinite, finishedAt > 0,
              let range = raw.range(of: "；采样 ") else {
            return raw
        }
        let suffix = String(raw[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        if !suffix.isEmpty, suffix.allSatisfy({ $0.isNumber || $0 == "." }) {
            return String(raw[..<range.lowerBound]) + "；采样于 " + timeText(finishedAt, date: false)
        }
        return raw
    }

    private var dnsForensicsCard: some View {
        let state = leakChecks.dns
        let result = state.displayResult
        let obs = result?.observations ?? []
        let resolvers = obs.filter { $0.kind == "resolver" }
        let httpRef = obs.first(where: { $0.kind == "http" })
        let ecsNote = result?.details.first(where: { $0.contains("Fake-IP") || $0.contains("ECS") })
        let codes = CountryIdentity.geoCodes(result?.externalJSON)
        let tint = style.verdictColor(state.verdict.state)
        let isFakeIpProtected = (result?.externalJSON?.contains("\"intercepted\":true") == true)
            || state.verdict.detail.contains("Fake-IP")
            || (ecsNote?.contains("Fake-IP") == true)
            || (state.verdict.state == .matched && httpRef?.country != nil && resolvers.contains(where: { $0.country != nil && $0.country != httpRef?.country }))

        return Surface(p, padding: 16) {
            VStack(alignment: .leading, spacing: 11) {
                HStack {
                    Label("DNS 权威递归解析出口", systemImage: "server.rack")
                        .font(WatchTypography.bodyStrong)
                    Spacer()
                    Badge(text: state.running ? "检测中…" : state.verdict.title, color: tint)
                }
                Text(cleanVerdictDetail(state.verdict.detail, finishedAt: result?.finishedAt))
                    .font(WatchTypography.small)
                    .foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if isFakeIpProtected {
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 6) {
                            Image(systemName: "checkmark.shield.fill")
                                .foregroundStyle(p.mint)
                                .font(.system(size: 13))
                            Text("Fake-IP 虚拟网卡已接管 AI 域名解析（Claude 连接零国内 DNS 暴露）")
                                .font(WatchTypography.captionStrong)
                                .foregroundStyle(p.text)
                        }
                        Text(ecsNote ?? "claude.ai 与 chatgpt.com 的 A / AAAA / HTTPS(65) 记录均在本地 0ms 拦截，建连时直达远端代理节点解析；Claude 不会发起 TXT 查询。")
                            .font(WatchTypography.small)
                            .foregroundStyle(p.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(p.mint.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(p.mint.opacity(0.28), lineWidth: 1))
                } else if let ecsNote {
                    let isGood = ecsNote.contains("Fake-IP") || ecsNote.contains("未检测到")
                    HStack(spacing: 6) {
                        Image(systemName: isGood ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                            .foregroundStyle(isGood ? p.mint : p.amber)
                            .font(.system(size: 12))
                        Text(ecsNote)
                            .font(WatchTypography.small)
                            .foregroundStyle(p.text)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background((isGood ? p.mint : p.amber).opacity(0.08), in: RoundedRectangle(cornerRadius: 7))
                }

                Divider()
                if isFakeIpProtected && !resolvers.isEmpty {
                    DisclosureGroup("底层 TXT 探针回显参考 (\(resolvers.count)) · 不走 Fake-IP，不影响 Claude 连接", isExpanded: $txtFallbackExpanded) {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(Array(resolvers.enumerated()), id: \.offset) { idx, item in
                                if idx > 0 { Divider() }
                                leakObservationCompactRow(item, codeOverride: codes[item.address])
                            }
                        }
                        .padding(.top, 8)
                    }
                    .font(WatchTypography.caption)
                    .foregroundStyle(p.secondary)
                    .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                } else {
                    Text("观测到的上游递归解析器 (\(resolvers.count))")
                        .font(WatchTypography.captionStrong)
                        .foregroundStyle(p.secondary)

                    if resolvers.isEmpty {
                        Text(state.running ? "正在并发向 Akamai 与 Google 权威 NS 发起回显查询…" : "暂无递归解析器样本")
                            .font(WatchTypography.caption).foregroundStyle(p.secondary)
                    } else {
                        ForEach(Array(resolvers.enumerated()), id: \.offset) { idx, item in
                            if idx > 0 { Divider() }
                            leakObservationCompactRow(item, codeOverride: codes[item.address])
                        }
                    }
                }

                if let httpRef {
                    Divider()
                    HStack {
                        Text("同轮代理 HTTP 对照出口").font(WatchTypography.small).foregroundStyle(p.secondary)
                        Spacer()
                        CountryFlag(code: codes[httpRef.address] ?? httpRef.country)
                        Text("\(httpRef.address) [\(httpRef.country ?? "—")]")
                            .font(WatchTypography.small.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private var webrtcForensicsCard: some View {
        let state = leakChecks.rtc
        let result = state.displayResult
        let obs = result?.observations ?? []
        let httpRef = obs.first(where: { $0.kind == "http" })
        let nonHttp = obs.filter { $0.kind != "http" }
        let localHost = nonHttp.filter { $0.kind == "mdns" || ($0.kind == "host" && LeakIPAddress($0.address)?.isPublic != true) }
        let publicCandidates = nonHttp.filter { item in !localHost.contains(where: { $0.address == item.address && $0.kind == item.kind }) }
        let publicHostIPv6 = publicCandidates.filter { $0.kind == "host" && $0.family == 6 }
        let codes = CountryIdentity.geoCodes(result?.externalJSON)
        let tint = style.verdictColor(state.verdict.state)

        return Surface(p, padding: 16) {
            VStack(alignment: .leading, spacing: 11) {
                HStack {
                    Label("WebRTC / STUN 反射与双栈网卡盘点", systemImage: "antenna.radiowaves.left.and.right")
                        .font(WatchTypography.bodyStrong)
                    Spacer()
                    Badge(text: state.running ? "检测中…" : state.verdict.title, color: tint)
                }
                Text(state.verdict.detail)
                    .font(WatchTypography.small)
                    .foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if !publicHostIPv6.isEmpty {
                    InlineNotice(
                        title: "检测到本机网卡挂载公网单播 IPv6 地址（\(publicHostIPv6.count) 个）",
                        detail: "若外部代理未开启 IPv6 接管，非沙箱浏览器可能经公网 IPv6 旁路直连；Watch 受控沙箱已默认阻断直连。",
                        symbol: "network.badge.shield.half.filled",
                        tint: p.amber,
                        p: p
                    )
                }

                Divider()
                Text("公网 STUN 反射与直连公网候选 (\(publicCandidates.count))")
                    .font(WatchTypography.captionStrong)
                    .foregroundStyle(p.secondary)

                if publicCandidates.isEmpty {
                    Text(state.running ? "正在并发探测 Cloudflare / Google STUN 与本机网卡…" : "未暴露公网 UDP 反射地址（或已被防火墙/沙箱阻断）")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                } else {
                    ForEach(LeakCandidateGroup.group(publicCandidates)) { grp in
                        if let first = grp.observations.first {
                            leakObservationCompactRow(
                                first,
                                codeOverride: codes[grp.id.address],
                                suffix: grp.sourceCount > 1 ? "\(grp.sourceCount) 台 STUN 验证" : nil
                            )
                        }
                    }
                }

                if !localHost.isEmpty {
                    Divider()
                    DisclosureGroup("本机局域网与虚拟隧道网卡地址 (\(localHost.count))", isExpanded: $localInterfacesExpanded) {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Array(localHost.enumerated()), id: \.offset) { _, localItem in
                                HStack {
                                    Text(localItem.address)
                                        .font(WatchTypography.small.monospaced())
                                        .textSelection(.enabled)
                                    Spacer()
                                    Text(localItem.source)
                                        .font(WatchTypography.small)
                                        .foregroundStyle(p.secondary)
                                }
                            }
                        }
                        .padding(.top, 6)
                    }
                    .font(WatchTypography.caption)
                    .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                }

                if let httpRef {
                    Divider()
                    HStack {
                        Text("同轮代理 HTTP 对照出口").font(WatchTypography.small).foregroundStyle(p.secondary)
                        Spacer()
                        CountryFlag(code: codes[httpRef.address] ?? httpRef.country)
                        Text("\(httpRef.address) [\(httpRef.country ?? "—")]")
                            .font(WatchTypography.small.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private func leakObservationCompactRow(_ item: LeakObservation, codeOverride: String?, suffix: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Text(item.address)
                    .font(WatchTypography.mono.weight(.semibold))
                    .textSelection(.enabled)
                if let fam = item.family {
                    Badge(text: "IPv\(fam)", color: p.secondary)
                }
                Spacer()
                if let suffix {
                    Text(suffix).font(WatchTypography.small).foregroundStyle(p.blue)
                }
            }
            CountryLine(
                code: codeOverride ?? item.country,
                country: item.country,
                region: item.region,
                city: item.city,
                organization: item.isp,
                p: p
            )
            Text(item.source)
                .font(WatchTypography.small)
                .foregroundStyle(p.secondary)
        }
    }

    // MARK: - Module 04: Audit Provenance & Raw Evidence

    private var auditReceiptFooter: some View {
        Surface(p, padding: 14) {
            DisclosureGroup("采样上下文、多源接口回执状态与 SHA-256 证据摘要", isExpanded: $rawEvidenceExpanded) {
                VStack(alignment: .leading, spacing: 8) {
                    if let r = ipIntel.currentReport {
                        DetailRow(title: "IP 情报代理传输", value: r.transport ?? "受控本地回环代理", p: p, monospaced: true)
                        DetailRow(title: "原始响应 SHA-256", value: r.sha256 ?? "—", p: p, monospaced: true)
                        if let statuses = r.source_statuses {
                            Text("权威情报源子状态：")
                                .font(WatchTypography.captionStrong)
                                .padding(.top, 4)
                            Text(statuses.pretty)
                                .font(WatchTypography.small.monospaced())
                                .foregroundStyle(p.secondary)
                                .textSelection(.enabled)
                        }
                    }
                    Text("免责与边界说明：IP 纯净度评分、RPKI 与泄漏探针均反映本轮受控网络通道的客观技术特征，不访问或修改任何已登录 AI 账号凭据。")
                        .font(WatchTypography.small)
                        .foregroundStyle(p.secondary)
                        .padding(.top, 4)
                }
                .padding(.top, 10)
            }
            .font(WatchTypography.caption.weight(.medium))
            .foregroundStyle(p.secondary)
            .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
        }
    }

    // MARK: - Helpers

    private func moduleSectionBanner<Trailing: View>(
        code: String,
        title: String,
        subtitle: String,
        @ViewBuilder trailing: () -> Trailing
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(code)
                .font(WatchTypography.small.monospaced().weight(.semibold))
                .foregroundStyle(p.blue)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(p.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 5))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(WatchTypography.section)
                Text(subtitle).font(WatchTypography.small).foregroundStyle(p.secondary)
            }
            Spacer(minLength: 8)
            trailing()
        }
        .padding(.top, 4)
    }

    private func kvBadgeRow(key: String, text: String, badge: String, badgeColor: Color) -> some View {
        HStack(spacing: 8) {
            Text(key)
                .font(WatchTypography.caption)
                .foregroundStyle(p.secondary)
            Spacer(minLength: 8)
            if !text.isEmpty {
                Text(text)
                    .font(WatchTypography.caption)
                    .foregroundStyle(p.text)
                    .lineLimit(1)
            }
            Badge(text: badge, color: badgeColor)
        }
    }

    private func nonEmpty(_ s: String?) -> String? {
        guard let trimmed = s?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        return trimmed
    }

    private func formatAsnKind(_ raw: String?) -> String {
        switch raw?.lowercased() {
        case "isp": return "isp [宽带运营商]"
        case "hosting": return "hosting [机房 / 云托管]"
        case "business": return "business [商业企业网]"
        case "education": return "education [教育科研网]"
        case "government": return "government [政务公共网]"
        case "backbone": return "backbone [骨干网]"
        case .some(let v) where !v.isEmpty: return v
        default: return "未分类"
        }
    }

    private func scoreTint(_ score: Int?) -> Color {
        guard let score else { return p.secondary }
        if score >= 85 { return p.mint }
        if score >= 65 { return p.blue }
        if score >= 45 { return p.amber }
        return p.red
    }

    private func factorColor(_ status: String) -> Color {
        switch status {
        case "pass": return p.mint
        case "info": return p.blue
        case "warn": return p.amber
        case "fail": return p.red
        default: return p.secondary
        }
    }

    private func abuserTierColor(_ tier: String?) -> Color {
        switch tier {
        case "very_low", "low": return p.mint
        case "elevated": return p.amber
        case "high", "very_high": return p.red
        default: return p.secondary
        }
    }
}

/// Retained candidate grouper used by `NetworkPanoramaPage` for STUN observations.
struct LeakCandidateGroup: Identifiable {
    struct Key: Hashable {
        let address, kind: String
        let family: Int?
    }
    let id: Key
    var observations: [LeakObservation]
    var sourceCount: Int { Set(observations.map(\.source)).count }

    static func group(_ observations: [LeakObservation]) -> [Self] {
        var result: [Self] = []
        var indices: [Key: Int] = [:]
        for item in observations {
            let key = Key(
                address: LeakIPAddress(item.address)?.canonical ?? item.address,
                kind: item.kind,
                family: item.family
            )
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
