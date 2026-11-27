import SwiftUI

/// Single-authority AI VPN channel & node management workbench inside "代理与连接".
/// Allows switching between reusing the host VPN (TAG / Clash) and running Agent Watch's
/// isolated non-TUN `watch-vpn-core` tunnel without interfering with host VPNs or system proxy.
struct ManagedVpnPanel: View {
    @ObservedObject var store: ManagedVpnStore
    let p: Palette

    private enum SourceTab: String, CaseIterable, Identifiable {
        case builtin = "自带 VPN 服务"
        case custom = "自配节点 / 订阅"
        var id: String { rawValue }
    }

    @State private var sourceTab: SourceTab = .custom
    @State private var showImportSheet = false
    @State private var showServiceEditor = false
    @State private var serviceURLInput = ""
    @State private var serviceTokenInput = ""
    @State private var serviceLabelInput = "自带 VPN 服务"
    @State private var pendingDeleteNode: ManagedVpnNode?

    var body: some View {
        Surface(p, padding: 16) {
            VStack(alignment: .leading, spacing: 14) {
                headerRow
                if let err = store.errorMessage, !err.isEmpty {
                    InlineNotice(title: "独立 VPN 操作提示", detail: err,
                                 symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                } else if !store.message.isEmpty {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 12))
                            .foregroundStyle(p.mint)
                        Text(store.message)
                            .font(WatchTypography.caption)
                            .foregroundStyle(p.secondary)
                        Spacer()
                    }
                    .padding(.horizontal, 10).padding(.vertical, 7)
                    .background(p.mint.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                }

                if store.mode == .external {
                    externalSummaryStrip
                } else {
                    managedWorkbench
                }
            }
        }
        .task { await store.refresh() }
        .sheet(isPresented: $showImportSheet) {
            ManagedVpnImportSheet(store: store, p: p) {
                showImportSheet = false
            }
        }
        .confirmationDialog(
            "删除节点「\(pendingDeleteNode?.name ?? "")」？",
            isPresented: Binding(
                get: { pendingDeleteNode != nil },
                set: { if !$0 { pendingDeleteNode = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("确认删除", role: .destructive) {
                if let id = pendingDeleteNode?.id {
                    pendingDeleteNode = nil
                    Task { await store.deleteNode(id: id) }
                }
            }
            Button("取消", role: .cancel) { pendingDeleteNode = nil }
        } message: {
            Text("该节点的加密凭据将从本机 0600 私密库中彻底移除。")
        }
    }

    private var headerRow: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: store.mode == .managed ? "lock.shield.fill" : "network")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(store.mode == .managed ? p.mint : p.blue)
                .frame(width: 30, height: 30)
                .background((store.mode == .managed ? p.mint : p.blue).opacity(0.1), in: RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text("AI 专属 VPN 通道").font(WatchTypography.section)
                    if store.mode == .managed {
                        Badge(text: "独立无 TUN · 不影响本机 VPN", color: p.mint)
                    } else {
                        Badge(text: "复用本机外部 VPN", color: p.blue)
                    }
                }
                Text(store.mode == .managed
                     ? "仅接管受控 AI 流量，不开虚拟网卡、不改系统代理、不绑定固定网卡。"
                     : "当前只读监督本机外部代理（如 TAG / Clash）；可切换为独立内置 VPN 以彻底隔离日常上网。")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
            }

            Spacer(minLength: 10)

            Picker("VPN 通道模式", selection: Binding(
                get: { store.mode },
                set: { next in
                    guard next != store.mode else { return }
                    Task { await store.setMode(next) }
                }
            )) {
                Text("复用本机 VPN").tag(ManagedVpnMode.external)
                Text("独立内置 VPN").tag(ManagedVpnMode.managed)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 240)
            .disabled(store.busy)
        }
    }

    private var externalSummaryStrip: some View {
        HStack(spacing: 10) {
            Image(systemName: "info.circle")
                .foregroundStyle(p.secondary)
            Text(store.nodes.isEmpty
                 ? "如需为 Claude / ChatGPT 单独提供独立线路而不影响本机 TAG，请切换到「独立内置 VPN」导入节点或接入自带 VPN 服务。"
                 : "本地私密库已保存 \(store.nodes.count) 个独立节点；随时可切换至「独立内置 VPN」启用。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button(store.nodes.isEmpty ? "配置独立节点…" : "启用独立 VPN") {
                if store.nodes.isEmpty {
                    Task {
                        await store.setMode(.managed)
                        showImportSheet = true
                    }
                } else {
                    Task { await store.setMode(.managed) }
                }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(store.busy)
        }
        .padding(10)
        .background(p.elevated.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
    }

    private var managedWorkbench: some View {
        VStack(alignment: .leading, spacing: 12) {
            runtimeStatusBanner

            if let core = store.core, !core.available {
                InlineNotice(
                    title: "尚未检测到内置独立 VPN 内核组件（watch-vpn-core）",
                    detail: core.message ?? "请通过应用内更新升级到包含内置内核的正式构建包后启用。",
                    symbol: "shippingbox",
                    tint: p.amber,
                    p: p
                )
            }

            Divider()

            HStack(spacing: 10) {
                Picker("节点来源", selection: $sourceTab) {
                    ForEach(SourceTab.allCases) { tab in
                        let count = tab == .builtin ? store.builtinNodes.count : store.customNodes.count
                        Text("\(tab.rawValue) (\(count))").tag(tab)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 290)

                Spacer(minLength: 8)

                if sourceTab == .builtin {
                    if store.service?.configured == true {
                        Button {
                            Task { await store.syncBuiltinService() }
                        } label: {
                            Label("同步节点", systemImage: "arrow.triangle.2.circlepath")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .disabled(store.busy)
                    }
                    Button(showServiceEditor ? "收起设置" : (store.service?.configured == true ? "修改服务…" : "接入自带服务…")) {
                        withAnimation(.easeInOut(duration: 0.15)) { showServiceEditor.toggle() }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                } else {
                    Button {
                        showImportSheet = true
                    } label: {
                        Label("导入节点 / 订阅…", systemImage: "plus")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                }

                Button {
                    Task { await store.refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help("刷新独立 VPN 状态")
                .disabled(store.busy)
            }

            if sourceTab == .builtin {
                builtinServiceSection
            }

            nodeListSection(for: sourceTab == .builtin ? store.builtinNodes : store.customNodes)
        }
    }

    private var runtimeStatusBanner: some View {
        let state = store.runtime?.state ?? "inactive"
        let (label, tint): (String, Color) = {
            switch state {
            case "running": return ("独立隧道运行中", p.mint)
            case "starting": return ("正在启动独立内核…", p.blue)
            case "core_missing": return ("内核未安装", p.amber)
            case "error": return ("隧道启动异常", p.red)
            default: return ("待选定节点", p.secondary)
            }
        }()

        return HStack(spacing: 12) {
            Circle()
                .fill(tint)
                .frame(width: 9, height: 9)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(label).font(WatchTypography.bodyStrong)
                    if let node = store.selectedNode {
                        Badge(text: node.protocol_label, color: p.blue)
                    }
                }
                if let node = store.selectedNode {
                    HStack(spacing: 8) {
                        Text("当前节点：\(node.name)").font(WatchTypography.small).foregroundStyle(p.text)
                        if let ep = store.runtime?.upstream_endpoint, state == "running" {
                            Text("· 私密入口 \(ep)")
                                .font(WatchTypography.small.monospaced())
                                .foregroundStyle(p.secondary)
                        }
                        if let probe = node.probe, let ip = probe.egress_ip {
                            let cc = probe.country.map { " [\($0)]" } ?? ""
                            let ms = probe.latency_ms.map { " \($0)ms" } ?? ""
                            Text("· 实测出口 \(ip)\(cc)\(ms)")
                                .font(WatchTypography.small.monospaced())
                                .foregroundStyle(p.mint)
                        }
                    }
                } else if let errMsg = store.runtime?.error_message, !errMsg.isEmpty {
                    Text(errMsg).font(WatchTypography.small).foregroundStyle(p.amber)
                } else {
                    Text("请在下方接入「自带 VPN 服务」或导入自定义节点（支持 Clash YAML / vless:// / 订阅）。")
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                }
            }
            Spacer(minLength: 8)
            if let node = store.selectedNode {
                Button {
                    Task { await store.probeNode(id: node.id) }
                } label: {
                    if store.probingNodeIDs.contains(node.id) {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("实测出口", systemImage: "speedometer")
                    }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(store.probingNodeIDs.contains(node.id))
            }
        }
        .padding(11)
        .background(tint.opacity(0.07), in: RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(tint.opacity(0.24), lineWidth: 1))
    }

    @ViewBuilder
    private var builtinServiceSection: some View {
        if let svc = store.service, svc.configured, !showServiceEditor {
            HStack(spacing: 10) {
                Image(systemName: "cloud.fill").foregroundStyle(p.blue)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(svc.label.isEmpty ? "自带 VPN 服务" : svc.label)
                            .font(WatchTypography.caption.weight(.semibold))
                        if !svc.host.isEmpty {
                            Text(svc.host).font(WatchTypography.small.monospaced()).foregroundStyle(p.secondary)
                        }
                        if svc.has_token {
                            Badge(text: "已加密保存授权码", color: p.mint)
                        }
                    }
                    if let notice = svc.notice, !notice.isEmpty {
                        Text("服务公告：\(notice)").font(WatchTypography.small).foregroundStyle(p.secondary)
                    } else if let err = svc.last_error, !err.isEmpty {
                        Text("上次同步失败：\(err)").font(WatchTypography.small).foregroundStyle(p.amber)
                    } else if let ts = svc.last_synced_at {
                        Text("上次同步：\(timeText(Double(ts), date: true))")
                            .font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                }
                Spacer()
                Button("清除服务", role: .destructive) {
                    Task { await store.clearBuiltinService() }
                }
                .buttonStyle(.borderless)
                .font(WatchTypography.small)
                .disabled(store.busy)
            }
            .padding(10)
            .background(p.elevated.opacity(0.32), in: RoundedRectangle(cornerRadius: 8))
        }

        if showServiceEditor || store.service?.configured != true {
            VStack(alignment: .leading, spacing: 8) {
                Text("接入自带 VPN 服务（HTTPS 订阅 / 节点清单接口）")
                    .font(WatchTypography.caption.weight(.semibold))
                Text("填入您提供的 HTTPS 服务地址与可选授权码；响应兼容 JSON 节点清单、Clash YAML 与 Base64 订阅，凭据仅保存于本机 0600 私密库。")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
                HStack(spacing: 8) {
                    TextField("服务名称", text: $serviceLabelInput)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 130)
                    TextField("HTTPS 服务接入地址（如 https://vpn.example.com/nodes）", text: $serviceURLInput)
                        .textFieldStyle(.roundedBorder)
                }
                HStack(spacing: 8) {
                    SecureField("授权码 / Access Token（可选）", text: $serviceTokenInput)
                        .textFieldStyle(.roundedBorder)
                    Button("保存并同步节点") {
                        Task {
                            let ok = await store.saveAndSyncBuiltinService(
                                url: serviceURLInput,
                                token: serviceTokenInput,
                                label: serviceLabelInput
                            )
                            if ok {
                                serviceTokenInput = ""
                                showServiceEditor = false
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(store.busy || serviceURLInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .padding(10)
            .background(p.elevated.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    @ViewBuilder
    private func nodeListSection(for items: [ManagedVpnNode]) -> some View {
        if items.isEmpty {
            HStack(spacing: 10) {
                Image(systemName: "tray")
                    .foregroundStyle(p.secondary)
                Text(sourceTab == .builtin
                     ? "暂无自带服务节点，请先在上方填写接入地址并同步。"
                     : "暂无自定义节点；点击右上角「导入节点 / 订阅…」直接粘贴 Clash YAML（如 VLESS Reality）或分享链接即可。")
                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
            }
            .padding(.vertical, 10)
        } else {
            VStack(spacing: 6) {
                ForEach(items) { node in
                    nodeRow(node)
                }
            }
        }
    }

    private func nodeRow(_ node: ManagedVpnNode) -> some View {
        let isSelected = store.selectedNodeID == node.id
        let probing = store.probingNodeIDs.contains(node.id)
        return HStack(spacing: 10) {
            Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                .font(.system(size: 14))
                .foregroundStyle(isSelected ? p.mint : p.secondary.opacity(0.6))

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(node.name)
                        .font(WatchTypography.bodyStrong)
                        .foregroundStyle(p.text)
                        .lineLimit(1)
                    Badge(text: node.protocol_label, color: node.reality ? p.blue : p.secondary)
                    if let fp = node.fingerprint, !fp.isEmpty {
                        Badge(text: "uTLS:\(fp)", color: p.secondary)
                    }
                }
                HStack(spacing: 8) {
                    Text(node.server_masked)
                        .font(WatchTypography.small.monospaced())
                        .foregroundStyle(p.secondary)
                    if let sni = node.sni, !sni.isEmpty {
                        Text("SNI \(sni)")
                            .font(WatchTypography.small)
                            .foregroundStyle(p.secondary)
                    }
                    if let note = node.protocol_note, !note.isEmpty {
                        Text("· \(note)")
                            .font(WatchTypography.small)
                            .foregroundStyle(p.blue)
                    }
                }
                if let probe = node.probe {
                    if let err = probe.error, !err.isEmpty {
                        Text("最近测试失败：\(err)")
                            .font(WatchTypography.small)
                            .foregroundStyle(p.amber)
                    } else if let ip = probe.egress_ip {
                        let country = probe.country ?? "--"
                        let ms = probe.latency_ms.map { "\($0)ms" } ?? "--"
                        let isp = probe.isp.map { " · \($0)" } ?? ""
                        Text("实测出口 \(ip) · \(country) · \(ms)\(isp)")
                            .font(WatchTypography.small.monospaced())
                            .foregroundStyle(p.mint)
                    }
                }
            }

            Spacer(minLength: 8)

            Button {
                Task { await store.probeNode(id: node.id) }
            } label: {
                if probing {
                    ProgressView().controlSize(.small)
                } else {
                    Text("测速")
                }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(probing)

            Button(isSelected ? "使用中" : "选用") {
                Task { await store.selectNode(id: node.id) }
            }
            .buttonStyle(.borderedProminent)
            .tint(isSelected ? p.mint : p.blue)
            .controlSize(.small)
            .disabled(isSelected || store.busy)

            if !node.isBuiltinService {
                Button {
                    pendingDeleteNode = node
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(p.secondary)
                .help("删除节点")
                .disabled(store.busy)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background((isSelected ? p.mint.opacity(0.08) : p.elevated.opacity(0.28)), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(isSelected ? p.mint.opacity(0.35) : p.border.opacity(0.55), lineWidth: 1))
    }
}

private struct ManagedVpnImportSheet: View {
    @ObservedObject var store: ManagedVpnStore
    let p: Palette
    let onDismiss: () -> Void

    @State private var rawText = ""
    @State private var previewNodes: [ManagedVpnNode] = []
    @State private var previewError: String?
    @State private var previewing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("导入独立 VPN 节点或订阅").font(WatchTypography.pageTitle)
                    Text("直接粘贴 Clash YAML 节点片段、vless:// / vmess:// / trojan:// / ss:// / hy2:// 链接，或 HTTPS 订阅地址。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
                Spacer()
                Button("取消", action: onDismiss)
            }

            TextEditor(text: $rawText)
                .font(WatchTypography.mono)
                .frame(height: 170)
                .padding(6)
                .background(p.elevated.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(p.border, lineWidth: 1))

            HStack(spacing: 10) {
                Button(previewing ? "解析中…" : "预览解析结果") {
                    Task {
                        previewing = true
                        previewError = nil
                        let result = await store.previewImport(text: rawText, provider: "custom")
                        previewing = false
                        switch result {
                        case .success(let nodes):
                            previewNodes = nodes
                        case .failure(let error):
                            previewNodes = []
                            previewError = error.localizedDescription
                        }
                    }
                }
                .buttonStyle(.bordered)
                .disabled(previewing || rawText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                Text("支持自动纠偏 Clash `type: vmess` + `reality-opts/flow` 为 VLESS Reality。")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
                Spacer()
            }

            if let err = previewError {
                InlineNotice(title: "解析失败", detail: err, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
            } else if !previewNodes.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("解析预览（共 \(previewNodes.count) 个节点，敏感密钥已脱敏）：")
                        .font(WatchTypography.caption.weight(.semibold))
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(previewNodes) { node in
                                HStack(spacing: 8) {
                                    Badge(text: node.protocol_label, color: p.blue)
                                    Text(node.name).font(WatchTypography.caption.weight(.medium))
                                    Text(node.server_masked).font(WatchTypography.small.monospaced()).foregroundStyle(p.secondary)
                                    if let note = node.protocol_note {
                                        Text(note).font(WatchTypography.small).foregroundStyle(p.mint)
                                    }
                                    Spacer()
                                }
                                .padding(7)
                                .background(p.elevated.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
                            }
                        }
                    }
                    .frame(maxHeight: 130)
                }
            }

            HStack {
                Text("所有节点密钥仅保存于本机 0600 私密凭据库，绝不写入日志或普通配置。")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
                Spacer()
                Button("取消", action: onDismiss)
                Button(store.busy ? "导入中…" : "确认安全导入") {
                    Task {
                        let trimmed = rawText.trimmingCharacters(in: .whitespacesAndNewlines)
                        let isSingleURL = trimmed.hasPrefix("https://") && !trimmed.contains("\n") && !trimmed.contains(" ")
                        let ok = await store.commitImport(
                            text: isSingleURL ? nil : trimmed,
                            url: isSingleURL ? trimmed : nil,
                            provider: "custom"
                        )
                        if ok { onDismiss() }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.busy || rawText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(22)
        .frame(width: 660)
        .foregroundStyle(p.text)
        .background(p.surface)
    }
}
