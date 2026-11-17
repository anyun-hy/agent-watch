import SwiftUI

struct AIProcessCloseButton: View {
    let product: MonitoredProduct
    @ObservedObject var store: MonitorStore
    @ObservedObject var control: AIProcessControl
    @ObservedObject var switcher: SwitcherStore
    let p: Palette
    @State private var pending: AIProcessClosePlan?
    @State private var confirming = false
    @State private var message = ""
    @State private var showingMessage = false

    /// Manual force quit is explicitly confirmed, independent of risk policies.
    /// Automatic warn/close/force preferences do not change this button's scope.
    private var confirmationMessage: String {
        if control.isFixture { return "当前为隔离预览，只模拟关闭，不影响实际应用。" }
        let scope = product == .openAI
            ? "对象包括 ChatGPT / Codex 桌面应用、独立 CLI 及已核实的关联子进程。"
            : "对象包括 Claude Desktop、Claude Code 及已核实的关联子进程。"
        return "本次将强制结束已核实的进程，不等待程序正常退出。此按钮独立于后台风险处置策略。\n\n\(scope)\n\n当前对话和运行任务会中断，未保存内容可能丢失；请先保存工作。"
    }

    var body: some View {
        Button {
            Task {
                do {
                    let plan = try await control.prepare(product, sampled: store.snapshot?.processes ?? [],
                                                         backendPID: store.snapshot?.health.pid)
                    if plan.targets.isEmpty {
                        message = "当前未发现可核实的 \(product.title) 进程。"; showingMessage = true
                    } else { pending = plan; confirming = true }
                } catch { message = error.localizedDescription; showingMessage = true }
            }
        } label: {
            Label(control.busy ? "正在核对" : "强制结束 \(product.title)", systemImage: "power")
                .font(WatchTypography.caption.weight(.medium)).padding(.horizontal, 12).frame(height: 32)
                .foregroundStyle(p.red).background(p.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain).disabled(control.busy).opacity(control.busy ? 0.55 : 1)
        .help("核对身份后强制结束 \(product.title) 桌面应用、CLI 与关联子进程；未保存内容可能丢失")
        .accessibilityLabel("强制结束 \(product.title)")
        .confirmationDialog("强制结束 \(product.title)？", isPresented: $confirming, titleVisibility: .visible) {
            if let plan = pending {
                Button("强制结束 \(plan.targets.count) 个已核实进程", role: .destructive) {
                    Task {
                        message = await control.execute(plan); pending = nil; showingMessage = true
                        if !control.isFixture { store.refresh(full: true, manual: true) }
                    }
                }
            }
            Button("取消", role: .cancel) { pending = nil }
        } message: {
            Text(confirmationMessage)
        }
        .alert(control.isFixture ? "进程关闭 · 模拟结果" : "进程关闭结果", isPresented: $showingMessage) {
            Button("知道了", role: .cancel) {}
        } message: { Text(message) }
    }
}
