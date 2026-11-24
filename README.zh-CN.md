<div align="center">

# Agent Watch

**面向 AI 客户端的 macOS Seatbelt 网络隔离守护与多账号管理工具**

*基于 Rust 业务核心与原生 SwiftUI 构建，为 **Claude**、**ChatGPT** 与 **Codex**（桌面端及 CLI）提供代理断流保护、出口 IP 一致性校验、DNS/WebRTC 防漏监测与多账号安全切换。*

[![Platform](https://img.shields.io/badge/macOS-26.0%2B%20(Apple%20Silicon)-111827?logo=apple&logoColor=white)](https://github.com/anyun-hy/agent-watch/releases/latest)
[![Stack](https://img.shields.io/badge/Core-Rust%20%2B%20SwiftUI-EA580C?logo=rust&logoColor=white)](#架构概览)
[![Latest Release](https://img.shields.io/github/v/release/anyun-hy/agent-watch?label=Release&color=2563EB)](https://github.com/anyun-hy/agent-watch/releases/latest)
[![License](https://img.shields.io/badge/License-Apache_2.0-16A34A)](LICENSE)

[English](README.md) | **简体中文**

</div>

---

## 为什么选择 Agent Watch？

AI 桌面端与命令行工具常常在代理抖动时悄悄回退直连、绕过系统代理，或在会话中途切换出口 IP。**Agent Watch** 无需昂贵的 Apple Developer Network Extension 权限，即可在 macOS 上实现 Fail-Closed（失效即拦截）的网络守护：

| 核心能力 | 说明 |
| :--- | :--- |
| **Seatbelt 网络隔离与受控启动** | 通过 macOS Seatbelt 沙箱与固定本机环回网关受控启动 **Claude**、**ChatGPT**、**Codex**（桌面端与 CLI），杜绝未代理直连。 |
| **实时出口 IP 与防漏守卫** | 自动识别本机代理与活动网络，持续核验出口 IP 一致性、地区风险、DNS 与 WebRTC 状态；一旦代理脱离或 IP 漂移，按配置策略（`warn` 提醒 / `close` 断流 / `force` 强停）及时保护。 |
| **零手工配置初始化向导** | 首次启动自动完成环境与代理实测，无需手填 IP、节点或地区名单；提供可选的受控桌面入口与 CLI 封装，启动前自动复检。 |
| **事务化多账号切换（A/B）** | 完整 SHA-256 哈希校验、跨工具冲突防错槽检测与失败自动回滚，安全归档和切换账号资料。 |
| **实时连接拓扑与一键脱敏诊断** | 按服务分组展示平台、MCP 与组件实时连接；支持一键导出自动脱敏（剥离凭据、账号与原始 IP）的离线诊断 JSON，便于快速排障。 |
| **内置 RSA-4096 签名自动更新** | 应用内直连 GitHub Releases 检查并安装新版，严格验证 RSA-4096 签名与全量文件 SHA-256 哈希，原地升级并完整保留全部账号、配置与初始化状态。 |

---

## 系统要求

- **操作系统**：macOS 26.0 及以上
- **芯片架构**：Apple Silicon（`arm64`）
- **本地代理**：运行中的本地环回代理（如 TAG、HTTP/HTTPS 或 SOCKS5 代理）
- **运行依赖**：内置完整原生 Rust 引擎与 SwiftUI 应用，**无需预装 Python**

---

## 快速上手（下载即用）

普通用户无需本机编译，直接从 GitHub Releases 下载安装包即可：

1. 前往 [GitHub Releases](https://github.com/anyun-hy/agent-watch/releases/latest) 下载最新的 `Agent-Watch-<版本>-build<构建号>-arm64.dmg`（以及可选的 `.sha256` 校验文件）。
2. *（可选）* 核验安装包完整性：
   ```bash
   shasum -a 256 -c Agent-Watch-*-arm64.dmg.sha256
   ```
3. **打开 DMG** 并双击运行 **`安装或更新后台.command`**：
   - 自动校验应用签名、芯片架构与所有原生组件哈希；
   - 安装 `/Applications/Agent Watch.app` 并注册后台守护任务；
   - 旧版自动移入废纸篓，完整保留已有账号存档、日志与保护配置；
   - 不会擅自启动 Claude / ChatGPT / Codex，也不会改动你的 TAG 或其他代理软件配置。
4. 从「应用程序」打开 **Agent Watch**，按引导完成**首次初始化向导**：
   - 自动核对本地代理、出口 IP、DNS 与 WebRTC 环境；
   - 按需引导完成 macOS 辅助功能授权与一次性 Seatbelt 环回网关注册。

> **关于自签名提示**：发布包采用免费的本机临时签名（ad-hoc），未经过付费 Apple Developer ID 公证。首次打开若遇 macOS 拦截提示，请在「系统设置 › 隐私与安全性」中点击允许，或右键应用选择「打开」。

### 应用内一键更新

安装后，后续版本升级**无需再手动下载 DMG**：
- 打开 **Agent Watch → 后台保护** 页，点击 **检查更新 / 下载并安装更新**；
- 内置更新器从官方 GitHub Releases 拉取签名清单 `release-manifest.json`，使用内嵌 RSA-4096 公钥校验签名及每个文件的 SHA-256 哈希后自动完成原子替换，并保留全部账号与设置。

---

## 干净卸载与数据边界

运行 DMG 中的 **`卸载应用.command`**，或在终端执行：

```bash
"/Applications/Agent Watch.app/Contents/Resources/watch-engine" app-uninstall --apply
```

| 卸载器会清理的内容 | 严格保留（绝不触碰） |
| :--- | :--- |
| `/Applications/Agent Watch.app`（移入废纸篓） | 原生 `Claude.app`、`ChatGPT.app`、`Codex` |
| Agent Watch 自有后台 LaunchAgent | 当前活跃的 Claude / ChatGPT 登录资料与钥匙串 |
| Agent Watch 的 macOS 辅助功能记录 | TAG 及其他 VPN / 代理软件配置 |
| 经用户明确确认清理的本地状态 | 独立原版工具（如 `Claude Switcher` 等） |

---

## 隐私与安全设计

- **100% 本地运行**：无遥测、无埋点、无第三方数据上报。
- **代理配置只读核验**：仅只读观测外部代理运行事实，绝不擅自改写或重载你的代理规则。
- **诊断包自动脱敏**：在「活动记录」页或首次初始化向导中点击「导出诊断包」，会生成 `AgentWatch-diagnostics-*.json`，导出前自动剥离密钥、令牌、账号隐私与原始 IP 字面量。

---

## 架构概览

项目严格遵循「Rust 管业务、Swift 管界面与原生适配」的单一权威边界：

- **Rust 业务与守护核心（`crates/`）**：
  - `watch-core`：纯策略规则、进程/网络模型、内置发布源与重定向白名单。
  - `watch-runtime`：采样调度、证据核验、Fail-Closed 监督器（`ChannelSupervisor`）、事务化账号切换、应用生命周期与签名自动更新、离线脱敏诊断导出。
  - `watch-engine`：统一命令协议与常驻守护进程装配。
  - `watch-gateway-broker` & `watch-sandbox-launcher`：固定本机环回网关代理与 Seatbelt 沙箱启动器。
  - `watch-installer`：全量预检、重置与安装状态机。
- **macOS 原生界面（`monitor/`）**：SwiftUI 桌面监控面板（`Agent Watch.app`）、菜单栏常驻控制、实时连接拓扑图、WebKit DNS/WebRTC 探针与受控桌面入口封装。

### 开发与测试

```bash
# 检查 Rust 到 Swift 的策略表同步状态
python3 tools/generate-ai-policy-swift.py --check

# 运行纯核心规则单元测试与集成测试
cargo test -p claude-watch-core

# 运行自动更新、应用生命周期与离线诊断契约测试
cargo test -p claude-watch-runtime --lib diagnostic_bundle
cargo test -p claude-watch-runtime --test update_contracts --test update_permissions_regressions --test app_lifecycle_contracts
```

正式版通过 [.github/workflows/release.yml](.github/workflows/release.yml) 在 GitHub Actions（`macos-26` / `arm64`）上于推送 SemVer 标签（`vX.Y.Z`）时自动完成编译、打包与 RSA-4096 签名发布。

### 进阶文档

- [版本变更记录（CHANGELOG）](CHANGELOG.md)
- [架构设计与 Rust 迁移说明](docs/RUST_MIGRATION.md)
- [重装流程与安全边界](docs/REINSTALL_WORKFLOW.md)
- [Monitor 界面模块说明](monitor/README.md)

---

## 开源协议

Agent Watch 采用 **[Apache License 2.0](LICENSE)** 开源协议发布。

在保留版权与协议声明的前提下，你可以自由使用、修改、分发及商用本项目，并享有协议附带的明确专利授权条款。

### 第三方开源致谢

| 组件 / 资源 | 开源协议 | 许可文件 |
| :--- | :--- | :--- |
| **nono**（Seatbelt 沙箱能力） | Apache-2.0 | [monitor/ThirdParty/nono/LICENSE](monitor/ThirdParty/nono/LICENSE) |
| **Claude Switcher**（上游账号归档引擎） | MIT | [monitor/ThirdParty/ClaudeSwitcher/LICENSE](monitor/ThirdParty/ClaudeSwitcher/LICENSE) |
| **Lucide Icons**（拓扑图图标） | ISC / MIT | [monitor/Resources/Icons/LICENSE](monitor/Resources/Icons/LICENSE) |
| **flag-icons**（地区旗帜图标） | MIT | [monitor/Resources/Identity/FLAG-ICONS-LICENSE.txt](monitor/Resources/Identity/FLAG-ICONS-LICENSE.txt) |
