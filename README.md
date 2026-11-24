<div align="center">

# Agent Watch

**macOS Seatbelt Network Guard, Leak Protection & Multi-Account Manager for AI Clients**

*Protect **Claude**, **ChatGPT**, and **Codex** (Desktop & CLI) from proxy drops, IP drift, and DNS/WebRTC leaks — built with Rust and native SwiftUI.*

[![Platform](https://img.shields.io/badge/macOS-26.0%2B%20(Apple%20Silicon)-111827?logo=apple&logoColor=white)](https://github.com/anyun-hy/agent-watch/releases/latest)
[![Stack](https://img.shields.io/badge/Core-Rust%20%2B%20SwiftUI-EA580C?logo=rust&logoColor=white)](#architecture)
[![Latest Release](https://img.shields.io/github/v/release/anyun-hy/agent-watch?label=Release&color=2563EB)](https://github.com/anyun-hy/agent-watch/releases/latest)
[![License](https://img.shields.io/badge/License-Apache_2.0-16A34A)](LICENSE)

**English** | [简体中文](README.zh-CN.md)

</div>

---

## Why Agent Watch?

Desktop AI apps and coding CLIs frequently bypass system proxy settings, silently fall back to direct connections when a VPN flickers, or switch exit IPs mid-session. **Agent Watch** enforces fail-closed network isolation on macOS without requiring a paid Apple Developer Network Extension entitlement:

| Capability | What It Does |
| :--- | :--- |
| **Seatbelt Network Isolation** | Launches **Claude**, **ChatGPT**, and **Codex** (desktop & CLI) inside a controlled macOS Seatbelt sandbox routed exclusively through a pinned local gateway. |
| **Real-Time Egress & Leak Guard** | Automatically inspects your active loopback proxy, exit IP consistency, region posture, and DNS / WebRTC leak evidence. Responds on drift or detachment according to your policy (`warn`, `close`, or `force`). |
| **Controlled Entry & Pre-Flight Checks** | Opt-in controlled desktop wrappers and CLI entry points with automated pre-launch readiness checks — no manual IP or node configuration required. |
| **Transactional Account Switching (A/B)** | Archives and switches account profiles with full SHA-256 verification, split-brain guards, and automatic rollback if any step fails. |
| **Live Connection Graph & Offline Diagnostics** | Groups real-time platform, MCP, and component connections by service; exports one-click, PII-redacted diagnostic JSON bundles for troubleshooting. |
| **Built-In Signed Auto-Update** | Checks and installs official GitHub Releases directly from inside the app with RSA-4096 signature + SHA-256 payload verification, preserving all accounts, settings, and initialization state. |

---

## System Requirements

- **OS**: macOS 26.0 or later
- **Architecture**: Apple Silicon (`arm64`)
- **Proxy**: A local loopback proxy (such as TAG, HTTP/HTTPS, or SOCKS5)
- **Runtime**: Self-contained native Rust engine and SwiftUI app — no Python installation required

---

## Quick Start (Install from Release)

No local compilation is needed. Download the pre-built release directly from GitHub:

1. **Download** the latest `Agent-Watch-<version>-build<n>-arm64.dmg` (and optional `.sha256` checksum file) from [GitHub Releases](https://github.com/anyun-hy/agent-watch/releases/latest).
2. *(Optional)* Verify the download integrity:
   ```bash
   shasum -a 256 -c Agent-Watch-*-arm64.dmg.sha256
   ```
3. **Mount the DMG** and drag **`Agent Watch.app`** into **`Applications`** — no terminal scripts needed.
4. **Open Agent Watch** from `/Applications` and complete the guided **First-Run Wizard**.
   - Checks bundled integrity and guides macOS Accessibility permission.
   - Automatically installs the background agent and pinned local Seatbelt gateway right inside the GUI with a **single** administrator password prompt (routine timezone/IPv6/watchdog changes afterward require zero additional password prompts).
   - Never launches Claude / ChatGPT / Codex automatically and never edits your proxy/VPN configuration.

> **Ad-hoc Signing Note**: Releases are signed with a free local ad-hoc signature rather than a paid Apple Developer ID notarization. If macOS Gatekeeper warns on first launch, allow `Agent Watch.app` in **System Settings → Privacy & Security** or right-click → **Open**.

### Updating

Once installed, future updates require **zero manual DMG downloads**:
- Open **Agent Watch → Background Protection** and click **Check for Updates / Download & Install**.
- The built-in updater fetches `release-manifest.json` from GitHub Releases, verifies the embedded RSA-4096 signature and every file's SHA-256 digest, replaces the app atomically, and preserves all your data.

---

## Uninstalling & Data Boundaries

Run **`卸载应用.command`** inside the DMG, or run the built-in uninstaller directly:

```bash
"/Applications/Agent Watch.app/Contents/Resources/watch-engine" app-uninstall --apply
```

| Removed by Uninstaller | Strictly Preserved (Never Modified) |
| :--- | :--- |
| `/Applications/Agent Watch.app` (moved to Trash) | Native `Claude.app`, `ChatGPT.app`, `Codex` apps |
| Agent Watch background LaunchAgent | Active Claude / ChatGPT login data & keychains |
| Agent Watch macOS Accessibility entry | TAG / proxy / VPN software configuration |
| Optional user-confirmed local state | Independent legacy tools (`Claude Switcher`, etc.) |

---

## Troubleshooting & Privacy

- **100% Local**: Agent Watch has zero telemetry, analytics, or third-party reporting.
- **Read-Only Proxy Inspection**: Never overwrites or reloads your VPN/proxy configuration.
- **Redacted Diagnostic Export**: Need to debug a launch gate or proxy issue? Click **Export Diagnostic Bundle** in the Activity page or First-Run Wizard to save `AgentWatch-diagnostics-*.json`. Credentials, account details, session tokens, and raw IP literals are automatically redacted before writing to disk.

---

## Architecture

Agent Watch separates business authority cleanly from macOS UI adapters:

- **Rust Core & Daemon (`crates/`)** — Single source of truth for all rules, verification, state, and protection:
  - `watch-core`: Pure policy rules, process/network models, release source & redirect allowlists.
  - `watch-runtime`: Sampling, evidence verification, fail-closed `ChannelSupervisor`, transactional account switching, lifecycle & signed auto-updater, redacted diagnostic exporter.
  - `watch-engine`: CLI / IPC protocol and resident daemon orchestration.
  - `watch-gateway-broker` & `watch-sandbox-launcher`: Root-pinned loopback socket broker and Seatbelt launcher.
  - `watch-installer`: Clean reset, preflight, and installation workflow.
- **Native macOS UI (`monitor/`)** — SwiftUI desktop app (`Agent Watch.app`), menu bar controller, live connection graph, WebKit DNS/WebRTC leak probes, and controlled desktop entry wrapper.

### Development & Verification

```bash
# Verify Rust-to-Swift policy table sync
python3 tools/generate-ai-policy-swift.py --check

# Run pure core unit & integration tests
cargo test -p claude-watch-core

# Run updater, lifecycle, and diagnostic contract tests
cargo test -p claude-watch-runtime --lib diagnostic_bundle
cargo test -p claude-watch-runtime --test update_contracts --test update_permissions_regressions --test app_lifecycle_contracts
```

Releases are built and RSA-4096 signed automatically on GitHub Actions (`macos-26`, `arm64`) via [.github/workflows/release.yml](.github/workflows/release.yml) whenever a SemVer tag (`vX.Y.Z`) is pushed.

### Additional Documentation

- [Changelog](CHANGELOG.md)
- [Architecture & Rust Migration Notes](docs/RUST_MIGRATION.md)
- [Reinstall Workflow & Boundaries](docs/REINSTALL_WORKFLOW.md)
- [Monitor UI Module Notes](monitor/README.md)

---

## License

Agent Watch is open-source software licensed under the **[Apache License 2.0](LICENSE)**.

You are free to use, modify, and distribute this project (including for commercial use) under the terms of Apache-2.0, including its explicit patent grant, provided you retain the license and copyright notices.

### Third-Party Open-Source Notices

| Component / Asset | License | Notice File |
| :--- | :--- | :--- |
| **nono** (Seatbelt sandboxing) | Apache-2.0 | [monitor/ThirdParty/nono/LICENSE](monitor/ThirdParty/nono/LICENSE) |
| **Claude Switcher** (upstream account engine) | MIT | [monitor/ThirdParty/ClaudeSwitcher/LICENSE](monitor/ThirdParty/ClaudeSwitcher/LICENSE) |
| **Lucide Icons** (graph icons) | ISC / MIT | [monitor/Resources/Icons/LICENSE](monitor/Resources/Icons/LICENSE) |
| **flag-icons** (country flags) | MIT | [monitor/Resources/Identity/FLAG-ICONS-LICENSE.txt](monitor/Resources/Identity/FLAG-ICONS-LICENSE.txt) |
