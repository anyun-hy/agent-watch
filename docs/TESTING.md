# 分层测试入口

For installed-app runtime logs and safe diagnostic exports, see
[运行问题排查](DIAGNOSTICS.md). Test output and production runtime evidence are separate.

默认只执行 `watch-core` 的纯内存规则/契约测试：

```bash
cargo test
# 同一默认层，额外保留运行报告：
bash tools/test-all.sh
```

| 层级 | 入口 | 范围与证据 |
|---|---|---|
| Level 1 | `cargo test` 或 `bash tools/test-all.sh --level 1` | 纯规则，测试不创建进程、网络连接或原生系统服务；首次编译耗时另计，不要求 macOS GUI |
| Level 2 | `bash tools/test-all.sh --level 2` | 两个已有原生用例：真实内核归属及 HTTP/WS/CONNECT 网关转发；Seatbelt 子进程拒绝直连 TCP、VPN 端口、UDP/DNS 和 Unix relay，同时允许指定网关。只使用临时目录、自有进程及 loopback，无 root、launchd 或 `.app` 构建 |
| Level 3 | `bash tools/test-all.sh --level 3 --list` | 只列实机验收范围；真实 launchd/root Broker、安装版生命周期和真实账号操作需当次单独授权。该层不自动执行，不把排除项报告为通过 |

Level 1 的默认选择由根 `Cargo.toml` 的 `default-members` 定义。它也影响不带包参数的
`cargo build`：需要后台二进制时使用 `cargo build -p claude-watch-engine`；需要整个工作区时
显式加 `--workspace`。`cargo test --workspace` 仍是混合原生/GUI 夹具集，**不是 Level 1**。
包内或 `-p` 指定测试也属于显式选择，不受根目录默认成员范围限制。

Level 2 的权限或内核采集失败照实报失败，不跳过断言、不降级成模拟通过。其他已有定向
测试继续使用 `--only ID`；可用 `--level 2 --only rust.native_seatbelt` 单独复测本层用例。
Level 3 验收前须逐项核对目标服务、临时 root 夹具目录、1022 端口、清理范围及普通用户身份；
所用测试名称通过 `--level 3 --list` 查看。重装仍遵循 [重装流程](REINSTALL_WORKFLOW.md)，
agent 不构建 `.app`、DMG 或安装包，用户重装成功也不等于真实保护验收通过。

原混合夹具清单保留为显式入口：`bash tools/test-all.sh --all-fixtures --list`。
完整执行 `--all-fixtures` 会构建临时应用夹具，**agent 不得执行**；不因测试分层降低项目打包禁令。
以下原生环境要求和混合清单说明只适用于所选原生/GUI 项，不是 Level 1 的前置条件。

Run native fixtures without `sudo`. The current native desktop fixtures require Apple Silicon,
macOS 26+, Xcode's macOS SDK, the repository's Rust toolchain, Python 3 and Node.
The runner does not install missing tools. It opens temporary fixture windows,
uses local sockets and Seatbelt, and may stop processes created by the tests.
It does not launch real AI applications, modify VPN settings, or install services.
The retired NetworkExtension implementation and its dedicated tests are no longer
part of the build or test plan; the supported backend is Rust+nono/Seatbelt.

## Results

Each invocation creates a new, Git-ignored directory under
`.agent/test-runs/<timestamp>-<unique-id>/`. It prints the absolute path first.

- `SUMMARY.md`: result, duration, exit code and log link for every step.
- `results.json`: machine-readable results, commands, conditional skips, source
  snapshots and observed executable/component hashes.
- `logs/`: combined stdout/stderr for each step, including build failures.
- `plan.json`: the exact selected commands and dependencies.
- `run-info.json`: runner/manifest hashes and host metadata.
- `artifacts/`, `swift-cache/`: isolated build inputs and compiler cache.
- `tmp/`: link to this run's private short `/private/tmp/cw-t.*` directory;
  keeping socket paths short avoids macOS's Unix socket path-length limit.

The short temporary directory is recorded in `run-info.json` and retained for
inspection. Some existing fixture scripts remove their own files when done; their
stdout/stderr is still retained by this runner. Cargo uses the repository's
ignored `target/` because existing receipt tests require `target/debug`. One
legacy bridge script also uses the ignored `monitor/build/test-module-cache/`.

Failures do not stop unrelated steps. A failed prerequisite blocks only its
dependents. Compiler success, app-launch success and a test assertion pass are
distinct: native bridge scripts must print their actual completion marker and
must not print a failure marker. A failure or blocked step makes the final exit
code nonzero. Ctrl-C records interruption and stops only the active process group
created by the runner. Completed results are written after every step.

The source snapshots use the same digest algorithm as `BuildIdentity.json`,
captured before and after the selected run. They record the revision, dirty
state and source-tree digest; a test run does not invent an application version
or build number. Executed command paths are hashed before and after execution.
Cargo compiler artifacts, Swift outputs and explicitly declared components are
recorded separately: compiling or finding a file does not prove it was executed.
An artifact's existing build receipt is compared with the tested source; an old
receipt is not relabelled as current.

Observed source or executed-file changes mark the evidence binding unstable
without hiding individual test results. Matching endpoint snapshots are not an
immutable checkout, and fixture results are not installed-product acceptance.

Exit codes: `0` selected automatic steps passed (explicit exclusions remain),
`1` one or more steps failed/blocked, `2` invalid runner configuration, `130`
interrupted. Counts are **steps**, not individual assertions or real-host
acceptance scenarios.

## Coverage and exclusions

The explicit `--all-fixtures` plan builds all Rust workspace binaries before running the workspace tests
once. It also covers Python contracts, both routing checks, generated policy
parity, JavaScript probe fixtures, production Swift typechecking, and every
`monitor/tests/*Tests.swift` file through the reviewed
[`unified_swift_tests.json`](../tools/unified_swift_tests.json) recipes. Adding a
Swift test without adding a recipe fails inventory validation rather than
silently omitting the file.

The three normally ignored Rust cases have explicit preparation: kernel
listener diagnostics using owned ephemeral loopback sockets, the resident WebKit **fixture** runtime, and an
isolated copy of the gateway peer test executable signed ad hoc with
`runtime,library`. This signing is free, affects only that test copy, and does
not install or validate the production root service. The listener diagnostic
requires the exact selected socket endpoint, its owning PID and stable kernel
birth/audit identity. It fails if collection is unavailable or identities differ.
It does not require a VPN on port 7890 and does not occupy that port. Production
VPN-listener absence still fails its existing checks; this owned-socket fixture
does not claim that the actual VPN endpoint or gateway protection was accepted.

Live external probes, UI preview/image generators, real AI/Finder acceptance,
root service installation, VPN changes and long-running production acceptance
are excluded and listed. The optional `AIProcessControlTests --owned-force-child`
mode is not selected because it still contains PID-only cleanup; the default
policy, owned exec identity and owned-child TERM modes are included. The
Snapshot transport fixture no longer sends a cleanup SIGKILL to an unverified
orphan PID.

Failures remain visible in the original result directory. Corrective reruns
are separate evidence and do not overwrite an earlier whole-suite result.
The Python build-entry regressions compare the actual Cargo arguments and
environment used by the bootstrap and staging scripts using a private Cargo
fixture. The native startup regression copies the already-built engine and
read-only helpers into a private directory, runs an unregistered observe-only
daemon, verifies its first unready observation and kernel producer identity,
observes fresh publication for 16 seconds, then confirms the original worker
and its observed descendants have exited within the existing five-second stop
budget. It records monotonic timings and hashes of the copied runtime files.
It checks that this private publisher cannot pass the normal launchd verifier.
It installs no service, launches no AI, and modifies no VPN configuration.
The graph fixtures now check the existing desktop grouping while retaining
PID, actual connection and independent CLI distinctions. The live listener
diagnostic uses the production lsof-first/netstat-fallback collection path with
an explicit temporary port, requires the exact owner/endpoint and stable process metadata, and does
not claim TAG authentication, connection reachability or gateway protection.

## Inspect or rerun a narrow selection

```bash
# Read-only: list the default level, native level, or original mixed inventory.
bash tools/test-all.sh --list
bash tools/test-all.sh --level 2 --list
bash tools/test-all.sh --all-fixtures --list

# Preserve this rerun separately; existing output directories are refused.
bash tools/test-all.sh --only swift.VpnSettingsSaveTests

# Explicit new location for all logs and results.
bash tools/test-all.sh --output /private/tmp/watch-tests-new-run
```

`--only` includes dependencies and is labelled a selected run, never a full
suite pass. Tests requiring Rust-exported fixtures also require the workspace
test step that generates them in the **new** result directory; no old result is
treated as fresh evidence.
