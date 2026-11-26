# Net.Coffee 数据接入

界面入口为 `Sources/NetCoffeeStore.swift`、`NetCoffeeScorePage.swift`、`LeakCheckPages.swift`；DNS 与 WebRTC 采集由 Rust 引擎在进程内完成（`crates/watch-runtime/src/native_leak_probes.rs`）。

## 用途

- IP 评分与网络归属复用已有查询结果，保留原来源、时间和缺失字段；Net.Coffee 为主、IPLeak `json/{ip}` 为后备，结果在引擎内缓存 30 分钟。
- DNS 检测向系统当前的递归解析器查询 Akamai `whoami.ds.akahelp.net` 与 Google `o-o.myaddr.l.google.com` 的 TXT 回显，得到实际的递归出口，并与同轮代理 HTTP 出口（Cloudflare trace）比较；UDP 截断或被拦截时改用 TCP。DNS 递归 IP 与 HTTP IP 不要求完全相同；当前策略核对国家／地区。
- WebRTC 以 `getifaddrs` 枚举本机 host 候选（全局 IPv6 直接暴露会被识别），并发向多个 STUN 服务器取得 srflx 公网映射，达到法定数量后提前结束，与同轮 HTTP 出口比较；私有地址只作为本地观察展示。
- AI 服务诊断的 HTTP 出口、本机网络检测出口与真实应用连接是不同证据，不互相冒充。

当前环境页面会协调自动检测与后台刷新，DNS、WebRTC 和环境判定复用回执；网络检测三页打开时会自动载入最近结果，没有结果时自动检测一次。采样失败、查询限流、空结果和超时保留具体原因，不能直接判作“无泄漏”。

这些接口来自第三方服务，稳定性由上游决定。IP 评分不代表账号可用性；WebRTC 结果反映本机网络栈的暴露面，不能替浏览器内的所有页面保证无泄漏。

## 验证与资料

离线测试位于 `native_leak_probes` 单元测试、`receipt_contracts.rs`、`stun_contracts.rs`、`NetCoffeeTests.swift` 及相关泄漏回执测试。

`tests/build_ui_review.sh` 使用隔离样本，历史样本保留原时间。

实时验收材料位于忽略目录 `reports/netcoffee/`。早期网页脚本、REA 输出与研究包集中到根目录的 `local/research/netcoffee-20261019/`；这些资料不作为运行依赖，也不进入 Git。旧说明移到 `local/archive/`。
