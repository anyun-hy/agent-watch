import AppKit
import Foundation
import WebKit

@main
struct IPLeakBridgeTests {
    @MainActor static func main() {
        let live = CommandLine.arguments.contains("--live")
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let window = NSWindow(contentRect: NSRect(x: 120, y: 120, width: 640, height: 120),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.title = live ? "IPLeak DNS · 临时实测" : "IPLeak DNS · 隔离测试"

        if !live {
            let runner = IPLeakDNSRunner()
            var diagnostics: [(String, Bool)] = []
            runner.onDiagnostic = { diagnostics.append(($0, $1)) }
            runner.testBootstrap = #"""
            window.fetch = async function(raw) {
              const u = new URL(raw); let data;
              if (u.pathname === '/dnsdetection/') {
                const m = u.hostname.match(/^([0-9a-f]{40})-[0-7]\.ipleak\.net$/);
                if (!m) throw new Error('invalid DNS request');
                data = {session:m[1], ip:{'8.8.8.8':1}};
              } else if (u.hostname === 'ipleak.net' && u.pathname === '/json/') {
                data = {ip:'1.1.1.1',country_code:'JP'};
              } else if (u.hostname === 'ipleak.net' && u.pathname === '/json/8.8.8.8') {
                data = {ip:'8.8.8.8',country_code:'JP'};
              } else { throw new Error('unexpected endpoint'); }
              return new Response(JSON.stringify(data), {status:200,headers:{'Content-Type':'application/json'}});
            };
            """#
            runner.start(rounds: 5, id: UUID()) { result in
                guard result.status == "complete", result.errors.isEmpty,
                      result.observations.contains(where: { $0.kind == "resolver" && $0.address == "8.8.8.8" }),
                      result.observations.contains(where: { $0.kind == "http" && $0.address == "1.1.1.1" }) else {
                    fputs("FAIL: IPLeak isolated WebKit bridge: \(result.status) \(result.errors)\n", stderr)
                    exit(1)
                }
                guard diagnostics.contains(where: { $0.0 == "host_attached" && $0.1 }),
                      diagnostics.contains(where: { $0.0 == "navigation_finished" }),
                      diagnostics.contains(where: { $0.0 == "phase_dns" }),
                      diagnostics.contains(where: { $0.0 == "payload_received" }) else {
                    fputs("FAIL: IPLeak bridge lifecycle diagnostics missing\n", stderr); exit(1)
                }
                print("IPLeakBridgeTests: local page, WebKit, JS and native result passed with mocked network")
                exit(0)
            }
            app.run()
            _ = runner
            return
        }

        fputs("Live diagnostics now use the daemon evidence command; this adapter test only accepts --fixture.\n", stderr)
        exit(2)
    }
}
