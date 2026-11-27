import Foundation

@main
struct IpIntelStoreTests {
    @MainActor
    static func main() {
        func expect(_ value: Bool, _ message: String) {
            guard value else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }

        // 1. Page restoration & unified sidebar contracts
        expect(Page.protection.rawValue == "保护与设置", "protection page renamed to 保护与设置")
        expect(Page.restored("后台保护") == .protection, "legacy 后台保护 restores to .protection")
        expect(Page.restored("AI 连通检测") == .panorama, "legacy AI 连通检测 restores to .panorama")
        expect(Page.restored("泄漏检测") == .panorama, "legacy 泄漏检测 restores to .panorama")
        expect(Page.restored("IP 评分") == .panorama, "legacy IP 评分 restores to .panorama")
        expect(Page.diagnosticPages == [.panorama], "diagnostic sidebar consolidated into single panorama workbench")

        // 2. IpIntelStore fixture & validation contracts
        let store = IpIntelStore(isFixture: true)
        expect(store.currentReport?.isComplete == true, "fixture store loads complete IP intelligence report")
        expect((store.currentReport?.score?.value ?? 0) >= 90, "residential fixture scores excellent")
        expect(store.currentReport?.usage?.native_status == "native", "native IP status preserved")
        expect(store.currentReport?.rpki?.status == "valid", "RPKI status decoded")

        store.focusAndQuery("127.0.0.1")
        expect(store.errorMessage != nil, "loopback IP rejected without network")

        store.focusAndQuery("8.8.8.8")
        expect(store.selectedIP == "8.8.8.8", "public IP query updates selected IP")
        expect(store.currentReport?.is_datacenter == true, "datacenter IP profile decoded")
        expect((store.currentReport?.score?.value ?? 100) < 80, "datacenter IP receives itemized deduction")

        print("IpIntelStoreTests: 14 assertions passed")
    }
}
