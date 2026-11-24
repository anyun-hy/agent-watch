import Foundation

/// Read-only comparison between the running `/Applications/Agent Watch.app`
/// bundle identity and the installed background runtime under
/// `~/Library/Application Support/ClaudeWatch/runtime/`.
///
/// Never mutates files or decides authorization; it only detects a drag-upgrade
/// mismatch so the UI can invoke the authoritative `install-runtime --apply`.
struct RuntimeVersionMismatch: Equatable {
    let appVersion: String
    let appBuild: String
    let runtimeVersion: String?
    let runtimeBuild: String?

    var summary: String {
        let target = "\(appVersion) (Build \(appBuild))"
        if let rv = runtimeVersion, !rv.isEmpty {
            let rb = runtimeBuild.map { " (Build \($0))" } ?? ""
            return "应用已更新至 \(target)，但后台采集与 Seatbelt 网关仍为 \(rv)\(rb)。"
        }
        return "应用已更新至 \(target)，但后台运行组件版本较旧或不完整，建议立即同步。"
    }
}

enum RuntimeVersionSync {
    struct Identity: Equatable {
        let version: String
        let build: String
        let sourceTreeDigest: String?
    }

    static func currentMismatch(
        bundle: Bundle = .main,
        homeDirectory: String = NSHomeDirectory(),
        expectedAppPath: String = AccessibilityPermission.installedPath
    ) -> RuntimeVersionMismatch? {
        let currentPath = bundle.bundleURL.standardizedFileURL.path
        guard currentPath == expectedAppPath else { return nil }
        guard let app = readBundleIdentity(bundle: bundle) else { return nil }
        let runtimeDir = URL(fileURLWithPath: homeDirectory)
            .appendingPathComponent("Library/Application Support/ClaudeWatch/runtime", isDirectory: true)
        let enginePath = runtimeDir.appendingPathComponent("watch-engine").path
        guard FileManager.default.isExecutableFile(atPath: enginePath) else {
            return nil
        }
        let runtime = readDirectoryIdentity(directory: runtimeDir)
        if let runtime, identitiesMatch(app: app, runtime: runtime) {
            return nil
        }
        return RuntimeVersionMismatch(
            appVersion: app.version,
            appBuild: app.build,
            runtimeVersion: runtime?.version,
            runtimeBuild: runtime?.build
        )
    }

    static func identitiesMatch(app: Identity, runtime: Identity) -> Bool {
        if let appDigest = app.sourceTreeDigest, !appDigest.isEmpty,
           let runtimeDigest = runtime.sourceTreeDigest, !runtimeDigest.isEmpty {
            return appDigest == runtimeDigest && app.version == runtime.version && app.build == runtime.build
        }
        return app.version == runtime.version && app.build == runtime.build
    }

    private static func readBundleIdentity(bundle: Bundle) -> Identity? {
        if let resourcesURL = bundle.resourceURL,
           let fromResources = readDirectoryIdentity(directory: resourcesURL) {
            return fromResources
        }
        let info = bundle.infoDictionary ?? [:]
        guard let version = nonEmptyString(info["CFBundleShortVersionString"]),
              let build = nonEmptyString(info["CFBundleVersion"]) else {
            return nil
        }
        return Identity(version: version, build: build, sourceTreeDigest: nil)
    }

    static func readDirectoryIdentity(directory: URL) -> Identity? {
        let jsonURL = directory.appendingPathComponent("BuildIdentity.json")
        if let data = try? Data(contentsOf: jsonURL), data.count <= 64 * 1024,
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let version = nonEmptyString(json["app_version"]),
           let build = nonEmptyString(json["app_build"]) {
            return Identity(
                version: version,
                build: build,
                sourceTreeDigest: nonEmptyString(json["source_tree_digest"])
            )
        }
        let plistURL = directory.appendingPathComponent("BuildInfo.plist")
        if let data = try? Data(contentsOf: plistURL), data.count <= 64 * 1024,
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let version = nonEmptyString(plist["ProductVersion"]) ?? nonEmptyString(plist["CFBundleShortVersionString"]),
           let build = nonEmptyString(plist["AppBuild"]) ?? nonEmptyString(plist["CFBundleVersion"]) {
            return Identity(
                version: version,
                build: build,
                sourceTreeDigest: nonEmptyString(plist["SourceTreeDigest"])
            )
        }
        return nil
    }

    private static func nonEmptyString(_ raw: Any?) -> String? {
        guard let value = raw as? String else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
