use base64::{engine::general_purpose::STANDARD, Engine as _};
use claude_watch_runtime::update::*;
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::EncodePublicKey,
    rand_core::OsRng,
    signature::{SignatureEncoding, Signer},
    RsaPrivateKey,
};
use std::{collections::BTreeMap, fs, io::Write};
use uuid::Uuid;
fn temp() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("cw-update-{}", Uuid::new_v4()));
    fs::create_dir(&p).unwrap();
    p
}
#[test]
fn source_and_version_boundaries_never_enable_network() {
    assert_eq!(
        check_configured("", "").unwrap_err().code,
        "update_unconfigured"
    );
    assert!(check_configured(
        "https://updates.example/release",
        "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"
    )
    .is_ok());
    assert!(version_tuple("1.2.3").is_ok());
    assert!(version_tuple("v1.2").is_err());
}
#[test]
fn invalid_signature_and_unsafe_archive_are_rejected() {
    assert_eq!(
        verify_manifest(
            b"{}",
            b"bad",
            "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----",
            "arm64"
        )
        .unwrap_err()
        .code,
        "update_key_missing"
    );
    let root = temp();
    let zip = root.join("bad.zip");
    let file = fs::File::create(&zip).unwrap();
    let mut w = zip::ZipWriter::new(file);
    w.start_file("../escape", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"bad").unwrap();
    w.finish().unwrap();
    let release = Release {
        version: "1.0.0".into(),
        build: None,
        archive_url: "https://updates.example/release.zip".into(),
        archive_sha256: archive_hash(&zip).unwrap(),
        architecture: "arm64".into(),
        files: BTreeMap::new(),
    };
    assert_eq!(
        verify_extract(&zip, &root.join("out"), &release)
            .unwrap_err()
            .code,
        "unsafe_archive"
    );
    let _ = fs::remove_dir_all(root);
}
#[test]
fn rsa_signed_manifest_is_verified_before_archive_use() {
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public = key
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let body = serde_json::json!({"schema":1,"runtime_schema":2,"admin_abi":1,"version":"1.2.3","architecture":"arm64","archive_url":"https://updates.example/release.zip","archive_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","files":{"runtime/watch-engine":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}});
    let bytes = serde_json::to_vec(&body).unwrap();
    let sig = SigningKey::<rsa::sha2::Sha256>::new(key)
        .sign(&bytes)
        .to_vec();
    assert_eq!(
        verify_manifest(&bytes, &sig, &public, "arm64")
            .unwrap()
            .version,
        "1.2.3"
    );
}

struct Os {
    fail: bool,
}
impl UpdateOs for Os {
    fn restart_agent(&mut self) -> claude_watch_core::error::Result<()> {
        Ok(())
    }
    fn agent_healthy(&mut self) -> claude_watch_core::error::Result<bool> {
        Ok(true)
    }
    fn architecture(&mut self) -> claude_watch_core::error::Result<String> {
        Ok("arm64".into())
    }
    fn verify_app(&mut self, _: &std::path::Path, _: &str) -> claude_watch_core::error::Result<()> {
        Ok(())
    }
    fn health(&mut self) -> claude_watch_core::error::Result<()> {
        if self.fail {
            Err(claude_watch_core::error::CoreError::new(
                "health_failed",
                "fixture",
            ))
        } else {
            Ok(())
        }
    }
    fn installed_version(
        &mut self,
        _: &std::path::Path,
    ) -> claude_watch_core::error::Result<String> {
        Ok("1.0.0".into())
    }
}

#[test]
fn native_archives_require_matching_components_and_reject_old_business_resources() {
    for case in ["native", "legacy", "missing", "mismatch", "build_identity", "build_identity_missing", "build_identity_mismatch"] {
        let root = temp();
        let archive = root.join("release.zip");
        let mut contents = BTreeMap::<String, Vec<u8>>::new();
        contents.insert(
            "app/Agent Watch.app/Contents/Info.plist".into(),
            b"native-app".to_vec(),
        );
        for name in [
            "watch-engine",
            "watch-native-observer",
            "watch-process-control",
            "watch-admin.sh",
            "watch-native-collector.zsh",
            "BuildInfo.plist",
        ] {
            for prefix in [
                "runtime/",
                "app/Agent Watch.app/Contents/Resources/",
            ] {
                contents.insert(format!("{prefix}{name}"), name.as_bytes().to_vec());
            }
        }
        if case == "legacy" {
            contents.insert("claude-watch.sh".into(), b"old".to_vec());
        }
        if case == "missing" {
            contents.remove("runtime/watch-native-observer");
        }
        if case == "mismatch" {
            contents.insert("runtime/watch-engine".into(), b"different".to_vec());
        }
        if case.starts_with("build_identity") {
            contents.insert("app/Agent Watch.app/Contents/Resources/BuildIdentity.json".into(), b"identity".to_vec());
            if case != "build_identity_missing" {
                contents.insert("runtime/BuildIdentity.json".into(), if case == "build_identity_mismatch" { b"other".to_vec() } else { b"identity".to_vec() });
            }
        }
        let mut writer = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
        for (name, bytes) in &contents {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
        let release = Release {
            version: "3.0.0".into(),
            build: None,
            architecture: "arm64".into(),
            archive_url: "https://updates.example/release.zip".into(),
            archive_sha256: archive_hash(&archive).unwrap(),
            files: contents
                .iter()
                .map(|(name, bytes)| (name.clone(), claude_watch_runtime::storage::sha256(bytes)))
                .collect(),
        };
        let result = verify_extract(&archive, &root.join("out"), &release);
        if case == "native" || case == "build_identity" {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err().code,
                match case {
                    "legacy" => "unsafe_archive",
                    "missing" => "release_incomplete",
                    _ => "release_component_mismatch",
                }
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn new_native_failure_removes_new_roots_and_leaves_legacy_backend_untouched() {
    let root = temp();
    let paths = UpdatePaths {
        base: root.join("base"),
        app: root.join("app"),
        watch: root.join("watch"),
        backend: root.join("backend"),
    };
    fs::create_dir(&paths.watch).unwrap();
    fs::write(&paths.backend, b"legacy-unchanged").unwrap();
    let source = root.join("source");
    fs::create_dir_all(source.join("app")).unwrap();
    fs::write(source.join("app/Agent Watch.app"), b"new-app").unwrap();
    fs::write(source.join("runtime"), b"new-runtime").unwrap();
    let release = Release {
        version: "3.0.0".into(),
        build: None,
        architecture: "arm64".into(),
        archive_url: "https://updates.example/release.zip".into(),
        archive_sha256: String::new(),
        files: BTreeMap::new(),
    };
    let mut updater = Updater {
        paths,
        os: Os { fail: true },
        transport: NoNet,
    };
    assert_eq!(
        updater.apply_payload(&source, &release).unwrap_err().code,
        "health_failed"
    );
    assert!(!updater.paths.app.exists());
    assert!(!updater.paths.watch.join("runtime").exists());
    assert_eq!(
        fs::read(&updater.paths.backend).unwrap(),
        b"legacy-unchanged"
    );
    assert!(!updater.paths.base.join("update-transaction.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn old_three_root_journal_remains_recoverable_without_a_new_legacy_update_path() {
    let root = temp();
    let paths = UpdatePaths {
        base: root.join("base"),
        app: root.join("app"),
        watch: root.join("watch"),
        backend: root.join("backend"),
    };
    fs::create_dir(&paths.base).unwrap();
    fs::create_dir(&paths.watch).unwrap();
    let targets = [
        paths.app.clone(),
        paths.watch.join("runtime"),
        paths.backend.clone(),
    ];
    let records=targets.iter().map(|target|{
        fs::write(target,b"new").unwrap();fs::write(target.with_extension("cw-old"),b"old").unwrap();
        serde_json::json!({"target":target,"old":target.with_extension("cw-old"),"stage":target.with_extension("cw-new"),"existed":true,"started":true})
    }).collect::<Vec<_>>();
    fs::write(
        paths.base.join("update-transaction.json"),
        serde_json::to_vec(&serde_json::json!({"schema":1,"phase":"prepared","records":records}))
            .unwrap(),
    )
    .unwrap();
    let mut updater = Updater {
        paths,
        os: Os { fail: false },
        transport: NoNet,
    };
    updater.recover().unwrap();
    for target in targets {
        assert_eq!(fs::read(target).unwrap(), b"old");
    }
    assert!(!updater.paths.base.join("update-transaction.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_recovery_preflights_all_conflicts_before_restoring_any_root() {
    let root = temp();
    let paths = UpdatePaths {
        base: root.join("base"),
        app: root.join("app"),
        watch: root.join("watch"),
        backend: root.join("backend"),
    };
    fs::create_dir(&paths.base).unwrap();
    fs::create_dir(&paths.watch).unwrap();
    let targets = [paths.app.clone(), paths.watch.join("runtime")];
    let records=targets.iter().map(|target|{
        fs::write(target,b"new").unwrap();fs::write(target.with_extension("cw-old"),b"old").unwrap();
        serde_json::json!({"target":target,"old":target.with_extension("cw-old"),"stage":target.with_extension("cw-new"),"existed":true,"started":true,
            "before":{"":claude_watch_runtime::storage::sha256(b"old")},"after":{"":claude_watch_runtime::storage::sha256(b"new")}})
    }).collect::<Vec<_>>();
    let journal = paths.base.join("update-transaction.json");
    fs::write(
        &journal,
        serde_json::to_vec(&serde_json::json!({"schema":2,"phase":"prepared","records":records,"accessibility_reset_attempted":true}))
            .unwrap(),
    )
    .unwrap();
    fs::write(&paths.app, b"external-change").unwrap();
    let mut updater = Updater {
        paths,
        os: Os { fail: false },
        transport: NoNet,
    };
    let error = updater.recover().unwrap_err();
    assert_eq!(error.code, "update_rollback_conflict");
    assert!(error.message.contains("重新授权"));
    assert_eq!(fs::read(&updater.paths.app).unwrap(), b"external-change");
    assert_eq!(
        fs::read(updater.paths.watch.join("runtime")).unwrap(),
        b"new"
    );
    assert!(journal.exists());
    fs::remove_dir_all(root).unwrap();
}
struct EnvelopeTransport(Vec<u8>);
impl Transport for EnvelopeTransport {
    fn get(&mut self, _: &str, _: u64) -> claude_watch_core::error::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}
fn signed_envelope(archive_url: &str) -> (String, Vec<u8>) {
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public = key
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let manifest = serde_json::json!({
        "schema": 1,
        "runtime_schema": 2,
        "admin_abi": 1,
        "version": "1.2.3",
        "architecture": "arm64",
        "archive_url": archive_url,
        "archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "files": {"runtime/watch-engine": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
    });
    let payload = serde_json::to_vec(&manifest).unwrap();
    let signature = SigningKey::<rsa::sha2::Sha256>::new(key)
        .sign(&payload)
        .to_vec();
    (
        public,
        serde_json::to_vec(&serde_json::json!({
            "manifest": STANDARD.encode(payload),
            "signature": STANDARD.encode(signature)
        }))
        .unwrap(),
    )
}
#[test]
fn signed_base64_envelope_is_required_and_archive_url_is_not_unsigned() {
    let root = temp();
    let paths = UpdatePaths {
        base: root.join("base"),
        app: root.join("app"),
        watch: root.join("watch"),
        backend: root.join("backend"),
    };
    let (public, envelope) = signed_envelope("https://updates.example/release.zip");
    let mut available = Updater {
        paths: paths.clone(),
        os: Os { fail: false },
        transport: EnvelopeTransport(envelope),
    };
    assert_eq!(
        available
            .check("https://updates.example/manifest", &public, false)
            .unwrap()["status"],
        "available"
    );

    let (public, mut envelope) = signed_envelope("https://other.example/release.zip");
    let mut value: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    value["archive_url"] = serde_json::json!("https://updates.example/release.zip");
    envelope = serde_json::to_vec(&value).unwrap();
    let mut rejected = Updater {
        paths,
        os: Os { fail: false },
        transport: EnvelopeTransport(envelope),
    };
    assert_eq!(
        rejected
            .check("https://updates.example/manifest", &public, true)
            .unwrap_err()
            .code,
        "update_origin_mismatch"
    );
    let mut duplicate = Updater {
        paths: rejected.paths.clone(),
        os: Os { fail: false },
        transport: EnvelopeTransport(
            br#"{"manifest":"one","manifest":"two","signature":"three"}"#.to_vec(),
        ),
    };
    assert_eq!(
        duplicate
            .check("https://updates.example/manifest", &public, false)
            .unwrap_err()
            .code,
        "invalid_release"
    );
    let _ = fs::remove_dir_all(root);
}
struct NoNet;
impl Transport for NoNet {
    fn get(&mut self, _: &str, _: u64) -> claude_watch_core::error::Result<Vec<u8>> {
        panic!("must not fetch")
    }
}
#[test]
fn apply_false_is_unavailable_without_source_and_health_failure_restores_all_components() {
    let root = temp();
    let app = root.join("app");
    let watch = root.join("watch");
    let backend = root.join("backend");
    for p in [&app, &backend] {
        fs::write(p, "old").unwrap();
    }
    fs::create_dir(&watch).unwrap();
    fs::write(watch.join("runtime"), "old").unwrap();
    let paths = UpdatePaths {
        base: root.join("base"),
        app: app.clone(),
        watch: watch.clone(),
        backend: backend.clone(),
    };
    let mut up = Updater {
        paths,
        os: Os { fail: true },
        transport: NoNet,
    };
    fs::create_dir_all(&up.paths.base).unwrap();
    fs::write(
        up.paths.base.join("release.json"),
        r#"{"version":"0.9.0","runtime_schema":1}"#,
    )
    .unwrap();
    let source = root.join("payload");
    for p in [
        source.join("app/Agent Watch.app"),
        source.join("runtime"),
        source.join("claude-watch.sh"),
    ] {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, "new").unwrap();
    }
    let rel = Release {
        version: "1.0.0".into(),
        build: None,
        archive_url: "https://updates.example/release.zip".into(),
        archive_sha256: "".into(),
        architecture: "arm64".into(),
        files: BTreeMap::new(),
    };
    assert_eq!(
        up.apply_payload(&source, &rel).unwrap_err().code,
        "health_failed"
    );
    assert_eq!(fs::read_to_string(app).unwrap(), "old");
    assert_eq!(fs::read_to_string(watch.join("runtime")).unwrap(), "old");
    assert_eq!(fs::read_to_string(backend).unwrap(), "old");
    assert!(!root.join("base/update-transaction.json").exists());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(root.join("base/release.json")).unwrap()
        )
        .unwrap()["version"],
        "0.9.0"
    );
    let _ = fs::remove_dir_all(root);
}
#[test]
fn malicious_update_journal_cannot_target_unrelated_path() {
    let root = temp();
    let victim = root.join("victim");
    fs::write(&victim, "keep").unwrap();
    let paths = UpdatePaths {
        base: root.join("base"),
        app: root.join("app"),
        watch: root.join("watch"),
        backend: root.join("backend"),
    };
    fs::create_dir_all(&paths.base).unwrap();
    fs::write(paths.base.join("update-transaction.json"),serde_json::json!({"schema":1,"phase":"prepared","records":[{"target":victim,"old":root.join("x"),"stage":root.join("y")},{"target":"x","old":"x","stage":"x"},{"target":"x","old":"x","stage":"x"}]}).to_string()).unwrap();
    let mut up = Updater {
        paths,
        os: Os { fail: false },
        transport: NoNet,
    };
    assert_eq!(up.recover().unwrap_err().code, "invalid_update_journal");
    assert_eq!(fs::read_to_string(victim).unwrap(), "keep");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn failed_update_after_accessibility_reset_reports_required_reauthorization() {
    struct ResetThenFail {
        resets: usize,
        restarts: usize,
    }
    impl UpdateOs for ResetThenFail {
        fn architecture(&mut self) -> claude_watch_core::error::Result<String> {
            Ok("arm64".into())
        }
        fn verify_app(
            &mut self,
            _: &std::path::Path,
            _: &str,
        ) -> claude_watch_core::error::Result<()> {
            Ok(())
        }
        fn health(&mut self) -> claude_watch_core::error::Result<()> {
            Ok(())
        }
        fn should_reset_accessibility(&self, _: &std::path::Path) -> bool {
            true
        }
        fn reset_accessibility(
            &mut self,
            _: &std::path::Path,
            _: &str,
        ) -> claude_watch_core::error::Result<()> {
            self.resets += 1;
            Ok(())
        }
        fn restart_agent(&mut self) -> claude_watch_core::error::Result<()> {
            self.restarts += 1;
            Ok(())
        }
        fn agent_healthy(&mut self) -> claude_watch_core::error::Result<bool> {
            Ok(false)
        }
    }
    let root = temp();
    let paths = UpdatePaths {
        base: root.join("base"),
        app: root.join("app"),
        watch: root.join("watch"),
        backend: root.join("backend"),
    };
    fs::create_dir(&paths.watch).unwrap();
    fs::write(&paths.app, b"old app").unwrap();
    fs::write(paths.watch.join("runtime"), b"old runtime").unwrap();
    let source = root.join("source");
    fs::create_dir_all(source.join("app")).unwrap();
    fs::write(source.join("app/Agent Watch.app"), b"new app").unwrap();
    fs::write(source.join("runtime"), b"new runtime").unwrap();
    let release = Release {
        version: "3.0.0".into(),
        build: None,
        architecture: "arm64".into(),
        archive_url: "https://updates.example/release.zip".into(),
        archive_sha256: String::new(),
        files: BTreeMap::new(),
    };
    let mut updater = Updater {
        paths,
        os: ResetThenFail {
            resets: 0,
            restarts: 0,
        },
        transport: NoNet,
    };
    let error = updater.apply_payload(&source, &release).unwrap_err();
    assert_eq!(error.code, "update_rolled_back_reauthorization_required");
    assert!(error.message.contains("重新授权"));
    assert_eq!(updater.os.resets, 1);
    assert_eq!(updater.os.restarts, 2);
    assert_eq!(fs::read(&updater.paths.app).unwrap(), b"old app");
    assert_eq!(
        fs::read(updater.paths.watch.join("runtime")).unwrap(),
        b"old runtime"
    );
    assert!(!updater.paths.base.join("update-transaction.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_update_recovery_reports_possible_accessibility_reauthorization() {
    let root = temp();
    let paths = UpdatePaths {
        base: root.join("base"),
        app: root.join("app"),
        watch: root.join("watch"),
        backend: root.join("backend"),
    };
    fs::create_dir(&paths.base).unwrap();
    fs::create_dir(&paths.watch).unwrap();
    let targets = [paths.app.clone(), paths.watch.join("runtime")];
    let records=targets.iter().map(|target|serde_json::json!({"target":target,"old":target.with_extension("cw-old"),"stage":target.with_extension("cw-new"),"existed":false,"started":false,"before":null,"after":{}})).collect::<Vec<_>>();
    fs::write(paths.base.join("update-transaction.json"),serde_json::to_vec(&serde_json::json!({"schema":2,"phase":"prepared","records":records,"accessibility_reset_attempted":true})).unwrap()).unwrap();
    let mut updater = Updater {
        paths,
        os: Os { fail: false },
        transport: NoNet,
    };
    assert!(updater.recover().unwrap());
    assert!(!updater.paths.base.join("update-transaction.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn build_number_comparison_and_github_release_cdn_rules_work() {
    assert!(is_newer_release("3.0.0", Some(444), "3.0.0", Some(445)).unwrap());
    assert!(!is_newer_release("3.0.0", Some(445), "3.0.0", Some(445)).unwrap());
    assert!(!is_newer_release("3.0.0", Some(445), "3.0.0", Some(444)).unwrap());
    assert!(is_newer_release("3.0.0", Some(999), "3.0.1", Some(1)).unwrap());
    assert!(!is_newer_release("3.0.1", Some(1), "3.0.0", Some(999)).unwrap());
    assert!(!is_newer_release("3.0.0", Some(444), "3.0.0", None).unwrap());

    assert!(claude_watch_core::release_source::archive_origin_allowed(
        "https://github.com/anyun-hy/agent-watch/releases/latest/download/release-manifest.json",
        "https://github.com/anyun-hy/agent-watch/releases/download/v3.0.1/Agent-Watch-update.zip"
    ));
    assert!(claude_watch_core::release_source::archive_origin_allowed(
        "https://github.com/anyun-hy/agent-watch/releases/latest/download/release-manifest.json",
        "https://objects.githubusercontent.com/github-production-release-asset/foo.zip"
    ));
    assert!(!claude_watch_core::release_source::archive_origin_allowed(
        "https://github.com/anyun-hy/agent-watch/releases/latest/download/release-manifest.json",
        "https://evil.invalid/Agent-Watch-update.zip"
    ));
}

#[test]
fn package_release_update_script_output_verifies_end_to_end_in_rust_updater() {
    use std::process::Command;

    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let script = repo_root.join("tools/package-release-update.py");
    assert!(script.is_file(), "missing {}", script.display());

    let root = temp();
    let app = root.join("Fixture.app");
    let resources = app.join("Contents/Resources");
    let macos = app.join("Contents/MacOS");
    fs::create_dir_all(&resources).unwrap();
    fs::create_dir_all(&macos).unwrap();
    fs::write(app.join("Contents/Info.plist"), b"synthetic-info-plist").unwrap();
    fs::write(macos.join("AgentWatch"), b"synthetic-ui-bin").unwrap();
    for name in [
        "watch-engine",
        "watch-native-observer",
        "watch-process-control",
        "watch-admin.sh",
        "watch-sandbox-launcher",
        "watch-gateway-broker",
        "ControlledEntry",
        "watch-native-collector.zsh",
        "watch-leak-worker",
        "BuildInfo.plist",
        "BuildIdentity.json",
    ] {
        fs::write(resources.join(name), format!("synthetic-{name}")).unwrap();
    }

    // Generate ephemeral test RSA keypair via system openssl (never stored in repo).
    let priv_key = root.join("test-private.pem");
    let pub_key = root.join("test-public.pem");
    assert!(Command::new("/usr/bin/openssl")
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&priv_key)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("/usr/bin/openssl")
        .args(["pkey", "-in"])
        .arg(&priv_key)
        .args(["-pubout", "-out"])
        .arg(&pub_key)
        .status()
        .unwrap()
        .success());

    let archive_out = root.join("out/Agent-Watch-update-3.0.1-build501-arm64.zip");
    let manifest_out = root.join("out/release-manifest.json");
    let archive_url =
        "https://github.com/anyun-hy/agent-watch/releases/download/v3.0.1/Agent-Watch-update-3.0.1-build501-arm64.zip";

    let pkg = Command::new("python3")
        .arg(&script)
        .args(["--app", app.to_str().unwrap()])
        .args(["--version", "3.0.1"])
        .args(["--build", "501"])
        .args(["--architecture", "arm64"])
        .args(["--archive-url", archive_url])
        .args(["--archive-output", archive_out.to_str().unwrap()])
        .args(["--manifest-output", manifest_out.to_str().unwrap()])
        .args(["--private-key", priv_key.to_str().unwrap()])
        .args(["--public-key", pub_key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        pkg.status.success(),
        "packager failed: stdout={} stderr={}",
        String::from_utf8_lossy(&pkg.stdout),
        String::from_utf8_lossy(&pkg.stderr)
    );

    let public_pem = fs::read_to_string(&pub_key).unwrap();
    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_out).unwrap()).unwrap();
    let payload = STANDARD
        .decode(envelope["manifest"].as_str().unwrap())
        .unwrap();
    let signature = STANDARD
        .decode(envelope["signature"].as_str().unwrap())
        .unwrap();

    // 1. Rust verifier accepts Python/OpenSSL signed manifest and extracts archive cleanly.
    let release = verify_manifest(&payload, &signature, &public_pem, "arm64").unwrap();
    assert_eq!(release.version, "3.0.1");
    assert_eq!(release.build, Some(501));
    assert_eq!(release.archive_url, archive_url);
    assert_eq!(archive_hash(&archive_out).unwrap(), release.archive_sha256);

    let extracted = root.join("extracted");
    verify_extract(&archive_out, &extracted, &release).unwrap();
    assert!(extracted.join("app/Agent Watch.app/Contents/Info.plist").is_file());
    assert!(extracted.join("runtime/watch-engine").is_file());
    assert!(extracted.join("runtime/watch-gateway-broker").is_file());

    // 2. Tampering with 1 byte of signature fails closed.
    let mut bad_sig = signature.clone();
    bad_sig[0] ^= 0xff;
    assert_eq!(
        verify_manifest(&payload, &bad_sig, &public_pem, "arm64")
            .unwrap_err()
            .code,
        "release_signature_invalid"
    );

    let _ = fs::remove_dir_all(root);
}
