//! Authoritative per-product AI desktop, embedded CLI, and standalone CLI
//! version inspection and safe old-version cleanup (`claude` and `chatgpt`).
//!
//! All installation discovery, multi-version detection, and disk pruning run in
//! Rust using the same `target_discovery` catalog and `StateStore` boundaries.
//! Legacy `~/.claude-switcher` directories and signed `.app` bundles are
//! strictly read-only and are never mutated or deleted.

use crate::{
    commands::ReadRunner,
    managed_entry::DesktopManagedEntrySpec,
    native,
    storage::StateStore,
    target_discovery::{isolated_home, DiscoveredTarget, DiscoveryHandle, DiscoverySnapshot},
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::LaunchTarget,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const MAX_DIR_WALK_ENTRIES: usize = 65_536;
const MAX_PACKAGE_JSON_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopInstallInfo {
    pub path: String,
    pub bundle_id: String,
    pub version: String,
    pub build_version: String,
    pub selected: bool,
    pub sandbox_compat_mode: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiDesktopVersions {
    pub selected_version: String,
    pub selected_build: String,
    pub selected_path: String,
    pub selected_bundle_id: String,
    pub sandbox_compat_mode: bool,
    pub installs: Vec<DesktopInstallInfo>,
    pub multiple_versions: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CliInstallInfo {
    pub path: String,
    pub source_kind: String,
    pub source_label: String,
    pub version: String,
    pub selected: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiCliVersions {
    pub selected_version: String,
    pub selected_path: String,
    pub selected_source_label: String,
    pub installs: Vec<CliInstallInfo>,
    pub multiple_versions: bool,
    pub redundant_versions: Vec<String>,
    pub redundant_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddedCliVersions {
    pub present: bool,
    pub latest: String,
    pub path: String,
    pub source_label: String,
    pub bundled_in_app: bool,
    pub versions: Vec<String>,
    pub redundant_versions: Vec<String>,
    pub redundant_bytes: u64,
    pub legacy_redundant_versions: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProductVersionsReport {
    pub product: String,
    pub desktop: AiDesktopVersions,
    pub embedded_cli: EmbeddedCliVersions,
    pub standalone_cli: AiCliVersions,
    pub prunable_versions: Vec<String>,
    pub prunable_bytes: u64,
    pub has_warnings: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiVersionsReport {
    pub claude: ProductVersionsReport,
    pub chatgpt: ProductVersionsReport,
    pub has_multi_version_warnings: bool,
}

/// Parses a dotted numeric version string such as `2.1.328` into integer segments.
pub fn parse_numeric_version(raw: &str) -> Option<Vec<u64>> {
    let trimmed = raw.strip_prefix('v').unwrap_or(raw);
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut parsed = Vec::with_capacity(parts.len());
    for part in parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        parsed.push(part.parse::<u64>().ok()?);
    }
    Some(parsed)
}

fn compare_numeric_versions(a: &[u64], b: &[u64]) -> Ordering {
    let max_len = a.len().max(b.len());
    for idx in 0..max_len {
        let lhs = a.get(idx).copied().unwrap_or(0);
        let rhs = b.get(idx).copied().unwrap_or(0);
        match lhs.cmp(&rhs) {
            Ordering::Equal => continue,
            non_eq => return non_eq,
        }
    }
    a.len().cmp(&b.len())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NumericVersionKey(Vec<u64>);

impl Ord for NumericVersionKey {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_numeric_versions(&self.0, &other.0)
    }
}

impl PartialOrd for NumericVersionKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn cli_source_label(executable: &Path, source_kind: &str) -> String {
    let exe_str = executable.to_string_lossy();
    if source_kind == "verified_bundle_cli" || exe_str.contains(".app/Contents/Resources/") {
        return "桌面应用内置".into();
    }
    if source_kind == "homebrew"
        || exe_str.contains("/Caskroom/")
        || exe_str.contains("/Cellar/")
        || exe_str.starts_with("/opt/homebrew/")
    {
        return "Homebrew 安装".into();
    }
    if source_kind == "claude_native" || exe_str.contains(".local/share/claude/versions") {
        return "官方原生安装".into();
    }
    if exe_str.contains(".local/share/codex/versions") {
        return "本地版本目录".into();
    }
    match source_kind {
        "nvm" => "NVM (Node) 安装".into(),
        "fnm" => "FNM (Node) 安装".into(),
        "volta" | "volta_package" => "Volta 安装".into(),
        "npm" => "npm 全局安装".into(),
        "explicit_path" => "环境变量指定".into(),
        "supported_alias" => "标准命令入口".into(),
        "caller_path" | "daemon_path" => {
            if exe_str.contains("node_modules") {
                "npm 全局安装".into()
            } else {
                "系统 PATH".into()
            }
        }
        _ => {
            if exe_str.contains("node_modules") {
                "npm 全局安装".into()
            } else {
                "本地安装".into()
            }
        }
    }
}

pub fn inspect(store: &StateStore, runner: &dyn ReadRunner) -> AiVersionsReport {
    let snapshot = DiscoveryHandle::for_home(&store.paths.home).refresh(runner, native::now());
    inspect_from_snapshot(store, &snapshot)
}

pub fn inspect_from_snapshot(store: &StateStore, snapshot: &DiscoverySnapshot) -> AiVersionsReport {
    let claude = build_claude_report(store, snapshot);
    let chatgpt = build_chatgpt_report(store, snapshot);
    let has_multi_version_warnings = claude.has_warnings || chatgpt.has_warnings;
    AiVersionsReport {
        claude,
        chatgpt,
        has_multi_version_warnings,
    }
}

fn build_claude_report(store: &StateStore, snapshot: &DiscoverySnapshot) -> ProductVersionsReport {
    let desktop = collect_desktop_versions(snapshot, LaunchTarget::ClaudeDesktop);
    let embedded_cli = scan_embedded_claude_cli(store);
    let standalone_cli =
        collect_standalone_cli_versions(store, snapshot, LaunchTarget::ClaudeCli);

    let mut prunable_versions = embedded_cli.redundant_versions.clone();
    for v in &standalone_cli.redundant_versions {
        if !prunable_versions.contains(v) {
            prunable_versions.push(v.clone());
        }
    }
    let prunable_bytes = embedded_cli
        .redundant_bytes
        .saturating_add(standalone_cli.redundant_bytes);
    let has_warnings = desktop.multiple_versions
        || standalone_cli.multiple_versions
        || !prunable_versions.is_empty()
        || !embedded_cli.legacy_redundant_versions.is_empty();

    ProductVersionsReport {
        product: "claude".into(),
        desktop,
        embedded_cli,
        standalone_cli,
        prunable_versions,
        prunable_bytes,
        has_warnings,
    }
}

fn build_chatgpt_report(store: &StateStore, snapshot: &DiscoverySnapshot) -> ProductVersionsReport {
    let desktop = collect_desktop_versions(snapshot, LaunchTarget::ChatgptDesktop);
    let embedded_cli = collect_bundled_chatgpt_cli(snapshot, &desktop);
    let standalone_cli =
        collect_standalone_cli_versions(store, snapshot, LaunchTarget::CodexCli);

    let prunable_versions = standalone_cli.redundant_versions.clone();
    let prunable_bytes = standalone_cli.redundant_bytes;
    let has_warnings = desktop.multiple_versions
        || standalone_cli.multiple_versions
        || !prunable_versions.is_empty();

    ProductVersionsReport {
        product: "chatgpt".into(),
        desktop,
        embedded_cli,
        standalone_cli,
        prunable_versions,
        prunable_bytes,
        has_warnings,
    }
}

fn collect_desktop_versions(
    snapshot: &DiscoverySnapshot,
    target: LaunchTarget,
) -> AiDesktopVersions {
    let selected_bundle = snapshot
        .select(target, None)
        .ok()
        .and_then(|r| r.bundle.clone().or_else(|| Some(r.entry_path.clone())));

    // Deduplicate by canonical bundle path so `applications_root` and
    // `registered_application` pointing to the same `.app` count once.
    let mut by_bundle: BTreeMap<PathBuf, DesktopInstallInfo> = BTreeMap::new();
    for record in &snapshot.targets {
        if !record.valid() || record.target.cli() {
            continue;
        }
        if !record.kind().is_some_and(|k| target.accepts(k)) {
            continue;
        }
        let bundle_path = record
            .bundle
            .clone()
            .unwrap_or_else(|| record.entry_path.clone());
        let bundle_id = record.bundle_id.clone().unwrap_or_default();
        let version = record.app_version.clone().unwrap_or_default();
        let build_version = record.build_version.clone().unwrap_or_default();
        let selected = selected_bundle.as_ref() == Some(&bundle_path);
        let sandbox_compat_mode = bundle_id == "com.openai.codex"
            && DesktopManagedEntrySpec::bundle_has_aperitif_components(&bundle_path);

        by_bundle
            .entry(bundle_path.clone())
            .and_modify(|existing| {
                if existing.version.is_empty() && !version.is_empty() {
                    existing.version = version.clone();
                }
                if existing.build_version.is_empty() && !build_version.is_empty() {
                    existing.build_version = build_version.clone();
                }
                existing.selected |= selected;
                existing.sandbox_compat_mode |= sandbox_compat_mode;
            })
            .or_insert(DesktopInstallInfo {
                path: bundle_path.to_string_lossy().into_owned(),
                bundle_id,
                version,
                build_version,
                selected,
                sandbox_compat_mode,
            });
    }

    let mut installs: Vec<DesktopInstallInfo> = by_bundle.into_values().collect();
    installs.sort_by(|a, b| {
        b.selected
            .cmp(&a.selected)
            .then_with(|| a.path.cmp(&b.path))
    });

    let primary = installs
        .iter()
        .find(|i| i.selected)
        .or_else(|| {
            installs
                .iter()
                .find(|i| i.path.starts_with("/Applications/"))
        })
        .or_else(|| installs.first());

    let (
        selected_version,
        selected_build,
        selected_path,
        selected_bundle_id,
        sandbox_compat_mode,
    ) = match primary {
        Some(item) => (
            item.version.clone(),
            item.build_version.clone(),
            item.path.clone(),
            item.bundle_id.clone(),
            item.sandbox_compat_mode,
        ),
        None => (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            false,
        ),
    };

    let multiple_versions = installs.len() > 1;
    AiDesktopVersions {
        selected_version,
        selected_build,
        selected_path,
        selected_bundle_id,
        sandbox_compat_mode,
        installs,
        multiple_versions,
    }
}

fn is_bundled_cli_record(record: &DiscoveredTarget, executable: &Path) -> bool {
    record.source_kind == "verified_bundle_cli"
        || executable
            .to_string_lossy()
            .contains(".app/Contents/Resources/")
}

fn collect_bundled_chatgpt_cli(
    snapshot: &DiscoverySnapshot,
    desktop: &AiDesktopVersions,
) -> EmbeddedCliVersions {
    for record in &snapshot.targets {
        if record.target != LaunchTarget::CodexCli || !record.valid() {
            continue;
        }
        let Some(executable) = record.executable.as_ref() else {
            continue;
        };
        if !is_bundled_cli_record(record, executable) {
            continue;
        }
        let version = record
            .app_version
            .clone()
            .filter(|v| !v.is_empty())
            .or_else(|| {
                (!desktop.selected_version.is_empty()).then(|| desktop.selected_version.clone())
            })
            .unwrap_or_else(|| "随附于桌面端".into());
        return EmbeddedCliVersions {
            present: true,
            latest: version.clone(),
            path: executable.to_string_lossy().into_owned(),
            source_label: "ChatGPT 桌面应用内置".into(),
            bundled_in_app: true,
            versions: vec![version],
            redundant_versions: vec![],
            redundant_bytes: 0,
            legacy_redundant_versions: vec![],
        };
    }
    EmbeddedCliVersions {
        present: false,
        latest: String::new(),
        path: String::new(),
        source_label: "ChatGPT 桌面应用内置".into(),
        bundled_in_app: true,
        versions: vec![],
        redundant_versions: vec![],
        redundant_bytes: 0,
        legacy_redundant_versions: vec![],
    }
}

fn collect_standalone_cli_versions(
    store: &StateStore,
    snapshot: &DiscoverySnapshot,
    target: LaunchTarget,
) -> AiCliVersions {
    let selected_exe = snapshot
        .select(target, None)
        .ok()
        .and_then(|r| r.executable.clone());

    let mut by_exe: BTreeMap<PathBuf, CliInstallInfo> = BTreeMap::new();
    for record in &snapshot.targets {
        if record.target != target || !record.valid() || !record.launcher_supported {
            continue;
        }
        let Some(executable) = record.executable.as_ref() else {
            continue;
        };
        // Bundled ChatGPT.app CLI belongs to `embedded_cli`, not standalone CLI installs.
        if is_bundled_cli_record(record, executable) {
            continue;
        }
        let selected = selected_exe.as_ref() == Some(executable);
        let version = infer_cli_version(record).unwrap_or_default();
        let label = cli_source_label(executable, &record.source_kind);
        let entry = by_exe.entry(executable.clone());
        match entry {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(CliInstallInfo {
                    path: executable.to_string_lossy().into_owned(),
                    source_kind: record.source_kind.clone(),
                    source_label: label,
                    version,
                    selected,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let existing = slot.get_mut();
                existing.selected |= selected;
                if existing.source_kind == "supported_alias"
                    && record.source_kind != "supported_alias"
                {
                    existing.source_kind = record.source_kind.clone();
                    existing.source_label = label;
                }
                if existing.version.is_empty() && !version.is_empty() {
                    existing.version = version;
                }
            }
        }
    }

    let mut installs: Vec<CliInstallInfo> = by_exe.into_values().collect();
    installs.sort_by(|a, b| {
        b.selected
            .cmp(&a.selected)
            .then_with(|| a.path.cmp(&b.path))
    });

    // If the snapshot selected a bundled CLI, mark the first standalone install as selected
    // for standalone display if there is exactly one standalone install.
    if !installs.is_empty() && !installs.iter().any(|i| i.selected) && installs.len() == 1 {
        installs[0].selected = true;
    }

    let primary = installs.iter().find(|i| i.selected).or_else(|| installs.first());
    let (selected_version, selected_path, selected_source_label) = match primary {
        Some(item) => (
            item.version.clone(),
            item.path.clone(),
            item.source_label.clone(),
        ),
        None => (String::new(), String::new(), String::new()),
    };
    let multiple_versions = installs.len() > 1;
    let active_paths: BTreeSet<PathBuf> = installs
        .iter()
        .filter(|i| i.selected)
        .map(|i| PathBuf::from(&i.path))
        .collect();
    let (redundant_versions, redundant_bytes, _) =
        scan_prunable_standalone_cli_entries(store, target, &active_paths);

    AiCliVersions {
        selected_version,
        selected_path,
        selected_source_label,
        installs,
        multiple_versions,
        redundant_versions,
        redundant_bytes,
    }
}

fn looks_like_version(segment: &str) -> bool {
    if segment.is_empty() || segment.len() > 64 || segment.chars().any(char::is_control) {
        return false;
    }
    let trimmed = segment.strip_prefix('v').unwrap_or(segment);
    trimmed.bytes().next().is_some_and(|b| b.is_ascii_digit())
        && trimmed.contains('.')
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// Infers CLI version strictly from discovery metadata, safe path structure,
/// or nearby package.json without executing any external process.
fn infer_cli_version(record: &DiscoveredTarget) -> Option<String> {
    if let Some(version) = record.app_version.as_ref().filter(|v| !v.is_empty()) {
        return Some(version.clone());
    }
    for candidate in [
        record.script_entry.as_deref(),
        record.executable.as_deref(),
        Some(record.entry_path.as_path()),
    ]
    .into_iter()
    .flatten()
    {
        let parts: Vec<&str> = candidate
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        for window in parts.windows(3) {
            if matches!(window[0], "Caskroom" | "Cellar") && looks_like_version(window[2]) {
                return Some(window[2].to_owned());
            }
        }
        for window in parts.windows(2) {
            if window[0] == "versions" && looks_like_version(window[1]) {
                return Some(window[1].to_owned());
            }
        }
        for ancestor in candidate.ancestors().take(6) {
            if ancestor.ends_with("node_modules/@anthropic-ai/claude-code")
                || ancestor.ends_with("node_modules/@openai/codex")
            {
                if let Some(version) = read_package_json_version(&ancestor.join("package.json")) {
                    return Some(version);
                }
            }
        }
    }
    None
}

fn read_package_json_version(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_PACKAGE_JSON_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    let version = value.get("version")?.as_str()?.trim();
    if looks_like_version(version) {
        Some(version.to_owned())
    } else {
        None
    }
}

fn managed_embedded_cli_roots(store: &StateStore) -> Vec<PathBuf> {
    vec![
        store.paths.active().join("claude-code"),
        store.paths.accounts().join("A/profile/claude-code"),
        store.paths.accounts().join("B/profile/claude-code"),
        store.paths.accounts().join("A/claude-code"),
        store.paths.accounts().join("B/claude-code"),
    ]
}

fn legacy_embedded_cli_roots(store: &StateStore) -> Vec<PathBuf> {
    vec![
        store
            .paths
            .home
            .join(".claude-switcher/accounts/A/claude-code"),
        store
            .paths
            .home
            .join(".claude-switcher/accounts/B/claude-code"),
    ]
}

fn standalone_cli_version_roots(store: &StateStore, target: LaunchTarget) -> Vec<PathBuf> {
    let home = &store.paths.home;
    let isolated = isolated_home(home);
    match target {
        LaunchTarget::ClaudeCli => {
            let mut roots = vec![
                home.join(".local/share/claude/versions"),
                home.join("homebrew/Caskroom/claude-code"),
            ];
            if !isolated {
                roots.push(PathBuf::from("/opt/homebrew/Caskroom/claude-code"));
                roots.push(PathBuf::from("/usr/local/Caskroom/claude-code"));
            }
            roots
        }
        LaunchTarget::CodexCli => {
            let mut roots = vec![
                home.join(".local/share/codex/versions"),
                home.join("homebrew/Caskroom/codex"),
            ];
            if !isolated {
                roots.push(PathBuf::from("/opt/homebrew/Caskroom/codex"));
                roots.push(PathBuf::from("/usr/local/Caskroom/codex"));
            }
            roots
        }
        _ => vec![],
    }
}

fn scan_version_entries_in_root(
    root: &Path,
    allow_regular_files: bool,
) -> Vec<(NumericVersionKey, String, PathBuf)> {
    let uid = claude_watch_system::effective_uid();
    let Ok(meta) = fs::symlink_metadata(root) else {
        return vec![];
    };
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != uid {
        return vec![];
    }
    let Ok(entries) = fs::read_dir(root) else {
        return vec![];
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let Some(parsed) = parse_numeric_version(&name) else {
            continue;
        };
        let path = entry.path();
        let Ok(child_meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if child_meta.file_type().is_symlink() || child_meta.uid() != uid {
            continue;
        }
        if child_meta.is_dir() || (allow_regular_files && child_meta.is_file()) {
            found.push((NumericVersionKey(parsed), name, path));
        }
    }
    found
}

fn scan_version_dirs_in_root(
    store: &StateStore,
    root: &Path,
) -> Vec<(NumericVersionKey, String, PathBuf)> {
    if store.guarded(root).is_err() {
        return vec![];
    }
    scan_version_entries_in_root(root, false)
}

fn entry_size_no_symlink(root: &Path) -> u64 {
    let Ok(meta) = fs::symlink_metadata(root) else {
        return 0;
    };
    if meta.file_type().is_symlink() {
        return 0;
    }
    if meta.is_file() {
        return meta.len();
    }
    let mut total: u64 = 0;
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MAX_DIR_WALK_ENTRIES {
                return total;
            }
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

fn scan_prunable_standalone_cli_entries(
    store: &StateStore,
    target: LaunchTarget,
    active_paths: &BTreeSet<PathBuf>,
) -> (Vec<String>, u64, Vec<(String, PathBuf, u64)>) {
    let mut prunable_map: BTreeMap<NumericVersionKey, String> = BTreeMap::new();
    let mut total_bytes: u64 = 0;
    let mut prunable_paths: Vec<(String, PathBuf, u64)> = Vec::new();

    for root in standalone_cli_version_roots(store, target) {
        let entries = scan_version_entries_in_root(&root, true);
        if entries.len() <= 1 {
            continue;
        }
        let Some(latest_key) = entries.iter().map(|(k, _, _)| k).max().cloned() else {
            continue;
        };
        for (key, name, path) in entries {
            if key >= latest_key {
                continue;
            }
            // Never prune a path that is currently selected/active or contains an active binary.
            let is_active = active_paths
                .iter()
                .any(|active| active == &path || active.starts_with(&path));
            if is_active {
                continue;
            }
            let bytes = entry_size_no_symlink(&path);
            total_bytes = total_bytes.saturating_add(bytes);
            prunable_map.entry(key).or_insert_with(|| name.clone());
            prunable_paths.push((name, path, bytes));
        }
    }

    let versions: Vec<String> = prunable_map.into_values().rev().collect();
    (versions, total_bytes, prunable_paths)
}

fn scan_embedded_claude_cli(store: &StateStore) -> EmbeddedCliVersions {
    let mut managed_entries = Vec::new();
    let mut managed_map: BTreeMap<NumericVersionKey, String> = BTreeMap::new();
    for root in managed_embedded_cli_roots(store) {
        for (key, name, path) in scan_version_dirs_in_root(store, &root) {
            managed_map.entry(key.clone()).or_insert_with(|| name.clone());
            managed_entries.push((key, name, path));
        }
    }

    let latest_key = managed_map.keys().next_back().cloned();
    let latest = latest_key
        .as_ref()
        .and_then(|k| managed_map.get(k))
        .cloned()
        .unwrap_or_default();
    let latest_path = latest_key
        .as_ref()
        .and_then(|lk| {
            managed_entries
                .iter()
                .find(|(k, _, _)| k == lk)
                .map(|(_, _, p)| p.to_string_lossy().into_owned())
        })
        .unwrap_or_default();

    let versions: Vec<String> = managed_map.values().rev().cloned().collect();
    let mut redundant_versions = Vec::new();
    let mut redundant_bytes: u64 = 0;
    if let Some(ref latest_k) = latest_key {
        for (k, name) in managed_map.iter().rev() {
            if k < latest_k {
                redundant_versions.push(name.clone());
            }
        }
        for (k, _, path) in &managed_entries {
            if k < latest_k {
                redundant_bytes = redundant_bytes.saturating_add(entry_size_no_symlink(path));
            }
        }
    }

    // Read-only visibility into legacy `~/.claude-switcher` embedded CLI dirs.
    let mut legacy_map: BTreeMap<NumericVersionKey, String> = BTreeMap::new();
    for root in legacy_embedded_cli_roots(store) {
        for (key, name, _) in scan_version_dirs_in_root(store, &root) {
            legacy_map.entry(key).or_insert(name);
        }
    }
    let reference_latest = match (&latest_key, legacy_map.keys().next_back()) {
        (Some(a), Some(b)) => Some(a.max(b).clone()),
        (Some(a), None) => Some(a.clone()),
        (None, Some(b)) => Some(b.clone()),
        (None, None) => None,
    };
    let legacy_redundant_versions: Vec<String> = match reference_latest {
        Some(ref latest_k) => legacy_map
            .iter()
            .rev()
            .filter(|(k, _)| *k < latest_k)
            .map(|(_, name)| name.clone())
            .collect(),
        None => vec![],
    };

    EmbeddedCliVersions {
        present: !latest.is_empty(),
        latest,
        path: latest_path,
        source_label: "Claude 桌面端内置".into(),
        bundled_in_app: false,
        versions,
        redundant_versions,
        redundant_bytes,
        legacy_redundant_versions,
    }
}

/// Best-effort cleanup of older embedded Claude Code CLI directories inside a
/// single profile directory (`<profile>/claude-code`). Never touches symlinks
/// and never fails an account switch transaction.
pub fn prune_claude_code_dir(profile_root: &Path) {
    let dir = profile_root.join("claude-code");
    let Ok(meta) = fs::symlink_metadata(&dir) else {
        return;
    };
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return;
    }
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };
    let mut versions: Vec<(NumericVersionKey, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(parsed) = parse_numeric_version(&name) else {
            continue;
        };
        let path = entry.path();
        let Ok(child_meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !child_meta.is_dir() || child_meta.file_type().is_symlink() {
            continue;
        }
        versions.push((NumericVersionKey(parsed), path));
    }
    if versions.len() <= 1 {
        return;
    }
    versions.sort_by(|a, b| a.0.cmp(&b.0));
    let Some((latest_key, _)) = versions.last().cloned() else {
        return;
    };
    for (key, path) in versions {
        if key < latest_key {
            let _ = fs::remove_dir_all(path);
        }
    }
}

pub fn prune_embedded_claude_cli(
    store: &StateStore,
    claude_running: bool,
    apply: bool,
) -> Result<Value> {
    prune_product_cli(store, "claude", claude_running, apply)
}

/// Preview or execute safe cleanup of redundant older CLI versions for `claude`
/// (embedded Claude Code + standalone native/Caskroom old versions) or `chatgpt`
/// (standalone Codex CLI old versions). Never touches legacy `~/.claude-switcher`
/// or signed `.app` bundles.
pub fn prune_product_cli(
    store: &StateStore,
    product: &str,
    product_running: bool,
    apply: bool,
) -> Result<Value> {
    let (target, product_display, running_code, running_msg) = match product {
        "claude" => (
            LaunchTarget::ClaudeCli,
            "Claude Code",
            "claude_running",
            "请先退出 Claude 桌面端与 CLI，再清理旧版 Claude Code",
        ),
        "chatgpt" => (
            LaunchTarget::CodexCli,
            "Codex CLI",
            "chatgpt_running",
            "请先退出 ChatGPT / Codex，再清理旧版 Codex CLI",
        ),
        _ => {
            return Err(CoreError::new("invalid_arguments", "不支持的产品标识"));
        }
    };

    let embedded_before = if product == "claude" {
        scan_embedded_claude_cli(store)
    } else {
        EmbeddedCliVersions::default()
    };
    let (standalone_redundant, standalone_bytes, standalone_paths) =
        scan_prunable_standalone_cli_entries(store, target, &BTreeSet::new());

    if !apply {
        let mut preview_versions = embedded_before.redundant_versions.clone();
        for v in &standalone_redundant {
            if !preview_versions.contains(v) {
                preview_versions.push(v.clone());
            }
        }
        let preview_bytes = embedded_before
            .redundant_bytes
            .saturating_add(standalone_bytes);
        let message = if preview_versions.is_empty() {
            format!("当前没有可清理的旧版 {product_display}。")
        } else {
            format!(
                "预览：可清理 {} 个旧版 {}（{}），预计释放 {:.1} MB。",
                preview_versions.len(),
                product_display,
                preview_versions.join("、"),
                preview_bytes as f64 / (1024.0 * 1024.0)
            )
        };
        return Ok(json!({
            "status": "ok",
            "product": product,
            "applied": false,
            "latest": embedded_before.latest,
            "pruned_versions": preview_versions,
            "freed_bytes": preview_bytes,
            "remaining_versions": embedded_before.versions,
            "legacy_redundant_versions": embedded_before.legacy_redundant_versions,
            "message": message
        }));
    }

    let _guard = store.lock("operation", None)?;
    if store.paths.journal().exists() {
        return Err(CoreError::new(
            "recovery_required",
            "存在未完成的账号切换事务，请先恢复后再清理旧版本",
        ));
    }
    if product_running {
        return Err(CoreError::new(running_code, running_msg));
    }

    let uid = claude_watch_system::effective_uid();
    let mut pruned_versions: Vec<String> = Vec::new();
    let mut freed_bytes: u64 = 0;

    // 1. Prune Watch-managed embedded Claude Code directories if product == "claude"
    if product == "claude" {
        let mut managed_entries = Vec::new();
        let mut managed_map: BTreeMap<NumericVersionKey, String> = BTreeMap::new();
        for root in managed_embedded_cli_roots(store) {
            for (key, name, path) in scan_version_dirs_in_root(store, &root) {
                managed_map.entry(key.clone()).or_insert_with(|| name.clone());
                managed_entries.push((key, name, path));
            }
        }
        if let Some(latest_key) = managed_map.keys().next_back().cloned() {
            for (key, name, path) in managed_entries {
                if key >= latest_key {
                    continue;
                }
                store.guarded(&path)?;
                let meta = fs::symlink_metadata(&path).map_err(|_| {
                    CoreError::new("prune_cli_failed", "待清理的内置 Claude Code 目录不可读取")
                })?;
                if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != uid {
                    return Err(CoreError::new(
                        "unsafe_path",
                        "拒绝清理非常规目录或符号链接",
                    ));
                }
                let bytes = entry_size_no_symlink(&path);
                fs::remove_dir_all(&path).map_err(|_| {
                    CoreError::new("prune_cli_failed", "清理旧版内置 Claude Code 失败")
                })?;
                freed_bytes = freed_bytes.saturating_add(bytes);
                if !pruned_versions.contains(&name) {
                    pruned_versions.push(name);
                }
            }
        }
    }

    // 2. Prune standalone old versions in user-owned version roots
    for (name, path, bytes) in standalone_paths {
        let path_str = path.to_string_lossy();
        if path_str.contains(".claude-switcher") || path_str.contains(".app/") {
            continue;
        }
        let meta = fs::symlink_metadata(&path).map_err(|_| {
            CoreError::new("prune_cli_failed", "待清理的 CLI 旧版本路径不可读取")
        })?;
        if meta.file_type().is_symlink() || meta.uid() != uid {
            return Err(CoreError::new(
                "unsafe_path",
                "拒绝清理符号链接或非当前用户所有的版本目录",
            ));
        }
        if meta.is_dir() {
            fs::remove_dir_all(&path)
                .map_err(|_| CoreError::new("prune_cli_failed", "清理旧版 CLI 目录失败"))?;
        } else if meta.is_file() {
            fs::remove_file(&path)
                .map_err(|_| CoreError::new("prune_cli_failed", "清理旧版 CLI 文件失败"))?;
        }
        freed_bytes = freed_bytes.saturating_add(bytes);
        if !pruned_versions.contains(&name) {
            pruned_versions.push(name);
        }
    }

    let after = if product == "claude" {
        scan_embedded_claude_cli(store)
    } else {
        EmbeddedCliVersions::default()
    };
    let message = if pruned_versions.is_empty() {
        format!("当前没有可清理的旧版 {product_display}。")
    } else {
        format!(
            "已清理 {} 个旧版 {}（{}），释放 {:.1} MB。",
            pruned_versions.len(),
            product_display,
            pruned_versions.join("、"),
            freed_bytes as f64 / (1024.0 * 1024.0),
        )
    };

    Ok(json!({
        "status": "ok",
        "product": product,
        "applied": true,
        "latest": after.latest,
        "pruned_versions": pruned_versions,
        "freed_bytes": freed_bytes,
        "remaining_versions": after.versions,
        "legacy_redundant_versions": after.legacy_redundant_versions,
        "message": message
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use std::os::unix::fs::symlink;

    fn make_temp_store(prefix: &str) -> (PathBuf, StateStore) {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let store = StateStore::new(Paths::new(&dir).unwrap());
        (dir, store)
    }

    #[test]
    fn numeric_version_sorting_handles_multi_digit_segments() {
        let v9 = NumericVersionKey(parse_numeric_version("2.1.9").unwrap());
        let v10 = NumericVersionKey(parse_numeric_version("2.1.10").unwrap());
        let v328 = NumericVersionKey(parse_numeric_version("2.1.328").unwrap());
        assert!(v9 < v10);
        assert!(v10 < v328);
        assert!(parse_numeric_version("v0.170.0").is_some());
        assert!(parse_numeric_version("latest").is_none());
        assert!(parse_numeric_version("2.1.3.4.5").is_none());
        assert!(parse_numeric_version("../2.1.0").is_none());
    }

    #[test]
    fn desktop_deduplicates_same_bundle_and_separates_bundled_chatgpt_cli_from_standalone() {
        let (home, store) = make_temp_store("cw-ai-ver-desktop");
        let make_target = |source_kind: &str, bundle: &str, bundle_id: &str, ver: &str, build: &str| {
            DiscoveredTarget {
                target: LaunchTarget::ChatgptDesktop,
                source_kind: source_kind.into(),
                source_id: format!("chatgpt-desktop:{source_kind}:{bundle}"),
                entry_path: bundle.into(),
                bundle: Some(bundle.into()),
                bundle_id: Some(bundle_id.into()),
                app_version: Some(ver.into()),
                build_version: Some(build.into()),
                executable: Some(format!("{bundle}/Contents/MacOS/ChatGPT").into()),
                script_entry: None,
                interpreter: None,
                launcher_supported: true,
                child_executables: vec![],
                error_code: None,
            }
        };
        let bundled_cli = DiscoveredTarget {
            target: LaunchTarget::CodexCli,
            source_kind: "verified_bundle_cli".into(),
            source_id: "codex-cli:verified_bundle_cli:/Applications/ChatGPT.app".into(),
            entry_path: "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex".into(),
            bundle: Some("/Applications/ChatGPT.app".into()),
            bundle_id: Some("com.openai.codex".into()),
            app_version: Some("26.1117.41037".into()),
            build_version: Some("29803".into()),
            executable: Some("/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex".into()),
            script_entry: None,
            interpreter: None,
            launcher_supported: true,
            child_executables: vec![],
            error_code: None,
        };
        let brew_cli = DiscoveredTarget {
            target: LaunchTarget::CodexCli,
            source_kind: "daemon_path".into(),
            source_id: "codex-cli:daemon_path:/opt/homebrew/bin/codex".into(),
            entry_path: "/opt/homebrew/bin/codex".into(),
            bundle: None,
            bundle_id: None,
            app_version: None,
            build_version: None,
            executable: Some("/opt/homebrew/Caskroom/codex/0.170.0/bin/codex".into()),
            script_entry: None,
            interpreter: None,
            launcher_supported: true,
            child_executables: vec![],
            error_code: None,
        };
        // Bundled CLI + 1 Homebrew standalone CLI must NOT trigger a false multi-version warning!
        let single = DiscoverySnapshot {
            revision: "r1".into(),
            prior_revision: None,
            complete: true,
            targets: vec![
                make_target("applications_root", "/Applications/ChatGPT.app", "com.openai.codex", "26.1117.41037", "29803"),
                make_target("registered_application", "/Applications/ChatGPT.app", "com.openai.codex", "26.1117.41037", "29803"),
                bundled_cli,
                brew_cli,
            ],
            issues: vec![],
            preferred_sources: BTreeMap::new(),
        };
        let report = inspect_from_snapshot(&store, &single);
        assert_eq!(report.chatgpt.desktop.installs.len(), 1);
        assert!(!report.chatgpt.desktop.multiple_versions);
        assert_eq!(report.chatgpt.desktop.selected_version, "26.1117.41037");
        assert_eq!(report.chatgpt.desktop.selected_build, "29803");
        assert!(report.chatgpt.embedded_cli.present);
        assert!(report.chatgpt.embedded_cli.bundled_in_app);
        assert_eq!(report.chatgpt.embedded_cli.source_label, "ChatGPT 桌面应用内置");
        assert_eq!(report.chatgpt.standalone_cli.installs.len(), 1);
        assert!(!report.chatgpt.standalone_cli.multiple_versions);
        assert_eq!(report.chatgpt.standalone_cli.selected_version, "0.170.0");
        assert_eq!(report.chatgpt.standalone_cli.selected_source_label, "Homebrew 安装");
        assert!(!report.chatgpt.has_warnings);
        assert!(!report.has_multi_version_warnings);

        // Two distinct desktop bundles should trigger `multiple_versions` and `has_warnings`.
        let multi = DiscoverySnapshot {
            revision: "r2".into(),
            prior_revision: None,
            complete: true,
            targets: vec![
                make_target("applications_root", "/Applications/ChatGPT.app", "com.openai.codex", "26.1117.41037", "29803"),
                make_target("applications_root", "/Users/u/Applications/ChatGPT.app", "com.openai.chat", "1.2025.0", "100"),
            ],
            issues: vec![],
            preferred_sources: BTreeMap::new(),
        };
        let report2 = inspect_from_snapshot(&store, &multi);
        assert_eq!(report2.chatgpt.desktop.installs.len(), 2);
        assert!(report2.chatgpt.desktop.multiple_versions);
        assert!(report2.chatgpt.has_warnings);
        assert!(report2.has_multi_version_warnings);
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn embedded_and_standalone_cli_scan_and_prune_respect_safety_and_preserve_legacy() {
        let (home, store) = make_temp_store("cw-ai-ver-prune");
        let active_cli = store.paths.active().join("claude-code");
        let slot_a_cli = store.paths.accounts().join("A/profile/claude-code");
        let legacy_cli = store.paths.home.join(".claude-switcher/accounts/A/claude-code");
        let codex_cask = store.paths.home.join("homebrew/Caskroom/codex");
        fs::create_dir_all(active_cli.join("2.1.9")).unwrap();
        fs::create_dir_all(active_cli.join("2.1.10")).unwrap();
        fs::create_dir_all(slot_a_cli.join("2.1.8")).unwrap();
        fs::create_dir_all(legacy_cli.join("2.0.5")).unwrap();
        fs::create_dir_all(codex_cask.join("0.160.0")).unwrap();
        fs::create_dir_all(codex_cask.join("0.170.0")).unwrap();
        fs::write(active_cli.join("2.1.9/bin"), vec![1u8; 4096]).unwrap();
        fs::write(active_cli.join("2.1.10/bin"), vec![2u8; 4096]).unwrap();
        fs::write(slot_a_cli.join("2.1.8/bin"), vec![3u8; 2048]).unwrap();
        fs::write(legacy_cli.join("2.0.5/bin"), vec![4u8; 1024]).unwrap();
        fs::write(codex_cask.join("0.160.0/codex"), vec![5u8; 8192]).unwrap();
        fs::write(codex_cask.join("0.170.0/codex"), vec![6u8; 8192]).unwrap();
        // Symlink decoy must be ignored and never deleted.
        let decoy_target = home.join("keep-me");
        fs::create_dir_all(&decoy_target).unwrap();
        fs::write(decoy_target.join("precious"), b"keep").unwrap();
        symlink(&decoy_target, active_cli.join("2.1.1")).unwrap();

        let info = scan_embedded_claude_cli(&store);
        assert_eq!(info.latest, "2.1.10");
        assert_eq!(info.versions, vec!["2.1.10", "2.1.9", "2.1.8"]);
        assert_eq!(info.redundant_versions, vec!["2.1.9", "2.1.8"]);
        assert_eq!(info.redundant_bytes, 4096 + 2048);
        assert_eq!(info.legacy_redundant_versions, vec!["2.0.5"]);

        // Preview leaves everything untouched.
        let preview = prune_embedded_claude_cli(&store, false, false).unwrap();
        assert_eq!(preview["applied"], false);
        assert!(active_cli.join("2.1.9").exists());

        // Refuses while Claude is running.
        let err = prune_embedded_claude_cli(&store, true, true).unwrap_err();
        assert_eq!(err.code, "claude_running");
        assert!(active_cli.join("2.1.9").exists());

        // Apply removes strictly older managed versions only, keeps latest, symlink target, and legacy.
        let applied = prune_embedded_claude_cli(&store, false, true).unwrap();
        assert_eq!(applied["applied"], true);
        assert_eq!(applied["freed_bytes"], 4096 + 2048);
        assert_eq!(applied["pruned_versions"], json!(["2.1.9", "2.1.8"]));
        assert!(!active_cli.join("2.1.9").exists());
        assert!(!slot_a_cli.join("2.1.8").exists());
        assert!(active_cli.join("2.1.10/bin").exists());
        assert!(decoy_target.join("precious").exists());
        assert!(legacy_cli.join("2.0.5/bin").exists());

        // ChatGPT / Codex standalone old version pruning
        let gpt_err = prune_product_cli(&store, "chatgpt", true, true).unwrap_err();
        assert_eq!(gpt_err.code, "chatgpt_running");
        let gpt_applied = prune_product_cli(&store, "chatgpt", false, true).unwrap();
        assert_eq!(gpt_applied["applied"], true);
        assert_eq!(gpt_applied["pruned_versions"], json!(["0.160.0"]));
        assert_eq!(gpt_applied["freed_bytes"], 8192);
        assert!(!codex_cask.join("0.160.0").exists());
        assert!(codex_cask.join("0.170.0/codex").exists());

        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn cli_version_inference_reads_known_layout_paths() {
        let record = DiscoveredTarget {
            target: LaunchTarget::ClaudeCli,
            source_kind: "known_path".into(),
            source_id: "claude-cli:known_path:/Users/u/.local/share/claude/versions/2.1.77".into(),
            entry_path: "/Users/u/.local/bin/claude".into(),
            bundle: None,
            bundle_id: None,
            app_version: None,
            build_version: None,
            executable: Some("/Users/u/.local/share/claude/versions/2.1.77".into()),
            script_entry: None,
            interpreter: None,
            launcher_supported: true,
            child_executables: vec![],
            error_code: None,
        };
        assert_eq!(infer_cli_version(&record).as_deref(), Some("2.1.77"));

        let cask = DiscoveredTarget {
            target: LaunchTarget::CodexCli,
            source_kind: "homebrew".into(),
            source_id: "codex-cli:homebrew:/opt/homebrew/bin/codex".into(),
            entry_path: "/opt/homebrew/bin/codex".into(),
            bundle: None,
            bundle_id: None,
            app_version: None,
            build_version: None,
            executable: Some("/opt/homebrew/Caskroom/codex/0.114.0/codex-aarch64-apple-darwin".into()),
            script_entry: None,
            interpreter: None,
            launcher_supported: true,
            child_executables: vec![],
            error_code: None,
        };
        assert_eq!(infer_cli_version(&cask).as_deref(), Some("0.114.0"));
    }
}
