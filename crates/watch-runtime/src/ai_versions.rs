//! Authoritative AI desktop and CLI version inspection and safe embedded
//! Claude Code CLI pruning.
//!
//! All installation discovery, multi-version detection, and disk pruning run in
//! Rust using the same `target_discovery` catalog and `StateStore` boundaries.
//! Legacy `~/.claude-switcher` directories are strictly read-only and are never
//! mutated or deleted.

use crate::{
    commands::ReadRunner,
    managed_entry::DesktopManagedEntrySpec,
    native,
    storage::StateStore,
    target_discovery::{DiscoveredTarget, DiscoveryHandle, DiscoverySnapshot},
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::LaunchTarget,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs,
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
    pub seatbelt_incompatible: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiDesktopVersions {
    pub selected_version: String,
    pub selected_build: String,
    pub selected_path: String,
    pub selected_bundle_id: String,
    pub seatbelt_incompatible: bool,
    pub installs: Vec<DesktopInstallInfo>,
    pub multiple_versions: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CliInstallInfo {
    pub path: String,
    pub source_kind: String,
    pub version: String,
    pub selected: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiCliVersions {
    pub selected_version: String,
    pub selected_path: String,
    pub installs: Vec<CliInstallInfo>,
    pub multiple_versions: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmbeddedClaudeCliInfo {
    pub latest: String,
    pub versions: Vec<String>,
    pub redundant_versions: Vec<String>,
    pub redundant_bytes: u64,
    pub legacy_redundant_versions: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiVersionsReport {
    pub claude_desktop: AiDesktopVersions,
    pub chatgpt_desktop: AiDesktopVersions,
    pub claude_embedded_cli: EmbeddedClaudeCliInfo,
    pub claude_cli: AiCliVersions,
    pub codex_cli: AiCliVersions,
    pub has_multi_version_warnings: bool,
}

/// Parses a dotted numeric version string such as `2.1.328` into integer segments.
pub fn parse_numeric_version(raw: &str) -> Option<Vec<u64>> {
    if raw.is_empty() || raw.len() > 64 {
        return None;
    }
    let parts: Vec<&str> = raw.split('.').collect();
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

pub fn inspect(store: &StateStore, runner: &dyn ReadRunner) -> AiVersionsReport {
    let snapshot = DiscoveryHandle::for_home(&store.paths.home).refresh(runner, native::now());
    inspect_from_snapshot(store, &snapshot)
}

pub fn inspect_from_snapshot(store: &StateStore, snapshot: &DiscoverySnapshot) -> AiVersionsReport {
    let claude_desktop = collect_desktop_versions(snapshot, LaunchTarget::ClaudeDesktop);
    let chatgpt_desktop = collect_desktop_versions(snapshot, LaunchTarget::ChatgptDesktop);
    let claude_embedded_cli = scan_embedded_claude_cli(store);
    let claude_cli = collect_cli_versions(snapshot, LaunchTarget::ClaudeCli);
    let codex_cli = collect_cli_versions(snapshot, LaunchTarget::CodexCli);
    let has_multi_version_warnings = claude_desktop.multiple_versions
        || chatgpt_desktop.multiple_versions
        || claude_cli.multiple_versions
        || codex_cli.multiple_versions
        || !claude_embedded_cli.redundant_versions.is_empty()
        || !claude_embedded_cli.legacy_redundant_versions.is_empty();
    AiVersionsReport {
        claude_desktop,
        chatgpt_desktop,
        claude_embedded_cli,
        claude_cli,
        codex_cli,
        has_multi_version_warnings,
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
        let seatbelt_incompatible = bundle_id == "com.openai.codex"
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
                existing.seatbelt_incompatible |= seatbelt_incompatible;
            })
            .or_insert(DesktopInstallInfo {
                path: bundle_path.to_string_lossy().into_owned(),
                bundle_id,
                version,
                build_version,
                selected,
                seatbelt_incompatible,
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

    let (selected_version, selected_build, selected_path, selected_bundle_id, seatbelt_incompatible) =
        match primary {
            Some(item) => (
                item.version.clone(),
                item.build_version.clone(),
                item.path.clone(),
                item.bundle_id.clone(),
                item.seatbelt_incompatible,
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
        seatbelt_incompatible,
        installs,
        multiple_versions,
    }
}

fn collect_cli_versions(snapshot: &DiscoverySnapshot, target: LaunchTarget) -> AiCliVersions {
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
        let selected = selected_exe.as_ref() == Some(executable);
        let version = infer_cli_version(record).unwrap_or_default();
        let entry = by_exe.entry(executable.clone());
        match entry {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(CliInstallInfo {
                    path: executable.to_string_lossy().into_owned(),
                    source_kind: record.source_kind.clone(),
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

    let primary = installs.iter().find(|i| i.selected).or_else(|| installs.first());
    let (selected_version, selected_path) = match primary {
        Some(item) => (item.version.clone(), item.path.clone()),
        None => (String::new(), String::new()),
    };
    let multiple_versions = installs.len() > 1;
    AiCliVersions {
        selected_version,
        selected_path,
        installs,
        multiple_versions,
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

fn scan_version_dirs_in_root(
    store: &StateStore,
    root: &Path,
) -> Vec<(NumericVersionKey, String, PathBuf)> {
    if store.guarded(root).is_err() {
        return vec![];
    }
    let Ok(meta) = fs::symlink_metadata(root) else {
        return vec![];
    };
    if !meta.is_dir() || meta.file_type().is_symlink() {
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
        found.push((NumericVersionKey(parsed), name, path));
    }
    found
}

fn dir_size_no_symlink(root: &Path) -> u64 {
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

fn scan_embedded_claude_cli(store: &StateStore) -> EmbeddedClaudeCliInfo {
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
                redundant_bytes = redundant_bytes.saturating_add(dir_size_no_symlink(path));
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

    EmbeddedClaudeCliInfo {
        latest,
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

/// Preview or execute safe cleanup of redundant older embedded Claude Code CLI
/// versions in Watch-managed locations (`active/claude-code` and Watch account
/// slots). Never touches legacy `~/.claude-switcher`.
pub fn prune_embedded_claude_cli(
    store: &StateStore,
    claude_running: bool,
    apply: bool,
) -> Result<Value> {
    if !apply {
        let info = scan_embedded_claude_cli(store);
        let message = if info.redundant_versions.is_empty() {
            "当前没有可清理的旧版内置 Claude Code。".to_owned()
        } else {
            format!(
                "预览：可清理 {} 个旧版内置 Claude Code（保留最新 {}），预计释放 {:.1} MB。",
                info.redundant_versions.len(),
                info.latest,
                info.redundant_bytes as f64 / (1024.0 * 1024.0)
            )
        };
        return Ok(json!({
            "status": "ok",
            "applied": false,
            "latest": info.latest,
            "pruned_versions": info.redundant_versions,
            "freed_bytes": info.redundant_bytes,
            "remaining_versions": info.versions,
            "legacy_redundant_versions": info.legacy_redundant_versions,
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
    if claude_running {
        return Err(CoreError::new(
            "claude_running",
            "请先退出 Claude 桌面端，再清理旧版内置 Claude Code",
        ));
    }

    let mut managed_entries = Vec::new();
    let mut managed_map: BTreeMap<NumericVersionKey, String> = BTreeMap::new();
    for root in managed_embedded_cli_roots(store) {
        for (key, name, path) in scan_version_dirs_in_root(store, &root) {
            managed_map.entry(key.clone()).or_insert_with(|| name.clone());
            managed_entries.push((key, name, path));
        }
    }

    let Some(latest_key) = managed_map.keys().next_back().cloned() else {
        return Ok(json!({
            "status": "ok",
            "applied": true,
            "latest": "",
            "pruned_versions": [],
            "freed_bytes": 0,
            "remaining_versions": [],
            "message": "当前未检测到内置 Claude Code 版本目录。"
        }));
    };
    let latest = managed_map.get(&latest_key).cloned().unwrap_or_default();

    let mut pruned_set: BTreeMap<NumericVersionKey, String> = BTreeMap::new();
    let mut freed_bytes: u64 = 0;
    for (key, name, path) in managed_entries {
        if key >= latest_key {
            continue;
        }
        store.guarded(&path)?;
        let meta = fs::symlink_metadata(&path).map_err(|_| {
            CoreError::new("prune_cli_failed", "待清理的内置 Claude Code 目录不可读取")
        })?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(CoreError::new(
                "unsafe_path",
                "拒绝清理非常规目录或符号链接",
            ));
        }
        let bytes = dir_size_no_symlink(&path);
        fs::remove_dir_all(&path).map_err(|_| {
            CoreError::new("prune_cli_failed", "清理旧版内置 Claude Code 失败")
        })?;
        freed_bytes = freed_bytes.saturating_add(bytes);
        pruned_set.entry(key).or_insert(name);
    }

    let pruned_versions: Vec<String> = pruned_set.into_values().rev().collect();
    let after = scan_embedded_claude_cli(store);
    let message = if pruned_versions.is_empty() {
        "当前没有可清理的旧版内置 Claude Code。".to_owned()
    } else {
        format!(
            "已清理 {} 个旧版内置 Claude Code（{}），释放 {:.1} MB，保留最新 {}。",
            pruned_versions.len(),
            pruned_versions.join("、"),
            freed_bytes as f64 / (1024.0 * 1024.0),
            latest
        )
    };

    Ok(json!({
        "status": "ok",
        "applied": true,
        "latest": latest,
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
        assert!(parse_numeric_version("latest").is_none());
        assert!(parse_numeric_version("2.1.3.4.5").is_none());
        assert!(parse_numeric_version("../2.1.0").is_none());
    }

    #[test]
    fn desktop_deduplicates_same_bundle_and_flags_multiple_installs() {
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
        // Two discovery sources for the same bundle should deduplicate to 1 install.
        let single = DiscoverySnapshot {
            revision: "r1".into(),
            prior_revision: None,
            complete: true,
            targets: vec![
                make_target("applications_root", "/Applications/ChatGPT.app", "com.openai.codex", "26.1117.31558", "29513"),
                make_target("registered_application", "/Applications/ChatGPT.app", "com.openai.codex", "26.1117.31558", "29513"),
            ],
            issues: vec![],
            preferred_sources: BTreeMap::new(),
        };
        let report = inspect_from_snapshot(&store, &single);
        assert_eq!(report.chatgpt_desktop.installs.len(), 1);
        assert!(!report.chatgpt_desktop.multiple_versions);
        assert_eq!(report.chatgpt_desktop.selected_version, "26.1117.31558");
        assert_eq!(report.chatgpt_desktop.selected_build, "29513");

        // Two distinct bundles should trigger `multiple_versions`.
        let multi = DiscoverySnapshot {
            revision: "r2".into(),
            prior_revision: None,
            complete: true,
            targets: vec![
                make_target("applications_root", "/Applications/ChatGPT.app", "com.openai.codex", "26.1117.31558", "29513"),
                make_target("applications_root", "/Users/u/Applications/ChatGPT.app", "com.openai.chat", "1.2025.0", "100"),
            ],
            issues: vec![],
            preferred_sources: BTreeMap::new(),
        };
        let report2 = inspect_from_snapshot(&store, &multi);
        assert_eq!(report2.chatgpt_desktop.installs.len(), 2);
        assert!(report2.chatgpt_desktop.multiple_versions);
        assert!(report2.has_multi_version_warnings);
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn embedded_cli_scan_and_prune_respect_safety_and_preserve_legacy() {
        let (home, store) = make_temp_store("cw-ai-ver-prune");
        let active_cli = store.paths.active().join("claude-code");
        let slot_a_cli = store.paths.accounts().join("A/profile/claude-code");
        let legacy_cli = store.paths.home.join(".claude-switcher/accounts/A/claude-code");
        fs::create_dir_all(active_cli.join("2.1.9")).unwrap();
        fs::create_dir_all(active_cli.join("2.1.10")).unwrap();
        fs::create_dir_all(slot_a_cli.join("2.1.8")).unwrap();
        fs::create_dir_all(legacy_cli.join("2.0.5")).unwrap();
        fs::write(active_cli.join("2.1.9/bin"), vec![1u8; 4096]).unwrap();
        fs::write(active_cli.join("2.1.10/bin"), vec![2u8; 4096]).unwrap();
        fs::write(slot_a_cli.join("2.1.8/bin"), vec![3u8; 2048]).unwrap();
        fs::write(legacy_cli.join("2.0.5/bin"), vec![4u8; 1024]).unwrap();
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
