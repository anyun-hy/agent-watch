//! Built-in GitHub release source metadata and pure HTTPS/redirect policy rules.
//!
//! Never performs network I/O or embeds private keys. A user-configured
//! `(update_url, update_public_key)` pair overrides the built-in default;
//! partial configuration fails closed without mixing sources.

use url::Url;

pub const DEFAULT_RELEASE_REPO: &str = "anyun-hy/claude-watch";
pub const DEFAULT_RELEASE_MANIFEST_URL: &str =
    "https://github.com/anyun-hy/claude-watch/releases/latest/download/release-manifest.json";
pub const DEFAULT_RELEASE_PUBLIC_KEY_PEM: &str = include_str!("default_release_public_key.pem");

const GITHUB_RELEASE_HOSTS: [&str; 3] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveUpdateSource {
    pub url: String,
    pub public_key: String,
    pub is_builtin: bool,
}

/// Returns the built-in `(manifest_url, public_key_pem)` pair when a real
/// public key PEM has been embedded in `default_release_public_key.pem`.
pub fn builtin_release_source() -> Option<(&'static str, &'static str)> {
    let lines: Vec<&str> = DEFAULT_RELEASE_PUBLIC_KEY_PEM
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if lines.len() < 3
        || lines.first().copied() != Some("-----BEGIN PUBLIC KEY-----")
        || lines.last().copied() != Some("-----END PUBLIC KEY-----")
    {
        return None;
    }
    let body_len: usize = lines[1..lines.len() - 1].iter().map(|l| l.len()).sum();
    if body_len < 64 {
        return None;
    }
    Some((DEFAULT_RELEASE_MANIFEST_URL, DEFAULT_RELEASE_PUBLIC_KEY_PEM.trim()))
}

/// Resolves the active update source:
/// - Both configured -> use explicit user override (`is_builtin = false`).
/// - Both empty -> use built-in official GitHub release source when embedded.
/// - Only one set -> return `None` (never mix user URL with built-in key).
pub fn resolve_update_source(
    configured_url: &str,
    configured_key: &str,
) -> Option<EffectiveUpdateSource> {
    let url = configured_url.trim();
    let key = configured_key.trim();
    match (!url.is_empty(), !key.is_empty()) {
        (true, true) => Some(EffectiveUpdateSource {
            url: url.to_string(),
            public_key: key.to_string(),
            is_builtin: false,
        }),
        (false, false) => builtin_release_source().map(|(u, k)| EffectiveUpdateSource {
            url: u.to_string(),
            public_key: k.to_string(),
            is_builtin: true,
        }),
        _ => None,
    }
}

pub fn is_safe_https_url(raw: &str) -> bool {
    !raw.contains(char::is_whitespace)
        && Url::parse(raw).is_ok_and(|u| {
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.fragment().is_none()
        })
}

fn host_of(raw: &str) -> Option<String> {
    Url::parse(raw)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
}

fn is_github_release_host(host: &str) -> bool {
    GITHUB_RELEASE_HOSTS.contains(&host)
}

/// Returns whether an HTTPS redirect from `from_url` to `to_url` is permitted.
/// Only same-origin redirects or GitHub Releases CDN redirects (`github.com`
/// -> `github.com` / `objects.githubusercontent.com` /
/// `release-assets.githubusercontent.com`) are allowed.
pub fn redirect_allowed(from_url: &str, to_url: &str) -> bool {
    if !is_safe_https_url(from_url) || !is_safe_https_url(to_url) {
        return false;
    }
    let (Ok(from), Ok(to)) = (Url::parse(from_url), Url::parse(to_url)) else {
        return false;
    };
    if from.origin() == to.origin() {
        return true;
    }
    let Some(from_host) = from.host_str().map(|h| h.to_ascii_lowercase()) else {
        return false;
    };
    let Some(to_host) = to.host_str().map(|h| h.to_ascii_lowercase()) else {
        return false;
    };
    is_github_release_host(&from_host) && is_github_release_host(&to_host)
}

/// Returns whether `archive_url` is permitted for a signed manifest fetched from
/// `manifest_url`. Allows exact same origin, or official GitHub Releases URLs
/// belonging to the same repository when `manifest_url` is hosted on GitHub.
pub fn archive_origin_allowed(manifest_url: &str, archive_url: &str) -> bool {
    if !is_safe_https_url(manifest_url) || !is_safe_https_url(archive_url) {
        return false;
    }
    let (Ok(m), Ok(a)) = (Url::parse(manifest_url), Url::parse(archive_url)) else {
        return false;
    };
    if m.origin() == a.origin() {
        return true;
    }
    let Some(m_host) = host_of(manifest_url) else {
        return false;
    };
    let Some(a_host) = host_of(archive_url) else {
        return false;
    };
    m_host == "github.com" && is_github_release_host(&a_host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_update_source_prefers_complete_override_and_rejects_partial_config() {
        let custom = resolve_update_source(
            "https://updates.example/manifest.json",
            "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----",
        )
        .unwrap();
        assert!(!custom.is_builtin);
        assert_eq!(custom.url, "https://updates.example/manifest.json");
        assert!(resolve_update_source("https://updates.example/manifest.json", "").is_none());
        assert!(resolve_update_source("", "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----").is_none());
    }

    #[test]
    fn github_redirect_allowlist_permits_release_cdn_and_blocks_arbitrary_hosts_or_http() {
        let gh = "https://github.com/anyun-hy/claude-watch/releases/latest/download/release-manifest.json";
        assert!(redirect_allowed(
            gh,
            "https://github.com/anyun-hy/claude-watch/releases/download/v3.0.1/release-manifest.json"
        ));
        assert!(redirect_allowed(
            gh,
            "https://objects.githubusercontent.com/github-production-release-asset-2e65be/abc"
        ));
        assert!(redirect_allowed(
            gh,
            "https://release-assets.githubusercontent.com/github-production-release-asset-2e65be/abc"
        ));
        assert!(!redirect_allowed(
            gh,
            "http://objects.githubusercontent.com/downgrade"
        ));
        assert!(!redirect_allowed(
            gh,
            "https://evil.example.com/release.zip"
        ));
        assert!(!redirect_allowed(
            "https://updates.example/manifest.json",
            "https://objects.githubusercontent.com/other"
        ));
    }
}
