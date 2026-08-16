//! Clean-repo rescan cache: repos that scanned CLEAN in a completed run are skipped on
//! the next scan when the listing's `pushed_at` is unchanged — the single biggest saver
//! for retry/rescan cycles, which previously repeated the whole account's API cost.
//!
//! Only clean verdicts are cached (an infected repo is always rescanned), and the file
//! carries a detection-pack fingerprint so a pack update never trusts stale "clean"
//! verdicts. Every failure mode degrades to "scan everything" — the cache can make a scan
//! cheaper, never wronger.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wormward_core::Pack;

const CACHE_FILE: &str = "github-scan-cache.json";

#[derive(Serialize, Deserialize, Default)]
struct CacheFile {
    packs_fingerprint: String,
    repos: HashMap<String, CachedRepo>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CachedRepo {
    pushed_at: String,
    scanned_at: u64,
}

pub struct ScanCache {
    dir: Option<PathBuf>,
    fingerprint: String,
    repos: HashMap<String, CachedRepo>,
}

/// Fingerprint of the loaded detection packs: pack ids plus their signature/artifact/IOC
/// counts. Any pack change (new campaign, added signature) changes the fingerprint and
/// invalidates every cached "clean".
pub fn packs_fingerprint(packs: &[Pack]) -> String {
    let mut basis = String::new();
    for p in packs {
        basis.push_str(&format!(
            "{}:{}:{}:{}:{};",
            p.manifest.id,
            p.manifest.content_signatures.len(),
            p.manifest.artifacts.len(),
            p.manifest.ioc_domains.len(),
            p.manifest.bad_npm_packages.len(),
        ));
    }
    wormward_core::sha256_hex(basis.as_bytes())
}

/// The default cache directory: `$WORMWARD_CACHE_DIR`, else `~/.wormward`. None (no
/// caching at all) when neither resolves — a machine with no HOME just scans everything.
fn default_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("WORMWARD_CACHE_DIR") {
        return Some(PathBuf::from(d));
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".wormward"))
}

impl ScanCache {
    /// Load the cache for the current pack fingerprint. A missing/unreadable file or a
    /// fingerprint mismatch yields an empty cache (scan everything).
    pub fn load(fingerprint: &str) -> ScanCache {
        match default_dir() {
            Some(d) => ScanCache::load_from(&d, fingerprint),
            None => ScanCache { dir: None, fingerprint: fingerprint.into(), repos: HashMap::new() },
        }
    }

    pub fn load_from(dir: &Path, fingerprint: &str) -> ScanCache {
        let file: CacheFile = std::fs::read_to_string(dir.join(CACHE_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let repos = if file.packs_fingerprint == fingerprint { file.repos } else { HashMap::new() };
        ScanCache { dir: Some(dir.to_path_buf()), fingerprint: fingerprint.into(), repos }
    }

    /// True only for a repo recorded clean whose `pushed_at` is unchanged. Any doubt —
    /// no listing timestamp, unknown repo, changed timestamp — means "scan it".
    pub fn is_clean_unchanged(&self, full_name: &str, pushed_at: Option<&str>) -> bool {
        match (self.repos.get(full_name), pushed_at) {
            (Some(c), Some(p)) => c.pushed_at == p,
            _ => false,
        }
    }

    pub fn record_clean(&mut self, full_name: &str, pushed_at: &str) {
        self.repos.insert(
            full_name.to_string(),
            CachedRepo { pushed_at: pushed_at.to_string(), scanned_at: wormward_core::now_secs() },
        );
    }

    /// Best-effort write; failures are ignored (the cache can only make scans cheaper).
    pub fn save(&self) {
        let Some(dir) = &self.dir else { return };
        let file = CacheFile {
            packs_fingerprint: self.fingerprint.clone(),
            repos: self.repos.clone(),
        };
        let Ok(json) = serde_json::to_string_pretty(&file) else { return };
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(dir.join(CACHE_FILE), json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_clean_repos_and_honors_pushed_at() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut c = ScanCache::load_from(tmp.path(), "fp1");
        assert!(!c.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
        c.record_clean("me/a", "2026-08-01T00:00:00Z");
        c.save();
        let c2 = ScanCache::load_from(tmp.path(), "fp1");
        assert!(c2.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
        // A different pushed_at (repo changed) must rescan.
        assert!(!c2.is_clean_unchanged("me/a", Some("2026-08-02T00:00:00Z")));
        // No pushed_at in the listing → never skip.
        assert!(!c2.is_clean_unchanged("me/a", None));
        // Unknown repo → never skip.
        assert!(!c2.is_clean_unchanged("me/b", Some("2026-08-01T00:00:00Z")));
    }

    #[test]
    fn pack_fingerprint_mismatch_ignores_the_cache() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut c = ScanCache::load_from(tmp.path(), "fp1");
        c.record_clean("me/a", "2026-08-01T00:00:00Z");
        c.save();
        // New packs → new fingerprint → stale "clean" verdicts are not trusted.
        let c2 = ScanCache::load_from(tmp.path(), "fp2");
        assert!(!c2.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
        // And saving under fp2 replaces the file's fingerprint.
        c2.save();
        let c3 = ScanCache::load_from(tmp.path(), "fp1");
        assert!(!c3.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
    }

    #[test]
    fn unreadable_cache_is_ignored() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("github-scan-cache.json"), "{not json").unwrap();
        let c = ScanCache::load_from(tmp.path(), "fp1");
        assert!(!c.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
    }

    #[test]
    fn fingerprint_tracks_pack_content() {
        let packs = wormward_packs::builtin_packs();
        let a = packs_fingerprint(&packs);
        let b = packs_fingerprint(&packs);
        assert_eq!(a, b, "fingerprint must be deterministic");
        assert!(!a.is_empty());
        assert_ne!(a, packs_fingerprint(&packs[..1]), "different pack sets must differ");
    }
}
