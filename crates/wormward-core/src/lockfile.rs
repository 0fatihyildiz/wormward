//! Lockfile parsing: extract `(ecosystem, name, version)` from the common lockfile formats so a
//! malicious package shipped *inside a resolved dependency tree* is caught even when the top-level
//! `package.json` looks clean. Parsers are pure (content in, entries out); [`check_lockfiles`]
//! drives them from a [`RepoFiles`] source and matches against a pack's `bad_packages`.
//!
//! Matching is version-aware and FP-safe: an entry only fires when its `(ecosystem, name)` is in
//! the pack's malicious list AND the version matches (or the list pins no versions = any version).

use std::path::Path;

use regex::Regex;

use crate::finding::{Finding, FindingKind, Severity};
use crate::matchers::Confidence;
use crate::pack::Pack;
use crate::repo_files::RepoFiles;

/// One resolved dependency read from a lockfile.
#[derive(Debug, Clone, PartialEq)]
pub struct LockEntry {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
}

impl LockEntry {
    fn new(ecosystem: &str, name: impl Into<String>, version: Option<String>) -> Self {
        LockEntry { ecosystem: ecosystem.into(), name: name.into(), version }
    }
}

/// Lockfiles we know how to read, in `(filename, ecosystem)` form. pnpm/yarn/npm all resolve npm
/// packages, so they share the `npm` ecosystem key.
pub const LOCKFILES: &[(&str, &str)] = &[
    ("package-lock.json", "npm"),
    ("npm-shrinkwrap.json", "npm"),
    ("pnpm-lock.yaml", "npm"),
    ("yarn.lock", "npm"),
    ("composer.lock", "composer"),
    ("Pipfile.lock", "pypi"),
    ("requirements.txt", "pypi"),
    ("go.sum", "go"),
];

/// A malicious `bad_packages` version list matches an entry when it pins no versions (any version
/// of that name is malicious) or explicitly lists the entry's version.
pub fn version_matches(entry: &LockEntry, versions: &[String]) -> bool {
    versions.is_empty() || entry.version.as_deref().is_some_and(|v| versions.iter().any(|w| w == v))
}

/// Dispatch to the right parser by lockfile name.
pub fn parse_lockfile(name: &str, content: &str) -> Vec<LockEntry> {
    match name {
        "package-lock.json" | "npm-shrinkwrap.json" => parse_npm_lock(content),
        "pnpm-lock.yaml" => parse_pnpm_lock(content),
        "yarn.lock" => parse_yarn_lock(content),
        "composer.lock" => parse_composer_lock(content),
        "Pipfile.lock" => parse_pipfile_lock(content),
        "requirements.txt" => parse_requirements_txt(content),
        "go.sum" => parse_go_sum(content),
        _ => Vec::new(),
    }
}

// ---- npm (package-lock.json / npm-shrinkwrap.json) ----

pub fn parse_npm_lock(json: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return out;
    };
    // v2/v3: "packages": { "node_modules/<name>": { "version": "x" } }
    if let Some(pkgs) = v.get("packages").and_then(|p| p.as_object()) {
        for (key, meta) in pkgs {
            if key.is_empty() {
                continue; // "" is the project root
            }
            // Take the segment after the last "node_modules/" so nested deps resolve to a name;
            // keep the leading @scope.
            let name = key.rsplit("node_modules/").next().unwrap_or(key);
            if name.is_empty() {
                continue;
            }
            let version = meta.get("version").and_then(|x| x.as_str()).map(String::from);
            out.push(LockEntry::new("npm", name, version));
        }
    }
    // v1: nested "dependencies": { name: { version, dependencies: {...} } }
    if let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) {
        collect_npm_v1_deps(deps, &mut out);
    }
    out
}

fn collect_npm_v1_deps(deps: &serde_json::Map<String, serde_json::Value>, out: &mut Vec<LockEntry>) {
    for (name, meta) in deps {
        let version = meta.get("version").and_then(|x| x.as_str()).map(String::from);
        out.push(LockEntry::new("npm", name.clone(), version));
        if let Some(nested) = meta.get("dependencies").and_then(|d| d.as_object()) {
            collect_npm_v1_deps(nested, out);
        }
    }
}

// ---- pnpm (pnpm-lock.yaml) ----

pub fn parse_pnpm_lock(yaml: &str) -> Vec<LockEntry> {
    // Modern pnpm (v6/v9) package keys: `/name@version(...)`, `name@version:`, `/@scope/name@ver`.
    // We deliberately skip the legacy v5 `/name/version` form (rare) to avoid scope ambiguity.
    let re = Regex::new(r"(?m)^\s*/?'?(@?[\w.-]+(?:/[\w.-]+)?)@([0-9][\w.+-]*)").unwrap();
    let mut out = Vec::new();
    for c in re.captures_iter(yaml) {
        out.push(LockEntry::new("npm", &c[1], Some(c[2].to_string())));
    }
    out
}

// ---- yarn v1 (yarn.lock) ----

pub fn parse_yarn_lock(text: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.starts_with(char::is_whitespace) {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("version ") {
                let version = rest.trim().trim_matches('"').to_string();
                for name in &current {
                    out.push(LockEntry::new("npm", name.clone(), Some(version.clone())));
                }
            }
        } else if line.trim_end().ends_with(':') {
            // Header: `name@range[, name@range]:` — collect the distinct names (before the last @).
            current = line
                .trim_end()
                .trim_end_matches(':')
                .split(',')
                .filter_map(|spec| yarn_name(spec.trim()))
                .collect();
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Extract the package name from a yarn spec like `"@scope/name@^1.2.3"` (name = before last `@`).
fn yarn_name(spec: &str) -> Option<String> {
    let spec = spec.trim().trim_matches('"');
    let at = spec.rfind('@')?;
    if at == 0 {
        return None; // a bare "@scope" with no name
    }
    Some(spec[..at].to_string())
}

impl PartialOrd for LockEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for LockEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.ecosystem, &self.name, &self.version).cmp(&(
            &other.ecosystem,
            &other.name,
            &other.version,
        ))
    }
}
impl Eq for LockEntry {}

// ---- composer (composer.lock) ----

pub fn parse_composer_lock(json: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return out;
    };
    for section in ["packages", "packages-dev"] {
        if let Some(arr) = v.get(section).and_then(|p| p.as_array()) {
            for pkg in arr {
                if let Some(name) = pkg.get("name").and_then(|n| n.as_str()) {
                    let version = pkg.get("version").and_then(|x| x.as_str()).map(String::from);
                    out.push(LockEntry::new("composer", name, version));
                }
            }
        }
    }
    out
}

// ---- pypi (Pipfile.lock / requirements.txt) ----

pub fn parse_pipfile_lock(json: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return out;
    };
    for section in ["default", "develop"] {
        if let Some(obj) = v.get(section).and_then(|d| d.as_object()) {
            for (name, meta) in obj {
                let version = meta
                    .get("version")
                    .and_then(|x| x.as_str())
                    .map(|s| s.trim_start_matches("==").to_string());
                out.push(LockEntry::new("pypi", name.clone(), version));
            }
        }
    }
    out
}

pub fn parse_requirements_txt(text: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, version)) = line.split_once("==") {
            let name = name.trim().to_string();
            let version = version.trim().split([';', ' ']).next().unwrap_or("").to_string();
            if !name.is_empty() {
                out.push(LockEntry::new("pypi", name, Some(version)));
            }
        }
    }
    out
}

// ---- go (go.sum) ----

pub fn parse_go_sum(text: &str) -> Vec<LockEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(module), Some(version)) = (fields.next(), fields.next()) else {
            continue;
        };
        let version = version.trim_end_matches("/go.mod").to_string();
        out.push(LockEntry::new("go", module, Some(version)));
    }
    out.sort();
    out.dedup();
    out
}

// ---- scanner entry point ----

/// Scan every lockfile present in `files` for packages in `pack.bad_packages`. Community-tier
/// matches are downgraded to `Low` severity (advisory lead) so a single-source list never yields a
/// hard critical/"infected" verdict on its own.
pub fn check_lockfiles(repo: &Path, files: &dyn RepoFiles, pack: &Pack) -> Vec<Finding> {
    let mut findings = Vec::new();
    if pack.manifest.bad_packages.is_empty() {
        return findings;
    }
    for (name, _eco) in LOCKFILES {
        let Some(content) = files.read(Path::new(name)) else {
            continue;
        };
        for entry in parse_lockfile(name, &content) {
            let Some(bads) = pack.manifest.bad_packages.get(&entry.ecosystem) else {
                continue;
            };
            for bad in bads {
                if bad.name == entry.name && version_matches(&entry, &bad.versions) {
                    let community = bad.confidence == Confidence::Community;
                    let ver = entry.version.as_deref().map(|v| format!("@{v}")).unwrap_or_default();
                    // Community-tier findings carry a distinct `pkg-community:` id so a caller can
                    // suppress leads without threading a flag through the whole scan pipeline.
                    let prefix = if community { "pkg-community" } else { "pkg" };
                    findings.push(Finding {
                        campaign: pack.manifest.id.clone(),
                        severity: if community {
                            Severity::Low
                        } else {
                            pack.manifest.severity.clone()
                        },
                        repo: repo.to_path_buf(),
                        file: Some(std::path::PathBuf::from(name)),
                        signature_id: format!("{prefix}:{}:{}{ver}", entry.ecosystem, entry.name),
                        kind: FindingKind::NpmPackage,
                        evidence: format!(
                            "malicious {} package '{}'{ver} resolved in {name}{}",
                            entry.ecosystem,
                            entry.name,
                            if community { " (community-sourced lead)" } else { "" }
                        ),
                        remediable: false,
                        online: None,
                        git_ref: None,
                    });
                }
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matching_is_exact_or_any() {
        let e = LockEntry::new("npm", "x", Some("1.1.6".into()));
        assert!(version_matches(&e, &[]), "empty list = any version");
        assert!(version_matches(&e, &["1.1.6".into()]));
        assert!(!version_matches(&e, &["9.9.9".into()]));
        let no_ver = LockEntry::new("npm", "x", None);
        assert!(version_matches(&no_ver, &[]));
        assert!(!version_matches(&no_ver, &["1.0.0".into()]), "unknown version can't match a pin");
    }

    #[test]
    fn parses_npm_v3_packages() {
        let json = r#"{"packages":{"":{},"node_modules/@common-stack/generate-plugin":{"version":"9.0.2-alpha.21"},"node_modules/left-pad":{"version":"1.3.0"}}}"#;
        let e = parse_npm_lock(json);
        assert!(e.contains(&LockEntry::new("npm", "@common-stack/generate-plugin", Some("9.0.2-alpha.21".into()))));
        assert!(e.contains(&LockEntry::new("npm", "left-pad", Some("1.3.0".into()))));
    }

    #[test]
    fn parses_npm_v1_nested_dependencies() {
        let json = r#"{"dependencies":{"a":{"version":"1.0.0","dependencies":{"tailwind-stylecss":{"version":"1.0.0"}}}}}"#;
        let e = parse_npm_lock(json);
        assert!(e.contains(&LockEntry::new("npm", "tailwind-stylecss", Some("1.0.0".into()))));
    }

    #[test]
    fn parses_pnpm_keys() {
        let yaml = "packages:\n  /tailwindcss-style-animate@1.1.6:\n    resolution: {integrity: sha512-x}\n  '@common-stack/generate-plugin@9.0.2-alpha.21':\n    resolution: {integrity: sha512-y}\n  tailwind-stylecss@2.0.0:\n    resolution: {integrity: sha512-z}\n";
        let e = parse_pnpm_lock(yaml);
        assert!(e.contains(&LockEntry::new("npm", "tailwindcss-style-animate", Some("1.1.6".into()))));
        assert!(e.contains(&LockEntry::new("npm", "@common-stack/generate-plugin", Some("9.0.2-alpha.21".into()))));
        assert!(e.contains(&LockEntry::new("npm", "tailwind-stylecss", Some("2.0.0".into()))));
    }

    #[test]
    fn parses_yarn_v1_blocks() {
        let text = "\"tailwindcss-style-animate@^1.1.6\":\n  version \"1.1.6\"\n  resolved \"https://x\"\n\n\"@scope/name@^2.0.0\", \"@scope/name@~2.0.1\":\n  version \"2.0.1\"\n";
        let e = parse_yarn_lock(text);
        assert!(e.contains(&LockEntry::new("npm", "tailwindcss-style-animate", Some("1.1.6".into()))));
        assert!(e.contains(&LockEntry::new("npm", "@scope/name", Some("2.0.1".into()))));
    }

    #[test]
    fn parses_composer_and_go_and_pypi() {
        let composer = r#"{"packages":[{"name":"thiio/kubernetes-php-sdk","version":"1.0.0"}]}"#;
        assert!(parse_composer_lock(composer)
            .contains(&LockEntry::new("composer", "thiio/kubernetes-php-sdk", Some("1.0.0".into()))));
        let go = "github.com/evil/mod v1.2.3/go.mod h1:abc=\ngithub.com/evil/mod v1.2.3 h1:def=\n";
        assert!(parse_go_sum(go).contains(&LockEntry::new("go", "github.com/evil/mod", Some("v1.2.3".into()))));
        let req = "graphalgo==0.1.0  # pinned\nrequests>=2.0\n";
        assert!(parse_requirements_txt(req).contains(&LockEntry::new("pypi", "graphalgo", Some("0.1.0".into()))));
    }
}
