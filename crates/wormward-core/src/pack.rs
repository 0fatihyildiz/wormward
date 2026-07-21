use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::finding::{Finding, Severity};
use crate::matchers::{Confidence, ContentSignature};

/// A known-malicious package, optionally pinned to specific versions. `versions` empty ⇒ any
/// version of that name is malicious. `confidence` tiers the trust (community ⇒ advisory only).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BadPackage {
    pub name: String,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Artifact {
    pub path: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PayloadStrip {
    pub strategy: String,
    #[serde(default)]
    pub markers: Vec<String>,
    /// Injected lines to delete from the surviving prefix after the payload is cut (e.g. the
    /// PolinRider `createRequire` ESM shim added at the top of the file). Each entry is a `re:`
    /// regex or a literal substring matched against a whole line. Empty by default.
    #[serde(default)]
    pub strip_lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct Remediation {
    #[serde(default)]
    pub config_payload: Option<PayloadStrip>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PackManifest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub references: Vec<String>,
    pub severity: Severity,
    #[serde(default)]
    pub target_files: Vec<String>,
    #[serde(default)]
    pub content_signatures: Vec<ContentSignature>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub gitignore_injections: Vec<String>,
    #[serde(default)]
    pub bad_npm_packages: Vec<String>,
    /// Version-aware, cross-ecosystem malicious packages, keyed by ecosystem
    /// (`npm`|`pypi`|`composer`|`go`). Consumed by lockfile and node_modules scanning.
    #[serde(default)]
    pub bad_packages: BTreeMap<String, Vec<BadPackage>>,
    #[serde(default)]
    pub ioc_domains: Vec<String>,
    #[serde(default)]
    pub analyzer: Option<String>,
    #[serde(default)]
    pub remediation: Option<Remediation>,
}

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("invalid pack manifest: {0}")]
    Manifest(String),
}

impl PackManifest {
    pub fn from_yaml(source: &str) -> Result<PackManifest, PackError> {
        serde_yaml::from_str(source).map_err(|e| PackError::Manifest(e.to_string()))
    }
}

pub struct ScannedFile {
    pub repo: PathBuf,
    pub path: PathBuf,
    pub content: String,
}

pub trait CampaignAnalyzer: Send + Sync {
    fn id(&self) -> &str;
    fn analyze(&self, file: &ScannedFile) -> Vec<Finding>;
    /// A STRICT payload fingerprint for scanning normally-EXCLUDED / generated code — build output
    /// (`.output`/`.next`/`dist`/`build`) and package caches (pnpm `.pnpm/`, `.bun/install/cache/`).
    /// Those locations are full of legit minified/generated code that trips the structural detectors
    /// (the whole-machine probe proved 452/832 legit bundles fire the capability gate), so this must
    /// fire ONLY on tells that never occur in legit code — a decoder DEFINITION or a version-tag
    /// marker — never on structural heuristics (padding / entropy) that legit bundles trip. Returns a
    /// reason on a hit, or `None`. Default: never fires.
    fn hidden_payload(&self, _content: &str) -> Option<String> {
        None
    }
}

pub struct Pack {
    pub manifest: PackManifest,
    pub analyzer: Option<Box<dyn CampaignAnalyzer>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matchers::SignatureKind;

    const SAMPLE: &str = r#"
id: polinrider
name: PolinRider
severity: critical
target_files:
  - "postcss.config.mjs"
content_signatures:
  - id: primary
    kind: literal
    value: '("rmcej%otb%",2857687)'
artifacts:
  - path: "temp_auto_push.bat"
    label: "Propagation script"
bad_npm_packages:
  - tailwindcss-style-animate
analyzer: polinrider
remediation:
  config_payload:
    strategy: strip_after_marker
    markers: ["global['!']="]
"#;

    #[test]
    fn parses_full_manifest() {
        let m = PackManifest::from_yaml(SAMPLE).unwrap();
        assert_eq!(m.id, "polinrider");
        assert_eq!(m.severity, Severity::Critical);
        assert_eq!(m.target_files, vec!["postcss.config.mjs".to_string()]);
        assert_eq!(m.content_signatures[0].kind, SignatureKind::Literal);
        assert_eq!(m.artifacts[0].path, "temp_auto_push.bat");
        assert_eq!(m.bad_npm_packages, vec!["tailwindcss-style-animate".to_string()]);
        assert_eq!(m.analyzer.as_deref(), Some("polinrider"));
        let strip = m.remediation.unwrap().config_payload.unwrap();
        assert_eq!(strip.strategy, "strip_after_marker");
    }

    #[test]
    fn parses_cross_ecosystem_bad_packages() {
        let m = PackManifest::from_yaml(
            "id: x\nname: X\nseverity: high\nbad_packages:\n  npm:\n    - {name: \"@common-stack/generate-plugin\", versions: [\"9.0.2-alpha.21\"]}\n  pypi:\n    - {name: graphalgo, confidence: community}\n",
        )
        .unwrap();
        assert_eq!(m.bad_packages["npm"][0].name, "@common-stack/generate-plugin");
        assert_eq!(m.bad_packages["npm"][0].versions, vec!["9.0.2-alpha.21".to_string()]);
        assert_eq!(m.bad_packages["npm"][0].confidence, crate::matchers::Confidence::Vendor);
        assert!(m.bad_packages["pypi"][0].versions.is_empty(), "empty versions = any version");
        assert_eq!(m.bad_packages["pypi"][0].confidence, crate::matchers::Confidence::Community);
    }

    #[test]
    fn bad_packages_defaults_empty() {
        let m = PackManifest::from_yaml("id: x\nname: X\nseverity: high\n").unwrap();
        assert!(m.bad_packages.is_empty());
    }

    #[test]
    fn missing_optional_fields_default_empty() {
        let m = PackManifest::from_yaml("id: x\nname: X\nseverity: high\n").unwrap();
        assert!(m.target_files.is_empty());
        assert!(m.artifacts.is_empty());
        assert!(m.analyzer.is_none());
    }

    #[test]
    fn invalid_yaml_is_error() {
        assert!(PackManifest::from_yaml("id: [unterminated").is_err());
    }
}
