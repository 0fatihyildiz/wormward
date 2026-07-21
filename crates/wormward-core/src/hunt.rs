//! Self-updating threat intelligence. Detection is already version-independent (it catches every
//! `_$_hex` decoder and every `global.x='N-N…'` tag structurally), so the value here is
//! ATTRIBUTION and SEED EXPANSION: turn each newly-found infection into fresh indicators (new
//! decoder names, new version-tag families, new typosquat package names) that feed `export-iocs`
//! and track the campaign's evolution — the loop that keeps the corpus current without a code change.
//!
//! The extractor is pure and deterministic; the network sweep that feeds it candidates is a thin
//! wrapper the CLI/`hunt` command supplies.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::typosquat::typosquat_of;

/// Version-tag families and decoder identifiers already catalogued — anything NOT here is "new"
/// intelligence worth recording. Kept small and data-driven; the campaign rotates these constantly.
pub const KNOWN_DECODERS: &[&str] = &["1e42", "8e2c", "3317", "46e0", "ccfc", "2d00", "abcd"];
pub const KNOWN_FAMILIES: &[&str] =
    &["5-3", "8-270", "8-2699", "9-4365", "9-0674", "9-5607", "10-590"];

/// New indicators mined from one found payload, relative to a known baseline.
#[derive(Debug, Default, PartialEq)]
pub struct NewIocs {
    /// `_$_<hex>` decoder identifiers not in the baseline.
    pub decoders: Vec<String>,
    /// `global.x='<family>-…'` version-tag family prefixes not in the baseline.
    pub version_families: Vec<String>,
    /// Dependency names (from an embedded package.json-ish blob) that look like typosquats.
    pub packages: Vec<String>,
}

impl NewIocs {
    pub fn is_empty(&self) -> bool {
        self.decoders.is_empty() && self.version_families.is_empty() && self.packages.is_empty()
    }
}

fn decoder_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"_\$_([0-9a-f]{4,})").unwrap())
}
fn family_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // `global.o='5-3-235'` / `global['!']='8-270-2'` -> capture the `<int>-<int>` family prefix.
    R.get_or_init(|| {
        Regex::new(r#"global\s*(?:\.\w+|\[\s*['"][^'"]+['"]\s*\])\s*=\s*['"]([0-9]+-[0-9]+)"#).unwrap()
    })
}
fn pkg_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // dependency names in a package.json-ish blob: `"name": "^x"` keys under a deps object.
    R.get_or_init(|| Regex::new(r#""([@a-z0-9][\w.@/-]{1,80})"\s*:\s*"[\^~>=<*\d]"#).unwrap())
}

/// Mine new decoder names, version-tag families, and typosquat package names from a found payload,
/// excluding anything already in the (lowercased) known sets. Deterministic and side-effect-free.
pub fn extract_new_iocs(
    content: &str,
    known_decoders: &HashSet<String>,
    known_families: &HashSet<String>,
) -> NewIocs {
    let mut decoders = HashSet::new();
    for c in decoder_re().captures_iter(content) {
        let d = c[1].to_string();
        if !known_decoders.contains(&d) {
            decoders.insert(d);
        }
    }
    let mut families = HashSet::new();
    for c in family_re().captures_iter(content) {
        let f = c[1].to_string();
        if !known_families.contains(&f) {
            families.insert(f);
        }
    }
    let mut packages = HashSet::new();
    for c in pkg_re().captures_iter(content) {
        let name = &c[1];
        if typosquat_of(name).is_some() {
            packages.insert(name.to_string());
        }
    }
    let mut d: Vec<String> = decoders.into_iter().collect();
    let mut f: Vec<String> = families.into_iter().collect();
    let mut p: Vec<String> = packages.into_iter().collect();
    d.sort();
    f.sort();
    p.sort();
    NewIocs { decoders: d, version_families: f, packages: p }
}

/// The default baseline as owned lowercase sets (from the `KNOWN_*` constants).
pub fn baseline() -> (HashSet<String>, HashSet<String>) {
    (
        KNOWN_DECODERS.iter().map(|s| s.to_string()).collect(),
        KNOWN_FAMILIES.iter().map(|s| s.to_string()).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_new_decoders_and_families_not_in_baseline() {
        let (kd, kf) = baseline();
        // wave with a KNOWN decoder (1e42) + family (8-270), and a NEW decoder (ffff) + family (11-42)
        let payload = "global.o='8-270-du';var _$_1e42=x;\nglobal['!']='11-42-1';var _$_ffff=y;";
        let got = extract_new_iocs(payload, &kd, &kf);
        assert_eq!(got.decoders, vec!["ffff".to_string()], "only the NEW decoder is reported");
        assert_eq!(got.version_families, vec!["11-42".to_string()], "only the NEW family");
    }

    #[test]
    fn known_iocs_produce_nothing() {
        let (kd, kf) = baseline();
        let payload = "global.o='5-3-235-du';var _$_1e42=(function(){})();";
        assert!(extract_new_iocs(payload, &kd, &kf).is_empty(), "all-known payload yields no new IOCs");
    }

    #[test]
    fn extracts_typosquat_package_from_embedded_manifest() {
        let (kd, kf) = baseline();
        // a package.json-ish blob referencing a typosquat delivery package + a legit one
        let blob = r#"{"dependencies":{"tailwindcss-style-animate":"^1.0.0","react":"^18.0.0"}}"#;
        let got = extract_new_iocs(blob, &kd, &kf);
        assert!(got.packages.contains(&"tailwindcss-style-animate".to_string()));
        assert!(!got.packages.contains(&"react".to_string()), "legit dep is not reported");
    }

    #[test]
    fn clean_content_yields_nothing() {
        let (kd, kf) = baseline();
        let clean = "export default { plugins: {} };\nconst x = require('lodash');\n";
        assert!(extract_new_iocs(clean, &kd, &kf).is_empty());
    }
}
