use std::sync::OnceLock;

use regex::Regex;
use wormward_core::{CampaignAnalyzer, Finding, FindingKind, ScannedFile, Severity};

fn marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Matches both `global.o='5-3-235-du'` (dot) and `global['!']='8-270-2'` (bracket).
    RE.get_or_init(|| Regex::new(r"global(\.\w+|\['[^']+'\])\s*=\s*'[\w-]+'").unwrap())
}

fn decoder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Family decoder-name pattern: `_$_1e42`, `_$_8e2c`, …
    RE.get_or_init(|| Regex::new(r"_\$_[0-9a-f]{4,}").unwrap())
}

fn seed_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{6,7}\b").unwrap())
}

pub struct PolinriderAnalyzer;

impl PolinriderAnalyzer {
    /// Confirm the obfuscation fingerprint regardless of dot/bracket notation or the
    /// specific decoder name / seed — so new variants are caught, not just known literals.
    fn confirm(content: &str) -> Option<String> {
        let has_marker = marker_re().is_match(content);
        let has_decoder = decoder_re().is_match(content) || content.contains("MDy");
        let has_seed = seed_re().is_match(content);
        if has_marker && has_decoder {
            return Some("obfuscation: injection marker + decoder".to_string());
        }
        if has_decoder && has_seed {
            return Some("obfuscation: decoder + shuffle seed".to_string());
        }
        None
    }
}

impl CampaignAnalyzer for PolinriderAnalyzer {
    fn id(&self) -> &str {
        "polinrider"
    }

    fn analyze(&self, file: &ScannedFile) -> Vec<Finding> {
        match Self::confirm(&file.content) {
            Some(reason) => vec![Finding {
                campaign: "polinrider".into(),
                severity: Severity::Critical,
                repo: file.repo.clone(),
                file: Some(file.path.clone()),
                signature_id: "analyzer-confirmed".into(),
                kind: FindingKind::Analyzer,
                evidence: format!("confirmed {reason}"),
                remediable: true,
                online: None,
                git_ref: None,
            }],
            None => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scanned(content: &str) -> ScannedFile {
        ScannedFile {
            repo: PathBuf::from("/repo"),
            path: PathBuf::from("postcss.config.mjs"),
            content: content.into(),
        }
    }

    #[test]
    fn confirms_bracket_variant() {
        let out = PolinriderAnalyzer
            .analyze(&scanned("export default {};\nglobal['!']='8-270-2';var _$_1e42=[];"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, FindingKind::Analyzer);
    }

    #[test]
    fn confirms_dot_notation_variant() {
        // The modus.builders variant: dot marker + _$_8e2c decoder.
        let out = PolinriderAnalyzer
            .analyze(&scanned("export default {};\nglobal.o='5-3-235-du';var _$_8e2c=[];"));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confirms_decoder_plus_seed() {
        let out = PolinriderAnalyzer.analyze(&scanned("var _$_8e2c = shuffle(3899501);"));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn no_finding_when_only_marker() {
        assert!(PolinriderAnalyzer.analyze(&scanned("global['!']='8-270-2';")).is_empty());
    }

    #[test]
    fn no_finding_on_clean_file() {
        assert!(PolinriderAnalyzer.analyze(&scanned("export default { plugins: {} };")).is_empty());
    }
}
