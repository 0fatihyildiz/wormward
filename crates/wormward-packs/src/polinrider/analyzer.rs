use std::sync::OnceLock;

use regex::Regex;
use wormward_core::{CampaignAnalyzer, Finding, FindingKind, ScannedFile, Severity};

fn marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Version-tag marker (`global.o='5-3-235-du'` / `global['!']='8-270-2'`) OR the
    // ESM re-entry shim (`global['r']=require` / `global.m=module`) — the shim is the
    // strongest marker-independent tell, present in both variants. Bracket keys and string
    // values may be single- OR double-quoted (some variants use `global["!"]="10"`), matching
    // the quote-agnostic remediation strip marker.
    RE.get_or_init(|| {
        Regex::new(
            r#"global(\.\w+|\[('[^']+'|"[^"]+")\])\s*=\s*(?:require\b|module\b|'[\w-]+'|"[\w-]+")"#,
        )
        .unwrap()
    })
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
        let has_decoder = decoder_re().is_match(content)
            || content.contains("MDy")
            || content.contains("createRequire(import.meta.url")
            // Structural string-shuffle tell: the decoder builds strings via a
            // String.fromCharCode(127) sentinel, present even when the decoder is renamed.
            || content.contains("String.fromCharCode(127)");
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
    fn confirms_double_quoted_bracket_marker_variant() {
        // The guide documents double-quoted `global["..."]` variants; our strip marker already
        // handles both quote styles, so the detection marker must too (single-quote-only was a
        // blind spot that let a double-quoted variant evade analyzer confirmation).
        let out = PolinriderAnalyzer
            .analyze(&scanned("export default {};\nglobal[\"!\"]=\"10\";var _$_1e42=[];"));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confirms_fromcharcode_decoder_variant() {
        // A renamed decoder (no `_$_` name) is still caught via the String.fromCharCode(127)
        // string-shuffle tell the guide calls out as the structural fingerprint.
        let out = PolinriderAnalyzer
            .analyze(&scanned("export default {};\nglobal.i='5-3-168';var y=String.fromCharCode(127);"));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confirms_esm_shim_variant() {
        // require/module ESM shim + decoder → confirm structurally.
        let out = PolinriderAnalyzer.analyze(&scanned(
            "export default {};\nglobal['r']=require;global['m']=module;var _$_8e2c=[];",
        ));
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
