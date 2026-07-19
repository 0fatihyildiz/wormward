use wormward_core::{CampaignAnalyzer, Finding, FindingKind, ScannedFile, Severity};

const INJECTION_MARKERS: &[&str] = &["global['!']=", "global['_V']="];
const DECODER_NAMES: &[&str] = &["_$_1e42", "MDy"];
const V1_SEEDS: &[&str] = &["2857687", "2667686"];
const V2_SEEDS: &[&str] = &["1111436", "3896884"];

pub struct PolinriderAnalyzer;

impl PolinriderAnalyzer {
    /// The strongest confirmation reason, or None if the file is not confirmed.
    fn confirm(content: &str) -> Option<String> {
        let has_marker = INJECTION_MARKERS.iter().any(|m| content.contains(m));
        if has_marker {
            if let Some(d) = DECODER_NAMES.iter().find(|d| content.contains(**d)) {
                return Some(format!("injection marker + decoder '{d}'"));
            }
        }
        if content.contains("_$_1e42") && V1_SEEDS.iter().any(|s| content.contains(s)) {
            return Some("decoder '_$_1e42' + v1 seed".to_string());
        }
        if content.contains("MDy") && V2_SEEDS.iter().any(|s| content.contains(s)) {
            return Some("decoder 'MDy' + v2 seed".to_string());
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
                evidence: format!("confirmed obfuscation: {reason}"),
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
    fn confirms_when_marker_and_decoder_present() {
        let f = scanned("export default {};\nglobal['!']='8-270-2';var _$_1e42=[];");
        let out = PolinriderAnalyzer.analyze(&f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, FindingKind::Analyzer);
        assert!(out[0].evidence.contains("_$_1e42"));
    }

    #[test]
    fn confirms_decoder_plus_seed_without_marker() {
        // No global['...'] marker, but decoder + a v1 seed => confirmed.
        let f = scanned("var _$_1e42 = shuffle(2667686);");
        let out = PolinriderAnalyzer.analyze(&f);
        assert_eq!(out.len(), 1);
        assert!(out[0].evidence.contains("v1 seed"));
    }

    #[test]
    fn no_finding_when_only_marker() {
        let f = scanned("global['!']='8-270-2';");
        assert!(PolinriderAnalyzer.analyze(&f).is_empty());
    }

    #[test]
    fn no_finding_on_clean_file() {
        let f = scanned("export default { plugins: {} };");
        assert!(PolinriderAnalyzer.analyze(&f).is_empty());
    }
}
