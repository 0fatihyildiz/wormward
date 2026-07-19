use wormward_core::{CampaignAnalyzer, Finding, FindingKind, ScannedFile, Severity};

const INJECTION_MARKERS: &[&str] = &["global['!']=", "global['_V']="];
const DECODER_NAMES: &[&str] = &["_$_1e42", "MDy"];

pub struct PolinriderAnalyzer;

impl CampaignAnalyzer for PolinriderAnalyzer {
    fn id(&self) -> &str {
        "polinrider"
    }

    fn analyze(&self, file: &ScannedFile) -> Vec<Finding> {
        let content = &file.content;
        let has_marker = INJECTION_MARKERS.iter().any(|m| content.contains(m));
        let decoder = DECODER_NAMES.iter().find(|d| content.contains(**d));

        match (has_marker, decoder) {
            (true, Some(decoder)) => vec![Finding {
                campaign: "polinrider".into(),
                severity: Severity::Critical,
                repo: file.repo.clone(),
                file: Some(file.path.clone()),
                signature_id: "analyzer-confirmed".into(),
                kind: FindingKind::Analyzer,
                evidence: format!(
                    "confirmed obfuscation: injection marker + decoder '{decoder}'"
                ),
                remediable: true,
            }],
            _ => vec![],
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
