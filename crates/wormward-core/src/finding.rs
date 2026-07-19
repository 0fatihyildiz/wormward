use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    ContentSignature,
    Artifact,
    GitignoreInjection,
    NpmPackage,
    IocDomain,
    GitReflog,
    Analyzer,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub campaign: String,
    pub severity: Severity,
    pub repo: PathBuf,
    pub file: Option<PathBuf>,
    pub signature_id: String,
    pub kind: FindingKind,
    pub evidence: String,
    pub remediable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_serializes_lowercase() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn finding_kind_serializes_snake_case() {
        let json = serde_json::to_string(&FindingKind::ContentSignature).unwrap();
        assert_eq!(json, "\"content_signature\"");
    }
}
