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
    Capability,
    /// A GitHub account-persistence finding (over-privileged token, injected SSH key, rogue
    /// self-hosted runner, exfil webhook, …) — surfaced by the read-only account audit.
    AccountAudit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnlineVerdict {
    pub malicious: bool,
    pub severity: Option<String>,
    pub osm_url: String,
    pub threat_id: Option<String>,
    pub message: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<OnlineVerdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
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

    #[test]
    fn capability_kind_serializes() {
        let json = serde_json::to_string(&FindingKind::Capability).unwrap();
        assert_eq!(json, "\"capability\"");
    }

    #[test]
    fn account_audit_kind_serializes() {
        let json = serde_json::to_string(&FindingKind::AccountAudit).unwrap();
        assert_eq!(json, "\"account_audit\"");
    }

    fn sample_finding(online: Option<OnlineVerdict>) -> Finding {
        Finding {
            campaign: "c".into(),
            severity: Severity::High,
            repo: PathBuf::from("/r"),
            file: None,
            signature_id: "s".into(),
            kind: FindingKind::NpmPackage,
            evidence: "e".into(),
            remediable: false,
            online,
            git_ref: None,
        }
    }

    #[test]
    fn online_field_omitted_when_none() {
        let json = serde_json::to_string(&sample_finding(None)).unwrap();
        assert!(!json.contains("online"));
    }

    #[test]
    fn online_field_present_when_set() {
        let f = sample_finding(Some(OnlineVerdict {
            malicious: true,
            severity: Some("high".into()),
            osm_url: "https://osm/x".into(),
            threat_id: Some("t".into()),
            message: None,
        }));
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(v["online"]["malicious"], true);
    }

    #[test]
    fn git_ref_omitted_when_none() {
        let json = serde_json::to_string(&sample_finding(None)).unwrap();
        assert!(!json.contains("git_ref"));
    }

    #[test]
    fn git_ref_present_when_set() {
        let mut f = sample_finding(None);
        f.git_ref = Some("origin/evil".into());
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(v["git_ref"], "origin/evil");
    }
}
