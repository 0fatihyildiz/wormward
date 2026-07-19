use std::path::{Path, PathBuf};

use crate::finding::{Finding, FindingKind};
use crate::pack::Pack;

#[derive(Debug, Clone, PartialEq)]
pub enum RemediationAction {
    StripPayload { file: PathBuf, markers: Vec<String> },
    DeleteFile { file: PathBuf },
    RemoveGitignoreLine { file: PathBuf, line: String },
}

impl RemediationAction {
    pub fn target(&self) -> &Path {
        match self {
            RemediationAction::StripPayload { file, .. } => file,
            RemediationAction::DeleteFile { file } => file,
            RemediationAction::RemoveGitignoreLine { file, .. } => file,
        }
    }
}

pub struct RemediationPlan {
    pub actions: Vec<RemediationAction>,
    pub manual: Vec<Finding>,
}

fn strip_markers<'a>(campaign: &str, packs: &'a [Pack]) -> Option<&'a Vec<String>> {
    let pack = packs.iter().find(|p| p.manifest.id == campaign)?;
    let payload = pack.manifest.remediation.as_ref()?.config_payload.as_ref()?;
    if payload.strategy == "strip_after_marker" && !payload.markers.is_empty() {
        Some(&payload.markers)
    } else {
        None
    }
}

/// Derive remediation actions from findings. Working-tree findings only; auto-cleanable
/// kinds become actions (deduped by target), the rest are returned as `manual`.
pub fn plan_remediation(findings: &[Finding], packs: &[Pack]) -> RemediationPlan {
    let mut actions: Vec<RemediationAction> = Vec::new();
    let mut manual: Vec<Finding> = Vec::new();

    fn push_unique(a: RemediationAction, actions: &mut Vec<RemediationAction>) {
        if !actions.contains(&a) {
            actions.push(a);
        }
    }

    for f in findings {
        // Deep-scan findings live on other branches — cannot edit safely here.
        if f.git_ref.is_some() {
            manual.push(f.clone());
            continue;
        }
        let file = match &f.file {
            Some(p) => p.clone(),
            None => {
                manual.push(f.clone());
                continue;
            }
        };
        match f.kind {
            FindingKind::Artifact => {
                push_unique(RemediationAction::DeleteFile { file }, &mut actions)
            }
            FindingKind::GitignoreInjection => {
                let line = f
                    .signature_id
                    .strip_prefix("gitignore:")
                    .unwrap_or("")
                    .to_string();
                push_unique(RemediationAction::RemoveGitignoreLine { file, line }, &mut actions);
            }
            FindingKind::ContentSignature | FindingKind::Analyzer => {
                match strip_markers(&f.campaign, packs) {
                    Some(markers) => push_unique(
                        RemediationAction::StripPayload { file, markers: markers.clone() },
                        &mut actions,
                    ),
                    None => manual.push(f.clone()),
                }
            }
            _ => manual.push(f.clone()),
        }
    }
    RemediationPlan { actions, manual }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::matchers::{ContentSignature, SignatureKind};
    use crate::pack::{Pack, PackManifest, PayloadStrip, Remediation};

    fn polinrider_pack() -> Pack {
        let manifest = PackManifest {
            id: "polinrider".into(),
            name: "PolinRider".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec!["postcss.config.mjs".into()],
            content_signatures: vec![ContentSignature {
                id: "primary".into(),
                kind: SignatureKind::Literal,
                value: "rmcej%otb%".into(),
            }],
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            ioc_domains: vec![],
            analyzer: None,
            remediation: Some(Remediation {
                config_payload: Some(PayloadStrip {
                    strategy: "strip_after_marker".into(),
                    markers: vec!["global['!']=".into()],
                }),
            }),
        };
        Pack { manifest, analyzer: None }
    }

    fn finding(kind: FindingKind, file: Option<&str>, sig: &str) -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: Severity::Critical,
            repo: PathBuf::from("/r"),
            file: file.map(PathBuf::from),
            signature_id: sig.into(),
            kind,
            evidence: "e".into(),
            remediable: true,
            online: None,
            git_ref: None,
        }
    }

    #[test]
    fn artifact_becomes_delete() {
        let plan = plan_remediation(
            &[finding(FindingKind::Artifact, Some("temp_auto_push.bat"), "artifact:temp_auto_push.bat")],
            &[polinrider_pack()],
        );
        assert_eq!(plan.actions, vec![RemediationAction::DeleteFile { file: PathBuf::from("temp_auto_push.bat") }]);
    }

    #[test]
    fn content_signature_becomes_strip_with_pack_markers() {
        let plan = plan_remediation(
            &[finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary")],
            &[polinrider_pack()],
        );
        assert_eq!(
            plan.actions,
            vec![RemediationAction::StripPayload {
                file: PathBuf::from("postcss.config.mjs"),
                markers: vec!["global['!']=".into()],
            }]
        );
    }

    #[test]
    fn gitignore_injection_becomes_remove_line() {
        let plan = plan_remediation(
            &[finding(FindingKind::GitignoreInjection, Some(".gitignore"), "gitignore:config.bat")],
            &[polinrider_pack()],
        );
        assert_eq!(
            plan.actions,
            vec![RemediationAction::RemoveGitignoreLine {
                file: PathBuf::from(".gitignore"),
                line: "config.bat".into(),
            }]
        );
    }

    #[test]
    fn npm_and_deep_and_no_strategy_are_manual() {
        let mut npm = finding(FindingKind::NpmPackage, Some("package.json"), "npm:x");
        npm.remediable = false;
        let mut deep = finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary");
        deep.git_ref = Some("evil".into());
        let mut no_strategy = finding(FindingKind::ContentSignature, Some("f.js"), "x");
        no_strategy.campaign = "shai-hulud".into();
        let plan = plan_remediation(&[npm, deep, no_strategy], &[polinrider_pack()]);
        assert!(plan.actions.is_empty());
        assert_eq!(plan.manual.len(), 3);
    }

    #[test]
    fn duplicate_findings_on_one_file_dedupe() {
        let plan = plan_remediation(
            &[
                finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary"),
                finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), "xor-key-primary"),
            ],
            &[polinrider_pack()],
        );
        assert_eq!(plan.actions.len(), 1);
    }
}
