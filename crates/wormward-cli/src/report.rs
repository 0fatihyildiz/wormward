use wormward_core::{ScanReport, Severity};

fn severity_tag(sev: &Severity) -> &'static str {
    match sev {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

pub fn render_text(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("Scanned {} git repositories.\n", report.repos_scanned));
    if report.findings.is_empty() {
        out.push_str("No infections found.\n");
        return out;
    }
    out.push_str(&format!("{} finding(s):\n", report.findings.len()));
    for f in &report.findings {
        let file = f
            .file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string());
        // file:line when the finding knows where it matched.
        let file = match &f.excerpt {
            Some(e) => format!("{file}:{}", e.line),
            None => file,
        };
        let branch = f
            .git_ref
            .as_deref()
            .map(|r| format!(" (branch: {r})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  [{}] {} :: {} :: {}{} — {}\n",
            severity_tag(&f.severity),
            f.campaign,
            f.repo.display(),
            file,
            branch,
            f.evidence,
        ));
        if let Some(e) = &f.excerpt {
            out.push_str(&format!("      └ {}\n", e.text));
        }
        if let Some(v) = &f.online {
            let status = if v.malicious { "OSM: MALICIOUS" } else { "OSM: not flagged" };
            let link = if v.osm_url.is_empty() {
                String::new()
            } else {
                format!(" — {}", v.osm_url)
            };
            let note = v
                .message
                .as_deref()
                .filter(|m| !m.is_empty())
                .map(|m| format!(" ({m})"))
                .unwrap_or_default();
            out.push_str(&format!("      └ {status}{link}{note}\n"));
        }
    }
    out
}

pub fn render_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

pub fn render_github_text(outcomes: &[wormward_github::pipeline::RepoOutcome], applied: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!("Checked {} repo(s).\n", outcomes.len()));
    for o in outcomes {
        out.push_str(&format!(
            "\n{} — {} finding(s){}\n",
            o.repo.full_name,
            o.findings.len(),
            o.error.as_ref().map(|e| format!(" [error: {e}]")).unwrap_or_default(),
        ));
        // Enumerate each finding (with its branch for deep-scan hits) so cross-branch
        // detections are actionable in text mode, not just a count.
        for f in &o.findings {
            let file = f
                .file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string());
            let branch = f
                .git_ref
                .as_deref()
                .map(|r| format!(" (branch: {r})"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  [{}] {} :: {}{} — {}\n",
                severity_tag(&f.severity),
                f.campaign,
                file,
                branch,
                f.evidence,
            ));
        }
        for a in &o.actions {
            out.push_str(&format!("  action: {a}\n"));
        }
        if !o.pushed.is_empty() {
            out.push_str(&format!("  pushed: {}\n", o.pushed.join(", ")));
        }
    }
    if !applied {
        out.push_str("\n(dry-run; pass --fix --yes to remediate, --push --yes to force-push)\n");
    }
    out
}

pub fn render_github_json(outcomes: &[wormward_github::pipeline::RepoOutcome]) -> String {
    serde_json::to_string_pretty(outcomes).unwrap_or_else(|_| "[]".into())
}

/// Render the read-only account-persistence audit findings as their own section. They are
/// advisory (`remediable = false`): each line says what to review/rotate, never an auto-fix.
pub fn render_audit_text(findings: &[wormward_core::Finding]) -> String {
    let mut out = String::new();
    out.push_str("\n== Account audit (read-only; advisory) ==\n");
    if findings.is_empty() {
        out.push_str("  no account findings.\n");
        return out;
    }
    for f in findings {
        out.push_str(&format!(
            "  [{}] {} — {}\n",
            severity_tag(&f.severity),
            f.repo.display(), // "github:account" or "github:owner/repo"
            f.evidence,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use wormward_core::{Finding, FindingKind};

    fn report_with_finding() -> ScanReport {
        ScanReport {
            repos_scanned: 3,
            findings: vec![Finding {
                campaign: "polinrider".into(),
                severity: Severity::Critical,
                repo: PathBuf::from("/home/u/proj"),
                file: Some(PathBuf::from("postcss.config.mjs")),
                signature_id: "primary".into(),
                kind: FindingKind::ContentSignature,
                evidence: "content signature 'primary' matched".into(),
                remediable: true,
                online: None,
                git_ref: None,
                excerpt: None,
            }],
        }
    }

    #[test]
    fn renders_findings() {
        let text = render_text(&report_with_finding());
        assert!(text.contains("Scanned 3 git repositories."));
        assert!(text.contains("[CRITICAL]"));
        assert!(text.contains("polinrider"));
        assert!(text.contains("postcss.config.mjs"));
    }

    #[test]
    fn renders_clean() {
        let report = ScanReport { repos_scanned: 5, findings: vec![] };
        let text = render_text(&report);
        assert!(text.contains("No infections found."));
    }

    #[test]
    fn renders_json_with_findings_array() {
        let json = render_json(&report_with_finding());
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["repos_scanned"], 3);
        assert_eq!(value["findings"][0]["campaign"], "polinrider");
        assert_eq!(value["findings"][0]["severity"], "critical");
        assert_eq!(value["findings"][0]["kind"], "content_signature");
    }

    #[test]
    fn renders_online_verdict_line() {
        let mut r = report_with_finding();
        r.findings[0].online = Some(wormward_core::OnlineVerdict {
            malicious: true,
            severity: Some("high".into()),
            osm_url: "https://osm/x".into(),
            threat_id: Some("t".into()),
            message: None,
        });
        let text = render_text(&r);
        assert!(text.contains("OSM: MALICIOUS"));
        assert!(text.contains("https://osm/x"));
    }

    #[test]
    fn renders_branch_when_git_ref_set() {
        let mut r = report_with_finding();
        r.findings[0].git_ref = Some("origin/evil".into());
        assert!(render_text(&r).contains("(branch: origin/evil)"));
    }

    #[test]
    fn renders_account_audit_section() {
        let findings = vec![Finding {
            campaign: "account-audit".into(),
            severity: Severity::High,
            repo: PathBuf::from("github:account"),
            file: None,
            signature_id: "account:token-scope".into(),
            kind: FindingKind::AccountAudit,
            evidence: "over-privileged scopes (admin:public_key) — rotate first".into(),
            remediable: false,
            online: None,
            git_ref: None,
            excerpt: None,
        }];
        let text = render_audit_text(&findings);
        assert!(text.contains("Account audit"));
        assert!(text.contains("[HIGH]"));
        assert!(text.contains("github:account"));
        assert!(text.contains("admin:public_key"));
        assert!(render_audit_text(&[]).contains("no account findings"));
    }

    #[test]
    fn github_text_enumerates_findings_with_branch() {
        use wormward_github::pipeline::RepoOutcome;
        use wormward_github::RepoRef;
        let f = Finding {
            campaign: "polinrider".into(),
            severity: Severity::Critical,
            repo: PathBuf::from("/tmp/me__proj"),
            file: Some(PathBuf::from("postcss.config.mjs")),
            signature_id: "primary".into(),
            kind: FindingKind::ContentSignature,
            evidence: "content signature 'primary' matched".into(),
            remediable: true,
            online: None,
            git_ref: Some("origin/evil".into()),
            excerpt: None,
        };
        let outcomes = vec![RepoOutcome {
            repo: RepoRef {
                full_name: "me/proj".into(),
                clone_url: "https://x/r.git".into(),
                default_branch: "main".into(),
                fork: false,
            },
            findings: vec![f],
            actions: vec![],
            pushed: vec![],
            error: None,
            manual_review: false,
        }];
        let text = render_github_text(&outcomes, false);
        // The individual finding is enumerated, not just counted, and carries its branch.
        assert!(text.contains("[CRITICAL]"));
        assert!(text.contains("postcss.config.mjs"));
        assert!(text.contains("(branch: origin/evil)"));
        assert!(text.contains("content signature 'primary' matched"));
    }
}
