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
}
