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
        out.push_str(&format!(
            "  [{}] {} :: {} :: {} — {}\n",
            severity_tag(&f.severity),
            f.campaign,
            f.repo.display(),
            file,
            f.evidence,
        ));
    }
    out
}

pub fn render_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
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
}
