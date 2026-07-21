//! SARIF 2.1.0 serialization of [`Finding`]s, for upload to the GitHub Security tab (code
//! scanning) or any SARIF-consuming dashboard. A thin projection of our findings — no new state.

use serde_json::json;

use crate::finding::{Finding, Severity};

/// SARIF `level` for a severity. GitHub renders `error` as a failing alert, `warning`/`note` as
/// lower-priority. Critical/High → error, Medium → warning, Low/Info → note.
fn level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Render findings as a SARIF 2.1.0 log document (pretty JSON).
pub fn to_sarif(findings: &[Finding]) -> String {
    let mut rule_ids: Vec<String> = Vec::new();
    for f in findings {
        if !rule_ids.contains(&f.signature_id) {
            rule_ids.push(f.signature_id.clone());
        }
    }
    let rules: Vec<_> = rule_ids.iter().map(|id| json!({ "id": id, "name": id })).collect();
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            // SARIF `artifactLocation.uri` is a URI reference, which uses forward slashes. On
            // Windows `PathBuf::join` yields backslashes, so normalize — otherwise the paths in an
            // upload to GitHub code scanning are malformed and don't map to files in the repo.
            let uri = match &f.file {
                Some(file) => f.repo.join(file).to_string_lossy().replace('\\', "/"),
                None => f.repo.to_string_lossy().replace('\\', "/"),
            };
            json!({
                "ruleId": f.signature_id,
                "level": level(&f.severity),
                "message": { "text": f.evidence },
                "locations": [{
                    "physicalLocation": { "artifactLocation": { "uri": uri } }
                }],
                "properties": { "campaign": f.campaign, "kind": f.kind }
            })
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "wormward",
                "informationUri": "https://github.com/OpenSourceMalware/PolinRider",
                "rules": rules
            }},
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FindingKind, Severity};
    use std::path::PathBuf;

    fn f(sev: Severity, sig: &str) -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: sev,
            repo: PathBuf::from("/r"),
            file: Some(PathBuf::from("postcss.config.mjs")),
            signature_id: sig.into(),
            kind: FindingKind::ContentSignature,
            evidence: "marked".into(),
            remediable: true,
            online: None,
            git_ref: None,
        }
    }

    #[test]
    fn emits_valid_sarif_shape() {
        let out = to_sarif(&[f(Severity::Critical, "primary"), f(Severity::Medium, "ioc-domain:x")]);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "wormward");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        assert_eq!(v["runs"][0]["results"][1]["level"], "warning");
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "/r/postcss.config.mjs"
        );
    }

    #[test]
    fn uri_uses_forward_slashes_for_nested_paths() {
        // A nested repo-relative path must serialize with forward slashes on every OS (SARIF URIs
        // are not OS-native paths); on Windows PathBuf::join would otherwise emit backslashes.
        let mut finding = f(Severity::Critical, "primary");
        finding.repo = PathBuf::from("/r");
        finding.file = Some(PathBuf::from("apps").join("web").join("postcss.config.mjs"));
        let v: serde_json::Value = serde_json::from_str(&to_sarif(&[finding])).unwrap();
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "/r/apps/web/postcss.config.mjs"
        );
    }

    #[test]
    fn empty_findings_still_valid() {
        let v: serde_json::Value = serde_json::from_str(&to_sarif(&[])).unwrap();
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
