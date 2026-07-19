use std::collections::HashMap;

use wormward_core::{Finding, FindingKind, OnlineVerdict};
use wormward_osm::{CheckQuery, CheckResult, OsmClient};

/// (report_type, resource_identifier, ecosystem) for a finding OSM can check.
fn enrichable(f: &Finding) -> Option<(String, String, Option<String>)> {
    match f.kind {
        FindingKind::NpmPackage => f
            .signature_id
            .strip_prefix("npm:")
            .map(|name| ("package".to_string(), name.to_string(), Some("npm".to_string()))),
        FindingKind::IocDomain => f
            .signature_id
            .strip_prefix("ioc-domain:")
            .map(|d| ("domain".to_string(), d.to_string(), None)),
        _ => None,
    }
}

fn verdict_from(res: CheckResult) -> OnlineVerdict {
    let (threat_id, severity) = match res.details {
        Some(d) => (
            Some(d.threat_id).filter(|s| !s.is_empty()),
            res.scan_severity
                .or_else(|| Some(d.severity_level).filter(|s| !s.is_empty())),
        ),
        None => (None, res.scan_severity),
    };
    OnlineVerdict {
        malicious: res.malicious,
        severity,
        osm_url: res.osm_url,
        threat_id,
        message: res.message,
    }
}

/// Query OSM for each unique enrichable finding, attach verdicts. Errors become
/// warnings; findings without a verdict keep `online: None`. Never fails.
pub fn enrich(findings: &mut [Finding], client: &OsmClient) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut cache: HashMap<(String, String, Option<String>), Option<OnlineVerdict>> = HashMap::new();

    for f in findings.iter() {
        if let Some((rt, id, eco)) = enrichable(f) {
            let key = (rt.clone(), id.clone(), eco.clone());
            if cache.contains_key(&key) {
                continue;
            }
            let q = CheckQuery {
                report_type: rt.clone(),
                resource_identifier: id.clone(),
                ecosystem: eco,
                version: None,
            };
            match client.check(&q) {
                Ok(res) => {
                    cache.insert(key, Some(verdict_from(res)));
                }
                Err(e) => {
                    warnings.push(format!("OSM check failed for {rt} '{id}': {e}"));
                    cache.insert(key, None);
                }
            }
        }
    }

    for f in findings.iter_mut() {
        if let Some((rt, id, eco)) = enrichable(f) {
            if let Some(Some(v)) = cache.get(&(rt, id, eco)) {
                f.online = Some(v.clone());
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use std::path::PathBuf;
    use wormward_core::Severity;

    fn npm_finding(pkg: &str) -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: Severity::Critical,
            repo: PathBuf::from("/r"),
            file: Some(PathBuf::from("package.json")),
            signature_id: format!("npm:{pkg}"),
            kind: FindingKind::NpmPackage,
            evidence: "e".into(),
            remediable: false,
            online: None,
        }
    }

    #[test]
    fn attaches_verdict_and_dedupes() {
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/check-malicious")
                .query_param("resource_identifier", "evilpkg");
            then.status(200).json_body(serde_json::json!({
                "malicious": true, "osm_url": "https://osm/x", "threat_count": 1,
                "details": { "threat_id": "t1", "severity_level": "high", "description": "d" }
            }));
        });
        let client = OsmClient::new(server.base_url(), "t".into());
        let mut findings = vec![npm_finding("evilpkg"), npm_finding("evilpkg")]; // duplicate => 1 call
        let warnings = enrich(&mut findings, &client);
        assert!(warnings.is_empty());
        m.assert_hits(1);
        assert_eq!(findings[0].online.as_ref().unwrap().osm_url, "https://osm/x");
        assert_eq!(findings[1].online.as_ref().unwrap().threat_id.as_deref(), Some("t1"));
    }

    #[test]
    fn api_error_becomes_warning_not_panic() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/check-malicious");
            then.status(500);
        });
        let client = OsmClient::new(server.base_url(), "t".into());
        let mut findings = vec![npm_finding("x")];
        let warnings = enrich(&mut findings, &client);
        assert_eq!(warnings.len(), 1);
        assert!(findings[0].online.is_none());
    }

    fn domain_finding(domain: &str) -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: Severity::Medium,
            repo: PathBuf::from("/r"),
            file: Some(PathBuf::from("postcss.config.mjs")),
            signature_id: format!("ioc-domain:{domain}"),
            kind: FindingKind::IocDomain,
            evidence: "e".into(),
            remediable: false,
            online: None,
        }
    }

    #[test]
    fn enriches_domain_finding_as_report_type_domain() {
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/check-malicious")
                .query_param("report_type", "domain")
                .query_param("resource_identifier", "evil.vercel.app");
            then.status(200)
                .json_body(serde_json::json!({ "malicious": true, "osm_url": "https://osm/d" }));
        });
        let client = OsmClient::new(server.base_url(), "t".into());
        let mut findings = vec![domain_finding("evil.vercel.app")];
        let warnings = enrich(&mut findings, &client);
        m.assert();
        assert!(warnings.is_empty());
        assert!(findings[0].online.as_ref().unwrap().malicious);
    }
}
