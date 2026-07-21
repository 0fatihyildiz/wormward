use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use wormward_core::{Finding, FindingKind, OnlineVerdict};

#[derive(Debug, Clone)]
pub struct CheckQuery {
    pub report_type: String,
    pub resource_identifier: String,
    pub ecosystem: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ThreatDetails {
    #[serde(default)]
    pub threat_id: String,
    #[serde(default)]
    pub severity_level: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckResult {
    pub malicious: bool,
    #[serde(default)]
    pub scan_severity: Option<String>,
    #[serde(default)]
    pub osm_url: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub details: Option<ThreatDetails>,
}

#[derive(Debug, thiserror::Error)]
pub enum OsmError {
    #[error("authentication failed (401) — check OSM API token")]
    Auth,
    #[error("rate limited (429)")]
    RateLimited,
    #[error("HTTP error {0}")]
    Http(u16),
    #[error("network error: {0}")]
    Network(String),
    #[error("response decode error: {0}")]
    Decode(String),
}

pub struct OsmClient {
    base_url: String,
    token: String,
}

impl OsmClient {
    pub fn new(base_url: String, token: String) -> Self {
        OsmClient { base_url, token }
    }

    pub fn check(&self, q: &CheckQuery) -> Result<CheckResult, OsmError> {
        let url = format!("{}/check-malicious", self.base_url.trim_end_matches('/'));
        let mut req = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .query("report_type", &q.report_type)
            .query("resource_identifier", &q.resource_identifier);
        if let Some(e) = &q.ecosystem {
            req = req.query("ecosystem", e);
        }
        if let Some(v) = &q.version {
            req = req.query("version", v);
        }
        match req.call() {
            Ok(resp) => {
                let body = resp.into_string().map_err(|e| OsmError::Network(e.to_string()))?;
                serde_json::from_str::<CheckResult>(&body).map_err(|e| OsmError::Decode(e.to_string()))
            }
            Err(ureq::Error::Status(401, _)) => Err(OsmError::Auth),
            // At confirm-only volume (a few deduped lookups per scan) rate limiting is
            // effectively unreachable; the caller surfaces 429 as a per-item warning
            // rather than retrying.
            Err(ureq::Error::Status(429, _)) => Err(OsmError::RateLimited),
            Err(ureq::Error::Status(code, _)) => Err(OsmError::Http(code)),
            Err(ureq::Error::Transport(t)) => Err(OsmError::Network(t.to_string())),
        }
    }
}

/// Result of a pre-install package check.
#[derive(Debug, Clone, Serialize)]
pub struct PackageCheck {
    pub name: String,
    pub version: String,
    pub malicious: bool,
    pub reason: String,
}

/// Pre-install delivery-vector check: fetch an npm package's metadata + entry file from the registry
/// / a per-file CDN (no install, no code execution) and run the FP-safe dropper verdict. Shared by
/// the CLI (`check-package`) and the desktop GUI so they never drift.
pub fn check_npm_package(name: &str) -> Result<PackageCheck, OsmError> {
    check_npm_package_at(name, "https://registry.npmjs.org", "https://unpkg.com")
}

/// Like [`check_npm_package`] but with explicit registry / per-file-CDN base URLs (for testing).
pub fn check_npm_package_at(name: &str, registry: &str, cdn: &str) -> Result<PackageCheck, OsmError> {
    // `name` or `name@version`; a scoped name keeps its leading `@`.
    let (pkg, ver) = match name.rfind('@') {
        Some(i) if i > 0 => (&name[..i], &name[i + 1..]),
        _ => (name, "latest"),
    };
    let meta_url = format!("{registry}/{pkg}/{ver}");
    let body = ureq::get(&meta_url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
        .map_err(|e| OsmError::Network(e.to_string()))?
        .into_string()
        .map_err(|e| OsmError::Decode(e.to_string()))?;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let version = v.get("version").and_then(|x| x.as_str()).unwrap_or(ver).to_string();
    let main = v.get("main").and_then(|x| x.as_str()).unwrap_or("index.js");
    // Fetch just the entry file (no tarball extraction). A 404 → treat as no entry (metadata-only).
    let entry_url = format!("{cdn}/{pkg}@{version}/{main}");
    let entry = ureq::get(&entry_url)
        .timeout(std::time::Duration::from_secs(20))
        .call()
        .ok()
        .and_then(|r| r.into_string().ok());
    let malicious = wormward_core::package_dropper_verdict(&body, entry.as_deref());
    Ok(PackageCheck {
        name: pkg.to_string(),
        version,
        malicious,
        reason: if malicious {
            "dropper behaviour detected pre-install".into()
        } else {
            "no dropper behaviour observed".into()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    fn query(rt: &str, id: &str, eco: Option<&str>) -> CheckQuery {
        CheckQuery {
            report_type: rt.into(),
            resource_identifier: id.into(),
            ecosystem: eco.map(|s| s.into()),
            version: None,
        }
    }

    #[test]
    fn check_npm_package_flags_dropper_and_spares_clean() {
        let reg = MockServer::start();
        let cdn = MockServer::start();
        // Malicious: entry file carries the injected-payload structure.
        reg.mock(|when, then| {
            when.method(GET).path("/evil/latest");
            then.status(200).json_body(serde_json::json!({"version":"1.0.0","main":"index.js"}));
        });
        cdn.mock(|when, then| {
            when.method(GET).path("/evil@1.0.0/index.js");
            then.status(200).body("var _$_1e42=(function(a){return eval(a)})('x');");
        });
        let r = check_npm_package_at("evil", &reg.base_url(), &cdn.base_url()).unwrap();
        assert!(r.malicious, "dropper entry must be flagged");
        // Clean: benign entry, benign scripts.
        reg.mock(|when, then| {
            when.method(GET).path("/good/latest");
            then.status(200).json_body(
                serde_json::json!({"version":"2.0.0","main":"index.js","scripts":{"build":"tsc"}}),
            );
        });
        cdn.mock(|when, then| {
            when.method(GET).path("/good@2.0.0/index.js");
            then.status(200).body("module.exports = function(){ return 1; };");
        });
        let r2 = check_npm_package_at("good", &reg.base_url(), &cdn.base_url()).unwrap();
        assert!(!r2.malicious, "clean package must not be flagged");
        assert_eq!(r2.version, "2.0.0");
    }

    #[test]
    fn parses_malicious_true_response() {
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/check-malicious")
                .query_param("report_type", "package")
                .query_param("resource_identifier", "evil-pkg")
                .header("authorization", "Bearer osm_test");
            then.status(200).json_body(serde_json::json!({
                "malicious": true, "scan_severity": "high", "threat_count": 2,
                "osm_url": "https://opensourcemalware.com/threat/abc",
                "message": null,
                "details": { "threat_id": "abc", "severity_level": "high", "description": "npm worm" }
            }));
        });
        let client = OsmClient::new(server.base_url(), "osm_test".into());
        let res = client.check(&query("package", "evil-pkg", Some("npm"))).unwrap();
        m.assert();
        assert!(res.malicious);
        assert_eq!(res.osm_url, "https://opensourcemalware.com/threat/abc");
        assert_eq!(res.details.unwrap().threat_id, "abc");
    }

    #[test]
    fn parses_not_malicious_response() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/check-malicious");
            then.status(200).json_body(serde_json::json!({ "malicious": false, "threat_count": 0 }));
        });
        let client = OsmClient::new(server.base_url(), "osm_test".into());
        let res = client.check(&query("domain", "example.com", None)).unwrap();
        assert!(!res.malicious);
    }

    #[test]
    fn maps_401_to_auth_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/check-malicious");
            then.status(401);
        });
        let client = OsmClient::new(server.base_url(), "bad".into());
        assert!(matches!(client.check(&query("package", "x", Some("npm"))), Err(OsmError::Auth)));
    }

    #[test]
    fn maps_429_to_rate_limited() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/check-malicious");
            then.status(429);
        });
        let client = OsmClient::new(server.base_url(), "t".into());
        assert!(matches!(client.check(&query("package", "x", Some("npm"))), Err(OsmError::RateLimited)));
    }

    #[test]
    fn malformed_body_is_decode_error() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/check-malicious");
            then.status(200).body("not json");
        });
        let client = OsmClient::new(server.base_url(), "t".into());
        assert!(matches!(client.check(&query("package", "x", Some("npm"))), Err(OsmError::Decode(_))));
    }
}

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

/// Query OSM for each unique enrichable finding, attach verdicts. Errors become warnings;
/// findings without a verdict keep `online: None`. Never fails.
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
mod enrich_tests {
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
            git_ref: None,
            excerpt: None,
        }
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
            git_ref: None,
            excerpt: None,
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
        let mut findings = vec![npm_finding("evilpkg"), npm_finding("evilpkg")];
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
