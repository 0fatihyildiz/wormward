use serde::Deserialize;

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
