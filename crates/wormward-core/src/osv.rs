//! Optional bridge to Google's `osv-scanner`: if the binary is on PATH, gate a project's lockfiles
//! against the live OSV database and surface `MAL-*` (malicious-package) advisories as findings —
//! a signal beyond our static `bad_packages` list. Absent binary ⇒ empty (never a hard failure).

use std::path::Path;

/// A malicious-package advisory reported by osv-scanner.
#[derive(Debug, Clone, PartialEq)]
pub struct OsvHit {
    pub package: String,
    pub advisory: String,
}

/// Parse `osv-scanner --format json` output, keeping only `MAL-*` (malicious) advisories — we care
/// about supply-chain malware, not every CVE. Pure (no IO), so it is unit-testable from a fixture.
pub fn parse_osv_json(json: &str) -> Vec<OsvHit> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return out;
    };
    for result in v.get("results").and_then(|r| r.as_array()).into_iter().flatten() {
        for pkg in result.get("packages").and_then(|p| p.as_array()).into_iter().flatten() {
            let name = pkg
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or_default();
            for vuln in pkg.get("vulnerabilities").and_then(|x| x.as_array()).into_iter().flatten() {
                if let Some(id) = vuln.get("id").and_then(|i| i.as_str()) {
                    if id.starts_with("MAL-") {
                        out.push(OsvHit { package: name.to_string(), advisory: id.to_string() });
                    }
                }
            }
        }
    }
    out
}

fn command_exists(bin: &str) -> bool {
    crate::proc::command(bin).arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

/// Recursively gate `dir`'s lockfiles against OSV. Returns empty (with no error) when `osv-scanner`
/// is not installed. osv-scanner exits non-zero when it finds advisories, so stdout is parsed
/// regardless of exit status.
pub fn osv_scan(dir: &Path) -> Vec<OsvHit> {
    if !command_exists("osv-scanner") {
        return Vec::new();
    }
    match crate::proc::command("osv-scanner").args(["--format", "json", "-r"]).arg(dir).output() {
        Ok(o) => parse_osv_json(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

/// True when `osv-scanner` is available (so a caller can warn if `--osv` was requested but the tool
/// is missing, rather than silently finding nothing).
pub fn osv_available() -> bool {
    command_exists("osv-scanner")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_only_mal_advisories() {
        let json = r#"{"results":[{"packages":[
            {"package":{"name":"evil-pkg","ecosystem":"npm"},"vulnerabilities":[
                {"id":"MAL-2026-1234"},{"id":"GHSA-xxxx-yyyy-zzzz"}]},
            {"package":{"name":"safe-pkg"},"vulnerabilities":[{"id":"CVE-2021-0001"}]}
        ]}]}"#;
        let hits = parse_osv_json(json);
        assert_eq!(hits, vec![OsvHit { package: "evil-pkg".into(), advisory: "MAL-2026-1234".into() }]);
    }

    #[test]
    fn parse_empty_or_garbage_is_empty() {
        assert!(parse_osv_json("").is_empty());
        assert!(parse_osv_json("not json").is_empty());
        assert!(parse_osv_json(r#"{"results":[]}"#).is_empty());
    }
}
