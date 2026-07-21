//! Takedown-oriented IOC export. Where `rules.rs` emits *detection* rules (YARA/Sigma/Suricata),
//! this emits *disruption* artifacts: the machine-readable indicator set, an npm abuse-report draft
//! (the malicious packages — getting them removed kills the delivery vector), and a STIX 2.1 bundle
//! for sharing with the ecosystem. Pure generators over pack data, deterministic so they can be
//! diffed and tested; timestamps are a fixed constant, not wall-clock, for reproducibility.

use std::collections::BTreeSet;

use crate::matchers::{sha256_hex, SignatureKind};
use crate::pack::Pack;

/// Fixed STIX `created`/`modified` stamp — deterministic output (no wall-clock).
const STIX_STAMP: &str = "2026-07-21T00:00:00.000Z";

/// The disruption-relevant indicators pulled from the loaded packs, deduped and sorted.
pub struct Iocs {
    pub campaigns: Vec<String>,
    /// `(ecosystem, package-name, malicious-versions)`. An EMPTY version list means the package is
    /// wholly malicious (report for removal). A non-empty list means an otherwise-legit package with
    /// specific compromised versions (e.g. `axios`) — report the VERSIONS, never removal of the name.
    pub packages: Vec<(String, String, Vec<String>)>,
    /// C2 / bootstrap domains.
    pub domains: Vec<String>,
    /// On-chain wallets and exfil IPs (the `c2-*` literal signatures).
    pub addresses: Vec<String>,
    /// Dropped-artifact filenames (propagation scripts, etc.).
    pub artifacts: Vec<String>,
}

impl Iocs {
    /// Packages that are wholly malicious (every version) — safe to report for removal.
    pub fn removable_packages(&self) -> impl Iterator<Item = &(String, String, Vec<String>)> {
        self.packages.iter().filter(|(_, _, v)| v.is_empty())
    }
    /// Otherwise-legit packages with specific compromised versions — report the versions only.
    pub fn versioned_packages(&self) -> impl Iterator<Item = &(String, String, Vec<String>)> {
        self.packages.iter().filter(|(_, _, v)| !v.is_empty())
    }
}

/// Collect every disruption-relevant IOC from the loaded packs.
pub fn collect_iocs(packs: &[Pack]) -> Iocs {
    let mut campaigns = BTreeSet::new();
    let mut packages = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut artifacts = BTreeSet::new();
    for p in packs {
        let m = &p.manifest;
        campaigns.insert(m.id.clone());
        for name in &m.bad_npm_packages {
            packages.insert(("npm".to_string(), name.clone(), Vec::new()));
        }
        for (eco, bads) in &m.bad_packages {
            for b in bads {
                packages.insert((eco.clone(), b.name.clone(), b.versions.clone()));
            }
        }
        for d in &m.ioc_domains {
            domains.insert(d.clone());
        }
        for a in &m.artifacts {
            artifacts.insert(a.path.clone());
        }
        // On-chain / IP C2 constants carry `c2-` signature ids; other literals (xor keys, decoder
        // names, whole-file hashes) are detection internals, not takedown targets.
        for s in &m.content_signatures {
            if s.id.starts_with("c2-") && matches!(s.kind, SignatureKind::Literal) {
                addresses.insert(s.value.clone());
            }
        }
    }
    Iocs {
        campaigns: campaigns.into_iter().collect(),
        packages: packages.into_iter().collect(),
        domains: domains.into_iter().collect(),
        addresses: addresses.into_iter().collect(),
        artifacts: artifacts.into_iter().collect(),
    }
}

/// A flat, grouped, machine-readable indicator dump (the canonical feed).
pub fn to_ioc_list(packs: &[Pack]) -> String {
    let i = collect_iocs(packs);
    let mut out = String::new();
    out.push_str(&format!("# wormward IOC export — campaigns: {}\n", i.campaigns.join(", ")));
    out.push_str("\n[packages]\n");
    for (eco, name, versions) in &i.packages {
        if versions.is_empty() {
            out.push_str(&format!("{eco}:{name}\n"));
        } else {
            out.push_str(&format!("{eco}:{name}@{}\n", versions.join(",")));
        }
    }
    out.push_str("\n[domains]\n");
    for d in &i.domains {
        out.push_str(&format!("{d}\n"));
    }
    out.push_str("\n[addresses]\n");
    for a in &i.addresses {
        out.push_str(&format!("{a}\n"));
    }
    out.push_str("\n[artifacts]\n");
    for a in &i.artifacts {
        out.push_str(&format!("{a}\n"));
    }
    out
}

/// A ready-to-submit npm abuse-report draft. Reporting these packages for removal is the single
/// highest-leverage disruption: it cuts the delivery vector at the source.
pub fn to_npm_report(packs: &[Pack]) -> String {
    let i = collect_iocs(packs);
    let mut out = String::new();
    out.push_str("Subject: Malware — coordinated typosquat/supply-chain packages\n\n");
    out.push_str(&format!(
        "The following npm packages are part of the {} supply-chain campaign(s). They ship an \
         obfuscated dropper that injects a self-propagating payload into a victim project's build \
         config and source files, and resolve C2 via on-chain dead-drops.\n\n",
        i.campaigns.join(", ")
    ));
    out.push_str("Wholly-malicious packages (remove — every version is malicious):\n");
    for (eco, name, _) in i.removable_packages().filter(|(e, ..)| e == "npm") {
        let _ = eco;
        out.push_str(&format!("- https://www.npmjs.com/package/{name}\n"));
    }
    // A legit package (e.g. `axios`) with specific compromised versions must NOT be reported for
    // removal — only the malicious versions are actionable (unpublish/deprecate those releases).
    let versioned: Vec<_> = i.versioned_packages().filter(|(e, ..)| e == "npm").collect();
    if !versioned.is_empty() {
        out.push_str("\nCompromised versions of otherwise-legit packages (do NOT remove the package \
                      — deprecate/unpublish only these versions):\n");
        for (_, name, versions) in versioned {
            out.push_str(&format!("- {name}: {}\n", versions.join(", ")));
        }
    }
    out.push_str("\nAssociated C2 domains (for correlation):\n");
    for d in &i.domains {
        out.push_str(&format!("- {d}\n"));
    }
    out
}

/// Deterministic UUID-shaped id from a value's sha256 (first 32 hex → 8-4-4-4-12), so STIX ids are
/// stable across runs.
fn stable_uuid(seed: &str) -> String {
    let h = sha256_hex(seed.as_bytes());
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn stix_indicator(pattern_type: &str, pattern: &str, name: &str) -> String {
    let id = stable_uuid(pattern);
    format!(
        "    {{\n      \"type\": \"indicator\",\n      \"spec_version\": \"2.1\",\n      \
         \"id\": \"indicator--{id}\",\n      \"created\": \"{STIX_STAMP}\",\n      \
         \"modified\": \"{STIX_STAMP}\",\n      \"name\": {name},\n      \
         \"pattern_type\": \"{pattern_type}\",\n      \"pattern\": {pattern}\n    }}"
    )
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A minimal STIX 2.1 bundle of `indicator` objects for the packages, domains, and addresses —
/// a standard format for sharing the campaign IOCs with the ecosystem.
pub fn to_stix(packs: &[Pack]) -> String {
    let i = collect_iocs(packs);
    let mut objs: Vec<String> = Vec::new();
    for (eco, name, versions) in &i.packages {
        let vsuffix = if versions.is_empty() { String::new() } else { format!("@{}", versions.join(",")) };
        let pat = json_str(&format!("[software:name = '{name}' AND software:vendor = '{eco}']"));
        objs.push(stix_indicator(
            "stix",
            &pat,
            &json_str(&format!("malicious package {eco}:{name}{vsuffix}")),
        ));
    }
    for d in &i.domains {
        let pat = json_str(&format!("[domain-name:value = '{d}']"));
        objs.push(stix_indicator("stix", &pat, &json_str(&format!("C2 domain {d}"))));
    }
    for a in &i.addresses {
        let pat = json_str(&format!("[x-onchain:value = '{a}']"));
        objs.push(stix_indicator("stix", &pat, &json_str(&format!("C2 address {a}"))));
    }
    let bundle_id = stable_uuid(&i.campaigns.join(","));
    format!(
        "{{\n  \"type\": \"bundle\",\n  \"id\": \"bundle--{bundle_id}\",\n  \"objects\": [\n{}\n  ]\n}}",
        objs.join(",\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::matchers::{ContentSignature, SignatureKind};
    use crate::pack::{Artifact, BadPackage, Pack, PackManifest};
    use std::collections::BTreeMap;

    fn pack() -> Pack {
        let mut bad = BTreeMap::new();
        bad.insert(
            "npm".to_string(),
            vec![
                BadPackage { name: "evil-typosquat".into(), versions: vec![], confidence: Default::default() },
                // A legit package with a compromised version (axios-bluenoroff shape).
                BadPackage {
                    name: "axios".into(),
                    versions: vec!["1.7.2".into()],
                    confidence: Default::default(),
                },
            ],
        );
        let manifest = PackManifest {
            id: "polinrider".into(),
            name: "PolinRider".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec![],
            content_signatures: vec![
                ContentSignature {
                    id: "c2-tron-primary".into(),
                    kind: SignatureKind::Literal,
                    value: "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP".into(),
                },
                ContentSignature {
                    id: "xor-key".into(),
                    kind: SignatureKind::Literal,
                    value: "not-an-address".into(),
                },
            ],
            artifacts: vec![Artifact {
                path: "temp_auto_push.bat".into(),
                label: "propagation".into(),
            }],
            gitignore_injections: vec![],
            bad_npm_packages: vec!["tailwindcss-style-animate".into()],
            bad_packages: bad,
            ioc_domains: vec!["vscode-settings-bootstrap.vercel.app".into()],
            analyzer: None,
            remediation: None,
        };
        Pack { manifest, analyzer: None }
    }

    #[test]
    fn collect_pulls_the_right_iocs() {
        let i = collect_iocs(&[pack()]);
        assert!(i.removable_packages().any(|(_, n, _)| n == "tailwindcss-style-animate"));
        assert!(i.removable_packages().any(|(_, n, _)| n == "evil-typosquat"));
        // axios is version-pinned, NOT removable.
        assert!(i.versioned_packages().any(|(_, n, v)| n == "axios" && v == &["1.7.2".to_string()]));
        assert!(!i.removable_packages().any(|(_, n, _)| n == "axios"));
        assert!(i.domains.contains(&"vscode-settings-bootstrap.vercel.app".to_string()));
        // c2- signature is a takedown address; xor-key is NOT.
        assert!(i.addresses.contains(&"TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP".to_string()));
        assert!(!i.addresses.contains(&"not-an-address".to_string()));
        assert!(i.artifacts.contains(&"temp_auto_push.bat".to_string()));
    }

    #[test]
    fn npm_report_never_asks_to_remove_a_version_pinned_legit_package() {
        let r = to_npm_report(&[pack()]);
        assert!(r.contains("npmjs.com/package/tailwindcss-style-animate"), "wholly-malicious listed");
        assert!(r.contains("vscode-settings-bootstrap.vercel.app"), "C2 domain listed");
        // axios must NOT be in the removal list, only in the version-deprecation section.
        assert!(!r.contains("npmjs.com/package/axios"), "must not ask to remove legit axios");
        assert!(r.contains("axios: 1.7.2"), "axios's compromised version is reported instead");
    }

    #[test]
    fn stix_is_deterministic_valid_json_shape() {
        let a = to_stix(&[pack()]);
        let b = to_stix(&[pack()]);
        assert_eq!(a, b, "STIX output must be deterministic");
        assert!(a.contains("\"type\": \"bundle\""));
        assert!(a.contains("\"type\": \"indicator\""));
        assert!(a.contains("tailwindcss-style-animate"));
        // parses as JSON
        serde_json::from_str::<serde_json::Value>(&a).expect("STIX must be valid JSON");
    }

    #[test]
    fn ioc_list_is_grouped() {
        let l = to_ioc_list(&[pack()]);
        assert!(l.contains("[packages]"));
        assert!(l.contains("npm:tailwindcss-style-animate"));
        assert!(l.contains("[domains]"));
        assert!(l.contains("[addresses]"));
    }
}
