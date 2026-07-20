//! Export the pack IOC catalog as detection rules for third-party engines: YARA (file content),
//! Sigma (endpoint process-creation), and Suricata (network C2). Lets teams consume wormward's
//! curated indicators without running the binary. Generated deterministically from the packs.

use crate::matchers::SignatureKind;
use crate::pack::Pack;

fn yara_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sig_value<'a>(pack: &'a Pack, id: &str) -> Option<&'a str> {
    pack.manifest
        .content_signatures
        .iter()
        .find(|s| s.id == id && s.kind == SignatureKind::Literal)
        .map(|s| s.value.as_str())
}

/// Obfuscation markers safe to put in an endpoint/process rule — the specific injection
/// fingerprints, not IPs/wallets/hashes (those are network/file indicators).
fn obfuscation_markers(pack: &Pack) -> Vec<String> {
    ["primary", "secondary", "variant-april", "decoder-v1"]
        .iter()
        .filter_map(|id| sig_value(pack, id).map(String::from))
        .collect()
}

/// YARA: one rule per pack, matching any of its literal content signatures.
pub fn to_yara(packs: &[Pack]) -> String {
    let mut out = String::new();
    for pack in packs {
        let literals: Vec<&str> = pack
            .manifest
            .content_signatures
            .iter()
            .filter(|s| s.kind == SignatureKind::Literal)
            .map(|s| s.value.as_str())
            .collect();
        if literals.is_empty() {
            continue;
        }
        let name = format!("wormward_{}", pack.manifest.id.replace('-', "_"));
        out.push_str(&format!(
            "rule {name} {{\n    meta:\n        description = \"{}\"\n        author = \"wormward\"\n    strings:\n",
            yara_escape(&pack.manifest.name)
        ));
        for (i, v) in literals.iter().enumerate() {
            out.push_str(&format!("        $s{i} = \"{}\"\n", yara_escape(v)));
        }
        out.push_str("    condition:\n        any of them\n}\n\n");
    }
    out
}

/// Sigma: an endpoint process-creation rule per pack — `node -e` (or any process) whose command
/// line carries an injection marker.
pub fn to_sigma(packs: &[Pack]) -> String {
    let mut out = String::new();
    for pack in packs {
        let markers = obfuscation_markers(pack);
        if markers.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "title: {} loader process\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains:\n",
            pack.manifest.name
        ));
        for m in &markers {
            // Single-quote YAML scalars; escape embedded single quotes by doubling.
            out.push_str(&format!("      - '{}'\n", m.replace('\'', "''")));
        }
        out.push_str("  condition: selection\nlevel: critical\n---\n");
    }
    out
}

/// Suricata: DNS + IP rules for a pack's C2 domains and hardcoded exfil IPs.
pub fn to_suricata(packs: &[Pack]) -> String {
    let mut out = String::new();
    let mut sid = 1_990_001u32;
    for pack in packs {
        for domain in &pack.manifest.ioc_domains {
            out.push_str(&format!(
                "alert dns any any -> any any (msg:\"wormward {} C2 domain {domain}\"; dns.query; content:\"{domain}\"; nocase; sid:{sid}; rev:1;)\n",
                pack.manifest.id
            ));
            sid += 1;
        }
        for sig in &pack.manifest.content_signatures {
            let is_ip = sig.id.starts_with("c2-exfil-ip") || sig.id == "c2-ethereum-ip";
            if is_ip && sig.kind == SignatureKind::Literal {
                out.push_str(&format!(
                    "alert ip any any -> {} any (msg:\"wormward {} exfil IP {}\"; sid:{sid}; rev:1;)\n",
                    sig.value, pack.manifest.id, sig.value
                ));
                sid += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    // Pure generators tested over a hand-built manifest.
    use crate::finding::Severity;
    use crate::matchers::ContentSignature;
    use crate::pack::{Pack, PackManifest};

    fn pack() -> Pack {
        let manifest = PackManifest {
            id: "demo-x".into(),
            name: "Demo".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec![],
            content_signatures: vec![
                ContentSignature { id: "primary".into(), kind: SignatureKind::Literal, value: r#"("rmcej%otb%",2857687)"#.into() },
                ContentSignature { id: "variant-april".into(), kind: SignatureKind::Literal, value: r#""Cot%3t=shtP""#.into() },
                ContentSignature { id: "c2-exfil-ip-primary".into(), kind: SignatureKind::Literal, value: "136.0.9.8".into() },
            ],
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            bad_packages: Default::default(),
            ioc_domains: vec!["default-configuration.vercel.app".into()],
            analyzer: None,
            remediation: None,
        };
        Pack { manifest, analyzer: None }
    }

    #[test]
    fn yara_escapes_quotes_and_lists_literals() {
        let y = to_yara(&[pack()]);
        assert!(y.contains("rule wormward_demo_x"));
        assert!(y.contains(r#"$s1 = "\"Cot%3t=shtP\"""#), "double-quote value must be escaped: {y}");
        assert!(y.contains("any of them"));
    }

    #[test]
    fn sigma_uses_only_obfuscation_markers() {
        let s = to_sigma(&[pack()]);
        assert!(s.contains("CommandLine|contains"));
        assert!(s.contains("rmcej%otb%"));
        assert!(!s.contains("136.0.9.8"), "IPs must not go into the process rule");
    }

    #[test]
    fn suricata_emits_dns_and_ip_rules() {
        let s = to_suricata(&[pack()]);
        assert!(s.contains("dns.query; content:\"default-configuration.vercel.app\""));
        assert!(s.contains("-> 136.0.9.8 any"));
        assert!(s.contains("sid:1990001"));
    }
}
