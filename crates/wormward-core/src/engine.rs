use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use regex::RegexSet;

use crate::finding::Severity;
use crate::matchers::{sha256_hex, SignatureKind};
use crate::pack::Pack;

#[derive(Debug, Clone, PartialEq)]
pub struct SigHit {
    pub pack_id: String,
    pub signature_id: String,
    pub severity: Severity,
}

struct SigMeta {
    pack_id: String,
    signature_id: String,
    severity: Severity,
}

pub struct SignatureEngine {
    literal: Option<AhoCorasick>,
    literal_meta: Vec<SigMeta>,
    regex_set: Option<RegexSet>,
    regex_meta: Vec<SigMeta>,
    sha256: HashMap<String, SigMeta>, // lowercase digest -> meta
}

impl SignatureEngine {
    pub fn build(packs: &[Pack]) -> SignatureEngine {
        let mut literal_patterns: Vec<String> = Vec::new();
        let mut literal_meta: Vec<SigMeta> = Vec::new();
        let mut regex_patterns: Vec<String> = Vec::new();
        let mut regex_meta: Vec<SigMeta> = Vec::new();
        let mut sha256: HashMap<String, SigMeta> = HashMap::new();

        for pack in packs {
            let m = &pack.manifest;
            for sig in &m.content_signatures {
                let meta = SigMeta {
                    pack_id: m.id.clone(),
                    signature_id: sig.id.clone(),
                    severity: m.severity.clone(),
                };
                match sig.kind {
                    SignatureKind::Literal => {
                        literal_patterns.push(sig.value.clone());
                        literal_meta.push(meta);
                    }
                    SignatureKind::Regex => {
                        // Skip patterns that don't compile (mirrors signature_matches).
                        if regex::Regex::new(&sig.value).is_ok() {
                            regex_patterns.push(sig.value.clone());
                            regex_meta.push(meta);
                        }
                    }
                    SignatureKind::Sha256 => {
                        sha256.insert(sig.value.to_ascii_lowercase(), meta);
                    }
                }
            }
        }

        let literal = if literal_patterns.is_empty() {
            None
        } else {
            AhoCorasick::new(&literal_patterns).ok()
        };
        let regex_set = if regex_patterns.is_empty() {
            None
        } else {
            RegexSet::new(&regex_patterns).ok()
        };

        SignatureEngine { literal, literal_meta, regex_set, regex_meta, sha256 }
    }

    pub fn scan_content(&self, content: &str) -> Vec<SigHit> {
        let mut hits = Vec::new();
        let mut seen_literal = vec![false; self.literal_meta.len()];

        if let Some(ac) = &self.literal {
            for m in ac.find_overlapping_iter(content) {
                let idx = m.pattern().as_usize();
                if !seen_literal[idx] {
                    seen_literal[idx] = true;
                    let meta = &self.literal_meta[idx];
                    hits.push(SigHit {
                        pack_id: meta.pack_id.clone(),
                        signature_id: meta.signature_id.clone(),
                        severity: meta.severity.clone(),
                    });
                }
            }
        }

        if let Some(set) = &self.regex_set {
            for idx in set.matches(content).into_iter() {
                let meta = &self.regex_meta[idx];
                hits.push(SigHit {
                    pack_id: meta.pack_id.clone(),
                    signature_id: meta.signature_id.clone(),
                    severity: meta.severity.clone(),
                });
            }
        }

        if !self.sha256.is_empty() {
            let digest = sha256_hex(content.as_bytes());
            if let Some(meta) = self.sha256.get(&digest) {
                hits.push(SigHit {
                    pack_id: meta.pack_id.clone(),
                    signature_id: meta.signature_id.clone(),
                    severity: meta.severity.clone(),
                });
            }
        }

        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::matchers::{ContentSignature, SignatureKind};
    use crate::pack::{Pack, PackManifest};

    fn pack_with(sigs: Vec<ContentSignature>) -> Pack {
        let manifest = PackManifest {
            id: "polinrider".into(),
            name: "PolinRider".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec![],
            content_signatures: sigs,
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            ioc_domains: vec![],
            analyzer: None,
            remediation: None,
        };
        Pack { manifest, analyzer: None }
    }

    fn lit(id: &str, value: &str) -> ContentSignature {
        ContentSignature { id: id.into(), kind: SignatureKind::Literal, value: value.into() }
    }

    #[test]
    fn literal_hits_report_pack_and_signature() {
        let pack = pack_with(vec![lit("primary", "rmcej%otb%"), lit("other", "ZZZ")]);
        let engine = SignatureEngine::build(&[pack]);
        let hits = engine.scan_content("prefix rmcej%otb% suffix");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pack_id, "polinrider");
        assert_eq!(hits[0].signature_id, "primary");
        assert_eq!(hits[0].severity, Severity::Critical);
    }

    #[test]
    fn each_literal_signature_reported_at_most_once() {
        let pack = pack_with(vec![lit("primary", "aa")]);
        let engine = SignatureEngine::build(&[pack]);
        // "aa" occurs twice (overlapping); still one hit for the signature.
        assert_eq!(engine.scan_content("aaaa").len(), 1);
    }
}
