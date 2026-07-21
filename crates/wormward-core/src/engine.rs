use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use regex::{RegexSet, RegexSetBuilder};

use crate::finding::Severity;
use crate::matchers::{sha256_hex, shannon_entropy, SignatureKind};
use crate::pack::Pack;

#[derive(Debug, Clone, PartialEq)]
pub struct SigHit {
    pub pack_id: String,
    pub signature_id: String,
    pub severity: Severity,
    /// Byte offset of the match in the scanned content, where the matcher has one (literal /
    /// regex). Whole-content kinds (sha256, entropy tail) carry `None`.
    pub offset: Option<usize>,
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
    // Individually-compiled copies of the set's patterns, indexed like `regex_meta`: the set
    // answers WHICH patterns matched, these answer WHERE (for the finding excerpt).
    regexes: Vec<regex::Regex>,
    // lowercase digest -> every signature carrying that digest. Multiple packs can
    // share a digest, so we keep a Vec instead of collapsing to a single meta.
    sha256: HashMap<String, Vec<SigMeta>>,
    // (threshold bits/byte, meta) — fires when the content's last-512-byte tail
    // entropy exceeds the threshold.
    entropy: Vec<(f64, SigMeta)>,
}

impl SignatureEngine {
    pub fn build(packs: &[Pack]) -> SignatureEngine {
        let mut literal_patterns: Vec<String> = Vec::new();
        let mut literal_meta: Vec<SigMeta> = Vec::new();
        let mut regex_patterns: Vec<String> = Vec::new();
        let mut regex_meta: Vec<SigMeta> = Vec::new();
        let mut regexes: Vec<regex::Regex> = Vec::new();
        let mut sha256: HashMap<String, Vec<SigMeta>> = HashMap::new();
        let mut entropy: Vec<(f64, SigMeta)> = Vec::new();

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
                        // Skip patterns that don't compile rather than failing the whole build.
                        // The compiled single regex is kept for match-position lookup.
                        if let Ok(re) = regex::Regex::new(&sig.value) {
                            regex_patterns.push(sig.value.clone());
                            regex_meta.push(meta);
                            regexes.push(re);
                        }
                    }
                    SignatureKind::Sha256 => {
                        sha256.entry(sig.value.to_ascii_lowercase()).or_default().push(meta);
                    }
                    SignatureKind::EntropyOver => {
                        // An unparseable threshold -> f64::MAX, so the signature never fires.
                        let threshold = sig.value.parse().unwrap_or(f64::MAX);
                        entropy.push((threshold, meta));
                    }
                }
            }
        }

        let literal = if literal_patterns.is_empty() {
            None
        } else {
            // A build failure here (`.ok()` -> None) disables literal matching for the
            // whole run; documented rather than left silent. In practice this only fails
            // on pathological input, not on well-formed pack literals.
            AhoCorasick::new(&literal_patterns).ok()
        };
        let regex_set = if regex_patterns.is_empty() {
            None
        } else {
            // Raise the compiled-program size limit so large combined pattern sets still
            // compile (the default is easy to exceed once many packs are loaded). A build
            // failure here (`.ok()` -> None) disables regex matching for the whole run;
            // documented rather than left silent.
            RegexSetBuilder::new(&regex_patterns).size_limit(1 << 24).build().ok()
        };

        SignatureEngine { literal, literal_meta, regex_set, regex_meta, regexes, sha256, entropy }
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
                        offset: Some(m.start()),
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
                    offset: self.regexes[idx].find(content).map(|m| m.start()),
                });
            }
        }

        if !self.sha256.is_empty() {
            let digest = sha256_hex(content.as_bytes());
            if let Some(metas) = self.sha256.get(&digest) {
                // Multiple signatures can share a digest; emit a hit for every one.
                for meta in metas {
                    hits.push(SigHit {
                        pack_id: meta.pack_id.clone(),
                        signature_id: meta.signature_id.clone(),
                        severity: meta.severity.clone(),
                        offset: None, // whole-content match — no position
                    });
                }
            }
        }

        if !self.entropy.is_empty() {
            // Payloads are appended, so measure the tail's randomness (last 512 bytes).
            let bytes = content.as_bytes();
            let tail = &bytes[bytes.len().saturating_sub(512)..];
            let ent = shannon_entropy(tail);
            for (threshold, meta) in &self.entropy {
                if ent > *threshold {
                    hits.push(SigHit {
                        pack_id: meta.pack_id.clone(),
                        signature_id: meta.signature_id.clone(),
                        severity: meta.severity.clone(),
                        offset: None, // tail-statistic match — no single position
                    });
                }
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
        pack_with_id("polinrider", sigs)
    }

    fn pack_with_id(id: &str, sigs: Vec<ContentSignature>) -> Pack {
        let manifest = PackManifest {
            id: id.into(),
            name: "PolinRider".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec![],
            content_signatures: sigs,
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            bad_packages: Default::default(),
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

    fn sig(kind: SignatureKind, id: &str, value: &str) -> ContentSignature {
        ContentSignature { id: id.into(), kind, value: value.into() }
    }

    #[test]
    fn regex_signature_matches() {
        let pack = pack_with(vec![sig(SignatureKind::Regex, "g", r"global\['[!_A-Za-z]+'\]=")]);
        let engine = SignatureEngine::build(&[pack]);
        let hits = engine.scan_content("var x; global['!']='8-270-2';");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].signature_id, "g");
    }

    #[test]
    fn invalid_regex_is_ignored() {
        let pack = pack_with(vec![sig(SignatureKind::Regex, "bad", "(unclosed")]);
        let engine = SignatureEngine::build(&[pack]);
        assert!(engine.scan_content("anything").is_empty());
    }

    #[test]
    fn sha256_signature_matches_exact_content() {
        let digest = crate::matchers::sha256_hex(b"payload");
        let pack = pack_with(vec![sig(SignatureKind::Sha256, "h", &digest)]);
        let engine = SignatureEngine::build(&[pack]);
        assert_eq!(engine.scan_content("payload").len(), 1);
        assert!(engine.scan_content("other").is_empty());
    }

    #[test]
    fn entropy_over_signature_fires_on_high_entropy_tail() {
        let pack = pack_with(vec![sig(SignatureKind::EntropyOver, "ent", "5.0")]);
        let engine = SignatureEngine::build(&[pack]);
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let blob: String = (0..600).map(|i| B64[(i * 37) % B64.len()] as char).collect();
        assert_eq!(engine.scan_content(&blob).len(), 1);
        // Plain config stays below threshold.
        assert!(engine.scan_content("export default { plugins: {} };\n").is_empty());
    }

    #[test]
    fn literal_and_regex_hits_carry_match_offset() {
        // The excerpt shown in results needs WHERE the signature matched, not just that it did.
        let pack = pack_with(vec![lit("primary", "rmcej%otb%")]);
        let engine = SignatureEngine::build(&[pack]);
        let content = "prefix rmcej%otb% suffix";
        let hits = engine.scan_content(content);
        assert_eq!(hits[0].offset, Some(content.find("rmcej%otb%").unwrap()));

        let pack = pack_with(vec![sig(SignatureKind::Regex, "g", r"global\['[!_A-Za-z]+'\]=")]);
        let engine = SignatureEngine::build(&[pack]);
        let content = "var x; global['!']='8-270-2';";
        let hits = engine.scan_content(content);
        assert_eq!(hits[0].offset, Some(content.find("global['!']=").unwrap()));

        // Whole-content kinds have no meaningful position.
        let digest = crate::matchers::sha256_hex(b"payload");
        let pack = pack_with(vec![sig(SignatureKind::Sha256, "h", &digest)]);
        let engine = SignatureEngine::build(&[pack]);
        assert_eq!(engine.scan_content("payload")[0].offset, None);
    }

    #[test]
    fn shared_sha256_digest_emits_hit_per_pack() {
        // Two packs declare the same digest; a matching file must yield one hit each,
        // not a single collapsed hit.
        let digest = crate::matchers::sha256_hex(b"payload");
        let pack_a = pack_with_id("alpha", vec![sig(SignatureKind::Sha256, "h", &digest)]);
        let pack_b = pack_with_id("beta", vec![sig(SignatureKind::Sha256, "h", &digest)]);
        let engine = SignatureEngine::build(&[pack_a, pack_b]);
        let hits = engine.scan_content("payload");
        assert_eq!(hits.len(), 2);
        let mut ids: Vec<&str> = hits.iter().map(|h| h.pack_id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }
}
