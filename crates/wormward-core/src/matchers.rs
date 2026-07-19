use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureKind {
    Literal,
    Regex,
    Sha256,
    EntropyOver,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ContentSignature {
    pub id: String,
    pub kind: SignatureKind,
    pub value: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Shannon entropy (bits/byte) of a byte slice.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn signature_matches(sig: &ContentSignature, content: &str) -> bool {
    match sig.kind {
        SignatureKind::Literal => content.contains(&sig.value),
        SignatureKind::Regex => regex::Regex::new(&sig.value)
            .map(|re| re.is_match(content))
            .unwrap_or(false),
        SignatureKind::Sha256 => sha256_hex(content.as_bytes()).eq_ignore_ascii_case(&sig.value),
        SignatureKind::EntropyOver => {
            // Payloads are appended, so measure the tail's randomness.
            let bytes = content.as_bytes();
            let tail = &bytes[bytes.len().saturating_sub(512)..];
            let threshold: f64 = sig.value.parse().unwrap_or(f64::MAX);
            shannon_entropy(tail) > threshold
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(kind: SignatureKind, value: &str) -> ContentSignature {
        ContentSignature { id: "t".into(), kind, value: value.into() }
    }

    #[test]
    fn literal_matches_substring() {
        let s = sig(SignatureKind::Literal, "rmcej%otb%");
        assert!(signature_matches(&s, "prefix rmcej%otb% suffix"));
        assert!(!signature_matches(&s, "nothing here"));
    }

    #[test]
    fn regex_matches_pattern() {
        let s = sig(SignatureKind::Regex, r"global\['[!_A-Za-z]+'\]=");
        assert!(signature_matches(&s, "var x; global['!']='8-270-2';"));
        assert!(!signature_matches(&s, "console.log('ok')"));
    }

    #[test]
    fn invalid_regex_does_not_match() {
        let s = sig(SignatureKind::Regex, r"(unclosed");
        assert!(!signature_matches(&s, "anything"));
    }

    #[test]
    fn sha256_matches_exact_content() {
        let digest = sha256_hex(b"payload");
        let s = sig(SignatureKind::Sha256, &digest);
        assert!(signature_matches(&s, "payload"));
        assert!(!signature_matches(&s, "other"));
    }

    #[test]
    fn entropy_over_flags_high_entropy_tail() {
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let blob: String = (0..600).map(|i| B64[(i * 37) % B64.len()] as char).collect();
        let s = sig(SignatureKind::EntropyOver, "5.0");
        assert!(signature_matches(&s, &blob));
    }

    #[test]
    fn entropy_over_ignores_plain_config() {
        let s = sig(SignatureKind::EntropyOver, "5.0");
        assert!(!signature_matches(&s, "export default { plugins: { tailwindcss: {} } };\n"));
    }
}
