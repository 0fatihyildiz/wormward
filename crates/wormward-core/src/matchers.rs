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

// Note: per-signature matching lives in `engine::SignatureEngine` (single-pass over
// all packs). The former standalone `signature_matches` was a drift-prone duplicate
// and has been removed; entropy/sha256/regex/literal semantics are owned by the engine.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_zero_for_empty_and_uniform() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    }

    #[test]
    fn entropy_high_for_diverse_bytes() {
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let blob: Vec<u8> = (0..600).map(|i| B64[(i * 37) % B64.len()]).collect();
        assert!(shannon_entropy(&blob) > 5.0);
    }

    #[test]
    fn sha256_hex_is_stable_and_distinct() {
        assert_eq!(sha256_hex(b"payload"), sha256_hex(b"payload"));
        assert_ne!(sha256_hex(b"payload"), sha256_hex(b"other"));
    }
}
