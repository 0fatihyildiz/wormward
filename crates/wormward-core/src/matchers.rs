use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureKind {
    Literal,
    Regex,
    Sha256,
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

pub fn signature_matches(sig: &ContentSignature, content: &str) -> bool {
    match sig.kind {
        SignatureKind::Literal => content.contains(&sig.value),
        SignatureKind::Regex => regex::Regex::new(&sig.value)
            .map(|re| re.is_match(content))
            .unwrap_or(false),
        SignatureKind::Sha256 => sha256_hex(content.as_bytes()).eq_ignore_ascii_case(&sig.value),
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
}
