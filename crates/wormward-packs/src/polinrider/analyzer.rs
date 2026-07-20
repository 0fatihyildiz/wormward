use std::sync::OnceLock;

use regex::Regex;
use wormward_core::{CampaignAnalyzer, Finding, FindingKind, ScannedFile, Severity};

fn marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Version-tag marker (`global.o='5-3-235-du'` / `global['!']='8-270-2'`) OR the
    // ESM re-entry shim (`global['r']=require` / `global.m=module`) — the shim is the
    // strongest marker-independent tell, present in both variants. Bracket keys and string
    // values may be single- OR double-quoted (some variants use `global["!"]="10"`), matching
    // the quote-agnostic remediation strip marker.
    RE.get_or_init(|| {
        Regex::new(
            r#"global(\.\w+|\[('[^']+'|"[^"]+")\])\s*=\s*(?:require\b|module\b|'[\w-]+'|"[\w-]+")"#,
        )
        .unwrap()
    })
}

fn decoder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Family decoder-name pattern: `_$_1e42`, `_$_8e2c`, …
    RE.get_or_init(|| Regex::new(r"_\$_[0-9a-f]{4,}").unwrap())
}

/// A shuffle SEED bound to its structure: a string literal, then the seed, then the closing paren
/// of a call — i.e. an IIFE argument like `("rmcej%otb%",2857687)` or `(...})('str',3899501)`. A
/// bare 6-7 digit number is NEVER a seed, so digit runs inside integrity/tarball hashes cannot
/// masquerade as one.
fn seed_arg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"['"][^'"]*['"]\s*,\s*\d{6,7}\s*\)"#).unwrap())
}

/// An arrow function WITH A BODY (`=> {`). Part of the JS-code veto — an arrow-function decoder is
/// executable code; `=>` alone (e.g. in a comment) is not required to match without the block.
fn arrow_body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"=>\s*\{").unwrap())
}

/// HARD VETO: at least one token a working string-shuffle + eval decoder CANNOT exist without.
///
/// The list is deliberately COMPREHENSIVE, not just the two or three most common forms, so an
/// attacker who reads this cannot simply swap `eval(`→`Function(` or `charAt`→`.slice(` to slip
/// past it: any functional decoder must (a) derive/rearrange a string — needing at least one
/// char-access / string method — AND (b) execute it — needing at least one code-generation sink.
/// A "decoder" that uses NONE of these cannot decode or run anything; it is not a decoder.
///
/// Meanwhile inert files — lockfiles (`yarn.lock`, `package-lock.json`, `pnpm-lock.yaml`), tarball
/// SHA / integrity base64, pnpm `*-index.json` — contain paths, URLs, hashes, versions and sizes,
/// and NONE of these parenthesized code tokens. So requiring one kills those false positives while
/// leaving true-positive coverage of real payloads intact. Note this is only ONE of several layers:
/// the exact-literal signatures, the capability behavioral engine, and the padding/entropy
/// signatures fire independently of this veto.
fn has_js_code_token(content: &str) -> bool {
    // Code-generation / execution sinks — the derived string has to run somehow.
    const SINKS: &[&str] = &[
        "eval(",
        "atob(",
        "Function(", // covers `new Function(` and `(0,Function)(`
        "setTimeout(",
        "setInterval(",
        "import(",
        "require(",
        "execScript(",
        "constructor(",
    ];
    // Char access / string-derivation methods — a shuffle decoder has to touch characters.
    const STRING_OPS: &[&str] = &[
        "function(",
        "function (",
        "String.fromCharCode",
        "fromCodePoint",
        "charCodeAt",
        "charAt",
        "codePointAt",
        ".split(",
        ".join(",
        ".slice(",
        ".substr",
        ".substring",
        ".replace(",
        ".reverse(",
        ".map(",
        ".reduce(",
        ".at(",
        "unescape(",
        "decodeURIComponent(",
    ];
    arrow_body_re().is_match(content)
        || SINKS.iter().any(|t| content.contains(t))
        || STRING_OPS.iter().any(|t| content.contains(t))
}

pub struct PolinriderAnalyzer;

impl PolinriderAnalyzer {
    /// Confirm the obfuscation fingerprint regardless of dot/bracket notation or the
    /// specific decoder name / seed — so new variants are caught, not just known literals.
    fn confirm(content: &str) -> Option<String> {
        // HARD VETO (highest-leverage precision fix): a string-shuffle decoder is impossible
        // without executable JS. Without a code token, suppress regardless of decoder-like
        // substrings or digit runs — this is what stops lockfiles / CAS metadata (SHA hashes,
        // integrity base64, tarball URLs) from confirming.
        if !has_js_code_token(content) {
            return None;
        }
        let has_marker = marker_re().is_match(content);
        // The actual string-shuffle decoder. These are obfuscation tells with no legitimate use:
        // the `_$_xxxx` family name, the MDy sentinel, or the String.fromCharCode(127) shuffle
        // (present even when the decoder is renamed).
        let strong_decoder = decoder_re().is_match(content)
            || content.contains("MDy")
            || content.contains("String.fromCharCode(127)");
        // The ESM re-entry shim PolinRider injects so its payload can call require(). This is
        // ALSO a legitimate CJS/ESM interop pattern in normal bundles, so it only counts toward
        // confirmation alongside an injection marker — never on its own, and never as the
        // "decoder" in the marker-less branch (that FP'd on legit npx-cached bundles).
        let has_shim = content.contains("createRequire(import.meta.url");
        // Proximity: the seed must be an IIFE argument, never a bare number.
        let has_seed = seed_arg_re().is_match(content);
        if has_marker && (strong_decoder || has_shim) {
            return Some("obfuscation: injection marker + decoder".to_string());
        }
        if strong_decoder && has_seed {
            return Some("obfuscation: decoder + shuffle seed".to_string());
        }
        None
    }
}

impl CampaignAnalyzer for PolinriderAnalyzer {
    fn id(&self) -> &str {
        "polinrider"
    }

    fn analyze(&self, file: &ScannedFile) -> Vec<Finding> {
        match Self::confirm(&file.content) {
            Some(reason) => vec![Finding {
                campaign: "polinrider".into(),
                severity: Severity::Critical,
                repo: file.repo.clone(),
                file: Some(file.path.clone()),
                signature_id: "analyzer-confirmed".into(),
                kind: FindingKind::Analyzer,
                evidence: format!("confirmed {reason}"),
                remediable: true,
                online: None,
                git_ref: None,
            }],
            None => vec![],
        }
    }
}

/// The PolinRider obfuscation fingerprint as a reusable predicate over arbitrary text — a
/// process command line, a cache file, a config blob — returning the confirmation reason or
/// `None`. Shared with the file analyzer (`PolinriderAnalyzer::analyze`) so machine-level checks
/// (`wormward doctor`) can never drift from the repo scanner's detection.
pub fn polinrider_fingerprint(text: &str) -> Option<String> {
    PolinriderAnalyzer::confirm(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scanned(content: &str) -> ScannedFile {
        ScannedFile {
            repo: PathBuf::from("/repo"),
            path: PathBuf::from("postcss.config.mjs"),
            content: content.into(),
        }
    }

    #[test]
    fn confirms_bracket_variant() {
        // Real payloads carry the decoder IIFE (`function(`), so the fixtures do too — the veto
        // requires a JS-code token, which every genuine string-shuffle decoder has.
        let out = PolinriderAnalyzer.analyze(&scanned(
            "export default {};\nglobal['!']='8-270-2';var _$_1e42=(function(a,b){return a})('x',7);",
        ));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, FindingKind::Analyzer);
    }

    #[test]
    fn confirms_dot_notation_variant() {
        // The modus.builders variant: dot marker + _$_8e2c decoder.
        let out = PolinriderAnalyzer.analyze(&scanned(
            "export default {};\nglobal.o='5-3-235-du';var _$_8e2c=(function(a,b){return a})('x',7);",
        ));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confirms_double_quoted_bracket_marker_variant() {
        // The guide documents double-quoted `global["..."]` variants; our strip marker already
        // handles both quote styles, so the detection marker must too (single-quote-only was a
        // blind spot that let a double-quoted variant evade analyzer confirmation).
        let out = PolinriderAnalyzer.analyze(&scanned(
            "export default {};\nglobal[\"!\"]=\"10\";var _$_1e42=(function(a,b){return a})('x',7);",
        ));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confirms_fromcharcode_decoder_variant() {
        // A renamed decoder (no `_$_` name) is still caught via the String.fromCharCode(127)
        // string-shuffle tell the guide calls out as the structural fingerprint.
        let out = PolinriderAnalyzer
            .analyze(&scanned("export default {};\nglobal.i='5-3-168';var y=String.fromCharCode(127);"));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confirms_esm_shim_variant() {
        // require/module ESM shim + decoder → confirm structurally.
        let out = PolinriderAnalyzer.analyze(&scanned(
            "export default {};\nglobal['r']=require;global['m']=module;var _$_8e2c=(function(a,b){return a})('x',7);",
        ));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn confirms_decoder_plus_seed() {
        // Decoder name + a shuffle IIFE whose args are a string + the seed. The seed is bound to
        // the IIFE structure (proximity), never a bare number.
        let out = PolinriderAnalyzer
            .analyze(&scanned("var _$_8e2c=(function(a,b){return a})(\"seedstr\",3899501);"));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn true_positive_shuffle_iife_with_code_token_preserved() {
        // Acceptance: decoder name + shuffle IIFE with a string+seed arg + a JS code token.
        let payload = "export default {};\n\
             var _$_1e42=(function(a,y){var p=a.length;return a})(\"rmcej%otb%\",2857687);";
        assert_eq!(PolinriderAnalyzer.analyze(&scanned(payload)).len(), 1);
    }

    #[test]
    fn true_positive_dot_marker_with_fromcharcode_or_eval_preserved() {
        // Acceptance: dot marker + decoder + a char-manipulation / eval sink.
        let payload =
            "global.o='5-3-235-du';var _$_8e2c=eval(atob('Zm9v'));var z=String.fromCharCode(120);";
        assert_eq!(PolinriderAnalyzer.analyze(&scanned(payload)).len(), 1);
    }

    #[test]
    fn no_finding_when_only_marker() {
        assert!(PolinriderAnalyzer.analyze(&scanned("global['!']='8-270-2';")).is_empty());
    }

    #[test]
    fn no_finding_on_clean_file() {
        assert!(PolinriderAnalyzer.analyze(&scanned("export default { plugins: {} };")).is_empty());
    }

    #[test]
    fn veto_resists_evasion_via_uncommon_tokens() {
        // Anti-evasion: a payload that dodges the obvious tokens (function(/eval/fromCharCode) still
        // cannot avoid EVERY string-op + exec sink — a working shuffle-decoder here uses
        // .slice/.reverse + Function(). Decoder name + IIFE-arg seed + code tokens → still confirmed.
        let payload =
            "var _$_9f3a=g(a.slice(0).reverse());var run=Function(_$_9f3a)(\"s\",1234567);";
        assert_eq!(PolinriderAnalyzer.analyze(&scanned(payload)).len(), 1);
    }

    #[test]
    fn no_finding_on_yarn_lock_metadata() {
        // A real yarn.lock: integrity base64 that happens to contain the "MDy" decoder sentinel and
        // 6-7 digit runs inside tarball/integrity hashes — but ZERO executable-JS tokens. The
        // "decoder + shuffle seed" matcher must NOT fire on inert hash metadata.
        let lock = "# yarn lockfile v1\n\nbetter-opn@^3.0.0:\n  version \"3.0.2\"\n  \
             resolved \"https://registry.yarnpkg.com/better-opn/-/better-opn-3.0.2.tgz#a1b2c3d4\"\n  \
             integrity sha512-MDy/EXAMPLEbase64/hash/1234567/paddingAbCd==\n";
        assert!(PolinriderAnalyzer.analyze(&scanned(lock)).is_empty(), "yarn.lock must not confirm");
    }

    #[test]
    fn no_finding_on_pnpm_index_json_metadata() {
        // pnpm store `<hash>-index.json`: file paths + integrity hashes + sizes, not code.
        let idx = "{\"name\":\"foo\",\"files\":{\"index.js\":\
             {\"integrity\":\"sha512-MDyabc0123456789def+/==\",\"size\":987654}}}";
        assert!(
            PolinriderAnalyzer.analyze(&scanned(idx)).is_empty(),
            "pnpm index.json must not confirm"
        );
    }

    #[test]
    fn does_not_confirm_legit_esm_createrequire_bundle() {
        // Regression (found by dogfooding `doctor` on the npx cache): a legit ESM bundle commonly
        // does createRequire(import.meta.url) for CJS interop and carries large numeric constants.
        // Without an injection marker OR a real string-shuffle decoder, the createRequire shim
        // alone must NOT confirm — it is a legitimate pattern, not obfuscation.
        let out = PolinriderAnalyzer.analyze(&scanned(
            "import { createRequire } from 'module';\n\
             const require = createRequire(import.meta.url);\n\
             const BUILD = 1234567;\nexport default {};",
        ));
        assert!(out.is_empty(), "createRequire + a numeric constant is not an infection: {out:?}");
    }
}
