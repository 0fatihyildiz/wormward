# Remediation, GitHub Mode, and Faster Search — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Wormward from detection-only into a tool that also remediates worm infections locally and across a GitHub account, with a faster multi-signature scan engine.

**Architecture:** A `SignatureEngine` compiled once from all packs replaces the per-signature scan loop; a new `remediate` module plans and applies fixes (working-tree by default, cross-branch history rewrite behind a flag); a new `wormward-github` crate enumerates and orchestrates account-wide clone/scan/fix/push. `scan` stays read-only and unchanged.

**Tech Stack:** Rust 2021 workspace; `aho-corasick` + `regex` (matching), `ignore` (walker), `ureq` + `serde_json` (GitHub API), `git` CLI + `git filter-repo` (history rewrite), `rayon` (parallelism), `clap` (CLI). Tests: `tempfile`, `httpmock`.

## Global Constraints

- Rust edition `2021`; workspace versions from `Cargo.toml` `[workspace.package]` (version `0.1.0`, license `MIT`).
- Reuse existing workspace deps by `{ workspace = true }`; add new deps to `[workspace.dependencies]` first, then reference them.
- `scan`, `list-packs`, `check` subcommands and the JSON `Finding` shape MUST remain unchanged (behavior-preserving).
- Exit codes for every command: `0` clean/fully remediated, `1` infections found or remaining, `2` error.
- Destructive operations default to dry-run. Working-tree writes require `--yes`; branch history rewrite requires `--rewrite-branches` **and** `--yes`; remote force-push requires `--push` **and** `--yes`.
- Never blank a file: if a payload-strip marker is absent, downgrade to manual-review and leave the file untouched.
- The file walker MUST NOT honor `.gitignore`/hidden rules (the worm hides artifacts via `.gitignore`); it still prunes `.git` and `node_modules`.
- Commit-message style matches the repo: plain imperative ("Add …", "Refactor …"), no `feat:` prefix.
- Run `cargo test --workspace` green before each commit.

## File Structure

**wormward-core** (`crates/wormward-core/src/`)
- `engine.rs` — *new*. `SignatureEngine`: builds Aho-Corasick + RegexSet + sha256 tables from packs; `scan_content` returns hits.
- `scanner.rs` — *modify*. `scan_files` rewritten to read each file once and use `SignatureEngine`; keeps IOC/analyzer/artifact/gitignore/npm behavior.
- `walk.rs` — *modify*. `discover_repos` / `walk_repo_files` move to the `ignore` crate (ignore rules disabled).
- `remediate.rs` — *new*. `plan`, `apply_working_tree`, action/outcome types.
- `rewrite.rs` — *new*. `plan_branch_rewrites`, `apply_branch_rewrites`, filter-repo blob-callback generation.
- `lib.rs` — *modify*. Register + re-export new modules.

**wormward-github** (`crates/wormward-github/`) — *new crate*
- `Cargo.toml`, `src/lib.rs` — `RepoRef`, `RepoHost`, `GitHubHost`, auth resolution.
- `src/pipeline.rs` — per-repo `run` (clone → scan → fix → push).

**wormward-cli** (`crates/wormward-cli/src/`)
- `main.rs` — *modify*. Add `Fix` and `Github` subcommands.
- `report.rs` — *modify*. Render remediation plans/outcomes (text + JSON).

**Workspace**
- `Cargo.toml` — *modify*. Add `aho-corasick`, `ignore` to `[workspace.dependencies]`; add `wormward-github` to members.

---
## Phase 1 — Faster search engine

### Task 1: Add deps and a literal `SignatureEngine`

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]`)
- Modify: `crates/wormward-core/Cargo.toml`
- Create: `crates/wormward-core/src/engine.rs`
- Modify: `crates/wormward-core/src/lib.rs`

**Interfaces:**
- Consumes: `Pack`, `PackManifest`, `ContentSignature`, `SignatureKind`, `Severity`, `sha256_hex`.
- Produces:
  - `pub struct SigHit { pub pack_id: String, pub signature_id: String, pub severity: Severity }`
  - `impl SignatureEngine { pub fn build(packs: &[Pack]) -> SignatureEngine; pub fn scan_content(&self, content: &str) -> Vec<SigHit> }`

- [ ] **Step 1: Add workspace deps**

In `Cargo.toml` under `[workspace.dependencies]` add:

```toml
aho-corasick = "1"
ignore = "0.4"
```

In `crates/wormward-core/Cargo.toml` under `[dependencies]` add:

```toml
aho-corasick = { workspace = true }
ignore = { workspace = true }
```

- [ ] **Step 2: Write the failing test**

Create `crates/wormward-core/src/engine.rs`:

```rust
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p wormward-core engine::tests::literal_hits_report_pack_and_signature`
Expected: FAIL — `SignatureEngine` not found.

- [ ] **Step 4: Implement the literal engine**

Add above the `#[cfg(test)]` block in `engine.rs`:

```rust
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
```

Register the module in `crates/wormward-core/src/lib.rs`:

```rust
pub mod engine;
```

and add to the re-export block:

```rust
pub use engine::{SigHit, SignatureEngine};
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p wormward-core engine`
Expected: PASS (both engine tests).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/wormward-core/Cargo.toml crates/wormward-core/src/engine.rs crates/wormward-core/src/lib.rs
git commit -m "Add SignatureEngine for single-pass multi-signature matching"
```

---

### Task 2: Cover regex and sha256 signatures in the engine

**Files:**
- Modify: `crates/wormward-core/src/engine.rs` (tests only — impl already handles these)

**Interfaces:**
- Consumes/Produces: unchanged from Task 1.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `engine.rs`:

```rust
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
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p wormward-core engine`
Expected: PASS (impl from Task 1 already handles regex/sha256).

- [ ] **Step 3: Commit**

```bash
git add crates/wormward-core/src/engine.rs
git commit -m "Test regex and sha256 paths of SignatureEngine"
```

---

### Task 3: Rewrite `scan_files` to use the engine (behavior-preserving)

**Files:**
- Modify: `crates/wormward-core/src/scanner.rs:120-180` (the `scan_files` function)

**Interfaces:**
- Consumes: `SignatureEngine`, `SigHit`, existing `build_globset`, `check_artifacts`, `check_gitignore`, `check_npm`.
- Produces: `scan_files(repo, files, packs)` unchanged signature and findings; internally reads each file once.

- [ ] **Step 1: Add a binary/large-file guard test**

Add to the `tests` module in `scanner.rs`:

```rust
#[test]
fn binary_file_is_not_content_matched() {
    let tmp = TempDir::new().unwrap();
    let repo = make_repo(&tmp);
    // Target-named file, signature present, but contains a NUL byte early.
    let mut bytes = b"\x00".to_vec();
    bytes.extend_from_slice(b"rmcej%otb%");
    std::fs::write(repo.join("postcss.config.mjs"), bytes).unwrap();
    assert!(scan_repo(&repo, &[literal_pack()]).is_empty());
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p wormward-core scanner::tests::binary_file_is_not_content_matched`
Expected: FAIL — the current code flags it (read_to_string succeeds; NUL is valid UTF-8).

- [ ] **Step 3: Rewrite `scan_files`**

Replace the body of `scan_files` in `scanner.rs` with:

```rust
const MAX_CONTENT_BYTES: usize = 5 * 1024 * 1024;

fn looks_binary(content: &str) -> bool {
    content.as_bytes().iter().take(8192).any(|&b| b == 0)
}

/// Apply all file-based pack checks to a file source. Findings have git_ref = None;
/// the deep-scan caller stamps the branch ref afterward.
pub fn scan_files(repo: &Path, files: &dyn RepoFiles, packs: &[Pack]) -> Vec<Finding> {
    let engine = SignatureEngine::build(packs);
    // Per-pack target globsets, indexed alongside `packs`.
    let globsets: Vec<GlobSet> =
        packs.iter().map(|p| build_globset(&p.manifest.target_files)).collect();

    let mut findings = Vec::new();

    for rel in files.paths() {
        // Which packs target this file?
        let targeting: Vec<usize> = globsets
            .iter()
            .enumerate()
            .filter(|(_, g)| g.is_match(rel))
            .map(|(i, _)| i)
            .collect();
        if targeting.is_empty() {
            continue;
        }
        let content = match files.read(rel) {
            Some(c) => c,
            None => continue,
        };
        if content.len() > MAX_CONTENT_BYTES || looks_binary(&content) {
            continue;
        }
        let targeting_ids: std::collections::HashSet<&str> =
            targeting.iter().map(|&i| packs[i].manifest.id.as_str()).collect();

        // Content signatures via the shared engine, gated by target membership.
        for hit in engine.scan_content(&content) {
            if !targeting_ids.contains(hit.pack_id.as_str()) {
                continue;
            }
            findings.push(Finding {
                campaign: hit.pack_id.clone(),
                severity: hit.severity.clone(),
                repo: repo.to_path_buf(),
                file: Some(rel.clone()),
                signature_id: hit.signature_id.clone(),
                kind: FindingKind::ContentSignature,
                evidence: format!("content signature '{}' matched", hit.signature_id),
                remediable: true,
                online: None,
                git_ref: None,
            });
        }

        // IOC domains + analyzer stay per-pack (small lists; not worth the engine).
        for &i in &targeting {
            let pack = &packs[i];
            for domain in &pack.manifest.ioc_domains {
                if content.contains(domain) {
                    findings.push(Finding {
                        campaign: pack.manifest.id.clone(),
                        severity: Severity::Medium,
                        repo: repo.to_path_buf(),
                        file: Some(rel.clone()),
                        signature_id: format!("ioc-domain:{domain}"),
                        kind: FindingKind::IocDomain,
                        evidence: format!("C2 indicator domain '{domain}' referenced"),
                        remediable: false,
                        online: None,
                        git_ref: None,
                    });
                }
            }
            if let Some(analyzer) = &pack.analyzer {
                let scanned = ScannedFile {
                    repo: repo.to_path_buf(),
                    path: rel.clone(),
                    content: content.clone(),
                };
                findings.extend(analyzer.analyze(&scanned));
            }
        }
    }

    for pack in packs {
        findings.extend(check_artifacts(repo, files, pack));
        findings.extend(check_gitignore(repo, files, pack));
        findings.extend(check_npm(repo, files, pack));
    }
    findings
}
```

Add the engine import near the top of `scanner.rs`:

```rust
use crate::engine::SignatureEngine;
```

- [ ] **Step 4: Run the full core test suite (parity check)**

Run: `cargo test -p wormward-core`
Expected: PASS — all existing scanner tests (`flags_infected_config_file`, `non_target_file_ignored`, `detects_config_in_subdirectory`, `flags_ioc_domain_even_without_content_signature`, `analyzer_findings_are_included`, deep-scan tests, etc.) plus the new binary test.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/scanner.rs
git commit -m "Refactor scan_files onto SignatureEngine with binary/size skip"
```

---

### Task 4: Move the walker to the `ignore` crate (ignore rules disabled)

**Files:**
- Modify: `crates/wormward-core/src/walk.rs`

**Interfaces:**
- Consumes: `ignore::WalkBuilder`, `ignore::WalkState`.
- Produces: `discover_repos(root) -> Vec<PathBuf>` and `walk_repo_files(repo) -> Vec<PathBuf>` — unchanged signatures.

- [ ] **Step 1: Add a test that gitignored malware is still walked**

Add to the `tests` module in `walk.rs`:

```rust
#[test]
fn walk_includes_gitignored_files() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    touch(&repo.join(".gitignore"));
    fs::write(repo.join(".gitignore"), "config.bat\n").unwrap();
    touch(&repo.join("config.bat")); // hidden by .gitignore, must still be walked
    touch(&repo.join(".git/config"));

    let files = walk_repo_files(repo);
    let names: Vec<String> = files
        .iter()
        .map(|p| p.strip_prefix(repo).unwrap().to_string_lossy().replace('\\', "/"))
        .collect();
    assert!(names.contains(&"config.bat".to_string()));
    assert!(!names.iter().any(|n| n.starts_with(".git/")));
}
```

- [ ] **Step 2: Run it to verify it fails to compile/behaves**

Run: `cargo test -p wormward-core walk::tests::walk_includes_gitignored_files`
Expected: PASS with current walkdir (walkdir ignores `.gitignore`). This test is a **regression guard** for the swap — it must stay green after Step 3. Note it now, keep it after.

- [ ] **Step 3: Replace walkdir with `ignore`**

Replace the top of `walk.rs` (imports + both functions) with:

```rust
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ignore::{WalkBuilder, WalkState};

fn is_pruned_dir(name: &str) -> bool {
    name == ".git" || name == "node_modules"
}

fn base_builder(root: &Path) -> WalkBuilder {
    let mut b = WalkBuilder::new(root);
    // Walk everything: the worm hides artifacts via .gitignore, so ignore rules
    // must NOT filter our view. We only use `ignore` for its fast parallel walker.
    b.git_ignore(false)
        .git_exclude(false)
        .git_global(false)
        .ignore(false)
        .hidden(false)
        .parents(false)
        .standard_filters(false);
    b
}

pub fn discover_repos(root: &Path) -> Vec<PathBuf> {
    let found = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let mut b = base_builder(root);
    // Prune node_modules (never a repo root we care about); detect .git in-callback.
    b.filter_entry(|e| e.file_name() != "node_modules");
    b.build_parallel().run(|| {
        let found = Arc::clone(&found);
        Box::new(move |res| {
            if let Ok(entry) = res {
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                if is_dir && entry.file_name() == ".git" {
                    if let Some(parent) = entry.path().parent() {
                        found.lock().unwrap().push(parent.to_path_buf());
                    }
                    return WalkState::Skip; // do not descend into .git internals
                }
            }
            WalkState::Continue
        })
    });
    let mut repos = Arc::try_unwrap(found).unwrap().into_inner().unwrap();
    repos.sort();
    repos.dedup();
    repos
}

pub fn walk_repo_files(repo: &Path) -> Vec<PathBuf> {
    let files = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let mut b = base_builder(repo);
    b.filter_entry(|e| {
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        !(is_dir && e.depth() > 0 && is_pruned_dir(&e.file_name().to_string_lossy()))
    });
    b.build_parallel().run(|| {
        let files = Arc::clone(&files);
        Box::new(move |res| {
            if let Ok(entry) = res {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    files.lock().unwrap().push(entry.into_path());
                }
            }
            WalkState::Continue
        })
    });
    Arc::try_unwrap(files).unwrap().into_inner().unwrap()
}
```

Remove the now-unused `use walkdir::WalkDir;`. Leave the `#[cfg(test)]` module (add the new test from Step 1 to it).

- [ ] **Step 4: Run the walk tests**

Run: `cargo test -p wormward-core walk`
Expected: PASS — `discovers_git_repos`, `walk_skips_git_and_node_modules`, and `walk_includes_gitignored_files`.

Note: `discovers_git_repos` asserts equality against a sorted vec; `discover_repos` already sorts, so order is stable.

- [ ] **Step 5: Drop the walkdir dependency**

Remove `walkdir = { workspace = true }` from `crates/wormward-core/Cargo.toml` (no longer referenced). Keep it in `[workspace.dependencies]` only if another crate uses it (none do — remove there too).

Run: `cargo test -p wormward-core`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-core/src/walk.rs crates/wormward-core/Cargo.toml Cargo.toml
git commit -m "Move file walker to the ignore crate (ignore rules disabled)"
```
## Phase 2 — Local remediation (`fix`)

### Task 5: `remediate::plan` — pure planning

**Files:**
- Create: `crates/wormward-core/src/remediate.rs`
- Modify: `crates/wormward-core/src/lib.rs`

**Interfaces:**
- Consumes: `Finding`, `FindingKind`, `Pack`, `PackManifest.remediation` (`Remediation.config_payload: Option<PayloadStrip>` with `strategy: String`, `markers: Vec<String>`).
- Produces:
  - `pub enum ActionKind { StripPayload { markers: Vec<String> }, DeleteFile, RemoveGitignoreLine { line: String }, ManualReview { reason: String } }`
  - `pub struct PlannedAction { pub repo: PathBuf, pub file: Option<PathBuf>, pub campaign: String, pub kind: ActionKind }`
  - `pub fn plan(findings: &[Finding], packs: &[Pack]) -> Vec<PlannedAction>`

- [ ] **Step 1: Write the failing tests**

Create `crates/wormward-core/src/remediate.rs`:

```rust
use std::path::PathBuf;

use crate::finding::{Finding, FindingKind};
use crate::pack::Pack;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ActionKind {
    StripPayload { markers: Vec<String> },
    DeleteFile,
    RemoveGitignoreLine { line: String },
    ManualReview { reason: String },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PlannedAction {
    pub repo: PathBuf,
    pub file: Option<PathBuf>,
    pub campaign: String,
    pub kind: ActionKind,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::matchers::{ContentSignature, SignatureKind};
    use crate::pack::{PackManifest, PayloadStrip, Remediation};

    fn pack() -> Pack {
        let manifest = PackManifest {
            id: "polinrider".into(),
            name: "PolinRider".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec!["postcss.config.mjs".into()],
            content_signatures: vec![ContentSignature {
                id: "primary".into(),
                kind: SignatureKind::Literal,
                value: "rmcej%otb%".into(),
            }],
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            ioc_domains: vec![],
            analyzer: None,
            remediation: Some(Remediation {
                config_payload: Some(PayloadStrip {
                    strategy: "strip_after_marker".into(),
                    markers: vec!["global['!']=".into()],
                }),
            }),
        };
        Pack { manifest, analyzer: None }
    }

    fn finding(kind: FindingKind, file: Option<&str>, remediable: bool) -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: Severity::Critical,
            repo: PathBuf::from("/r"),
            file: file.map(PathBuf::from),
            signature_id: "s".into(),
            kind,
            evidence: "e".into(),
            remediable,
            online: None,
            git_ref: None,
        }
    }

    #[test]
    fn content_signature_becomes_strip_payload() {
        let f = finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), true);
        let actions = plan(&[f], &[pack()]);
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0].kind,
            ActionKind::StripPayload { markers: vec!["global['!']=".into()] }
        );
    }

    #[test]
    fn artifact_becomes_delete_file() {
        let f = finding(FindingKind::Artifact, Some("temp_auto_push.bat"), true);
        let actions = plan(&[f], &[pack()]);
        assert_eq!(actions[0].kind, ActionKind::DeleteFile);
    }

    #[test]
    fn gitignore_injection_becomes_remove_line() {
        let mut f = finding(FindingKind::GitignoreInjection, Some(".gitignore"), true);
        f.evidence = "'config.bat' injected into .gitignore".into();
        f.signature_id = "gitignore:config.bat".into();
        let actions = plan(&[f], &[pack()]);
        assert_eq!(
            actions[0].kind,
            ActionKind::RemoveGitignoreLine { line: "config.bat".into() }
        );
    }

    #[test]
    fn npm_and_ioc_become_manual_review() {
        let npm = finding(FindingKind::NpmPackage, Some("package.json"), false);
        let ioc = finding(FindingKind::IocDomain, Some("postcss.config.mjs"), false);
        let actions = plan(&[npm, ioc], &[pack()]);
        assert_eq!(actions.len(), 2);
        assert!(matches!(actions[0].kind, ActionKind::ManualReview { .. }));
        assert!(matches!(actions[1].kind, ActionKind::ManualReview { .. }));
    }

    #[test]
    fn strip_without_markers_downgrades_to_manual_review() {
        let mut p = pack();
        p.manifest.remediation = None; // no strip rule available
        let f = finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), true);
        let actions = plan(&[f], &[p]);
        assert!(matches!(actions[0].kind, ActionKind::ManualReview { .. }));
    }

    #[test]
    fn duplicate_strip_actions_are_deduped() {
        let f1 = finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), true);
        let mut f2 = finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), true);
        f2.signature_id = "secondary".into();
        let actions = plan(&[f1, f2], &[pack()]);
        assert_eq!(actions.len(), 1); // same repo+file+strip collapse
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wormward-core remediate`
Expected: FAIL — `plan` not defined.

- [ ] **Step 3: Implement `plan`**

Add above the test module in `remediate.rs`:

```rust
fn markers_for(campaign: &str, packs: &[Pack]) -> Option<Vec<String>> {
    let pack = packs.iter().find(|p| p.manifest.id == campaign)?;
    let strip = pack.manifest.remediation.as_ref()?.config_payload.as_ref()?;
    if strip.strategy == "strip_after_marker" && !strip.markers.is_empty() {
        Some(strip.markers.clone())
    } else {
        None
    }
}

/// Parse the injected line out of a gitignore finding's signature id
/// ("gitignore:<line>"); falls back to None if the shape is unexpected.
fn gitignore_line(signature_id: &str) -> Option<String> {
    signature_id.strip_prefix("gitignore:").map(|s| s.to_string())
}

pub fn plan(findings: &[Finding], packs: &[Pack]) -> Vec<PlannedAction> {
    let mut actions: Vec<PlannedAction> = Vec::new();

    for f in findings {
        let kind = match f.kind {
            FindingKind::ContentSignature | FindingKind::Analyzer => {
                match markers_for(&f.campaign, packs) {
                    Some(markers) => ActionKind::StripPayload { markers },
                    None => ActionKind::ManualReview {
                        reason: "no strip_after_marker rule for this campaign".into(),
                    },
                }
            }
            FindingKind::Artifact => ActionKind::DeleteFile,
            FindingKind::GitignoreInjection => match gitignore_line(&f.signature_id) {
                Some(line) => ActionKind::RemoveGitignoreLine { line },
                None => ActionKind::ManualReview {
                    reason: "could not determine injected .gitignore line".into(),
                },
            },
            FindingKind::NpmPackage => ActionKind::ManualReview {
                reason: "malicious npm dependency: edit package.json and reinstall".into(),
            },
            FindingKind::IocDomain => ActionKind::ManualReview {
                reason: "C2 domain reference: inspect and remove manually".into(),
            },
            FindingKind::GitReflog => ActionKind::ManualReview {
                reason: "amended history in reflog: review git history manually".into(),
            },
        };

        let candidate = PlannedAction {
            repo: f.repo.clone(),
            file: f.file.clone(),
            campaign: f.campaign.clone(),
            kind,
        };
        // Dedup by (repo, file, kind).
        if !actions.iter().any(|a| {
            a.repo == candidate.repo && a.file == candidate.file && a.kind == candidate.kind
        }) {
            actions.push(candidate);
        }
    }

    actions
}
```

Register in `lib.rs`:

```rust
pub mod remediate;
```

and re-export:

```rust
pub use remediate::{plan, ActionKind, PlannedAction};
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wormward-core remediate`
Expected: PASS (all six tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/remediate.rs crates/wormward-core/src/lib.rs
git commit -m "Add remediate::plan mapping findings to remediation actions"
```

---

### Task 6: `apply_working_tree` — perform the fixes

**Files:**
- Modify: `crates/wormward-core/src/remediate.rs`
- Modify: `crates/wormward-core/src/lib.rs` (re-exports)

**Interfaces:**
- Consumes: `PlannedAction`, `ActionKind`.
- Produces:
  - `pub enum ApplyStatus { Planned, Applied, Skipped(String), Failed(String) }`
  - `pub struct ActionOutcome { pub action: PlannedAction, pub status: ApplyStatus }`
  - `pub fn apply_working_tree(plan: &[PlannedAction], dry_run: bool) -> Vec<ActionOutcome>`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `remediate.rs`:

```rust
use std::fs;
use tempfile::TempDir;

fn strip_action(repo: &std::path::Path, file: &str) -> PlannedAction {
    PlannedAction {
        repo: repo.to_path_buf(),
        file: Some(PathBuf::from(file)),
        campaign: "polinrider".into(),
        kind: ActionKind::StripPayload { markers: vec!["global['!']=".into()] },
    }
}

#[test]
fn strip_payload_truncates_at_marker() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    fs::write(
        repo.join("postcss.config.mjs"),
        "export default {};\nglobal['!']='8-270-2';var _$=payload;\n",
    )
    .unwrap();

    let out = apply_working_tree(&[strip_action(repo, "postcss.config.mjs")], false);
    assert_eq!(out[0].status, ApplyStatus::Applied);
    let cleaned = fs::read_to_string(repo.join("postcss.config.mjs")).unwrap();
    assert_eq!(cleaned, "export default {};\n");
}

#[test]
fn strip_payload_without_marker_is_skipped_and_file_untouched() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    let original = "export default {};\n";
    fs::write(repo.join("postcss.config.mjs"), original).unwrap();

    let out = apply_working_tree(&[strip_action(repo, "postcss.config.mjs")], false);
    assert!(matches!(out[0].status, ApplyStatus::Skipped(_)));
    assert_eq!(fs::read_to_string(repo.join("postcss.config.mjs")).unwrap(), original);
}

#[test]
fn delete_file_removes_artifact() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();
    let action = PlannedAction {
        repo: repo.to_path_buf(),
        file: Some(PathBuf::from("temp_auto_push.bat")),
        campaign: "polinrider".into(),
        kind: ActionKind::DeleteFile,
    };
    let out = apply_working_tree(&[action], false);
    assert_eq!(out[0].status, ApplyStatus::Applied);
    assert!(!repo.join("temp_auto_push.bat").exists());
}

#[test]
fn remove_gitignore_line_drops_only_that_line() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    fs::write(repo.join(".gitignore"), "node_modules\nconfig.bat\ndist\n").unwrap();
    let action = PlannedAction {
        repo: repo.to_path_buf(),
        file: Some(PathBuf::from(".gitignore")),
        campaign: "polinrider".into(),
        kind: ActionKind::RemoveGitignoreLine { line: "config.bat".into() },
    };
    let out = apply_working_tree(&[action], false);
    assert_eq!(out[0].status, ApplyStatus::Applied);
    assert_eq!(
        fs::read_to_string(repo.join(".gitignore")).unwrap(),
        "node_modules\ndist\n"
    );
}

#[test]
fn dry_run_changes_nothing() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    let original = "export default {};\nglobal['!']='x';payload\n";
    fs::write(repo.join("postcss.config.mjs"), original).unwrap();
    let out = apply_working_tree(&[strip_action(repo, "postcss.config.mjs")], true);
    assert_eq!(out[0].status, ApplyStatus::Planned);
    assert_eq!(fs::read_to_string(repo.join("postcss.config.mjs")).unwrap(), original);
}

#[test]
fn manual_review_is_reported_not_applied() {
    let tmp = TempDir::new().unwrap();
    let action = PlannedAction {
        repo: tmp.path().to_path_buf(),
        file: Some(PathBuf::from("package.json")),
        campaign: "polinrider".into(),
        kind: ActionKind::ManualReview { reason: "npm".into() },
    };
    let out = apply_working_tree(&[action], false);
    assert!(matches!(out[0].status, ApplyStatus::Skipped(_)));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wormward-core remediate`
Expected: FAIL — `apply_working_tree`, `ApplyStatus`, `ActionOutcome` not defined.

- [ ] **Step 3: Implement apply**

Add to `remediate.rs` (above the tests):

```rust
use std::path::Path;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum ApplyStatus {
    Planned,
    Applied,
    Skipped(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ActionOutcome {
    pub action: PlannedAction,
    pub status: ApplyStatus,
}

fn abs(repo: &Path, file: &Option<PathBuf>) -> Option<PathBuf> {
    file.as_ref().map(|f| repo.join(f))
}

/// Write `content` to `path` atomically (temp file in same dir, then rename).
fn atomic_write(path: &Path, content: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".wormward-tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f")
    ));
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)
}

fn strip_after_marker(content: &str, markers: &[String]) -> Option<String> {
    let cut = markers.iter().filter_map(|m| content.find(m)).min()?;
    let mut kept = content[..cut].to_string();
    while kept.ends_with('\n') || kept.ends_with('\r') {
        kept.pop();
    }
    kept.push('\n');
    Some(kept)
}

fn apply_one(action: &PlannedAction) -> ApplyStatus {
    let target = match abs(&action.repo, &action.file) {
        Some(p) => p,
        None => return ApplyStatus::Skipped("no file associated with action".into()),
    };
    match &action.kind {
        ActionKind::StripPayload { markers } => {
            let content = match std::fs::read_to_string(&target) {
                Ok(c) => c,
                Err(e) => return ApplyStatus::Failed(format!("read: {e}")),
            };
            match strip_after_marker(&content, markers) {
                Some(cleaned) => match atomic_write(&target, &cleaned) {
                    Ok(()) => ApplyStatus::Applied,
                    Err(e) => ApplyStatus::Failed(format!("write: {e}")),
                },
                None => ApplyStatus::Skipped("no strip marker present in file".into()),
            }
        }
        ActionKind::DeleteFile => match std::fs::remove_file(&target) {
            Ok(()) => ApplyStatus::Applied,
            Err(e) => ApplyStatus::Failed(format!("delete: {e}")),
        },
        ActionKind::RemoveGitignoreLine { line } => {
            let content = match std::fs::read_to_string(&target) {
                Ok(c) => c,
                Err(e) => return ApplyStatus::Failed(format!("read: {e}")),
            };
            let kept: Vec<&str> =
                content.lines().filter(|l| l.trim() != line.as_str()).collect();
            let mut out = kept.join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            match atomic_write(&target, &out) {
                Ok(()) => ApplyStatus::Applied,
                Err(e) => ApplyStatus::Failed(format!("write: {e}")),
            }
        }
        ActionKind::ManualReview { reason } => ApplyStatus::Skipped(reason.clone()),
    }
}

pub fn apply_working_tree(plan: &[PlannedAction], dry_run: bool) -> Vec<ActionOutcome> {
    plan.iter()
        .map(|action| {
            let status = if dry_run { ApplyStatus::Planned } else { apply_one(action) };
            ActionOutcome { action: action.clone(), status }
        })
        .collect()
}
```

Re-export in `lib.rs`:

```rust
pub use remediate::{apply_working_tree, ActionOutcome, ApplyStatus};
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wormward-core remediate`
Expected: PASS (all apply + plan tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/remediate.rs crates/wormward-core/src/lib.rs
git commit -m "Add apply_working_tree to perform remediation actions"
```

---

### Task 7: `fix` CLI subcommand

**Files:**
- Modify: `crates/wormward-cli/src/main.rs`
- Modify: `crates/wormward-cli/src/report.rs`
- Modify: `crates/wormward-cli/tests/cli.rs`

**Interfaces:**
- Consumes: `wormward_core::{scan, scan_deep, plan, apply_working_tree, ActionOutcome, ApplyStatus}`, `builtin_packs()`.
- Produces: `wormward fix [dirs] [--deep] [--yes] [--format]` (branch-rewrite flag added in Phase 3).

- [ ] **Step 1: Add a CLI integration test**

The existing `cli.rs` spawns the binary via a `bin()` helper
(`fn bin() -> Command { Command::new(env!("CARGO_BIN_EXE_wormward")) }`) — reuse
it; do not add `assert_cmd`. `tempfile` is already a dev-dependency. Add to
`crates/wormward-cli/tests/cli.rs`:

```rust
#[test]
fn fix_dry_run_reports_but_does_not_modify() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("proj");
    fs::create_dir_all(repo.join(".git")).unwrap();
    let cfg = repo.join("postcss.config.mjs");
    let original = "export default {};\nglobal['!']='8-270-2';var _$_1e42=1;payload\n";
    fs::write(&cfg, original).unwrap();

    // Dry run (no --yes): exit 1 (infection found), file unchanged.
    let out = bin().arg("fix").arg(repo.to_str().unwrap()).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(fs::read_to_string(&cfg).unwrap(), original);

    // Apply (--yes): exit 0, payload stripped.
    let out = bin().arg("fix").arg(repo.to_str().unwrap()).arg("--yes").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(fs::read_to_string(&cfg).unwrap(), "export default {};\n");
}
```

(`fs`, `TempDir`, and `bin` are already imported/defined at the top of `cli.rs`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wormward-cli fix_dry_run_reports_but_does_not_modify`
Expected: FAIL — `fix` subcommand does not exist (clap error / non-matching exit code).

- [ ] **Step 3: Add the `Fix` subcommand**

In `main.rs`, add to `enum Command`:

```rust
    /// Remove detected infections (dry-run unless --yes).
    Fix {
        /// Directories to scan and remediate (default: current directory).
        #[arg(default_value = ".")]
        dirs: Vec<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Also inspect every branch tip (needed before --rewrite-branches).
        #[arg(long)]
        deep: bool,
        /// Apply changes. Without this flag, fix only prints the plan.
        #[arg(long)]
        yes: bool,
    },
```

Add the match arm in `main()`:

```rust
        Command::Fix { dirs, format, deep, yes } => {
            for dir in &dirs {
                if !dir.exists() {
                    eprintln!("error: path does not exist: {}", dir.display());
                    return ExitCode::from(2);
                }
            }
            let packs = builtin_packs();
            let report = if deep { scan_deep(&dirs, &packs) } else { scan(&dirs, &packs) };
            let plan = wormward_core::plan(&report.findings, &packs);
            let outcomes = wormward_core::apply_working_tree(&plan, !yes);
            match format {
                OutputFormat::Text => print!("{}", report::render_fix_text(&report, &outcomes, yes)),
                OutputFormat::Json => println!("{}", report::render_fix_json(&report, &outcomes)),
            }
            // Exit 0 only if nothing needs manual review and (when applying) nothing failed.
            let unresolved = outcomes.iter().any(|o| {
                matches!(o.status, wormward_core::ApplyStatus::Failed(_))
                    || matches!(o.status, wormward_core::ApplyStatus::Skipped(_))
                    || (!yes && matches!(o.status, wormward_core::ApplyStatus::Planned))
            });
            if report.findings.is_empty() {
                ExitCode::from(0)
            } else if unresolved {
                ExitCode::from(1)
            } else {
                ExitCode::from(0)
            }
        }
```

Add to the `use` line: `use wormward_core::{scan, scan_deep};` already exists — extend to import nothing else (calls are path-qualified as `wormward_core::plan` etc.).

- [ ] **Step 4: Add report renderers**

In `report.rs` add:

```rust
use wormward_core::remediate::{ActionKind, ActionOutcome, ApplyStatus};
use wormward_core::scanner::ScanReport;

pub fn render_fix_text(report: &ScanReport, outcomes: &[ActionOutcome], applied: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Scanned {} repo(s); {} finding(s).\n",
        report.repos_scanned,
        report.findings.len()
    ));
    if outcomes.is_empty() {
        out.push_str("No remediation actions.\n");
        return out;
    }
    out.push_str(if applied { "Applied actions:\n" } else { "Planned actions (dry-run; pass --yes to apply):\n" });
    for o in outcomes {
        let file = o.action.file.as_ref().map(|f| f.display().to_string()).unwrap_or_default();
        let verb = match &o.action.kind {
            ActionKind::StripPayload { .. } => "strip payload",
            ActionKind::DeleteFile => "delete file",
            ActionKind::RemoveGitignoreLine { .. } => "clean .gitignore",
            ActionKind::ManualReview { .. } => "manual review",
        };
        let status = match &o.status {
            ApplyStatus::Planned => "planned".to_string(),
            ApplyStatus::Applied => "applied".to_string(),
            ApplyStatus::Skipped(r) => format!("skipped: {r}"),
            ApplyStatus::Failed(r) => format!("FAILED: {r}"),
        };
        out.push_str(&format!(
            "  [{}] {} {} ({})\n",
            o.action.campaign, verb, file, status
        ));
    }
    out
}

pub fn render_fix_json(report: &ScanReport, outcomes: &[ActionOutcome]) -> String {
    let value = serde_json::json!({
        "repos_scanned": report.repos_scanned,
        "findings": report.findings,
        "actions": outcomes,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
}
```

Ensure `wormward-core` re-exports the `remediate` and `scanner` modules publicly (they are `pub mod`), and that `ScanReport` is reachable at `wormward_core::scanner::ScanReport` (it is). If `report.rs` prefers the flat re-exports, use `wormward_core::{ActionKind, ActionOutcome, ApplyStatus, ScanReport}` instead — all are re-exported in `lib.rs`.

- [ ] **Step 5: Run the CLI test**

Run: `cargo test -p wormward-cli`
Expected: PASS — including `fix_dry_run_reports_but_does_not_modify` and the existing CLI tests.

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-cli/src/main.rs crates/wormward-cli/src/report.rs crates/wormward-cli/tests/cli.rs crates/wormward-cli/Cargo.toml Cargo.toml
git commit -m "Add fix subcommand for working-tree remediation"
```
## Phase 3 — Cross-branch history rewrite (`--rewrite-branches`)

### Task 8: `plan_branch_rewrites` + blob-callback generation

**Files:**
- Create: `crates/wormward-core/src/rewrite.rs`
- Modify: `crates/wormward-core/src/lib.rs`

**Interfaces:**
- Consumes: `Finding`, `FindingKind`, `Pack`, `remediate::markers_for` behavior (reimplemented locally to avoid coupling).
- Produces:
  - `pub struct BranchRewritePlan { pub repo: PathBuf, pub branch: String, pub backup_ref: String, pub blob_callback: String, pub markers: Vec<String> }`
  - `pub fn plan_branch_rewrites(findings: &[Finding], packs: &[Pack], timestamp: u64) -> Vec<BranchRewritePlan>`
  - `pub fn blob_callback(markers: &[String]) -> String`

- [ ] **Step 1: Write the failing tests**

Create `crates/wormward-core/src/rewrite.rs`:

```rust
use std::path::PathBuf;

use crate::finding::{Finding, FindingKind};
use crate::pack::Pack;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BranchRewritePlan {
    pub repo: PathBuf,
    pub branch: String,
    pub backup_ref: String,
    pub blob_callback: String,
    pub markers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::matchers::{ContentSignature, SignatureKind};
    use crate::pack::{PackManifest, PayloadStrip, Remediation};

    fn pack() -> Pack {
        let manifest = PackManifest {
            id: "polinrider".into(),
            name: "PolinRider".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec!["postcss.config.mjs".into()],
            content_signatures: vec![ContentSignature {
                id: "primary".into(),
                kind: SignatureKind::Literal,
                value: "rmcej%otb%".into(),
            }],
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            ioc_domains: vec![],
            analyzer: None,
            remediation: Some(Remediation {
                config_payload: Some(PayloadStrip {
                    strategy: "strip_after_marker".into(),
                    markers: vec!["global['!']=".into()],
                }),
            }),
        };
        Pack { manifest, analyzer: None }
    }

    fn branch_finding(branch: &str) -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: Severity::Critical,
            repo: PathBuf::from("/r"),
            file: Some(PathBuf::from("postcss.config.mjs")),
            signature_id: "primary".into(),
            kind: FindingKind::ContentSignature,
            evidence: "e".into(),
            remediable: true,
            online: None,
            git_ref: Some(branch.into()),
        }
    }

    #[test]
    fn plans_one_rewrite_per_infected_branch() {
        let findings = vec![branch_finding("origin/evil"), branch_finding("origin/evil")];
        let plans = plan_branch_rewrites(&findings, &[pack()], 1_700_000_000);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].branch, "origin/evil");
        assert_eq!(plans[0].backup_ref, "refs/wormward-backup/origin/evil-1700000000");
    }

    #[test]
    fn findings_without_git_ref_are_ignored() {
        let mut f = branch_finding("origin/evil");
        f.git_ref = None; // working-tree finding, handled by apply_working_tree
        assert!(plan_branch_rewrites(&[f], &[pack()], 1).is_empty());
    }

    #[test]
    fn non_strippable_kinds_do_not_create_rewrites() {
        let mut f = branch_finding("origin/evil");
        f.kind = FindingKind::NpmPackage;
        assert!(plan_branch_rewrites(&[f], &[pack()], 1).is_empty());
    }

    #[test]
    fn blob_callback_encodes_markers_as_hex() {
        let cb = blob_callback(&["global['!']=".into()]);
        // "global['!']=" hex-encoded, decoded in the Python callback.
        assert!(cb.contains("bytes.fromhex"));
        assert!(cb.contains(&hex::encode("global['!']=")));
        assert!(cb.contains("blob.data"));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wormward-core rewrite`
Expected: FAIL — `plan_branch_rewrites` / `blob_callback` not defined.

- [ ] **Step 3: Implement**

Add above the tests in `rewrite.rs`:

```rust
fn markers_for(campaign: &str, packs: &[Pack]) -> Option<Vec<String>> {
    let pack = packs.iter().find(|p| p.manifest.id == campaign)?;
    let strip = pack.manifest.remediation.as_ref()?.config_payload.as_ref()?;
    if strip.strategy == "strip_after_marker" && !strip.markers.is_empty() {
        Some(strip.markers.clone())
    } else {
        None
    }
}

fn is_strippable(kind: &FindingKind) -> bool {
    matches!(kind, FindingKind::ContentSignature | FindingKind::Analyzer)
}

/// A git-filter-repo `--blob-callback` (Python) that truncates each blob at the
/// first occurring marker. Markers are hex-encoded to avoid quoting hazards.
pub fn blob_callback(markers: &[String]) -> String {
    let hexes: Vec<String> = markers.iter().map(|m| format!("\"{}\"", hex::encode(m))).collect();
    format!(
        "import sys\n\
         markers = [bytes.fromhex(h) for h in [{}]]\n\
         data = blob.data\n\
         best = -1\n\
         for m in markers:\n\
         \x20   i = data.find(m)\n\
         \x20   if i != -1 and (best == -1 or i < best):\n\
         \x20       best = i\n\
         if best != -1:\n\
         \x20   blob.data = data[:best].rstrip(b\"\\r\\n\") + b\"\\n\"\n",
        hexes.join(", ")
    )
}

pub fn plan_branch_rewrites(
    findings: &[Finding],
    packs: &[Pack],
    timestamp: u64,
) -> Vec<BranchRewritePlan> {
    let mut plans: Vec<BranchRewritePlan> = Vec::new();
    for f in findings {
        let branch = match &f.git_ref {
            Some(b) => b.clone(),
            None => continue,
        };
        if !is_strippable(&f.kind) {
            continue;
        }
        let markers = match markers_for(&f.campaign, packs) {
            Some(m) => m,
            None => continue,
        };
        // One rewrite per (repo, branch).
        if plans.iter().any(|p| p.repo == f.repo && p.branch == branch) {
            continue;
        }
        plans.push(BranchRewritePlan {
            repo: f.repo.clone(),
            branch: branch.clone(),
            backup_ref: format!("refs/wormward-backup/{branch}-{timestamp}"),
            blob_callback: blob_callback(&markers),
            markers,
        });
    }
    plans
}
```

Register in `lib.rs`:

```rust
pub mod rewrite;
```

and re-export:

```rust
pub use rewrite::{blob_callback, plan_branch_rewrites, BranchRewritePlan};
```

Note: `hex` is already a dependency of `wormward-core`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p wormward-core rewrite`
Expected: PASS (all four tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/rewrite.rs crates/wormward-core/src/lib.rs
git commit -m "Add branch-rewrite planning and filter-repo blob callback"
```

---

### Task 9: `apply_branch_rewrites` + wire `--rewrite-branches` into `fix`

**Files:**
- Modify: `crates/wormward-core/src/rewrite.rs`
- Modify: `crates/wormward-cli/src/main.rs`
- Modify: `crates/wormward-cli/src/report.rs`

**Interfaces:**
- Consumes: `BranchRewritePlan`, `ActionOutcome`/`ApplyStatus` from `remediate`.
- Produces:
  - `pub fn filter_repo_available() -> bool`
  - `pub fn apply_branch_rewrites(plans: &[BranchRewritePlan], dry_run: bool) -> Vec<RewriteOutcome>`
  - `pub struct RewriteOutcome { pub plan: BranchRewritePlan, pub status: RewriteStatus }`
  - `pub enum RewriteStatus { Planned, RewrittenBackedUp, Skipped(String), Failed(String) }`

- [ ] **Step 1: Write tests (dry-run + tool detection)**

Add to the `tests` module in `rewrite.rs`:

```rust
#[test]
fn dry_run_creates_no_refs_and_runs_nothing() {
    let plans = vec![BranchRewritePlan {
        repo: PathBuf::from("/nonexistent"),
        branch: "origin/evil".into(),
        backup_ref: "refs/wormward-backup/origin/evil-1".into(),
        blob_callback: blob_callback(&["global['!']=".into()]),
        markers: vec!["global['!']=".into()],
    }];
    let out = apply_branch_rewrites(&plans, true);
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0].status, RewriteStatus::Planned));
}

#[test]
fn missing_filter_repo_is_skipped_with_message() {
    // Simulated by pointing at a repo path that can't run; when filter-repo is
    // absent this returns Skipped, otherwise Failed on the bogus path. Either way
    // it must not panic and must not be RewrittenBackedUp.
    let plans = vec![BranchRewritePlan {
        repo: PathBuf::from("/definitely/not/a/repo"),
        branch: "origin/evil".into(),
        backup_ref: "refs/wormward-backup/origin/evil-1".into(),
        blob_callback: blob_callback(&["global['!']=".into()]),
        markers: vec!["global['!']=".into()],
    }];
    let out = apply_branch_rewrites(&plans, false);
    assert!(matches!(
        out[0].status,
        RewriteStatus::Skipped(_) | RewriteStatus::Failed(_)
    ));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wormward-core rewrite::tests::dry_run_creates_no_refs_and_runs_nothing`
Expected: FAIL — types/functions not defined.

- [ ] **Step 3: Implement apply + detection**

Add to `rewrite.rs`:

```rust
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum RewriteStatus {
    Planned,
    RewrittenBackedUp,
    Skipped(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RewriteOutcome {
    pub plan: BranchRewritePlan,
    pub status: RewriteStatus,
}

pub fn filter_repo_available() -> bool {
    Command::new("git")
        .args(["filter-repo", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git_ok(repo: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn rewrite_one(plan: &BranchRewritePlan) -> RewriteStatus {
    if !filter_repo_available() {
        return RewriteStatus::Skipped(
            "git filter-repo not found on PATH; install it to rewrite branch history \
             (pip install git-filter-repo). Working-tree fixes were still applied."
                .into(),
        );
    }
    // Backup the branch ref before rewriting.
    if let Err(e) = git_ok(&plan.repo, &["update-ref", &plan.backup_ref, &plan.branch]) {
        return RewriteStatus::Failed(format!("backup ref: {e}"));
    }
    // Rewrite just this branch's history, stripping the payload from every blob.
    let args = [
        "filter-repo",
        "--force",
        "--refs",
        &plan.branch,
        "--blob-callback",
        &plan.blob_callback,
    ];
    match git_ok(&plan.repo, &args) {
        Ok(()) => RewriteStatus::RewrittenBackedUp,
        Err(e) => RewriteStatus::Failed(format!("filter-repo: {e}")),
    }
}

pub fn apply_branch_rewrites(plans: &[BranchRewritePlan], dry_run: bool) -> Vec<RewriteOutcome> {
    plans
        .iter()
        .map(|plan| {
            let status = if dry_run { RewriteStatus::Planned } else { rewrite_one(plan) };
            RewriteOutcome { plan: plan.clone(), status }
        })
        .collect()
}
```

Re-export in `lib.rs`:

```rust
pub use rewrite::{apply_branch_rewrites, filter_repo_available, RewriteOutcome, RewriteStatus};
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wormward-core rewrite`
Expected: PASS.

- [ ] **Step 5: Add `--rewrite-branches` to the `Fix` subcommand**

In `main.rs`, add to the `Fix` variant fields:

```rust
        /// Rewrite infected branch history via git filter-repo (implies --deep).
        #[arg(long)]
        rewrite_branches: bool,
```

Update the `Command::Fix` match arm: force deep scanning when rewriting, run branch rewrites after working-tree apply:

```rust
        Command::Fix { dirs, format, deep, yes, rewrite_branches } => {
            for dir in &dirs {
                if !dir.exists() {
                    eprintln!("error: path does not exist: {}", dir.display());
                    return ExitCode::from(2);
                }
            }
            let packs = builtin_packs();
            let deep = deep || rewrite_branches;
            let report = if deep { scan_deep(&dirs, &packs) } else { scan(&dirs, &packs) };
            let plan = wormward_core::plan(&report.findings, &packs);
            let outcomes = wormward_core::apply_working_tree(&plan, !yes);

            let rewrites = if rewrite_branches {
                let rplans = wormward_core::plan_branch_rewrites(
                    &report.findings,
                    &packs,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                );
                wormward_core::apply_branch_rewrites(&rplans, !yes)
            } else {
                Vec::new()
            };

            match format {
                OutputFormat::Text => {
                    print!("{}", report::render_fix_text(&report, &outcomes, yes));
                    print!("{}", report::render_rewrite_text(&rewrites, yes));
                }
                OutputFormat::Json => {
                    println!("{}", report::render_fix_json_with_rewrites(&report, &outcomes, &rewrites))
                }
            }

            let unresolved = outcomes.iter().any(|o| {
                matches!(o.status, wormward_core::ApplyStatus::Failed(_))
                    || matches!(o.status, wormward_core::ApplyStatus::Skipped(_))
                    || (!yes && matches!(o.status, wormward_core::ApplyStatus::Planned))
            }) || rewrites.iter().any(|r| {
                matches!(r.status, wormward_core::RewriteStatus::Failed(_))
                    || matches!(r.status, wormward_core::RewriteStatus::Skipped(_))
                    || (!yes && matches!(r.status, wormward_core::RewriteStatus::Planned))
            });

            if report.findings.is_empty() {
                ExitCode::from(0)
            } else if unresolved {
                ExitCode::from(1)
            } else {
                ExitCode::from(0)
            }
        }
```

- [ ] **Step 6: Add rewrite renderers**

In `report.rs` add:

```rust
use wormward_core::rewrite::{RewriteOutcome, RewriteStatus};

pub fn render_rewrite_text(rewrites: &[RewriteOutcome], applied: bool) -> String {
    if rewrites.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str(if applied {
        "Branch history rewrites:\n"
    } else {
        "Planned branch rewrites (dry-run; pass --yes to apply):\n"
    });
    for r in rewrites {
        let status = match &r.status {
            RewriteStatus::Planned => "planned".to_string(),
            RewriteStatus::RewrittenBackedUp => {
                format!("rewritten (backup: {})", r.plan.backup_ref)
            }
            RewriteStatus::Skipped(m) => format!("skipped: {m}"),
            RewriteStatus::Failed(m) => format!("FAILED: {m}"),
        };
        out.push_str(&format!("  {} ({})\n", r.plan.branch, status));
    }
    out
}

pub fn render_fix_json_with_rewrites(
    report: &ScanReport,
    outcomes: &[ActionOutcome],
    rewrites: &[RewriteOutcome],
) -> String {
    let value = serde_json::json!({
        "repos_scanned": report.repos_scanned,
        "findings": report.findings,
        "actions": outcomes,
        "branch_rewrites": rewrites,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
}
```

- [ ] **Step 7: Run the workspace test suite**

Run: `cargo test --workspace`
Expected: PASS. (The end-to-end filter-repo test is deferred: add an ignored/skip-if-missing test only if `git filter-repo` is available in CI.)

- [ ] **Step 8: Commit**

```bash
git add crates/wormward-core/src/rewrite.rs crates/wormward-core/src/lib.rs crates/wormward-cli/src/main.rs crates/wormward-cli/src/report.rs
git commit -m "Apply branch rewrites via filter-repo behind --rewrite-branches"
```
## Phase 4 — GitHub account mode (`github`)

### Task 10: New `wormward-github` crate + auth resolution

**Files:**
- Modify: `Cargo.toml` (workspace members + deps)
- Create: `crates/wormward-github/Cargo.toml`
- Create: `crates/wormward-github/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct RepoRef { pub full_name: String, pub clone_url: String, pub default_branch: String, pub fork: bool }`
  - `pub enum GithubError { Auth(String), Http(String), Parse(String) }` (impl `std::error::Error` + `Display`)
  - `pub fn resolve_token(explicit: Option<&str>) -> Result<String, GithubError>`

- [ ] **Step 1: Register the crate**

In workspace `Cargo.toml`:

```toml
members = [
  "crates/wormward-core",
  "crates/wormward-packs",
  "crates/wormward-cli",
  "crates/wormward-osm",
  "crates/wormward-github",
]
```

Create `crates/wormward-github/Cargo.toml`:

```toml
[package]
name = "wormward-github"
edition.workspace = true
version.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
ureq = { workspace = true }
rayon = { workspace = true }
tempfile = { workspace = true }
wormward-core = { path = "../wormward-core" }
wormward-packs = { path = "../wormward-packs" }

[dev-dependencies]
httpmock = { workspace = true }
```

- [ ] **Step 2: Write the failing test**

Create `crates/wormward-github/src/lib.rs`:

```rust
use serde::{Deserialize, Serialize};

// Serialize is required because RepoOutcome (Task 12) serializes an embedded RepoRef.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoRef {
    pub full_name: String,
    pub clone_url: String,
    #[serde(default)]
    pub default_branch: String,
    #[serde(default)]
    pub fork: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("github auth: {0}")]
    Auth(String),
    #[error("github http: {0}")]
    Http(String),
    #[error("github parse: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_token_wins() {
        let t = resolve_token(Some("tok_explicit")).unwrap();
        assert_eq!(t, "tok_explicit");
    }

    #[test]
    fn env_token_used_when_no_explicit() {
        // SAFETY: single-threaded test.
        std::env::set_var("GITHUB_TOKEN", "tok_env");
        let t = resolve_token(None).unwrap();
        assert_eq!(t, "tok_env");
        std::env::remove_var("GITHUB_TOKEN");
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p wormward-github explicit_token_wins`
Expected: FAIL — `resolve_token` not defined.

- [ ] **Step 4: Implement `resolve_token`**

Add to `lib.rs` above the tests:

```rust
use std::process::Command;

pub fn resolve_token(explicit: Option<&str>) -> Result<String, GithubError> {
    if let Some(t) = explicit {
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(t) = std::env::var(var) {
            if !t.is_empty() {
                return Ok(t);
            }
        }
    }
    // Fall back to the gh CLI.
    if let Ok(out) = Command::new("gh").args(["auth", "token"]).output() {
        if out.status.success() {
            let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !t.is_empty() {
                return Ok(t);
            }
        }
    }
    Err(GithubError::Auth(
        "no token: pass --token, set GITHUB_TOKEN/GH_TOKEN, or run `gh auth login`".into(),
    ))
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p wormward-github`
Expected: PASS. (Run with `--test-threads=1` if env-var tests interleave: `cargo test -p wormward-github -- --test-threads=1`.)

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/wormward-github/Cargo.toml crates/wormward-github/src/lib.rs
git commit -m "Add wormward-github crate with token resolution"
```

---

### Task 11: `RepoHost` enumeration with pagination

**Files:**
- Modify: `crates/wormward-github/src/lib.rs`

**Interfaces:**
- Consumes: `RepoRef`, `GithubError`, `ureq`.
- Produces:
  - `pub trait RepoHost { fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError>; }`
  - `pub struct GitHubHost { pub token: String, pub base_url: String }`
  - `impl GitHubHost { pub fn new(token: String) -> Self /* base_url = api.github.com */ }`

- [ ] **Step 1: Write the failing test (httpmock, two pages)**

Add to the `tests` module in `lib.rs`:

```rust
use httpmock::prelude::*;

#[test]
fn lists_repos_across_pages_and_filters_forks() {
    let server = MockServer::start();
    let next = format!("<{}/user/repos?page=2>; rel=\"next\"", server.base_url());
    server.mock(|when, then| {
        when.method(GET).path("/user/repos").query_param("page", "1");
        then.status(200)
            .header("Link", next.as_str())
            .json_body(serde_json::json!([
                {"full_name":"me/a","clone_url":"https://x/a.git","default_branch":"main","fork":false},
                {"full_name":"me/forked","clone_url":"https://x/f.git","default_branch":"main","fork":true}
            ]));
    });
    server.mock(|when, then| {
        when.method(GET).path("/user/repos").query_param("page", "2");
        then.status(200).json_body(serde_json::json!([
            {"full_name":"me/b","clone_url":"https://x/b.git","default_branch":"dev","fork":false}
        ]));
    });

    let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
    let repos = host.list_repos(false).unwrap();
    let names: Vec<&str> = repos.iter().map(|r| r.full_name.as_str()).collect();
    assert_eq!(names, vec!["me/a", "me/b"]); // fork filtered out, both pages merged
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wormward-github lists_repos_across_pages_and_filters_forks`
Expected: FAIL — `RepoHost` / `GitHubHost` not defined.

- [ ] **Step 3: Implement enumeration**

Add to `lib.rs`:

```rust
pub trait RepoHost {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError>;
}

pub struct GitHubHost {
    pub token: String,
    pub base_url: String,
}

impl GitHubHost {
    pub fn new(token: String) -> Self {
        GitHubHost { token, base_url: "https://api.github.com".into() }
    }
}

/// Extract the URL for rel="next" from a GitHub Link header, if present.
fn next_link(link_header: &str) -> Option<String> {
    for part in link_header.split(',') {
        let seg = part.trim();
        if seg.contains("rel=\"next\"") {
            let start = seg.find('<')?;
            let end = seg.find('>')?;
            return Some(seg[start + 1..end].to_string());
        }
    }
    None
}

impl RepoHost for GitHubHost {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError> {
        let mut url = format!("{}/user/repos?affiliation=owner&per_page=100&page=1", self.base_url);
        let mut all: Vec<RepoRef> = Vec::new();
        loop {
            let resp = ureq::get(&url)
                .set("Authorization", &format!("Bearer {}", self.token))
                .set("User-Agent", "wormward")
                .set("Accept", "application/vnd.github+json")
                .call()
                .map_err(|e| GithubError::Http(e.to_string()))?;
            let link = resp.header("Link").map(|s| s.to_string());
            let body = resp.into_string().map_err(|e| GithubError::Http(e.to_string()))?;
            let page: Vec<RepoRef> =
                serde_json::from_str(&body).map_err(|e| GithubError::Parse(e.to_string()))?;
            all.extend(page);
            match link.as_deref().and_then(next_link) {
                Some(next) => url = next,
                None => break,
            }
        }
        if !include_forks {
            all.retain(|r| !r.fork);
        }
        Ok(all)
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p wormward-github`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-github/src/lib.rs
git commit -m "Enumerate owner repos with Link-header pagination"
```

---

### Task 12: Per-repo pipeline (clone → scan → fix → push)

**Files:**
- Create: `crates/wormward-github/src/pipeline.rs`
- Modify: `crates/wormward-github/src/lib.rs` (`pub mod pipeline;`)

**Interfaces:**
- Consumes: `RepoRef`, `RepoHost`, `wormward_core::{scan_repo, deep_scan_repo, plan, apply_working_tree, plan_branch_rewrites, apply_branch_rewrites}`, `wormward_packs::builtin_packs`.
- Produces:
  - `pub struct GithubRunOpts { pub clone_dir: Option<PathBuf>, pub include_forks: bool, pub fix: bool, pub rewrite_branches: bool, pub push: bool, pub yes: bool }`
  - `pub struct RepoOutcome { pub repo: RepoRef, pub findings: Vec<Finding>, pub actions: Vec<ActionOutcome>, pub rewrites: Vec<RewriteOutcome>, pub pushed: Vec<String>, pub error: Option<String> }`
  - `pub fn run(opts: &GithubRunOpts, host: &dyn RepoHost, packs: &[Pack]) -> Result<Vec<RepoOutcome>, GithubError>`

- [ ] **Step 1: Write the integration test (bare origin, no network)**

Create `crates/wormward-github/src/pipeline.rs` with the test first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;
    use wormward_packs::builtin_packs;

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C").arg(dir).args(args)
            .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status().unwrap();
        assert!(status.success());
    }

    struct FakeHost { repo: RepoRef }
    impl RepoHost for FakeHost {
        fn list_repos(&self, _include_forks: bool) -> Result<Vec<RepoRef>, GithubError> {
            Ok(vec![self.repo.clone()])
        }
    }

    #[test]
    fn fixes_infected_repo_end_to_end() {
        // Build a source repo with an infected file, then a bare "origin".
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        git(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(
            src.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';var _$_1e42=1;\n(\"rmcej%otb%\",2857687)\n",
        ).unwrap();
        git(&src, &["add", "."]);
        git(&src, &["commit", "-q", "-m", "infected"]);

        let bare = tmp.path().join("origin.git");
        Command::new("git").args(["init", "-q", "--bare", bare.to_str().unwrap()]).status().unwrap();
        git(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git(&src, &["push", "-q", "origin", "main"]);

        let clone_dir = tmp.path().join("work");
        let host = FakeHost {
            repo: RepoRef {
                full_name: "me/proj".into(),
                clone_url: format!("file://{}", bare.display()),
                default_branch: "main".into(),
                fork: false,
            },
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir),
            include_forks: false,
            fix: true,
            rewrite_branches: false,
            push: false,
            yes: true,
        };

        let outcomes = run(&opts, &host, &builtin_packs()).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].error.is_none());
        assert!(!outcomes[0].findings.is_empty());
        assert!(outcomes[0].actions.iter().any(|a| matches!(
            a.status, wormward_core::ApplyStatus::Applied
        )));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p wormward-github fixes_infected_repo_end_to_end`
Expected: FAIL — `run`, `GithubRunOpts`, `RepoOutcome` not defined.

- [ ] **Step 3: Implement the pipeline**

Add above the tests in `pipeline.rs`:

```rust
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use rayon::prelude::*;
use wormward_core::finding::Finding;
use wormward_core::pack::Pack;
use wormward_core::remediate::ActionOutcome;
use wormward_core::rewrite::RewriteOutcome;

use crate::{GithubError, RepoHost, RepoRef};

#[derive(Debug, Clone)]
pub struct GithubRunOpts {
    pub clone_dir: Option<PathBuf>,
    pub include_forks: bool,
    pub fix: bool,
    pub rewrite_branches: bool,
    pub push: bool,
    pub yes: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RepoOutcome {
    pub repo: RepoRef,
    pub findings: Vec<Finding>,
    pub actions: Vec<ActionOutcome>,
    pub rewrites: Vec<RewriteOutcome>,
    pub pushed: Vec<String>,
    pub error: Option<String>,
}

fn git(dir: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .arg("-C").arg(dir).args(args)
        .output().map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn process_repo(repo: &RepoRef, opts: &GithubRunOpts, packs: &[Pack], base: &Path) -> RepoOutcome {
    let mut outcome = RepoOutcome {
        repo: repo.clone(),
        findings: Vec::new(),
        actions: Vec::new(),
        rewrites: Vec::new(),
        pushed: Vec::new(),
        error: None,
    };
    let dest = base.join(repo.full_name.replace('/', "__"));

    // Clone with all branches.
    if let Err(e) = Command::new("git")
        .args(["clone", "--no-single-branch", "-q", &repo.clone_url, dest.to_str().unwrap_or("")])
        .status()
        .map_err(|e| e.to_string())
        .and_then(|s| if s.success() { Ok(()) } else { Err("clone failed".into()) })
    {
        outcome.error = Some(format!("clone: {e}"));
        return outcome;
    }

    // Scan working tree + all branch tips.
    let mut findings = wormward_core::scan_repo(&dest, packs);
    findings.extend(wormward_core::deep_scan_repo(&dest, packs));
    outcome.findings = findings.clone();

    if !opts.fix || findings.is_empty() {
        return outcome;
    }

    // Working-tree remediation.
    let plan = wormward_core::plan(&findings, packs);
    outcome.actions = wormward_core::apply_working_tree(&plan, !opts.yes);
    if opts.yes {
        let _ = git(&dest, &["add", "-A"]);
        let _ = git(&dest, &["commit", "-m", "wormward: remove worm payload"]);
    }

    // Branch history rewrite.
    if opts.rewrite_branches {
        let rplans = wormward_core::plan_branch_rewrites(&findings, packs, now_secs());
        outcome.rewrites = wormward_core::apply_branch_rewrites(&rplans, !opts.yes);
    }

    // Force-push cleaned branches (backups first).
    if opts.push && opts.yes {
        let ts = now_secs();
        // Push a backup of the default branch before force-pushing.
        let backup = format!("refs/heads/{}:refs/heads/wormward-backup/{}-{}", repo.default_branch, repo.default_branch, ts);
        if let Err(e) = git(&dest, &["push", "origin", &backup]) {
            outcome.error = Some(format!("backup push: {e}"));
            return outcome;
        }
        match git(&dest, &["push", "--force-with-lease", "origin", &repo.default_branch]) {
            Ok(()) => outcome.pushed.push(repo.default_branch.clone()),
            Err(e) => outcome.error = Some(format!("force-push: {e}")),
        }
    }

    outcome
}

pub fn run(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
) -> Result<Vec<RepoOutcome>, GithubError> {
    let repos = host.list_repos(opts.include_forks)?;

    // Resolve a base clone directory (temp dir kept alive for the whole run).
    let tmp_guard;
    let base: PathBuf = match &opts.clone_dir {
        Some(d) => {
            std::fs::create_dir_all(d).map_err(|e| GithubError::Http(e.to_string()))?;
            d.clone()
        }
        None => {
            tmp_guard = tempfile::TempDir::new().map_err(|e| GithubError::Http(e.to_string()))?;
            tmp_guard.path().to_path_buf()
        }
    };

    let outcomes: Vec<RepoOutcome> = repos
        .par_iter()
        .map(|repo| process_repo(repo, opts, packs, &base))
        .collect();
    Ok(outcomes)
}
```

Add `pub mod pipeline;` to `lib.rs`. Ensure `wormward_core` re-exports `scan_repo` and `deep_scan_repo` (they are in `lib.rs`'s re-export block already). Confirm `Finding`, `Pack`, `ActionOutcome`, `RewriteOutcome` paths are `pub` (they are).

Note on the `tmp_guard` lifetime: bind it in the same scope as `base` so the temp dir is not dropped before the parallel clones run.

- [ ] **Step 4: Run tests**

Run: `cargo test -p wormward-github`
Expected: PASS — `fixes_infected_repo_end_to_end` plus the earlier enumeration/auth tests.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-github/src/pipeline.rs crates/wormward-github/src/lib.rs
git commit -m "Add per-repo GitHub pipeline: clone, scan, fix, push"
```

---

### Task 13: `github` CLI subcommand

**Files:**
- Modify: `crates/wormward-cli/Cargo.toml` (depend on `wormward-github`)
- Modify: `crates/wormward-cli/src/main.rs`
- Modify: `crates/wormward-cli/src/report.rs`

**Interfaces:**
- Consumes: `wormward_github::{resolve_token, GitHubHost, RepoHost, pipeline::{run, GithubRunOpts, RepoOutcome}}`.
- Produces: `wormward github [--token] [--clone-dir] [--include-forks] [--fix] [--rewrite-branches] [--push] [--yes] [--format]`.

- [ ] **Step 1: Add the dependency**

In `crates/wormward-cli/Cargo.toml` `[dependencies]`:

```toml
wormward-github = { path = "../wormward-github" }
```

- [ ] **Step 2: Add the `Github` subcommand (compile-check as the test)**

This command hits the network, so it is validated by a compile + `--help` smoke test rather than a live run. Add to `enum Command` in `main.rs`:

```rust
    /// Scan (and optionally remediate) every repo on the logged-in GitHub account.
    Github {
        /// GitHub token (else GITHUB_TOKEN/GH_TOKEN, else `gh auth token`).
        #[arg(long)]
        token: Option<String>,
        /// Directory to clone into (default: a temp dir removed after the run).
        #[arg(long)]
        clone_dir: Option<PathBuf>,
        /// Include forks (default: skip them).
        #[arg(long)]
        include_forks: bool,
        /// Remediate infected working trees.
        #[arg(long)]
        fix: bool,
        /// Rewrite infected branch history (implies --fix; needs git filter-repo).
        #[arg(long)]
        rewrite_branches: bool,
        /// Force-push cleaned branches back to origin (backs up first).
        #[arg(long)]
        push: bool,
        /// Actually perform writes/pushes. Without this, only prints the plan.
        #[arg(long)]
        yes: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
```

Add the match arm:

```rust
        Command::Github {
            token, clone_dir, include_forks, fix, rewrite_branches, push, yes, format,
        } => {
            let token = match wormward_github::resolve_token(token.as_deref()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let host = wormward_github::GitHubHost::new(token);
            let opts = wormward_github::pipeline::GithubRunOpts {
                clone_dir,
                include_forks,
                fix: fix || rewrite_branches,
                rewrite_branches,
                push,
                yes,
            };
            let outcomes = match wormward_github::pipeline::run(&opts, &host, &builtin_packs()) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            match format {
                OutputFormat::Text => print!("{}", report::render_github_text(&outcomes, yes)),
                OutputFormat::Json => println!("{}", report::render_github_json(&outcomes)),
            }
            let any_findings = outcomes.iter().any(|o| !o.findings.is_empty());
            let any_error = outcomes.iter().any(|o| o.error.is_some());
            if any_error {
                ExitCode::from(2)
            } else if any_findings {
                ExitCode::from(1)
            } else {
                ExitCode::from(0)
            }
        }
```

- [ ] **Step 3: Add renderers**

In `report.rs`:

```rust
use wormward_github::pipeline::RepoOutcome;

pub fn render_github_text(outcomes: &[RepoOutcome], applied: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!("Checked {} repo(s).\n", outcomes.len()));
    for o in outcomes {
        out.push_str(&format!(
            "\n{} — {} finding(s){}\n",
            o.repo.full_name,
            o.findings.len(),
            o.error.as_ref().map(|e| format!(" [error: {e}]")).unwrap_or_default(),
        ));
        for a in &o.actions {
            out.push_str(&format!("  action: {:?} -> {:?}\n", a.action.kind, a.status));
        }
        for r in &o.rewrites {
            out.push_str(&format!("  rewrite: {} -> {:?}\n", r.plan.branch, r.status));
        }
        if !o.pushed.is_empty() {
            out.push_str(&format!("  pushed: {}\n", o.pushed.join(", ")));
        }
    }
    if !applied {
        out.push_str("\n(dry-run; pass --yes to apply, --push to force-push)\n");
    }
    out
}

pub fn render_github_json(outcomes: &[RepoOutcome]) -> String {
    serde_json::to_string_pretty(outcomes).unwrap_or_else(|_| "[]".into())
}
```

Add `wormward-github = { path = "../wormward-github" }` is already added in Step 1; `report.rs` now references it, so no extra Cargo change.

- [ ] **Step 4: Smoke-test the CLI surface**

Run: `cargo build --workspace` then `cargo run -p wormward-cli -- github --help`
Expected: build succeeds; help lists `--token`, `--clone-dir`, `--include-forks`, `--fix`, `--rewrite-branches`, `--push`, `--yes`, `--format`.

Run: `cargo test --workspace`
Expected: PASS (all crates).

- [ ] **Step 5: Update the README**

Add a "Remediation" and "GitHub account mode" section to `README.md` documenting:

```text
wormward fix ~ --yes                         # strip payloads, delete artifacts, clean .gitignore
wormward fix ~ --rewrite-branches --yes      # also rewrite infected branch history (needs git filter-repo)
wormward github --fix --yes                  # scan + remediate every repo on your GitHub account
wormward github --fix --rewrite-branches --push --yes   # also force-push cleaned branches (backs up first)
```

Note the dry-run-by-default behavior and the `git filter-repo` requirement for branch rewriting.

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-cli/Cargo.toml crates/wormward-cli/src/main.rs crates/wormward-cli/src/report.rs README.md
git commit -m "Add github subcommand for account-wide scan and remediation"
```

---

## Final verification

- [ ] Run `cargo test --workspace` — all green.
- [ ] Run `cargo clippy --workspace --all-targets` — no new warnings (fix any introduced).
- [ ] Run `cargo run -p wormward-cli -- scan .` — confirms detection still works and is unchanged.
- [ ] Manual: `wormward fix <infected-fixture>` dry-run prints a plan; `--yes` cleans it; re-scan is clean.
