# GitHub Scan Speed Rebalance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore near-original GitHub-scan wall-clock speed (adaptive pacing + clone transfer diet) with zero loss of anti-flagging protection or detection coverage.

**Architecture:** Pacing becomes signal-gated in `wormward-github/src/lib.rs`; scan clones become `--no-checkout` + blob-size-filtered with tree-based default-tip scanning in `pipeline.rs`, with the two filesystem-only detection passes preserved via selective materialization. Supporting exports land in `wormward-core`. Spec: `docs/superpowers/specs/2026-08-17-github-scan-speed-design.md`.

**Tech Stack:** Rust only (no frontend changes).

## Global Constraints

- TDD: behavioral changes start with a test watched failing for the right reason.
- Do NOT run `cargo fmt`. No new third-party dependencies.
- Fixture commits use `--no-verify`; the standard infected payload string is `"export default {};\nglobal['!']='8-270-2';\n(\"rmcej%otb%\",2857687)\n"`.
- Fix-path clone behavior (Blobless / Full) must be byte-identical to today; only the scan clone shape changes.
- Run `cargo test -p wormward-github` (and `-p wormward-core` where core changes) before committing each task; full sweep is Task 4.

---

### Task 1: Adaptive pacing

**Files:**
- Modify: `crates/wormward-github/src/lib.rs` (`GitHubHost` struct/`new`; `call`'s pacing block and rate-limit arm; two existing mock-server tests)

**Interfaces:**
- Produces: pacing applies only while `pace_engaged` is true; `#[cfg(test)] pub(crate) fn pace_engaged_for_tests(&self) -> bool` accessor. Nothing else consumes this.

- [ ] **Step 1: Write the failing test state**

Add the field (default false), the accessor, and gate the existing pacing block — but do NOT yet set the flag anywhere:

```rust
    /// Pacing engages only after GitHub signals rate pressure (any 429, or a 403 with a
    /// rate signature). Healthy accounts keep full parallel speed; the first warning
    /// smooths every subsequent request for the host's lifetime. The secondary-limit
    /// breaker (serialization) layers on top unchanged.
    pace_engaged: std::sync::atomic::AtomicBool,
```

Initialize `pace_engaged: std::sync::atomic::AtomicBool::new(false)` in `GitHubHost::new`. Wrap the pacing block inside `call` (the block that locks `next_request`, computes `pace_slot`, and sleeps):

```rust
            if self.pace_engaged.load(std::sync::atomic::Ordering::Relaxed) {
                // ... existing pacing block unchanged ...
            }
```

Add near the other impl fns:

```rust
    /// Test-only visibility into pacing engagement.
    #[cfg(test)]
    pub(crate) fn pace_engaged_for_tests(&self) -> bool {
        self.pace_engaged.load(std::sync::atomic::Ordering::Relaxed)
    }
```

Then extend two existing mock-server tests:
- In `secondary_rate_limit_403_is_retried_then_surfaced` (next to the existing `assert!(host.throttle_hint())`): `assert!(host.pace_engaged_for_tests(), "a rate-limited response must engage pacing");`
- In the paginated success-path test (next to its existing `assert!(!host.throttle_hint(), ...)`): `assert!(!host.pace_engaged_for_tests(), "healthy traffic must stay unpaced");`

- [ ] **Step 2: Run, verify RED**

Run: `cargo test -p wormward-github secondary_rate_limit_403_is_retried_then_surfaced`
Expected: FAIL at the new engagement assertion (nothing sets the flag yet). The success-path test passes.

- [ ] **Step 3: Implement engagement**

In `call`'s rate-limit match arm (where `secondary_hit` is conditionally stored), unconditionally engage pacing for any rate-shaped response, before the retry sleep:

```rust
                    // Any rate-shaped response engages pacing for the host's lifetime:
                    // the retried request and everything after it goes out smoothed.
                    self.pace_engaged.store(true, std::sync::atomic::Ordering::Relaxed);
```

(Keep the existing `if retry_after.is_some() { secondary_hit ... }` as-is — the breaker stays secondary-only.)

- [ ] **Step 4: Run, verify GREEN**

Run: `cargo test -p wormward-github`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-github/src/lib.rs
git commit -m "perf(github): pace requests only after GitHub signals rate pressure"
```

---

### Task 2: `CloneShape` + core exports (parallel-safe with Task 1: different files)

**Files:**
- Modify: `crates/wormward-core/src/scanner.rs` (make `MAX_CONTENT_BYTES` and `scan_build_output` pub; new `disk_pass_dirs`)
- Modify: `crates/wormward-core/src/lib.rs` (exports)
- Modify: `crates/wormward-github/src/pipeline.rs` (`clone_repo` signature + both call sites)

**Interfaces:**
- Produces (Task 3 consumes): `wormward_core::MAX_CONTENT_BYTES: usize`, `wormward_core::disk_pass_dirs() -> Vec<&'static str>`, `wormward_core::scan_build_output(repo, packs)`; `enum CloneShape { Blobless, Full, ScanDiet }` in pipeline.rs; `clone_repo(repo, dest, token, shape: CloneShape, depth)`.
- Behavior guard: `Blobless`/`Full` produce exactly today's git args; `ScanDiet` is wired at `fallback_clone_scan`'s call site in THIS task (Task 3 restructures the rest of that function). Note: after this task the scan clone is `--no-checkout`, so `fallback_clone_scan`'s working-tree scan would find nothing — Task 3 immediately follows; to keep THIS task's tree green, wire `ScanDiet` args WITHOUT `--no-checkout` first (filter only), and let Task 3 add `--no-checkout` when it switches to tree scanning. The enum's doc comment states this staging.

- [ ] **Step 1: Core exports (mechanical; existing tests are the net)**

In `crates/wormward-core/src/scanner.rs`:
- `const MAX_CONTENT_BYTES` → `pub const MAX_CONTENT_BYTES`, and extend its doc comment: "Exported so scan clones can `--filter=blob:limit=` on the same threshold — the scanner never reads bigger files, so bigger blobs are dead transfer weight."
- `fn scan_build_output` → `pub fn scan_build_output` (doc comment already present).
- Add near `NOT_BUILD_SCANNED`:

```rust
/// Dirs whose detection passes read the FILESYSTEM rather than a git tree: the
/// build-output dirs covered by [`scan_build_output`] plus `node_modules` (the
/// installed-package sweep). A checkout-less scan clone materializes exactly these
/// dirs when committed, so both passes keep their coverage without a full checkout.
pub fn disk_pass_dirs() -> Vec<&'static str> {
    let mut dirs: Vec<&'static str> = crate::surface::EXCLUDED_DIRS
        .iter()
        .filter(|d| !NOT_BUILD_SCANNED.contains(d))
        .copied()
        .collect();
    dirs.push("node_modules");
    dirs
}
```

(If `EXCLUDED_DIRS`'s type makes `.copied()` wrong, adapt — it is a `&[&str]`-shaped constant; check `crates/wormward-core/src/surface.rs`. `NOT_BUILD_SCANNED` contains `.wormward-backup` and `target` — those are correctly excluded here too; `node_modules` is added back explicitly because the node_modules sweep IS a disk pass.)

In `crates/wormward-core/src/lib.rs`, add `scan_build_output`, `disk_pass_dirs`, and `MAX_CONTENT_BYTES` to the `pub use scanner::{...}` list.

Run: `cargo test -p wormward-core` — all pass (pure visibility changes).

- [ ] **Step 2: Write the failing enum test**

In `pipeline.rs` tests — the guard that `ScanDiet` transfers less than `Full` is not directly assertable offline, but the args are. Make `clone_shape_args` a pure function so it is testable:

```rust
    #[test]
    fn clone_shape_args_match_their_consumers() {
        assert_eq!(clone_shape_args(CloneShape::Blobless), vec!["--filter=blob:none".to_string()]);
        assert_eq!(clone_shape_args(CloneShape::Full), Vec::<String>::new());
        assert_eq!(
            clone_shape_args(CloneShape::ScanDiet),
            vec![format!("--filter=blob:limit={}", wormward_core::MAX_CONTENT_BYTES)]
        );
    }
```

- [ ] **Step 3: Run, verify RED (compile failure → stub → assertion failure), then implement**

```rust
/// How much of the repo a clone transfers, per consumer.
#[derive(Clone, Copy, PartialEq, Debug)]
enum CloneShape {
    /// `--filter=blob:none`: refs/history without blobs; checkout materializes only the
    /// default tip's files. The FIX path's default (it touches only the default tree).
    Blobless,
    /// No filter: every blob. The FIX path when branch tips will be cleaned (worktree
    /// materialization would otherwise lazy-fetch blob-by-blob).
    Full,
    /// `--filter=blob:limit=MAX_CONTENT_BYTES`: the SCAN shape — the scanner never reads
    /// files above that size, so bigger blobs are dead transfer weight. (`--no-checkout`
    /// joins this shape when the scan switches to tree-based reading; staged separately
    /// so each change lands green.)
    ScanDiet,
}

fn clone_shape_args(shape: CloneShape) -> Vec<String> {
    match shape {
        CloneShape::Blobless => vec!["--filter=blob:none".to_string()],
        CloneShape::Full => Vec::new(),
        CloneShape::ScanDiet => {
            vec![format!("--filter=blob:limit={}", wormward_core::MAX_CONTENT_BYTES)]
        }
    }
}
```

Change `clone_repo`'s `blobless: bool` parameter to `shape: CloneShape`; replace the `if blobless { cmd.arg("--filter=blob:none"); }` block with `for a in clone_shape_args(shape) { cmd.arg(a); }`. Update the doc comment's blobless paragraph to describe the three shapes. Update both call sites:
- `fix_scanned`: `clone_repo(&sr.repo, &dest, token, if clean_branches { CloneShape::Full } else { CloneShape::Blobless }, None)`
- `fallback_clone_scan`: `clone_repo(repo, &dest, token, CloneShape::ScanDiet, Some(1))`

- [ ] **Step 4: Run, verify GREEN**

Run: `cargo test -p wormward-github && cargo test -p wormward-core`
Expected: all pass (ScanDiet without `--no-checkout` keeps the working-tree scan functional; blob-limit filtering is invisible to local-path fixtures, whose files are all tiny).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/scanner.rs crates/wormward-core/src/lib.rs crates/wormward-github/src/pipeline.rs
git commit -m "refactor(github): CloneShape enum + core exports for the scan clone diet"
```

---

### Task 3: Checkout-less tree-based scan clone

**Files:**
- Modify: `crates/wormward-github/src/pipeline.rs` (`fallback_clone_scan`; `CloneShape::ScanDiet` args gain `--no-checkout`; new helper + tests)

**Interfaces:**
- Consumes: Task 2's exports and `CloneShape`; `wormward_core::{GitTree, RepoFiles, rev_parse, scan_tree, scan_node_modules, scan_build_output, disk_pass_dirs}`.
- Produces: no new public surface; `fallback_clone_scan` behavior per spec.

- [ ] **Step 1: Write the failing coverage tests**

First find the payload strings the two disk passes detect: grep wormward-core's tests for `scan_build_output` and `scan_node_modules` usage (`grep -n "scan_build_output\|scan_node_modules" crates/wormward-core/src/scanner.rs` and read the nearby test fixtures) and reuse those exact fixture payloads. Then, in `pipeline.rs` tests:

```rust
    /// Bare origin whose default branch commits an infected file inside `dist/` — only
    /// the filesystem build-output pass detects it, so the clone path must materialize
    /// committed disk-pass dirs. `size` forces the clone route.
    fn make_dist_payload_origin(tmp: &TempDir, name: &str, dist_payload: &str) -> PathBuf {
        let src = tmp.path().join(format!("{name}-src"));
        std::fs::create_dir_all(src.join("dist")).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(src.join("readme.md"), "clean").unwrap();
        std::fs::write(src.join("dist/bundle.mjs"), dist_payload).unwrap();
        git_ok(&src, &["add", "-f", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "dist payload"]);
        let bare = tmp.path().join(format!("{name}.git"));
        Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .env("GIT_TEMPLATE_DIR", "")
            .arg(&bare)
            .status()
            .unwrap();
        git_ok(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git_ok(&src, &["push", "-q", "origin", "main"]);
        bare
    }

    #[test]
    fn clone_scan_detects_committed_build_output_payload() {
        let tmp = TempDir::new().unwrap();
        // PAYLOAD: copy the exact hidden-payload fixture string from wormward-core's
        // scan_build_output test (see Step 1 instructions) — do not invent one.
        let bare = make_dist_payload_origin(&tmp, "distpay", BUILD_OUTPUT_PAYLOAD);
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/distpay".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
                size: CLONE_SIZE_KB + 1,
                pushed_at: None,
            }],
        };
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: false,
            push: false,
            yes: false,
            orgs: vec![],
        };
        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        assert_eq!(
            scan.infected_full_names(),
            vec!["me/distpay".to_string()],
            "the build-output pass must still run on the clone path"
        );
    }

    #[test]
    fn clone_scan_detects_committed_node_modules_payload() {
        // Same shape with node_modules/<pkg>/… using the exact fixture the core
        // scan_node_modules tests detect; assert the repo is flagged via the clone route.
    }

    #[test]
    fn clone_scan_reports_auto_fixable_from_tree_reads() {
        // make_infected_origin fixture (strippable payload on the default tip),
        // size: CLONE_SIZE_KB + 1 → clone route. Assert scan_pass marks the repo
        // infected AND `scan.repos()[0].auto_fixable` — the read closure must work
        // without a checkout.
    }
```

Write all three fully (the second and third follow the first's shape; the third reuses `make_infected_origin` and asserts `auto_fixable`).

- [ ] **Step 2: Run, verify current state**

Run: `cargo test -p wormward-github clone_scan_`
Expected: all three PASS today (the clone still checks out and runs `scan_repo`). These are the safety net for the restructure — the RED for this task arrives in Step 3 when `--no-checkout` lands first, deliberately breaking them, and Step 4 restores them. Record both states.

- [ ] **Step 3: Flip ScanDiet to `--no-checkout`, watch the net catch it**

In `clone_shape_args`, ScanDiet becomes:

```rust
        CloneShape::ScanDiet => vec![
            format!("--filter=blob:limit={}", wormward_core::MAX_CONTENT_BYTES),
            "--no-checkout".to_string(),
        ],
```

Update the Task 2 args test's ScanDiet expectation accordingly. Run `cargo test -p wormward-github clone_scan_` — Expected: the three new tests (and other fallback-path tests) FAIL: no working tree, `scan_repo` finds nothing. That failure is the RED proving the tests guard the restructure.

- [ ] **Step 4: Restructure `fallback_clone_scan`**

```rust
/// Full local clone + scan for repos the API path shouldn't enumerate (big or truncated
/// trees). The clone is checkout-less and blob-size-filtered (CloneShape::ScanDiet): the
/// default tip is scanned as a git TREE — exact parity with the API path, whose
/// `.git/hooks`/reflog passes are working-tree-only and legitimately absent — and the
/// deep scan reads other tips via cat-file as always. The two FILESYSTEM detection
/// passes (committed build-output payloads, installed node_modules sweep) keep their
/// coverage via selective materialization: exactly the committed surface dirs are
/// checked out (usually none exist, so the common case pays nothing). The temp clone is
/// deleted on return; a later fix re-clones like any other repo.
fn fallback_clone_scan(repo: &RepoRef, packs: &[Pack], token: &str) -> ScannedRepo {
    let mut out = ScannedRepo {
        repo: repo.clone(),
        findings: Vec::new(),
        error: None,
        auto_fixable: false,
        branch_fixable: false,
    };
    let tmp = match tempfile::TempDir::new() {
        Ok(t) => t,
        Err(e) => {
            out.error = Some(format!("tempdir: {e}"));
            return out;
        }
    };
    let dest = tmp.path().join(sanitize_full_name(&repo.full_name));
    if let Err(e) = clone_repo(repo, &dest, token, CloneShape::ScanDiet, Some(1)) {
        out.error = Some(e);
        return out;
    }
    // Unborn HEAD (empty repo): nothing to scan — same as the API path's empty-branches
    // early return.
    let Some(head) = wormward_core::rev_parse(&dest, "HEAD") else {
        return out;
    };
    let Some(tree) = wormward_core::GitTree::new(&dest, &head) else {
        return out;
    };
    let mut findings = wormward_core::scan_tree(&dest, &tree, packs);
    // Disk-only passes: materialize exactly the committed surface dirs, if any.
    let committed_dirs: Vec<&str> = {
        let tops = top_level_tree_names(&dest, &head);
        wormward_core::disk_pass_dirs().into_iter().filter(|d| tops.contains(*d)).collect()
    };
    if !committed_dirs.is_empty() {
        let mut args = vec!["checkout", head.as_str(), "--"];
        args.extend(committed_dirs.iter().copied());
        // Best-effort: a failed materialization only narrows the two disk passes back
        // to nothing, never fails the scan.
        let _ = git(&dest, &args);
        findings.extend(wormward_core::scan_build_output(&dest, packs));
        findings.extend(wormward_core::scan_node_modules(&dest, packs));
    }
    findings.extend(deep_scan_repo(&dest, packs));
    // Fixability from tree reads (no checkout exists), same content `fix_scanned`'s
    // fresh clone will see.
    {
        use wormward_core::RepoFiles;
        out.auto_fixable = is_auto_fixable(&findings, packs, |rel| tree.read(rel));
    }
    out.branch_fixable = findings.iter().any(|f| f.git_ref.is_some() && f.remediable);
    // Re-label onto the virtual repo path: the temp clone path would dangle.
    let label = PathBuf::from(&repo.full_name);
    for f in &mut findings {
        f.repo = label.clone();
    }
    out.findings = findings;
    out
}

/// Top-level entry names of a commit's tree (`git ls-tree --name-only <commit>`, no -r).
fn top_level_tree_names(repo: &Path, commit: &str) -> std::collections::HashSet<String> {
    let out = wormward_core::proc::git()
        .arg("-C")
        .arg(repo)
        .args(["ls-tree", "--name-only", commit])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::to_string)
            .collect(),
        _ => Default::default(),
    }
}
```

Adapt imports to the file's existing style (several of these may already be imported at the top — check; `scan_node_modules`'s exact signature must be checked in wormward-core's lib.rs export before calling: adapt the call to it, and if it returns findings with absolute/relative path conventions differing from the other passes, mirror how `scan_repo` invokes it — read `scan_repo`'s body first).

- [ ] **Step 5: Run, verify GREEN across the crate**

Run: `cargo test -p wormward-github`
Expected: all pass, including the three Step-1 tests and every pre-existing fallback/truncated-tree/cache/fix test. Pre-existing tests that relied on working-tree scanning of the clone (if any assert working-tree-specific findings) need inspection, not blind edits — report any that had to change and why.

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-github/src/pipeline.rs
git commit -m "perf(github): checkout-less blob-limited scan clones with tree-based scanning"
```

---

### Task 4: Full verification sweep

**Files:** none (verification only)

- [ ] **Step 1:** `cargo test --workspace` — all pass.
- [ ] **Step 2:** `cd apps/desktop/src-tauri && cargo test` — all pass.
- [ ] **Step 3:** `cd apps/desktop && npm run check && npm test` — clean (no frontend changes expected; this is the regression net).
- [ ] **Step 4:** `cargo clippy --workspace 2>&1 | grep -c "^warning"` — at main's baseline (2). Do NOT run `cargo fmt`.
