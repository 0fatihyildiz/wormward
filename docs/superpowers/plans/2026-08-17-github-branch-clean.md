# GitHub Fix: Clean Infected Branch Tips — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `wormward github --fix --push` (and the desktop GitHub fix) rewrites infected branch tips clean and force-pushes them, with old tips preserved on the remote; branch-only repos become selectable.

**Architecture:** Reuse the local branch-clean machinery (`deep_scan_repo` → `plan_branch_cleans` → `apply_branch_cleans`) on the fix clone inside `fix_scanned` (crates/wormward-github/src/pipeline.rs). Backups are pushed to the remote as `wormward-backup/<leaf>-<ts>` branches because the clone is throwaway. Spec: `docs/superpowers/specs/2026-08-17-github-branch-clean-design.md`.

**Tech Stack:** Rust (cargo workspace), Tauri desktop backend (`apps/desktop/src-tauri`), Svelte frontend.

## Global Constraints

- TDD: every behavior change starts with a test you watch fail.
- Do NOT run `cargo fmt` (the repo has 603 pre-existing diffs on main; formatting is not enforced). Match surrounding style by hand.
- Pipeline tests run offline: bare fixture repos + `GitFakeHost` (serves the API from local git), file-path clone URLs. Follow the existing fixtures in `pipeline.rs`'s test module.
- Test payload string for infected fixtures (exactly): `"export default {};\nglobal['!']='8-270-2';\n(\"rmcej%otb%\",2857687)\n"` — the `rmcej%otb%` literal is the detection signature, `global['!']=` is the strip marker. Fixture commits need `--no-verify` (this machine has a worm-scanning pre-commit hook).
- Run tests from the workspace root with `cargo test -p wormward-github` unless stated otherwise. Desktop backend tests: `cd apps/desktop/src-tauri && cargo test`. Frontend: `cd apps/desktop && npm run check && npm test`.

---

### Task 1: `fix_scanned` cleans infected branch tips

**Files:**
- Modify: `crates/wormward-github/src/pipeline.rs` (imports at top; `fix_scanned` ~line 488; new helpers `fix_default_branch`, `fix_branch_tips`; new tests + one fixture in the test module)

**Interfaces:**
- Consumes: `deep_scan_repo`, `now_secs` (already imported at pipeline.rs:12); `apply_branch_cleans`, `plan_branch_cleans`, `branch_manual_findings`, `BranchCleanStatus` from `wormward_core` (add to the import list).
- Produces: `fix_scanned` unchanged signature; cleaned branches appear in `RepoOutcome.actions` as `"cleaned branch <name>"` strings and their leaf names in `RepoOutcome.pushed`. Task 2 relies on the `branch_preview` gate added here. Task 3 relies on nothing from this task but tests build on the same fixtures.

- [ ] **Step 1: Add fixture + write the failing test**

In the `pipeline.rs` test module, add a fixture for a repo infected on the default branch AND on a branch sharing the same payload (the worm shape — also exercises the HEAD-shared replay path end-to-end), plus two small bare-repo assertion helpers:

```rust
    /// Bare origin whose default branch (`main`) AND an `evil` branch both carry the payload
    /// (`evil` = `main` + one unrelated file, so the payload blob is SHARED with main's tip).
    fn make_wt_and_branch_infected_origin(tmp: &TempDir, name: &str) -> PathBuf {
        let src = tmp.path().join(format!("{name}-src"));
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(
            src.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';\n(\"rmcej%otb%\",2857687)\n",
        )
        .unwrap();
        git_ok(&src, &["add", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "infected"]);
        git_ok(&src, &["checkout", "-q", "-b", "evil"]);
        std::fs::write(src.join("unrelated.txt"), "clean").unwrap();
        git_ok(&src, &["add", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "unrelated"]);
        git_ok(&src, &["checkout", "-q", "main"]);
        let bare = tmp.path().join(format!("{name}.git"));
        Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .env("GIT_TEMPLATE_DIR", "")
            .arg(&bare)
            .status()
            .unwrap();
        git_ok(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git_ok(&src, &["push", "-q", "origin", "main"]);
        git_ok(&src, &["push", "-q", "origin", "evil"]);
        bare
    }

    /// A committed file's content at `refname` in a bare repo ("" if missing).
    fn bare_file(bare: &Path, refname: &str, file: &str) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(bare)
            .args(["show", &format!("{refname}:{file}")])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Short branch names in a bare repo.
    fn bare_branches(bare: &Path) -> Vec<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(bare)
            .args(["for-each-ref", "--format=%(refname:short)", "refs/heads"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).lines().map(String::from).collect()
    }
```

Then the failing test (branch-only repo, fix with push):

```rust
    #[test]
    fn fix_cleans_branch_only_repo_and_backs_up_on_remote() {
        // The GitHub scan reports the infected `evil` tip; the fix must rewrite it clean,
        // force-push it, and preserve the old tip as a wormward-backup branch ON THE REMOTE
        // (the clone is throwaway, so a local backup ref would be a lie).
        let tmp = TempDir::new().unwrap();
        let bare = make_branch_only_infected_origin(&tmp, "branchonly");
        let old_evil = String::from_utf8_lossy(
            &Command::new("git").arg("-C").arg(&bare).args(["rev-parse", "evil"]).output().unwrap().stdout,
        )
        .trim()
        .to_string();
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/branchonly".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        };
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: true,
            push: true,
            yes: true,
            orgs: vec![],
        };
        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        let outcomes = fix_pass(&scan, &opts, &builtin_packs(), "", None);
        let o = &outcomes[0];
        assert!(o.error.is_none(), "unexpected error: {:?}", o.error);
        assert!(o.pushed.contains(&"evil".to_string()), "pushed: {:?}", o.pushed);
        assert!(!o.manual_review, "a fully cleaned branch-only repo is not manual work");
        // Remote `evil` no longer carries the payload; `main` is untouched.
        assert!(!bare_file(&bare, "evil", "postcss.config.mjs").contains("rmcej%otb%"));
        // Old tip preserved on the remote.
        let backup = bare_branches(&bare)
            .into_iter()
            .find(|b| b.starts_with("wormward-backup/evil-"))
            .expect("remote wormward-backup/evil-<ts> branch must exist");
        let backup_oid = String::from_utf8_lossy(
            &Command::new("git").arg("-C").arg(&bare).args(["rev-parse", &backup]).output().unwrap().stdout,
        )
        .trim()
        .to_string();
        assert_eq!(backup_oid, old_evil, "backup must point at the pre-clean tip");
    }
```

- [ ] **Step 2: Run the test, verify it fails for the right reason**

Run: `cargo test -p wormward-github fix_cleans_branch_only_repo_and_backs_up_on_remote`
Expected: FAIL at the `pushed` (or `manual_review`) assertion — today a branch-only repo early-returns with `manual_review = true` and touches nothing.

- [ ] **Step 3: Restructure `fix_scanned` and add `fix_branch_tips`**

In `pipeline.rs`:

3a. Extend the `wormward_core` import list (top of file, ~line 11-14) with `apply_branch_cleans`, `plan_branch_cleans`, `branch_manual_findings`, and `BranchCleanStatus`.

3b. In `fix_scanned`, replace the block from `let preview = plan_remediation(...)` through the dry-run early return with:

```rust
    // Branch-only infections have no working-tree action. Branch tips CAN be cleaned, but
    // only when pushing — a rewritten tip in a throwaway clone that is never pushed
    // accomplishes nothing. Without --push, branch findings keep routing to manual review.
    let preview = plan_remediation(&sr.findings, packs);
    let branch_preview = if opts.push {
        plan_branch_cleans(&sr.findings, packs, 0)
    } else {
        Vec::new()
    };
    if preview.actions.is_empty() && branch_preview.is_empty() {
        outcome.manual_review = true;
        return outcome;
    }

    // Dry run: report the actions that WOULD be applied. No clone, no writes.
    if !opts.yes {
        outcome.actions = preview.actions.iter().map(describe_action).collect();
        return outcome;
    }
```

(The dry-run branch lines are Task 2; leave the dry-run body as-is here.)

3c. Change the clone call: branch cleaning reads branch blobs, so a blobless clone would lazily re-fetch each one over the network. Replace `clone_repo(&sr.repo, &dest, token, true, None)` with:

```rust
    // Blobless unless branch tips will be cleaned: the default-branch fix only touches the
    // default working tree, but a branch clean materializes OTHER tips' blobs, which a
    // blobless clone would lazily re-fetch one network round-trip at a time.
    let clean_branches = !branch_preview.is_empty();
    if let Err(e) = clone_repo(&sr.repo, &dest, token, !clean_branches, None) {
```

3d. Extract everything from `let local = scan_repo(&dest, packs);` down to the end of the `if opts.push { ... }` force-push block into a helper (mechanical move — the body is unchanged except every `return outcome;` becomes `return;`):

```rust
/// The default-branch remediation exactly as it always worked: local re-scan, plan, apply,
/// residual-verify (revert on failure), commit, optional backup + force-push. Mutates
/// `outcome` in place; early-exits leave it exactly as the old early returns did.
fn fix_default_branch(
    dest: &Path,
    sr: &ScannedRepo,
    opts: &GithubRunOpts,
    packs: &[Pack],
    token: &str,
    outcome: &mut RepoOutcome,
) {
    // ... moved body ...
}
```

and end `fix_scanned` with:

```rust
    fix_default_branch(&dest, sr, opts, packs, token, &mut outcome);
    if clean_branches {
        // Runs even when the default-branch fix bailed to manual review: each branch clean
        // strips-and-verifies independently in its own worktree.
        fix_branch_tips(&dest, sr, packs, token, &mut outcome);
    }
    outcome
```

Note: `fix_default_branch` sets `outcome.manual_review` on its early exits; `fix_branch_tips` must only ever OR-in `true`, never reset it to `false`.

3e. Add the branch-clean helper:

```rust
/// Clean every infected NON-default branch tip of the fix clone and force-push the rewrites.
/// Plans are re-derived from a fresh local deep scan (same "re-scan at fix time" philosophy
/// as the default-branch path). `origin/<default>` is excluded: after the default-branch
/// commit, its stale remote-tracking ref would otherwise be re-planned as an "infected tip"
/// next to the default-branch force-push. Old tips are pushed to the remote as
/// `wormward-backup/<leaf>-<ts>` branches BEFORE each rewrite — the clone is deleted after
/// the run, so a local backup ref could not be used for recovery.
fn fix_branch_tips(
    dest: &Path,
    sr: &ScannedRepo,
    packs: &[Pack],
    token: &str,
    outcome: &mut RepoOutcome,
) {
    let deep = deep_scan_repo(dest, packs);
    let default_rt = format!("origin/{}", sr.repo.default_branch);
    let ts = now_secs();
    let plans: Vec<_> = plan_branch_cleans(&deep, packs, ts)
        .into_iter()
        .filter(|p| p.branch != default_rt)
        .collect();
    for plan in plans {
        let leaf = plan.branch.strip_prefix("origin/").unwrap_or(&plan.branch).to_string();
        // Remote backup first; a failed backup push skips the branch (mirrors the
        // default-branch behavior — never rewrite what wasn't backed up).
        let backup = format!("refs/remotes/origin/{leaf}:refs/heads/wormward-backup/{leaf}-{ts}");
        if let Err(e) = git(dest, &["push", "origin", "--", &backup]) {
            outcome.manual_review = true;
            if outcome.error.is_none() {
                outcome.error = Some(redact(format!("branch backup push: {e}"), token));
            }
            continue;
        }
        for bo in apply_branch_cleans(&[plan], false, true) {
            match bo.status {
                BranchCleanStatus::Cleaned { pushed: true, .. } => {
                    outcome.actions.push(format!("cleaned branch {}", bo.plan.branch));
                    outcome.pushed.push(leaf.clone());
                }
                // Cleaned-but-not-pushed persists nowhere (throwaway clone) — that is not a fix.
                BranchCleanStatus::Cleaned { pushed: false, .. }
                | BranchCleanStatus::Planned => outcome.manual_review = true,
                BranchCleanStatus::Skipped(m) | BranchCleanStatus::Failed(m) => {
                    outcome.manual_review = true;
                    if outcome.error.is_none() {
                        outcome.error = Some(redact(format!("clean {}: {m}", bo.plan.branch), token));
                    }
                }
            }
        }
    }
    // Branch findings no clean action covers stay manual work (IOC domains, capability
    // findings, ...). The stale `origin/<default>` ref's findings don't count — the
    // default-branch fix (or its own manual_review) already accounts for that branch.
    if branch_manual_findings(&deep, packs)
        .iter()
        .any(|f| f.git_ref.as_deref() != Some(default_rt.as_str()))
    {
        outcome.manual_review = true;
    }
}
```

- [ ] **Step 4: Run the new test, verify it passes**

Run: `cargo test -p wormward-github fix_cleans_branch_only_repo_and_backs_up_on_remote`
Expected: PASS

- [ ] **Step 5: Add the guard tests (write, then run — these should pass immediately; if one fails, the implementation is wrong, not the test)**

```rust
    #[test]
    fn fix_without_push_leaves_branches_untouched() {
        // Without --push a branch clean cannot persist (throwaway clone), so nothing may be
        // rewritten and the repo stays manual review — exactly the old behavior.
        let tmp = TempDir::new().unwrap();
        let bare = make_branch_only_infected_origin(&tmp, "nopush");
        let before = bare_file(&bare, "evil", "postcss.config.mjs");
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/nopush".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        };
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: true,
            push: false,
            yes: true,
            orgs: vec![],
        };
        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        let outcomes = fix_pass(&scan, &opts, &builtin_packs(), "", None);
        assert!(outcomes[0].manual_review);
        assert!(outcomes[0].pushed.is_empty());
        assert_eq!(bare_file(&bare, "evil", "postcss.config.mjs"), before);
        assert!(bare_branches(&bare).iter().all(|b| !b.starts_with("wormward-backup/")));
    }

    #[test]
    fn fix_cleans_default_branch_and_branch_tip_together() {
        // Worm shape: same payload on main AND evil. One fix pass cleans both on the remote.
        // Also proves origin/main is not double-cleaned via the branch path.
        let tmp = TempDir::new().unwrap();
        let bare = make_wt_and_branch_infected_origin(&tmp, "both");
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/both".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        };
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: true,
            push: true,
            yes: true,
            orgs: vec![],
        };
        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        let outcomes = fix_pass(&scan, &opts, &builtin_packs(), "", None);
        let o = &outcomes[0];
        assert!(o.error.is_none(), "unexpected error: {:?}", o.error);
        assert!(!bare_file(&bare, "main", "postcss.config.mjs").contains("rmcej%otb%"));
        assert!(!bare_file(&bare, "evil", "postcss.config.mjs").contains("rmcej%otb%"));
        assert!(o.pushed.contains(&"main".to_string()) && o.pushed.contains(&"evil".to_string()));
        // The default branch is cleaned by the default-branch path ONLY — no
        // "cleaned branch origin/main" duplicate from the branch cleaner.
        assert!(
            o.actions.iter().all(|a| a != "cleaned branch origin/main"),
            "origin/<default> must be excluded from branch plans: {:?}",
            o.actions
        );
        // The unrelated file on evil survives (tip rewritten, not reset to main).
        assert_eq!(bare_file(&bare, "evil", "unrelated.txt"), "clean");
    }
```

Run: `cargo test -p wormward-github fix_without_push_leaves_branches_untouched fix_cleans_default_branch_and_branch_tip_together` — Expected: both PASS. Then the whole crate: `cargo test -p wormward-github` — Expected: all pass (the existing `branch_only_infection_is_reported_but_not_a_fix_candidate` test still passes: it uses `push: false` and only asserts on scan-pass selection, which this task does not touch).

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-github/src/pipeline.rs
git commit -m "feat(github): clean infected branch tips in the fix pass, with remote backups"
```

---

### Task 2: Dry run lists branch cleans

**Files:**
- Modify: `crates/wormward-github/src/pipeline.rs` (the dry-run block inside `fix_scanned`; one new test)

**Interfaces:**
- Consumes: the `branch_preview: Vec<BranchCleanPlan>` binding added in Task 1 (in scope right above the dry-run block) and `describe_action`.
- Produces: dry-run `RepoOutcome.actions` entries of the exact form `"branch {branch}: {describe_action(a)}"` (branch names here come from the API findings, e.g. `evil` — the applied path's names come from the clone's remote-tracking refs, e.g. `origin/evil`; this cosmetic difference is called out in the spec).

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn dry_run_lists_branch_cleans_and_touches_nothing() {
        let tmp = TempDir::new().unwrap();
        let bare = make_branch_only_infected_origin(&tmp, "dryrun");
        let before = bare_file(&bare, "evil", "postcss.config.mjs");
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/dryrun".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        };
        // fix+push requested but NOT confirmed (`yes: false`) → dry run.
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: true,
            push: true,
            yes: false,
            orgs: vec![],
        };
        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        let outcomes = fix_pass(&scan, &opts, &builtin_packs(), "", None);
        let o = &outcomes[0];
        assert!(
            o.actions.iter().any(|a| a.starts_with("branch evil: ")),
            "dry run must list the branch cleans: {:?}",
            o.actions
        );
        assert!(o.pushed.is_empty());
        assert_eq!(bare_file(&bare, "evil", "postcss.config.mjs"), before);
        assert!(bare_branches(&bare).iter().all(|b| !b.starts_with("wormward-backup/")));
    }
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test -p wormward-github dry_run_lists_branch_cleans_and_touches_nothing`
Expected: FAIL at the `actions` assertion (dry run currently lists only working-tree actions — empty here).

- [ ] **Step 3: Implement**

In `fix_scanned`'s dry-run block (from Task 1 step 3b), after `outcome.actions = preview.actions...`:

```rust
    if !opts.yes {
        outcome.actions = preview.actions.iter().map(describe_action).collect();
        // Branch cleans that WOULD run. Names come from the API findings' refs (`evil`);
        // the applied path names come from the clone's remote-tracking refs (`origin/evil`).
        for bp in &branch_preview {
            for a in &bp.actions {
                outcome.actions.push(format!("branch {}: {}", bp.branch, describe_action(a)));
            }
        }
        return outcome;
    }
```

- [ ] **Step 4: Run it, verify it passes; run the crate**

Run: `cargo test -p wormward-github` — Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-github/src/pipeline.rs
git commit -m "feat(github): list branch cleans in the fix dry run"
```

---

### Task 3: Branch-only repos become selectable (`branch_fixable`)

**Files:**
- Modify: `crates/wormward-github/src/pipeline.rs` (`ScannedRepo` struct ~line 120; `api_scan_repo`; `fallback_clone_scan`; `ScanPass::fixable_full_names` ~line 188; flip one existing test)
- Modify: `crates/wormward-cli/src/main.rs` (stale comment above the selection block, ~line 936-941)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub branch_fixable: bool` on `ScannedRepo`; `fixable_full_names` returns repos with `auto_fixable || branch_fixable`. The desktop (`github_scan` → `fixable_full_names`) picks this up with no backend code change.

- [ ] **Step 1: Flip the existing selection test (this is the failing test)**

In `pipeline.rs` tests, rename `branch_only_infection_is_reported_but_not_a_fix_candidate` to `branch_only_infection_is_a_fix_candidate`, update its doc comment, and replace its final assertion block with:

```rust
        // Branch-only repos are now fixable too: the fix pass cleans branch tips when
        // pushing, so they are legitimate selection candidates alongside working-tree repos.
        let mut fixable = scan.fixable_full_names(&builtin_packs());
        fixable.sort();
        assert_eq!(fixable, vec!["me/branchonly".to_string(), "me/wt".to_string()]);
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test -p wormward-github branch_only_infection_is_a_fix_candidate`
Expected: FAIL — `fixable` is currently `["me/wt"]`.

- [ ] **Step 3: Implement**

3a. `ScannedRepo` gains a field (after `auto_fixable`):

```rust
    /// True when at least one branch-tip finding (`git_ref` set) is remediable — the scan
    /// stamped `remediable` against that tip's actual content, so a plannable strip exists.
    /// Such repos are fixable via the branch cleaner when pushing.
    pub branch_fixable: bool,
```

3b. Initialize `branch_fixable: false` in both `ScannedRepo { ... }` literal constructors (`api_scan_repo` ~line 327 and `fallback_clone_scan` ~line 259). Then set it where each function finishes assembling findings:
- In `api_scan_repo`, right before `Ok(out)` at the end: `out.branch_fixable = out.findings.iter().any(|f| f.git_ref.is_some() && f.remediable);`
- In `fallback_clone_scan`, right before `out.findings = findings;`: `out.branch_fixable = findings.iter().any(|f| f.git_ref.is_some() && f.remediable);`

3c. `fixable_full_names` filter becomes `r.is_infected() && (r.auto_fixable || r.branch_fixable)`, and its doc comment is updated:

```rust
    /// `full_name`s of infected repos the fix pass can actually remediate: a working-tree
    /// action on the default branch (`auto_fixable`) OR a cleanable branch tip
    /// (`branch_fixable`, applied when pushing). Repos with neither (nothing plannable at
    /// all) stay in the scan results but are not selection candidates.
```

3d. Update the stale CLI comment in `crates/wormward-cli/src/main.rs` (~line 936, "repos infected only on other branches are still reported but not selectable") to:

```rust
            // Selection only matters when we will actually write (fix/push + yes). A
            // dry-run never prompts. Offer every repo `fix_pass` can remediate: a
            // working-tree action on the default branch or a cleanable branch tip. Repos
            // with nothing plannable are still reported but not selectable. With >1
            // candidate, let the user deselect any to leave alone; JSON output or no TTY
            // keeps all.
```

- [ ] **Step 4: Run the crate's tests**

Run: `cargo test -p wormward-github && cargo test -p wormward-cli`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-github/src/pipeline.rs crates/wormward-cli/src/main.rs
git commit -m "feat(github): branch-only infected repos are selectable fix candidates"
```

---

### Task 4: Desktop copy — consent modal and repo-list chip

**Files:**
- Modify: `apps/desktop/src/routes/Advanced.svelte` (GitHub confirm modal `#ghfix-title` paragraph ~line 655; the `branch-only` chip ~line 542 and its footnote ~line 548)

**Interfaces:**
- Consumes: nothing — `GithubRepoView.fixable` already reflects Task 3's `fixable_full_names` via the unchanged desktop backend.
- Produces: copy only; no new props or types.

- [ ] **Step 1: Update the confirm-modal copy**

Replace the modal paragraph (inside `{#if confirming}`, under `<h3 id="ghfix-title">Force-push cleaned history?</h3>`):

```svelte
      <p class="crit small">
        <strong>This is destructive and remote.</strong> Wormward will remediate
        {selectedNames.length} selected repo(s) and <strong>force-push</strong> the cleaned
        default branch — and any infected branch tips — to their GitHub remotes, overwriting
        remote history. Every pre-clean tip is backed up as a <code>wormward-backup/…</code>
        branch on its remote first.
      </p>
```

- [ ] **Step 2: Update the chip + footnote**

The `branch-only` chip at ~line 542 marks repos with `!r.fixable`. After Task 3 those are repos with nothing plannable at all, so rename the label and footnote (keep the chip markup structure as-is):
- Chip text: `branch-only` → `manual review`
- Footnote (the `{#if repos.some((r) => !r.fixable)}` block): replace the sentence inside it with exactly:

```svelte
        Repos marked “manual review” have no automatic clean action — open them on GitHub and
        review the flagged files by hand.
```

- [ ] **Step 3: Verify**

Run: `cd apps/desktop && npm run check && npm test`
Expected: 0 errors, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add apps/desktop/src/routes/Advanced.svelte
git commit -m "feat(desktop): GitHub fix consent copy covers branch-tip rewrites"
```

---

### Task 5: Full verification sweep

**Files:** none (verification only)

- [ ] **Step 1: Workspace tests**

Run: `cargo test --workspace`
Expected: all crates pass, 0 failed.

- [ ] **Step 2: Desktop backend tests**

Run: `cd apps/desktop/src-tauri && cargo test`
Expected: all pass (7+ tests).

- [ ] **Step 3: Frontend**

Run: `cd apps/desktop && npm run check && npm test`
Expected: 0 errors / 0 warnings; all vitest tests pass.

- [ ] **Step 4: Clippy regression check**

Run: `cargo clippy --workspace 2>&1 | grep -c "^warning"`
Expected: no more warnings than main's pre-existing count (2). Do NOT run `cargo fmt`.
