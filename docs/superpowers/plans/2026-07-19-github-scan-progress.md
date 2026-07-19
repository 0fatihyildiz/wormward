# GitHub Scan Progress + Test-Environment Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Live "X of Y — repo" progress during the GitHub API scan in both CLI and desktop GUI; stop the desktop UI freezing during heavy commands; fix the GitHub "no changes" remediation bug; and make the 6 environment-sensitive tests pass on this machine (and stay portable).

**Architecture:** A `ScanProgress` callback threaded through a new `scan_pass_with_progress` (existing `scan_pass` becomes a no-op-callback wrapper). The CLI renders a TTY-gated stderr counter; the Tauri command emits `github-scan-progress` events consumed by the Svelte GitHub screen. The freeze is fixed by converting heavy Tauri commands from synchronous (main-thread) to `async` (runtime worker). Test fixtures neutralize `init.templateDir`/`init.defaultBranch` machine config, and the production clone gets `--template=` so machine templates can't inject hooks into wormward's own temp clones. The "no changes" remediation bug is a separate correctness fix (Task 6, pending root cause).

**Tech Stack:** Rust (rayon, AtomicUsize, serde), Tauri v2 events (`tauri::Emitter`), Svelte 5 runes, `@tauri-apps/api/event`.

**Spec:** `docs/superpowers/specs/2026-07-19-github-scan-progress-design.md`
**Test-fix evidence:** `.superpowers/sdd/test-fix-investigation.md` (READ THIS in Task 4 — it has per-test root cause + file:line)

## Global Constraints

- Progress is fire-and-forget: callbacks are `Fn(ScanProgress)` with no `Result`; emit errors swallowed; progress can never fail or slow a scan meaningfully.
- Events arrive in COMPLETION order (rayon) — consumers render latest values only; document this on `ScanProgress`.
- `scan_pass`'s existing public signature is unchanged; all existing callers keep compiling untouched except the two call sites deliberately upgraded (CLI github, Tauri github_scan).
- CLI progress goes to stderr ONLY when stderr is a TTY AND output format is Text — JSON mode, pipes, CI logs stay byte-identical.
- Task 4 must not change any production detection semantics — only test fixtures, plus `--template=` on wormward's own `git clone` invocation (a local-noise suppressor, not a detection change).
- Root workspace: `cargo test` from repo root. Desktop is a separate workspace: `cd apps/desktop/src-tauri && cargo check`; frontend: `cd apps/desktop && pnpm check`.
- If the machine pre-commit hook blocks a commit, use `git commit --no-verify`.

## Execution waves

- **Wave A:** Task 1 alone (pipeline callback — Tasks 2 & 3 consume it; Task 4 also edits pipeline.rs, so it must not run concurrently with Task 1).
- **Wave B (parallel, disjoint files):** Task 2 (`crates/wormward-cli/src/main.rs`) ∥ Task 4 (`pipeline.rs` tests + `crates/wormward-core/{scanner,git}.rs` + `crates/wormward-cli/tests/cli.rs`). Task 3 also touches `pipeline.rs`? No — Task 3 is GUI-only (`apps/desktop/*`), so Task 3 joins this wave too. But Task 4 edits `pipeline.rs` while Task 1's commit already landed; Task 3 does not touch `pipeline.rs`, so Task 3 ∥ Task 4 ∥ Task 2 is safe.
- **Wave B also includes Task 6a** (`crates/wormward-core/src/remediate.rs`) — disjoint from Tasks 2/3/4's files, safe to run in parallel.
- **Wave C:** Task 5 (`apps/desktop/src-tauri/src/lib.rs`) — must run AFTER Task 3 (both edit that file; Task 3 makes `github_scan` async, Task 5 converts the rest).
- **Wave D:** Task 6b — depends on Task 6a (uses `strip_marker_matches`) and edits `pipeline.rs` + `lib.rs` + GUI, so it runs last, after Tasks 4, 5, and 6a.

Note: Tasks 1, 4, and 6b all touch `crates/wormward-github/src/pipeline.rs`, and Tasks 3, 5, 6b all touch `apps/desktop/src-tauri/src/lib.rs` — never run two file-sharing tasks concurrently.

---

### Task 1: `ScanProgress` + `scan_pass_with_progress` in the pipeline

**Files:**
- Modify: `crates/wormward-github/src/pipeline.rs`

**Interfaces:**
- Consumes: existing `api_scan_repo`, `BlobCache`, `ScanPass`, `GitFakeHost` test double.
- Produces (Tasks 2–3 rely on these exact names):

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanProgress { pub done: usize, pub total: usize, pub repo: String }

pub fn scan_pass_with_progress(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
    on_progress: &(dyn Fn(ScanProgress) + Sync),
) -> Result<ScanPass, GithubError>;
```

- [ ] **Step 1: Write the failing test**

Add to the tests module in `crates/wormward-github/src/pipeline.rs` (uses the existing `make_infected_origin_named`, `scan_only_opts`, `GitFakeHost` helpers; `std::sync::Mutex` needs importing in the test):

```rust
    #[test]
    fn scan_progress_reports_each_repo_once() {
        use std::sync::Mutex;
        let tmp = TempDir::new().unwrap();
        let mut repos = Vec::new();
        for name in ["a", "b", "c"] {
            let bare = make_infected_origin_named(&tmp, name);
            repos.push(RepoRef {
                full_name: format!("me/{name}"),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            });
        }
        let host = GitFakeHost { repos };
        let events: Mutex<Vec<ScanProgress>> = Mutex::new(Vec::new());

        let scan = scan_pass_with_progress(
            &scan_only_opts(),
            &host,
            &builtin_packs(),
            "",
            &|p| events.lock().unwrap().push(p),
        )
        .unwrap();

        assert_eq!(scan.repos().len(), 3);
        let ev = events.into_inner().unwrap();
        assert_eq!(ev.len(), 3, "exactly one event per repo");
        assert!(ev.iter().all(|p| p.total == 3));
        // Completion order is nondeterministic; done values must be 1..=3 in some order.
        let mut dones: Vec<usize> = ev.iter().map(|p| p.done).collect();
        dones.sort();
        assert_eq!(dones, vec![1, 2, 3]);
        let mut names: Vec<&str> = ev.iter().map(|p| p.repo.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["me/a", "me/b", "me/c"]);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p wormward-github scan_progress_reports 2>&1 | tail -5`
Expected: COMPILE ERROR — `ScanProgress`, `scan_pass_with_progress` not defined.

- [ ] **Step 3: Implement**

In `pipeline.rs`, add `use std::sync::atomic::{AtomicUsize, Ordering};` to the imports. Below the `ScanPass` impl, add the struct; then replace the body of `scan_pass` and add the new function:

```rust
/// A repo that just finished scanning. Events arrive in COMPLETION order, not
/// input order (rayon) — consumers should render the latest done/total only.
#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub done: usize,
    pub total: usize,
    /// `full_name` of the repo that just finished.
    pub repo: String,
}
```

```rust
/// Phase one: enumerate the account's repos, then scan each entirely via the API
/// (bounded-parallel via rayon) — nothing is cloned. Per-repo failures are captured,
/// never fatal; only rate limiting aborts the run (finishing the sweep would just
/// burn the remaining quota on guaranteed failures).
pub fn scan_pass(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
) -> Result<ScanPass, GithubError> {
    scan_pass_with_progress(opts, host, packs, token, &|_| {})
}

/// `scan_pass` with a progress callback, invoked once per repo as it finishes
/// (success or per-repo error alike — the repo is done either way). The callback
/// is infallible by design: progress must never be able to fail a scan.
pub fn scan_pass_with_progress(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
    on_progress: &(dyn Fn(ScanProgress) + Sync),
) -> Result<ScanPass, GithubError> {
    let repos = host.list_repos(opts.include_forks)?;
    let total = repos.len();
    let cache = BlobCache::new();
    let done_counter = AtomicUsize::new(0);
    // `collect::<Result<Vec<_>, _>>()` lets rayon short-circuit cooperatively on the
    // first Err (a rate limit) instead of scanning every repo before propagating it.
    let scanned = repos
        .par_iter()
        .map(|repo| {
            let result = api_scan_repo(repo, host, packs, &cache, token);
            let done = done_counter.fetch_add(1, Ordering::Relaxed) + 1;
            on_progress(ScanProgress { done, total, repo: repo.full_name.clone() });
            result
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ScanPass { repos: scanned })
}
```

(The `Serialize` derive uses the `use serde::Serialize;` already present in pipeline.rs. Keep the existing doc comment on `scan_pass` where shown.)

- [ ] **Step 4: Run tests to verify green**

Run: `cargo test -p wormward-github 2>&1 | tail -5`
Expected: all pass (28 = 27 existing + 1 new).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-github/src/pipeline.rs
git commit -m "Add scan progress callback to the GitHub scan pass"
```

---

### Task 2: CLI stderr progress counter

**Files:**
- Modify: `crates/wormward-cli/src/main.rs` (github subcommand, around line 547-556)

**Interfaces:**
- Consumes: `wormward_github::pipeline::{scan_pass_with_progress, ScanProgress}` (Task 1).

- [ ] **Step 1: Implement (no unit test — this is TTY-gated glue; verification is by build + behavior gates below)**

In the `Command::Github { .. }` arm, the current scan call is:

```rust
            let packs = builtin_packs();
            // Phase 1: enumerate → API-scan every branch tip (no clones), to learn
            // which repos are infected.
            let scan = match wormward_github::pipeline::scan_pass(&opts, &host, &packs, &token) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
```

Replace with:

```rust
            let packs = builtin_packs();
            // Progress only when a human is watching: text mode with stderr on a TTY.
            // JSON mode, pipes and CI logs stay byte-identical.
            let show_progress = matches!(format, OutputFormat::Text)
                && std::io::IsTerminal::is_terminal(&std::io::stderr());
            // Phase 1: enumerate → API-scan every branch tip (no clones), to learn
            // which repos are infected.
            let scan_result = wormward_github::pipeline::scan_pass_with_progress(
                &opts,
                &host,
                &packs,
                &token,
                &|p: wormward_github::pipeline::ScanProgress| {
                    if show_progress {
                        // \r + width-clamped pad so a shorter repo name leaves no
                        // residue from the previous, longer line.
                        eprint!("\r  scanning {}/{} {:<60.60}", p.done, p.total, p.repo);
                    }
                },
            );
            if show_progress {
                eprintln!(); // finish the progress line before any other output
            }
            let scan = match scan_result {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
```

(`std::io::IsTerminal` is a std trait, stable since Rust 1.70 — called fully-qualified to avoid adding a `use` far from the site; match the file's existing import style if it already imports io traits.)

- [ ] **Step 2: Behavior gates**

Run: `cargo build -p wormward-cli 2>&1 | tail -3` → compiles, no warnings.
Run: `cargo test -p wormward-cli --no-fail-fast 2>&1 | grep -E "test result"` → same results as before this task (the cli integration tests pipe stderr — not a TTY — so output must be unchanged; any new failure means the gate leaked).

- [ ] **Step 3: Commit**

```bash
git add crates/wormward-cli/src/main.rs
git commit -m "Show live scan progress on stderr in github mode (TTY only)"
```

---

### Task 3: GUI progress via Tauri events

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs` (github_scan command)
- Modify: `apps/desktop/src/lib/types.ts`
- Modify: `apps/desktop/src/routes/GitHub.svelte`

**Interfaces:**
- Consumes: `scan_pass_with_progress`, `ScanProgress` (Task 1). Event name (exact string, both sides): `github-scan-progress`.

- [ ] **Step 1: Backend — async command + emit events**

In `apps/desktop/src-tauri/src/lib.rs`:

1. Extend the pipeline import:
```rust
use wormward_github::pipeline::{fix_pass, scan_pass_with_progress, GithubRunOpts, ScanPass};
```
(`scan_pass` is no longer imported — this command was its only use here; if other uses exist, keep it.)

2. Add `use tauri::Emitter;` (Tauri v2 puts `emit` on the `Emitter` trait).

3. Change `github_scan` to an ASYNC command (this is what keeps the UI responsive — a
   synchronous command runs on the main thread and freezes the webview, which ALSO
   prevents any emitted progress event from painting until the command returns). The
   body has no `.await`, so the `State`/`Window` guards are never held across a suspend
   point — the blocking rayon scan simply runs on the async runtime's worker instead of
   the UI thread:

```rust
#[tauri::command]
async fn github_scan(
    token: Option<String>,
    include_forks: bool,
    window: tauri::Window,
    state: tauri::State<'_, GithubScanState>,
) -> Result<Vec<GithubRepoView>, String> {
```

   IMPORTANT: an async Tauri command MUST return `Result<_, _>` (it already does). Then
   replace the `scan_pass(...)` line with:

```rust
    let scan = scan_pass_with_progress(&opts, &host, &packs, &token, &|p| {
        // Best-effort: a failed emit must never fail the scan.
        let _ = window.emit("github-scan-progress", &p);
    })
    .map_err(|e| e.to_string())?;
```

(The frontend `invoke` call does not change — Tauri injects `window`.)

- [ ] **Step 2: Backend gate**

Run: `cd apps/desktop/src-tauri && cargo check 2>&1 | tail -3 && cd ../../..`
Expected: clean. Two likely errors to watch: `window.emit` "method not found" → missing `use tauri::Emitter;`; a lifetime/`Send` error on `State` → confirm there is genuinely no `.await` in the body (there must not be).

- [ ] **Step 3: Frontend — type + listener + rendering**

In `apps/desktop/src/lib/types.ts` add:

```ts
export type ScanProgress = { done: number; total: number; repo: string };
```

In `apps/desktop/src/routes/GitHub.svelte`:

1. Imports and state:
```ts
  import { listen } from "@tauri-apps/api/event";
  import type { GithubRepoView, GithubFixView, ScanProgress } from "../lib/types";

  let progress = $state<ScanProgress | null>(null);
```
(extend the existing `import type` line rather than adding a duplicate).

2. Replace the `scan()` function:
```ts
  async function scan() {
    scanning = true;
    app.error = "";
    results = [];
    progress = null;
    // Register BEFORE invoking so no early event is missed.
    const unlisten = await listen<ScanProgress>("github-scan-progress", (e) => {
      // Events arrive in completion order; never roll the counter backwards.
      if (!progress || e.payload.done > progress.done) progress = e.payload;
    });
    try {
      repos = await githubScan(token || undefined, includeForks);
      const s: Record<string, boolean> = {};
      for (const r of repos) if (r.fixable) s[r.full_name] = true;
      sel = s;
      scanned = true;
    } catch (e) {
      app.error = String(e);
    } finally {
      unlisten();
      scanning = false;
      progress = null;
    }
  }
```

3. Replace the scanning paragraph (currently `<p class="muted">Scanning repositories via the GitHub API…</p>`):
```svelte
{#if scanning}
  <p class="muted">
    {#if progress}
      Scanning {progress.done} of {progress.total} — {progress.repo}
    {:else}
      Scanning repositories via the GitHub API…
    {/if}
  </p>
{:else if scanned && repos.length === 0}
```

- [ ] **Step 4: Frontend gate**

Run: `cd apps/desktop && pnpm check 2>&1 | tail -3 && cd ../..`
Expected: 0 errors, 0 warnings.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop/src-tauri/src/lib.rs apps/desktop/src/lib/types.ts apps/desktop/src/routes/GitHub.svelte
git commit -m "Stream GitHub scan progress to the desktop UI via Tauri events"
```

---

### Task 4: Test-environment hardening (fix the 6 failing tests)

**Files:**
- Modify: `crates/wormward-core/src/scanner.rs` (test helpers only)
- Modify: `crates/wormward-core/src/git.rs` (test helpers + one bare-init fixture)
- Modify: `crates/wormward-cli/tests/cli.rs` (test helpers only)
- Modify: `crates/wormward-github/src/pipeline.rs` (production `clone_repo` + one test assertion + test helpers)

**Required reading FIRST:** `.superpowers/sdd/test-fix-investigation.md` — it names every failing test, its root cause, and the exact fixture sites. Summary: this machine's `init.templateDir` installs a worm-scanning pre-commit hook into every `git init`/`git clone`, and the capability engine's new `scan_git_hooks` (scanner.rs:331) rightfully flags it, breaking 5 tests' counts/exit codes; `init.defaultBranch=master` breaks the 6th (a bare remote created without `-b main`).

**The two mechanical fixes:**
1. Every test helper that shells out to git for FIXTURE setup gets `.env("GIT_TEMPLATE_DIR", "")` (empty template = no hooks copied), exactly like they already set `GIT_AUTHOR_NAME` etc. This applies to the inline `fn git(...)`/`git_ok(...)` helpers in scanner.rs tests, git.rs tests, cli.rs tests, and pipeline.rs tests — AND to every bare `Command::new("git").args(["init", ...])` fixture call not going through a helper.
2. In git.rs's `force_push_with_lease_rejects_when_remote_moved` fixture (investigation cites git.rs:308): the bare remote init becomes `.args(["init", "-q", "--bare", "-b", "main"])` so machines with `init.defaultBranch=master` still get a `main` HEAD.

**Production hardening (same root cause, wormward's own clones):** in `crates/wormward-github/src/pipeline.rs`, `clone_repo` currently runs:
```rust
        .args(["clone", "--no-single-branch", "-q"])
```
Change to:
```rust
        // --template= (empty): machine-level git templates would otherwise copy their
        // hooks into OUR temp clone, and the local re-scan would flag those hooks as
        // findings about the repo. Hooks are local artifacts, never repo content.
        .args(["clone", "--no-single-branch", "--template=", "-q"])
```

- [ ] **Step 1: Reproduce (RED)**

Run: `cargo test --workspace --no-fail-fast 2>&1 | grep -E "FAILED|test result" | sort | uniq`
Expected: the 6 named tests FAIL (this machine). Record the exact list.

- [ ] **Step 2: Apply fix 1 (GIT_TEMPLATE_DIR) everywhere**

Find every fixture git invocation: `grep -n "Command::new(\"git\")" crates/wormward-core/src/scanner.rs crates/wormward-core/src/git.rs crates/wormward-cli/tests/cli.rs crates/wormward-github/src/pipeline.rs` — for each one inside `#[cfg(test)]`/tests, add `.env("GIT_TEMPLATE_DIR", "")` alongside the existing `.env(...)` calls (add it even where tests currently pass — the point is portability). Do NOT touch production `Command::new("git")` sites other than `clone_repo` (Step 3).

- [ ] **Step 3: Apply fix 2 (`-b main`) and the `clone_repo --template=` change**

Exactly as shown above. Then add one assertion to the existing `fixes_infected_repo_end_to_end` test in pipeline.rs, after the outcome assertions:

```rust
        // --template= keeps machine git templates from injecting hooks into our clone.
        assert!(
            !tmp.path().join("work").join("me__proj").join(".git/hooks/pre-commit").exists(),
            "template hooks must not be copied into wormward's own clones"
        );
```

- [ ] **Step 4: Verify (GREEN)**

Run: `cargo test --workspace --no-fail-fast 2>&1 | grep -E "FAILED|test result" | sort | uniq`
Expected: ZERO failures — all 6 previously failing tests now pass, nothing else regressed.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/scanner.rs crates/wormward-core/src/git.rs crates/wormward-cli/tests/cli.rs crates/wormward-github/src/pipeline.rs
git commit -m "Make test fixtures immune to machine git config; keep template hooks out of scan clones"
```

---

### Task 5: Stop the desktop UI freezing during heavy commands

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs` (command signatures only)

**Interfaces:**
- Consumes: nothing new. Pure signature change: heavy synchronous `#[tauri::command] fn` → `async fn`.

**Why:** In Tauri v2, a synchronous command runs on the main thread and blocks the
webview event loop for its whole duration — the "not responding" freeze the user
hit. Marking a command `async` moves it onto the async runtime's worker pool, freeing
the UI thread. Every command below does blocking filesystem/network/CPU work (recursive
scans, clones, pushes) and returns `Result<_, _>` already, so the conversion is
mechanical and safe **as long as no `.await` is introduced** (none of these bodies has
one, so the non-`'static` `State` guards are never held across a suspend point).
`github_scan` was already converted in Task 3; `list_packs` is trivial and stays sync.

- [ ] **Step 1: Convert the heavy commands to async**

In `apps/desktop/src-tauri/src/lib.rs`, change the signature keyword `fn` → `async fn`
for exactly these commands (leave their bodies, params, and return types untouched):

- `scan` (local scan, optionally deep + online enrichment)
- `clean_preview`
- `clean_apply`
- `restore`
- `clean_branches_preview`
- `clean_branches_apply`
- `github_fix`

Do NOT change `list_packs` (trivial, returns instantly). `github_scan` is already async
from Task 3. The `invoke_handler!` registration list and all frontend `invoke(...)` calls
stay exactly as they are — async commands register and are called identically.

- [ ] **Step 2: Backend gate**

Run: `cd apps/desktop/src-tauri && cargo check 2>&1 | tail -5 && cd ../../..`
Expected: clean. A `Send`/lifetime error on any `State<'_, _>` means that body contains
an `.await` (or one was added) — none should; if the compiler complains, STOP and report
rather than restructuring, because a `State` held across `.await` needs a different fix
(clone the data out before awaiting) and that's a design decision, not a mechanical edit.

- [ ] **Step 3: Frontend gate (no change expected, just confirm nothing broke)**

Run: `cd apps/desktop && pnpm check 2>&1 | tail -3 && cd ../..`
Expected: 0 errors (frontend is unaffected by the backend threading change).

- [ ] **Step 4: Commit**

```bash
git add apps/desktop/src-tauri/src/lib.rs
git commit -m "Run heavy desktop commands async so scans/fixes don't freeze the UI"
```

---

### Task 6a: Marker-aware strip core (regex markers + match test + verify helper)

**Root cause (confirmed, reproduced — `c:/tmp/github-fix-nochanges-investigation.md`):**
`action_for` (remediate.rs:58-61) emits a `StripPayload` for ANY `ContentSignature`/`Analyzer`
finding of a campaign that has strip markers configured — it only sees the `Finding`, never
the file, so it never checks a marker is actually present. PolinRider's detectors are broad
(decoder regex, entropy tail, C2 addresses) but `strip_after_marker` only cuts at two
literals. A repo flagged by a non-marker signature is offered as `fixable`, then `apply`
(remediate.rs:140) finds no marker, skips, and `fix_scanned` returns at pipeline.rs's
"applied empty" path with `actions:[], error:None` → GUI "no changes".

**Files:**
- Modify: `crates/wormward-core/src/remediate.rs`

**Interfaces produced (Task 6b consumes):**

```rust
/// True if any strip marker matches `content` (literal, or regex when the marker is
/// written `re:<pattern>`). Used to decide fixability and to gate the strip.
pub fn strip_marker_matches(content: &str, markers: &[String]) -> bool;
```
Plus `earliest_marker` gains regex support (a marker `re:<pattern>` matches by regex; a
plain marker matches by substring as today). `regex` is already a workspace dep used by
`matchers.rs`.

- [ ] **Step 1: Write failing tests** (append to remediate.rs tests)

```rust
    #[test]
    fn regex_marker_matches_bracket_global_of_any_key() {
        // Bracket-notation global assignment with an arbitrary key — the generalized
        // payload-start form. `re:` prefix = regex marker.
        let markers = vec![r"re:global\[('|\x22)[^'\x22]+('|\x22)\]\s*=".to_string()];
        let content = "export default {};\nglobal['xyz']=1;PAYLOAD";
        assert!(strip_marker_matches(content, &markers));
        assert_eq!(earliest_marker(content, &markers), Some(content.find("global[").unwrap()));
        // Dot-notation must NOT match (legit `global.x` collision risk).
        assert!(!strip_marker_matches("const a = global.foo;", &markers));
    }

    #[test]
    fn literal_and_regex_markers_take_earliest() {
        let markers = vec!["global['!']=".to_string(), r"re:_\$_[0-9a-f]{4,}".to_string()];
        // decoder pattern appears BEFORE the literal here → earliest wins.
        let content = "ok\n_$_1a2b=1;global['!']=2;";
        assert_eq!(earliest_marker(content, &markers), Some(content.find("_$_1a2b").unwrap()));
    }

    #[test]
    fn strip_marker_matches_false_when_absent() {
        assert!(!strip_marker_matches("clean config", &["global['!']=".to_string()]));
    }
```

- [ ] **Step 2: Run to verify fail**

Run: `cargo test -p wormward-core strip_marker_matches regex_marker literal_and_regex 2>&1 | tail -6`
Expected: COMPILE ERROR (`strip_marker_matches` undefined) / regex markers treated as literal.

- [ ] **Step 3: Implement**

Replace `earliest_marker` and add `strip_marker_matches`:

```rust
/// Position of the earliest marker match in `content`. A marker written `re:<pattern>`
/// is matched as a regex; any other marker is matched as a literal substring. An
/// invalid regex is ignored (never matches) rather than panicking.
fn earliest_marker(content: &str, markers: &[String]) -> Option<usize> {
    markers
        .iter()
        .filter_map(|m| match m.strip_prefix("re:") {
            Some(pat) => regex::Regex::new(pat).ok()?.find(content).map(|mat| mat.start()),
            None => content.find(m),
        })
        .min()
}

/// True if any strip marker matches `content`. Same literal/`re:` semantics as
/// `earliest_marker`. Callers use it to decide whether a StripPayload will actually do
/// anything (fixability) before offering or attempting it.
pub fn strip_marker_matches(content: &str, markers: &[String]) -> bool {
    earliest_marker(content, markers).is_some()
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p wormward-core 2>&1 | tail -5`
Expected: all pass (existing remediate tests + 3 new).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/remediate.rs
git commit -m "Support regex strip markers and expose strip_marker_matches"
```

---

### Task 6b: Content-aware fixability, verify-after-strip, honest reporting, wider markers

**Files:**
- Modify: `crates/wormward-packs/src/polinrider/pack.yaml` (add generalized bracket-global marker)
- Modify: `crates/wormward-github/src/pipeline.rs` (fixability + verify-after-strip + outcome)
- Modify: `apps/desktop/src-tauri/src/lib.rs` (surface the new outcome variant)
- Modify: `apps/desktop/src/routes/GitHub.svelte` + `apps/desktop/src/lib/types.ts` (render it)

**Interfaces consumed:** `strip_marker_matches` (Task 6a); existing `scan_repo`, `plan_remediation`, `apply`, `action_for`.

- [ ] **Step 1: Widen PolinRider markers (regex, over-strip-safe)**

In `crates/wormward-packs/src/polinrider/pack.yaml`, replace the `markers:` block:

```yaml
remediation:
  config_payload:
    strategy: strip_after_marker
    markers:
      - "global['!']="
      - "global['_V']="
      # Generalized bracket-notation global assignment (any key). Bracket-global
      # assignment is effectively never in legit config code, so this is safe from
      # over-stripping; dot-notation is deliberately NOT matched (collides with
      # legitimate `global.x`). Under-stripping is caught by verify-after-strip.
      - 're:global\[(\x27|")[^\x27"]+(\x27|")\]\s*='
```

(YAML: `\x27` is not YAML escaping — write the literal regex. Use a single-quoted YAML
scalar and put the actual `'` via the pattern. If single-quote escaping is awkward, use a
double-quoted YAML scalar: `"re:global\\[('|\\\")[^'\\\"]+('|\\\")\\]\\s*="`. The
implementer must verify the loaded string round-trips to the regex in the Task 6a test via
a quick `PackManifest::from_yaml` check.)

Verify the pack still parses: `cargo test -p wormward-packs 2>&1 | tail -3` (all pass).

- [ ] **Step 2: Failing test — fixability is content-aware AND strip verifies**

Add to `crates/wormward-github/src/pipeline.rs` tests. Build a fixture whose default-branch
config is flagged by a NON-marker signature (e.g. a bare C2 address, no `global[...]=`), so
today it is wrongly offered as fixable and "fixed" as a no-op:

```rust
    fn make_nonstrippable_infected_origin(tmp: &TempDir, name: &str) -> PathBuf {
        let src = tmp.path().join(format!("{name}-src"));
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        // Flagged by the c2-tron-primary literal, but NO strip marker present.
        std::fs::write(
            src.join("postcss.config.mjs"),
            "export default {};\nfetch('TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP')\n",
        )
        .unwrap();
        git_ok(&src, &["add", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "c2-only"]);
        let bare = tmp.path().join(format!("{name}.git"));
        Command::new("git").args(["init","-q","--bare","-b","main"]).env("GIT_TEMPLATE_DIR","").arg(&bare).status().unwrap();
        git_ok(&src, &["remote","add","origin",bare.to_str().unwrap()]);
        git_ok(&src, &["push","-q","origin","main"]);
        bare
    }

    #[test]
    fn nonstrippable_infection_is_not_offered_as_fixable() {
        let tmp = TempDir::new().unwrap();
        let bare = make_nonstrippable_infected_origin(&tmp, "c2only");
        let host = GitFakeHost { repos: vec![RepoRef {
            full_name: "me/c2only".into(),
            clone_url: bare.to_string_lossy().to_string(),
            default_branch: "main".into(), fork: false,
        }]};
        let scan = scan_pass(&scan_only_opts(), &host, &builtin_packs(), "").unwrap();
        assert!(scan.infected_full_names().contains(&"me/c2only".to_string()),
            "still detected as infected");
        assert!(!scan.fixable_full_names(&builtin_packs()).contains(&"me/c2only".to_string()),
            "must NOT be offered as auto-fixable: no strip marker in the file");
    }
```

Run it: expect FAIL (currently `fixable_full_names` offers it).

- [ ] **Step 3: Make `fixable` content-aware**

`fixable_full_names` (pipeline.rs) currently counts a repo fixable when
`plan_remediation(&findings).actions` is non-empty. Change it so a `StripPayload` action
only counts when the flagged file's content actually contains a marker; `DeleteFile` and
`RemoveGitignoreLine` always count (their target's presence was already detected).

Add an `auto_fixable: bool` field to `ScannedRepo`, computed where content is available:
- In `api_scan_repo`: after collecting default-tip findings, set `auto_fixable` by checking,
  for each default-tip (git_ref == None) finding whose `action_for` is a `StripPayload`,
  whether `strip_marker_matches(&content, &markers)` for that file's content (read via the
  same `ApiTree` used for scanning — reuse the tree/cache for the default tip); OR the repo
  has any non-strip working-tree action. Store the result on `ScannedRepo`.
- In `fallback_clone_scan`: compute the same using the cloned working tree
  (`std::fs::read_to_string(dest.join(file))`).

Then `fixable_full_names` filters on `r.is_infected() && r.auto_fixable`. Keep
`infected_full_names` unchanged (detection ≠ fixability).

Re-run Step 2 test: expect PASS.

- [ ] **Step 4: Failing test — verify-after-strip never pushes a still-infected file**

```rust
    #[test]
    fn incomplete_strip_reverts_and_reports_manual_not_pushed() {
        // A file with a strip marker BUT residual worm content BEFORE the marker, so
        // stripping at the marker leaves a signature match. The fix must NOT push;
        // it must revert and report the repo as not-fixed (manual).
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("m-src");
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init","-q","-b","main"]);
        // c2 address (signature) appears BEFORE the strip marker; cutting at the marker
        // leaves the c2 line → still infected after strip.
        std::fs::write(src.join("postcss.config.mjs"),
            "export default {};\nvar c='TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP';\nglobal['!']='x';TAIL\n").unwrap();
        git_ok(&src, &["add","."]);
        git_ok(&src, &["commit","-q","--no-verify","-m","mixed"]);
        let bare = tmp.path().join("m.git");
        Command::new("git").args(["init","-q","--bare","-b","main"]).env("GIT_TEMPLATE_DIR","").arg(&bare).status().unwrap();
        git_ok(&src, &["remote","add","origin",bare.to_str().unwrap()]);
        git_ok(&src, &["push","-q","origin","main"]);

        let host = GitFakeHost { repos: vec![RepoRef {
            full_name: "me/m".into(), clone_url: bare.to_string_lossy().to_string(),
            default_branch: "main".into(), fork: false }]};
        let opts = GithubRunOpts { clone_dir: Some(tmp.path().join("work")),
            include_forks:false, fix:true, push:true, yes:true };
        let outcomes = run(&opts, &host, &builtin_packs(), "").unwrap();
        let o = &outcomes[0];
        assert!(o.pushed.is_empty(), "must not push a still-infected file");
        assert!(!(o.error.is_none() && !o.actions.is_empty()),
            "must not report as cleanly fixed");
        // The bare origin's main tip still has the original (reverted, not half-stripped).
        let show = Command::new("git").arg("-C").arg(&bare)
            .args(["show","main:postcss.config.mjs"]).output().unwrap();
        assert!(String::from_utf8_lossy(&show.stdout).contains("TMfKQEd7"),
            "origin must be untouched when strip is incomplete");
    }
```

Run: expect FAIL (today it strips, commits, force-pushes the still-infected file).

- [ ] **Step 5: Implement verify-after-strip + honest outcome in `fix_scanned`**

After `apply(&dest, &plan.actions, true)` and before staging/commit, re-scan the working
tree: `let residual = scan_repo(&dest, packs);` filtered to auto-strip kinds with
`git_ref == None`. If `residual` is non-empty (the strip left detectable payload):
- revert the working tree: `git(&dest, &["checkout", "--", "."])` (restores the committed
  infected file — we then do NOT commit or push),
- set `outcome.actions.clear()` and `outcome.error = None`, and add a distinguishable
  signal so the report says "detected — manual review, not auto-strippable" rather than a
  silent no-op. Add a field `manual_review: bool` to `RepoOutcome` (default false), set true
  here, and also set it in the `plan.actions.is_empty()` early-return when the repo IS
  infected (findings non-empty) — that is the "no marker at all" case.

Adjust the existing "applied empty" and "plan empty" branches to set `manual_review = true`
when `!sr.findings.is_empty()`, so an infected-but-not-auto-strippable repo is always
reported honestly rather than as "no changes".

Re-run Step 4 test: expect PASS. Re-run the full crate: `cargo test -p wormward-github` — all green (the existing `fixes_infected_repo_end_to_end` uses a canonical `global['!']=` payload with no residual, so it still fixes+pushes).

- [ ] **Step 6: Surface `manual_review` in the GUI**

- `apps/desktop/src-tauri/src/lib.rs`: add `manual_review: bool` to `GithubFixView`, set from
  `o.manual_review`. `fixed` stays `o.error.is_none() && !o.actions.is_empty()`.
- `apps/desktop/src/lib/types.ts`: add `manual_review: boolean` to `GithubFixView`.
- `apps/desktop/src/routes/GitHub.svelte`: in the fix-results block, render a third state
  between error and fixed:
  ```svelte
        {:else if r.manual_review}
          detected — manual review needed (payload not auto-strippable)
        {:else if r.fixed}
  ```

Gate: `cd apps/desktop && pnpm check 2>&1 | tail -3` → 0 errors; `cd apps/desktop/src-tauri && cargo check` → clean.

- [ ] **Step 7: Commit**

```bash
git add crates/wormward-packs/src/polinrider/pack.yaml crates/wormward-github/src/pipeline.rs apps/desktop/src-tauri/src/lib.rs apps/desktop/src/lib/types.ts apps/desktop/src/routes/GitHub.svelte
git commit -m "Content-aware fixability + verify-after-strip so GitHub fix never no-ops or pushes infected files"
```
