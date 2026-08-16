# API-Friendly GitHub Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the GitHub account scan's REST usage by orders of magnitude (clone-first routing, rescan cache), smooth what remains (pacing + breaker), and surface honest rate-limit messages with the real wait time.

**Architecture:** All changes live in `crates/wormward-github` (routing in `pipeline.rs`, HTTP client in `lib.rs`, new `scan_cache.rs`), plus message copy in `apps/desktop/src/lib/errors.ts` and one CLI print. Spec: `docs/superpowers/specs/2026-08-17-github-api-friendly-design.md`.

**Tech Stack:** Rust (ureq client, serde, rayon), Svelte/TS frontend, vitest.

## Global Constraints

- TDD: every behavior change starts with a test you watch fail for the right reason.
- Do NOT run `cargo fmt` (main has pre-existing diffs; formatting is not enforced). Match surrounding style by hand.
- No new Rust dependencies (no chrono — durations, not wall-clock times).
- Fixture commits use `--no-verify`; the infected-fixture payload string is exactly `"export default {};\nglobal['!']='8-270-2';\n(\"rmcej%otb%\",2857687)\n"`.
- Run `cargo test -p wormward-github` for crate checks; full sweep is Task 6.
- Rate-limit message suffix format is exactly `; limited for ~{N} min` (N = minutes rounded up, minimum 1).

---

### Task 1: Clone-first scan routing

**Files:**
- Modify: `crates/wormward-github/src/lib.rs` (`RepoRef` struct, ~line 10)
- Modify: `crates/wormward-github/src/pipeline.rs` (`api_scan_repo`; new const near `BIG_TREE_BLOBS` ~line 297; tests)
- Modify: every `RepoRef {` struct literal in the workspace (29 sites — grep `RepoRef {` across `crates/` and `apps/desktop/src-tauri/`; they are in tests and fixtures)

**Interfaces:**
- Produces: `RepoRef.size: u64` and `RepoRef.pushed_at: Option<String>` (serde-defaulted) — Task 5 consumes `pushed_at`. `CLONE_SIZE_KB: u64 = 64` in pipeline.rs. `CountingHost` test helper — Task 5's tests reuse it.

- [ ] **Step 1: Extend `RepoRef` and fix the literals (mechanical, no behavior change yet)**

In `lib.rs`, after the `fork` field:

```rust
    /// Bare-repo disk size in KB, from the repo listing. Drives clone-vs-REST scan
    /// routing (a big repo scans via one shallow clone on git smart-HTTP instead of
    /// hundreds of REST blob reads). Serde-defaulted: fixtures and old payloads read 0.
    #[serde(default)]
    pub size: u64,
    /// Last-push timestamp from the repo listing (ISO 8601). Powers the clean-repo
    /// rescan cache; never fetched separately.
    #[serde(default)]
    pub pushed_at: Option<String>,
```

Then `grep -rn "RepoRef {" crates apps/desktop/src-tauri --include="*.rs"` and add `size: 0, pushed_at: None,` to every struct literal (all are test/fixture code; production code only deserializes). Run `cargo test --workspace` — everything must still pass (pure field addition).

- [ ] **Step 2: Write the failing routing test**

In `pipeline.rs`'s test module, add a counting wrapper host and the test:

```rust
    /// Delegates to an inner GitFakeHost while counting per-repo API calls, so tests can
    /// assert a scan path made ZERO per-repo REST calls (the whole point of clone-first).
    struct CountingHost {
        inner: GitFakeHost,
        branches: std::sync::atomic::AtomicUsize,
        trees: std::sync::atomic::AtomicUsize,
        blobs: std::sync::atomic::AtomicUsize,
    }

    impl CountingHost {
        fn new(inner: GitFakeHost) -> Self {
            Self {
                inner,
                branches: Default::default(),
                trees: Default::default(),
                blobs: Default::default(),
            }
        }
    }

    impl RepoHost for CountingHost {
        fn list_repos(&self, f: bool, o: &[String]) -> Result<Vec<RepoRef>, GithubError> {
            self.inner.list_repos(f, o)
        }
        fn list_orgs(&self) -> Result<Vec<String>, GithubError> {
            self.inner.list_orgs()
        }
        fn list_branches(&self, n: &str) -> Result<Vec<Branch>, GithubError> {
            self.branches.fetch_add(1, Ordering::Relaxed);
            self.inner.list_branches(n)
        }
        fn get_tree(&self, n: &str, s: &str) -> Result<Tree, GithubError> {
            self.trees.fetch_add(1, Ordering::Relaxed);
            self.inner.get_tree(n, s)
        }
        fn get_blob(&self, n: &str, s: &str) -> Result<Option<String>, GithubError> {
            self.blobs.fetch_add(1, Ordering::Relaxed);
            self.inner.get_blob(n, s)
        }
    }
```

NOTE: `RepoHost` has more methods (webhooks/deploy keys/runners, used by the audit) — check the trait definition (lib.rs ~line 81-150); if they have no default impls, delegate them to `self.inner` the same way. The scan pass never calls them, so no counters needed.

```rust
    #[test]
    fn big_repo_scans_via_clone_with_zero_per_repo_rest_calls() {
        // A repo whose listing `size` exceeds CLONE_SIZE_KB must be scanned via one
        // shallow clone (git transport — no REST quota) WITHOUT even a list_branches
        // call. Detection coverage is unchanged: the clone scan still finds the payload.
        let tmp = TempDir::new().unwrap();
        let bare = make_infected_origin(&tmp);
        let host = CountingHost::new(GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/big".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
                size: CLONE_SIZE_KB + 1,
                pushed_at: None,
            }],
        });
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: false,
            push: false,
            yes: false,
            orgs: vec![],
        };
        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        assert_eq!(scan.infected_full_names(), vec!["me/big".to_string()]);
        assert_eq!(host.branches.load(Ordering::Relaxed), 0, "list_branches must not be called");
        assert_eq!(host.trees.load(Ordering::Relaxed), 0, "get_tree must not be called");
        assert_eq!(host.blobs.load(Ordering::Relaxed), 0, "get_blob must not be called");
    }

    #[test]
    fn small_repo_stays_on_the_rest_path() {
        // At or below the threshold the cheap REST path is kept (no clone overhead for
        // tiny repos): per-repo calls ARE made and the payload is still found.
        let tmp = TempDir::new().unwrap();
        let bare = make_infected_origin(&tmp);
        let host = CountingHost::new(GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/small".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
                size: CLONE_SIZE_KB,
                pushed_at: None,
            }],
        });
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: false,
            push: false,
            yes: false,
            orgs: vec![],
        };
        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        assert_eq!(scan.infected_full_names(), vec!["me/small".to_string()]);
        assert!(host.branches.load(Ordering::Relaxed) > 0, "REST path must be used");
    }
```

(If `Ordering` is not already imported in the test module, use `std::sync::atomic::Ordering` fully qualified.)

- [ ] **Step 3: Run, verify RED**

Run: `cargo test -p wormward-github big_repo_scans_via_clone`
Expected: FAIL — `list_branches must not be called` (the REST path currently runs for any size). `small_repo_stays_on_the_rest_path` should already pass.

- [ ] **Step 4: Implement the routing**

In `pipeline.rs`, next to `BIG_TREE_BLOBS`:

```rust
/// Listing-reported repo size (KB) above which a repo is scanned via a shallow clone
/// WITHOUT any per-repo REST calls. The clone rides git smart-HTTP, which does not draw
/// on the REST core quota — so routing on the listing's free `size` field turns the
/// scan's dominant cost (per-blob REST reads, the burst pattern that trips GitHub's
/// anti-abuse heuristics) into ordinary CI-shaped git traffic. Only tiny repos, where a
/// couple of REST calls are cheaper than a clone, stay on the API path; `tree_needs_clone`
/// remains the second net for repos that are small on disk but dense in files.
const CLONE_SIZE_KB: u64 = 64;
```

In `api_scan_repo`, immediately after the `let mut out = ScannedRepo { ... };` initialization and before `host.list_branches(...)`:

```rust
    // Clone-first: decided from the listing alone, before a single per-repo REST call.
    if repo.size > CLONE_SIZE_KB {
        return Ok(fallback_clone_scan(repo, packs, token));
    }
```

- [ ] **Step 5: Run, verify GREEN, run the crate**

Run: `cargo test -p wormward-github`
Expected: all pass. NOTE: existing tests construct fixtures with `size: 0` after Step 1, so they keep the REST path — no existing test's routing changes.

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-github/src/lib.rs crates/wormward-github/src/pipeline.rs
git add -u
git commit -m "feat(github): clone-first scan routing from the listing's size field"
```

---

### Task 2: Rate-limit messages carry the real wait duration

**Files:**
- Modify: `crates/wormward-github/src/lib.rs` (`call` ~lines 207-270; a new pure helper near `retry_wait`; tests near the existing mock-server rate-limit tests ~line 880+)

**Interfaces:**
- Produces: `RateLimited` detail strings gain the exact suffix `; limited for ~{N} min` when a hint exists. Task 3's frontend parsing depends on this exact format. Pure helper `limited_suffix(retry_after: Option<&str>, reset: Option<&str>, now_epoch: u64) -> Option<String>`.

- [ ] **Step 1: Write the failing unit test for the pure helper**

Near the existing `retry_wait` tests:

```rust
    #[test]
    fn limited_suffix_reports_minutes_rounded_up() {
        // Retry-After (delta seconds) wins; 90s → 2 min.
        assert_eq!(limited_suffix(Some("90"), None, 1000).as_deref(), Some("; limited for ~2 min"));
        // Reset epoch: 1000 + 1859s → 31 min.
        assert_eq!(limited_suffix(None, Some("2859"), 1000).as_deref(), Some("; limited for ~31 min"));
        // Sub-minute waits floor at 1 min; a past reset also reports the 1-min minimum
        // (the limit was JUST lifting — "~1 min" beats claiming nothing).
        assert_eq!(limited_suffix(Some("5"), None, 1000).as_deref(), Some("; limited for ~1 min"));
        assert_eq!(limited_suffix(None, Some("900"), 1000).as_deref(), Some("; limited for ~1 min"));
        // No hint at all → no suffix.
        assert_eq!(limited_suffix(None, None, 1000), None);
    }
```

- [ ] **Step 2: Run, verify RED (compile failure is expected — add a stub returning `None`, watch the assertions fail)**

Run: `cargo test -p wormward-github limited_suffix_reports_minutes`
Expected: FAIL on the first assertion with the stub in place.

- [ ] **Step 3: Implement the helper and wire it into both give-up paths**

Near `retry_wait`:

```rust
/// Human wait-duration suffix for a RateLimited detail: `"; limited for ~N min"`, N =
/// minutes until the hint rounds up (minimum 1 — a sub-minute or just-elapsed hint still
/// means "about a minute", never silence). `Retry-After` (delta seconds) wins over
/// `x-ratelimit-reset` (epoch seconds). None when no hint exists — the caller appends
/// nothing rather than inventing a wait. A duration needs no timezone handling, which is
/// why this is not a wall-clock time.
fn limited_suffix(retry_after: Option<&str>, reset: Option<&str>, now_epoch: u64) -> Option<String> {
    let secs: u64 = if let Some(ra) = retry_after.and_then(|s| s.trim().parse::<u64>().ok()) {
        ra
    } else if let Some(rs) = reset.and_then(|s| s.trim().parse::<u64>().ok()) {
        rs.saturating_sub(now_epoch)
    } else {
        return None;
    };
    let mins = secs.div_ceil(60).max(1);
    Some(format!("; limited for ~{mins} min"))
}
```

In `call`: the rate-limit arm already binds `retry_after` and `reset` per attempt. Hold the latest suffix across attempts alongside `last_rl_msg`:

```rust
        let mut last_suffix: Option<String> = None;
```

Inside the rate-limit arm, after `reset` is bound:

```rust
                    if let Some(s) = limited_suffix(retry_after.as_deref(), reset.as_deref(), now_epoch_secs()) {
                        last_suffix = Some(s);
                    }
```

Both give-up paths append it (empty when absent). Immediate give-up:

```rust
                            let detail = last_rl_msg.unwrap_or_else(|| format!("HTTP {code}"));
                            let suffix = last_suffix.unwrap_or_default();
                            return Err(GithubError::RateLimited(format!("{detail}{suffix} ({url})")));
```

Retries-exhausted path (after the loop):

```rust
    let detail = last_rl_msg.unwrap_or_else(|| format!("rate limited after {MAX_RATE_RETRIES} retries"));
    let suffix = last_suffix.unwrap_or_default();
    Err(GithubError::RateLimited(format!("{detail}{suffix} ({url})")))
```

(Ownership note: the loop moves `last_rl_msg`/`last_suffix` only in the return path — if the borrow checker complains about the loop, use `.clone()` on the suffix inside the loop arm; it is cold error-path code.)

- [ ] **Step 4: Extend the mock-server test**

Find the existing test that drives a rate-limit response through `call` via the local mock server (near line 887, e.g. the far-off-reset test). Add one assertion to it — or a sibling test using the same server harness — that the surfaced `RateLimited` message contains `"limited for ~"` when the mocked response carries an `x-ratelimit-reset` (or `Retry-After`) header, and does NOT contain it when the mocked 403 carries neither header but `x-ratelimit-remaining: 0` only. Follow the harness's existing style exactly.

- [ ] **Step 5: Run crate tests, verify GREEN**

Run: `cargo test -p wormward-github`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-github/src/lib.rs
git commit -m "feat(github): rate-limit errors report the actual wait duration"
```

---

### Task 3: Desktop rate-limit copy (parallel-safe: frontend only)

**Files:**
- Modify: `apps/desktop/src/lib/errors.ts`
- Modify: `apps/desktop/src/lib/errors.test.ts`

**Interfaces:**
- Consumes: the exact backend suffix `; limited for ~{N} min` (Task 2) and GitHub's anti-scraping body wording (the raw error may contain the word `scraping`). Frontend must degrade gracefully when the suffix is absent (older backend, no hint).

- [ ] **Step 1: Write the failing tests**

In `errors.test.ts`, replace/extend the rate-limit cases:

```ts
  it("maps 'rate limit' without a duration to the wait-and-retry message", () => {
    expect(humanizeError("github rate limit: HTTP 403 from ...")).toBe(
      "GitHub rate limit reached — wormward paused and retried, but it's still limited. Wait a few minutes and try again.",
    );
  });

  it("surfaces the backend's real wait duration when present", () => {
    expect(humanizeError("API rate limit exceeded; limited for ~31 min (https://api.github.com/...)")).toBe(
      "GitHub rate limit reached — wormward paused and retried, but it's still limited for about 31 more minutes. Wait and try again.",
    );
  });

  it("names the anti-scraping flag distinctly and advises smaller scans", () => {
    expect(
      humanizeError(
        "API rate limit exceeded for user ID 123. For more on scraping GitHub ...; limited for ~31 min (https://api.github.com/...)",
      ),
    ).toBe(
      "GitHub has temporarily flagged this account's API traffic. Wait about 31 minutes, then scan fewer repos or orgs at once.",
    );
  });
```

- [ ] **Step 2: Run, verify RED**

Run: `cd apps/desktop && npm test`
Expected: the two new tests FAIL (current code returns the generic message for all three).

- [ ] **Step 3: Implement**

In `errors.ts`, replace the current rate-limit mapping (keep it BEFORE the generic 403 branch, as the existing comment demands):

```ts
  const limited = s.match(/limited for ~(\d+) min/);
  // The anti-scraping flag is a different situation than quota: GitHub has judged the
  // traffic pattern abusive, so "try again" alone is bad advice — say what happened and
  // how to avoid re-tripping it. Checked before the generic rate-limit mapping.
  if (/scraping/i.test(s)) {
    const wait = limited ? `Wait about ${limited[1]} minutes, then` : "Wait a while, then";
    return `GitHub has temporarily flagged this account's API traffic. ${wait} scan fewer repos or orgs at once.`;
  }
  if (/rate limit/i.test(s)) {
    if (limited)
      return `GitHub rate limit reached — wormward paused and retried, but it's still limited for about ${limited[1]} more minutes. Wait and try again.`;
    return "GitHub rate limit reached — wormward paused and retried, but it's still limited. Wait a few minutes and try again.";
  }
```

(Adapt variable names to the file's existing style — it currently tests `/rate limit/i` against a lowercased or raw string `s`; read the function first and keep its conventions.)

- [ ] **Step 4: Run, verify GREEN**

Run: `cd apps/desktop && npm run check && npm test`
Expected: 0 errors; all tests pass, including the untouched error cases.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop/src/lib/errors.ts apps/desktop/src/lib/errors.test.ts
git commit -m "feat(desktop): honest rate-limit copy with real wait time and scraping-flag case"
```

---

### Task 4: Request pacing + secondary-limit circuit breaker

**Files:**
- Modify: `crates/wormward-github/src/lib.rs` (`GitHubHost` struct + `new`; `call`; `RepoHost` trait; pure pacing helper + tests)
- Modify: `crates/wormward-github/src/pipeline.rs` (`scan_pass_with_progress_cancellable` per-repo closure; one test)

**Interfaces:**
- Consumes: nothing from other tasks (merge-order independent, but runs after Task 2 because both edit `call` — coordinate textually, the changes are in different spots of the function).
- Produces: `RepoHost::throttle_hint(&self) -> bool` with a default `false` impl (mock hosts unaffected); `GitHubHost` paces all requests ≥150 ms apart and reports `throttle_hint() == true` after any secondary-limit response.

- [ ] **Step 1: Write the failing tests**

Pure pacing helper test (in lib.rs tests):

```rust
    #[test]
    fn pace_slot_spaces_request_starts() {
        use std::time::{Duration, Instant};
        let spacing = Duration::from_millis(150);
        let t0 = Instant::now();
        // First request: next-allowed is in the past → start now, no wait.
        let (wait, next) = pace_slot(t0, t0, spacing);
        assert_eq!(wait, Duration::ZERO);
        assert_eq!(next, t0 + spacing);
        // Second request arrives immediately → waits the remaining slot.
        let (wait2, next2) = pace_slot(next, t0, spacing);
        assert_eq!(wait2, spacing);
        assert_eq!(next2, t0 + spacing * 2);
        // A late arrival (past the slot) starts immediately and resets from now.
        let late = t0 + Duration::from_secs(5);
        let (wait3, next3) = pace_slot(next2, late, spacing);
        assert_eq!(wait3, Duration::ZERO);
        assert_eq!(next3, late + spacing);
    }
```

Breaker test (pipeline.rs tests) — a host whose hint is always on must still produce a complete, correct scan (exercises the serialized path):

```rust
    /// GitFakeHost with the throttle hint permanently on — drives the serialized-scan path.
    struct ThrottledHost(GitFakeHost);
    impl RepoHost for ThrottledHost {
        fn list_repos(&self, f: bool, o: &[String]) -> Result<Vec<RepoRef>, GithubError> {
            self.0.list_repos(f, o)
        }
        fn list_orgs(&self) -> Result<Vec<String>, GithubError> {
            self.0.list_orgs()
        }
        fn list_branches(&self, n: &str) -> Result<Vec<Branch>, GithubError> {
            self.0.list_branches(n)
        }
        fn get_tree(&self, n: &str, s: &str) -> Result<Tree, GithubError> {
            self.0.get_tree(n, s)
        }
        fn get_blob(&self, n: &str, s: &str) -> Result<Option<String>, GithubError> {
            self.0.get_blob(n, s)
        }
        fn throttle_hint(&self) -> bool {
            true
        }
    }

    #[test]
    fn throttled_scan_serializes_but_completes_with_full_results() {
        let tmp = TempDir::new().unwrap();
        let a = make_infected_origin_named(&tmp, "ta");
        let b = make_infected_origin_named(&tmp, "tb");
        let host = ThrottledHost(GitFakeHost {
            repos: vec![
                RepoRef {
                    full_name: "me/ta".into(),
                    clone_url: a.to_string_lossy().to_string(),
                    default_branch: "main".into(),
                    fork: false,
                    size: 0,
                    pushed_at: None,
                },
                RepoRef {
                    full_name: "me/tb".into(),
                    clone_url: b.to_string_lossy().to_string(),
                    default_branch: "main".into(),
                    fork: false,
                    size: 0,
                    pushed_at: None,
                },
            ],
        });
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: false,
            push: false,
            yes: false,
            orgs: vec![],
        };
        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        let mut infected = scan.infected_full_names();
        infected.sort();
        assert_eq!(infected, vec!["me/ta".to_string(), "me/tb".to_string()]);
    }
```

(Delegate the remaining `RepoHost` methods on `ThrottledHost` the same way as `CountingHost` if the trait requires them. If `ThrottledHost` duplicates too much delegation boilerplate, it may wrap `CountingHost`'s pattern — but do not refactor `GitFakeHost` itself.)

- [ ] **Step 2: Run, verify RED**

Run: `cargo test -p wormward-github pace_slot_spaces_request_starts throttled_scan_serializes`
Expected: compile failures for `pace_slot` and `throttle_hint` — add stubs (`pace_slot` returning `(Duration::ZERO, now)`, trait method default `false`) and watch `pace_slot_spaces_request_starts` FAIL on the second assertion. `throttled_scan_serializes_but_completes_with_full_results` will pass as soon as it compiles (the serialized path is a behavioral no-op for correctness) — its RED is the compile failure; note that in the report.

- [ ] **Step 3: Implement**

3a. Pure helper in lib.rs:

```rust
/// Compute a request's start slot under global pacing: returns (wait, new_next_allowed).
/// `next_allowed` is the earliest permitted start; a request arriving early waits out the
/// difference, a late one starts immediately and re-anchors the schedule at `now` (no
/// banking of unused slots — bursts stay capped at one request per spacing).
fn pace_slot(
    next_allowed: std::time::Instant,
    now: std::time::Instant,
    spacing: std::time::Duration,
) -> (std::time::Duration, std::time::Instant) {
    if next_allowed <= now {
        (std::time::Duration::ZERO, now + spacing)
    } else {
        (next_allowed - now, next_allowed + spacing)
    }
}
```

3b. `GitHubHost` gains fields (adjust `new` accordingly):

```rust
    /// Global pacer: the earliest Instant the NEXT request may start. Shared across every
    /// scan thread so the account's request rate is smooth (~6/s) instead of 8 workers
    /// bursting — burstiness, not volume, is what trips GitHub's secondary limit.
    next_request: std::sync::Mutex<std::time::Instant>,
    /// Sticky: set once any request observes a secondary rate limit (Retry-After present).
    /// `scan_pass` consults it via `throttle_hint` and serializes the rest of the run.
    secondary_hit: std::sync::atomic::AtomicBool,
```

Const near `MAX_RATE_RETRIES`:

```rust
/// Minimum spacing between request starts (global, all threads). ~6.6 req/s: fast enough
/// that pacing never dominates a scan, smooth enough to stop the burst signature.
const MIN_REQUEST_SPACING: std::time::Duration = std::time::Duration::from_millis(150);
```

At the top of `call` (before the retry loop) add pacing per attempt — place the pace inside the loop so retries are paced too:

```rust
            {
                let (wait, next) = {
                    let mut slot = self.next_request.lock().unwrap();
                    let (wait, next) = pace_slot(*slot, std::time::Instant::now(), MIN_REQUEST_SPACING);
                    *slot = next;
                    (wait, next)
                };
                let _ = next;
                if !wait.is_zero() {
                    std::thread::sleep(wait);
                }
            }
```

In the rate-limit arm, where `retry_after` is bound, mark the breaker when the secondary signature is present:

```rust
                    if retry_after.is_some() {
                        // Secondary limit (Retry-After while quota remains): remember it so
                        // the scan drops to serial instead of 8 workers re-tripping it.
                        self.secondary_hit.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
```

3c. `RepoHost` trait gains (with default so every existing impl/mock compiles unchanged):

```rust
    /// True when the host has observed throttling (e.g. a secondary rate limit) and the
    /// caller should reduce concurrency. Default false: mocks and fakes are never throttled.
    fn throttle_hint(&self) -> bool {
        false
    }
```

`GitHubHost`'s impl: `self.secondary_hit.load(Ordering::Relaxed)`.

3d. In `scan_pass_with_progress_cancellable` (pipeline.rs), create a serialization mutex before the parallel loop and consult the hint per repo inside the closure (the closure currently computes `result` then bumps the progress counter):

```rust
    // Once the host reports throttling, the rest of the run goes one-repo-at-a-time:
    // eight workers independently backing off into a tripped secondary limit is exactly
    // the pattern that escalates to an account-level abuse flag.
    let serial = std::sync::Mutex::new(());
```

and wrap the per-repo scan:

```rust
                let result = if host.throttle_hint() {
                    let _one_at_a_time = serial.lock().unwrap();
                    scan_one(repo)
                } else {
                    scan_one(repo)
                };
```

where `scan_one` is a small closure over the existing body (`|repo| { ... existing api_scan_repo/tree logic ... }`) — extract minimally; do not restructure the surrounding cancel/progress logic.

- [ ] **Step 4: Extend the existing secondary-limit mock-server test**

The existing test (~line 939, `secondary_rate_limit_403_is_retried_then_surfaced`) drives a real `GitHubHost` against the mock server. Add an assertion at its end: `assert!(host.throttle_hint());` — and add one to a non-rate-limited test (e.g. the plain success path) asserting `!host.throttle_hint()`.

- [ ] **Step 5: Run crate tests, verify GREEN**

Run: `cargo test -p wormward-github`
Expected: all pass. The mock-server tests exercise pacing implicitly; if any mock-server test becomes slow (>a few seconds) due to pacing sleeps, note it in the report — do NOT raise MIN_REQUEST_SPACING-related timeouts silently.

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-github/src/lib.rs crates/wormward-github/src/pipeline.rs
git commit -m "feat(github): global request pacing and secondary-limit circuit breaker"
```

---

### Task 5: Clean-repo rescan cache

**Files:**
- Create: `crates/wormward-github/src/scan_cache.rs`
- Modify: `crates/wormward-github/src/lib.rs` (add `pub mod scan_cache;`)
- Modify: `crates/wormward-github/src/pipeline.rs` (`scan_pass_with_progress_cancellable`; `ScanPass` gains `skipped_unchanged`; tests)
- Modify: `crates/wormward-cli/src/main.rs` (print skip count in the `github` command after the scan pass)

**Interfaces:**
- Consumes: `RepoRef.pushed_at` (Task 1); `CountingHost` (Task 1's test helper).
- Produces: `scan_cache::ScanCache` with `load(fingerprint) -> ScanCache`, `is_clean_unchanged(&self, full_name: &str, pushed_at: Option<&str>) -> bool`, `record_clean(&mut self, full_name: &str, pushed_at: &str)`, `save(&self)`; `scan_cache::packs_fingerprint(packs: &[Pack]) -> String`; `ScanPass::skipped_unchanged(&self) -> usize`.

- [ ] **Step 1: Write the failing cache-module tests**

`scan_cache.rs` with a `#[cfg(test)] mod tests` — tests first, module skeleton with stubs so they compile and FAIL:

```rust
    #[test]
    fn round_trips_clean_repos_and_honors_pushed_at() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut c = ScanCache::load_from(tmp.path(), "fp1");
        assert!(!c.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
        c.record_clean("me/a", "2026-08-01T00:00:00Z");
        c.save();
        let c2 = ScanCache::load_from(tmp.path(), "fp1");
        assert!(c2.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
        // A different pushed_at (repo changed) must rescan.
        assert!(!c2.is_clean_unchanged("me/a", Some("2026-08-02T00:00:00Z")));
        // No pushed_at in the listing → never skip.
        assert!(!c2.is_clean_unchanged("me/a", None));
        // Unknown repo → never skip.
        assert!(!c2.is_clean_unchanged("me/b", Some("2026-08-01T00:00:00Z")));
    }

    #[test]
    fn pack_fingerprint_mismatch_ignores_the_cache() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut c = ScanCache::load_from(tmp.path(), "fp1");
        c.record_clean("me/a", "2026-08-01T00:00:00Z");
        c.save();
        // New packs → new fingerprint → stale "clean" verdicts are not trusted.
        let c2 = ScanCache::load_from(tmp.path(), "fp2");
        assert!(!c2.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
        // And saving under fp2 replaces the file's fingerprint.
        c2.save();
        let c3 = ScanCache::load_from(tmp.path(), "fp1");
        assert!(!c3.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
    }

    #[test]
    fn unreadable_cache_is_ignored() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("github-scan-cache.json"), "{not json").unwrap();
        let c = ScanCache::load_from(tmp.path(), "fp1");
        assert!(!c.is_clean_unchanged("me/a", Some("2026-08-01T00:00:00Z")));
    }

    #[test]
    fn fingerprint_tracks_pack_content() {
        let packs = wormward_packs::builtin_packs();
        let a = packs_fingerprint(&packs);
        let b = packs_fingerprint(&packs);
        assert_eq!(a, b, "fingerprint must be deterministic");
        assert!(!a.is_empty());
        assert_ne!(a, packs_fingerprint(&packs[..1]), "different pack sets must differ");
    }
```

(`wormward-packs` is already a dev-dependency of this crate — the pipeline tests use `builtin_packs()`.)

- [ ] **Step 2: Run, verify RED**

Run: `cargo test -p wormward-github scan_cache`
Expected: FAIL on the assertions with the stub skeleton.

- [ ] **Step 3: Implement the module**

```rust
//! Clean-repo rescan cache: repos that scanned CLEAN in a completed run are skipped on
//! the next scan when the listing's `pushed_at` is unchanged — the single biggest saver
//! for retry/rescan cycles, which previously repeated the whole account's API cost.
//!
//! Only clean verdicts are cached (an infected repo is always rescanned), and the file
//! carries a detection-pack fingerprint so a pack update never trusts stale "clean"
//! verdicts. Every failure mode degrades to "scan everything" — the cache can make a scan
//! cheaper, never wronger.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wormward_core::Pack;

const CACHE_FILE: &str = "github-scan-cache.json";

#[derive(Serialize, Deserialize, Default)]
struct CacheFile {
    packs_fingerprint: String,
    repos: HashMap<String, CachedRepo>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CachedRepo {
    pushed_at: String,
    scanned_at: u64,
}

pub struct ScanCache {
    dir: Option<PathBuf>,
    fingerprint: String,
    repos: HashMap<String, CachedRepo>,
}

/// Fingerprint of the loaded detection packs: pack ids plus their signature/artifact/IOC
/// counts. Any pack change (new campaign, added signature) changes the fingerprint and
/// invalidates every cached "clean".
pub fn packs_fingerprint(packs: &[Pack]) -> String {
    let mut basis = String::new();
    for p in packs {
        basis.push_str(&format!(
            "{}:{}:{}:{}:{};",
            p.manifest.id,
            p.manifest.content_signatures.len(),
            p.manifest.artifacts.len(),
            p.manifest.ioc_domains.len(),
            p.manifest.bad_npm_packages.len(),
        ));
    }
    wormward_core::sha256_hex(basis.as_bytes())
}

/// The default cache directory: `$WORMWARD_CACHE_DIR`, else `~/.wormward`. None (no
/// caching at all) when neither resolves — a machine with no HOME just scans everything.
fn default_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("WORMWARD_CACHE_DIR") {
        return Some(PathBuf::from(d));
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".wormward"))
}

impl ScanCache {
    /// Load the cache for the current pack fingerprint. A missing/unreadable file or a
    /// fingerprint mismatch yields an empty cache (scan everything).
    pub fn load(fingerprint: &str) -> ScanCache {
        match default_dir() {
            Some(d) => ScanCache::load_from(&d, fingerprint),
            None => ScanCache { dir: None, fingerprint: fingerprint.into(), repos: HashMap::new() },
        }
    }

    pub fn load_from(dir: &Path, fingerprint: &str) -> ScanCache {
        let file: CacheFile = std::fs::read_to_string(dir.join(CACHE_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let repos = if file.packs_fingerprint == fingerprint { file.repos } else { HashMap::new() };
        ScanCache { dir: Some(dir.to_path_buf()), fingerprint: fingerprint.into(), repos }
    }

    /// True only for a repo recorded clean whose `pushed_at` is unchanged. Any doubt —
    /// no listing timestamp, unknown repo, changed timestamp — means "scan it".
    pub fn is_clean_unchanged(&self, full_name: &str, pushed_at: Option<&str>) -> bool {
        match (self.repos.get(full_name), pushed_at) {
            (Some(c), Some(p)) => c.pushed_at == p,
            _ => false,
        }
    }

    pub fn record_clean(&mut self, full_name: &str, pushed_at: &str) {
        self.repos.insert(
            full_name.to_string(),
            CachedRepo { pushed_at: pushed_at.to_string(), scanned_at: wormward_core::now_secs() },
        );
    }

    /// Best-effort write; failures are ignored (the cache can only make scans cheaper).
    pub fn save(&self) {
        let Some(dir) = &self.dir else { return };
        let file = CacheFile {
            packs_fingerprint: self.fingerprint.clone(),
            repos: self.repos.clone(),
        };
        let Ok(json) = serde_json::to_string_pretty(&file) else { return };
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(dir.join(CACHE_FILE), json);
    }
}
```

Add `pub mod scan_cache;` to lib.rs's module list. Check `wormward_core::sha256_hex`'s exact signature first (it is exported from `matchers`; if it takes `&str`, pass `&basis`). If `serde_json` is not already a direct dependency of wormward-github, add it to Cargo.toml `[dependencies]` (it is already in the workspace tree via other crates — this does not violate the no-new-deps constraint, which is about NEW third-party crates like chrono).

- [ ] **Step 4: Run, verify module tests GREEN**

Run: `cargo test -p wormward-github scan_cache`
Expected: all 4 pass.

- [ ] **Step 5: Write the failing integration test (cache skip in scan_pass)**

In pipeline.rs tests:

```rust
    #[test]
    fn second_scan_skips_unchanged_clean_repo_with_zero_calls() {
        // First completed scan records the clean repo; the second scan must skip it
        // without a single per-repo API call. WORMWARD_CACHE_DIR isolates the cache.
        let tmp = TempDir::new().unwrap();
        let cache_dir = tmp.path().join("cache");
        std::env::set_var("WORMWARD_CACHE_DIR", &cache_dir);
        // Clean bare origin (no payload).
        let src = tmp.path().join("clean-src");
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(src.join("readme.md"), "clean").unwrap();
        git_ok(&src, &["add", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "clean"]);
        let bare = tmp.path().join("clean.git");
        Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .env("GIT_TEMPLATE_DIR", "")
            .arg(&bare)
            .status()
            .unwrap();
        git_ok(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git_ok(&src, &["push", "-q", "origin", "main"]);

        let make_host = || {
            CountingHost::new(GitFakeHost {
                repos: vec![RepoRef {
                    full_name: "me/cached".into(),
                    clone_url: bare.to_string_lossy().to_string(),
                    default_branch: "main".into(),
                    fork: false,
                    size: 0,
                    pushed_at: Some("2026-08-17T00:00:00Z".into()),
                }],
            })
        };
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: false,
            push: false,
            yes: false,
            orgs: vec![],
        };
        let packs = builtin_packs();
        let first = make_host();
        let scan1 = scan_pass(&opts, &first, &packs, "").unwrap();
        assert!(scan1.infected_full_names().is_empty());
        assert!(first.branches.load(Ordering::Relaxed) > 0, "first scan really scanned");
        assert_eq!(scan1.skipped_unchanged(), 0);

        let second = make_host();
        let scan2 = scan_pass(&opts, &second, &packs, "").unwrap();
        assert!(scan2.infected_full_names().is_empty());
        assert_eq!(second.branches.load(Ordering::Relaxed), 0, "unchanged clean repo must be skipped");
        assert_eq!(second.trees.load(Ordering::Relaxed), 0);
        assert_eq!(scan2.skipped_unchanged(), 1);
        std::env::remove_var("WORMWARD_CACHE_DIR");
    }
```

CAUTION — env vars are process-global and cargo tests run threaded: wrap the `set_var`/`remove_var` region so parallel tests can't interleave. Check how other tests in this workspace handle env (grep `set_var`); if there is no existing serial-test convention, guard with a local `static ENV_LOCK: Mutex<()>` in the test module and take it in this test (it is the only env-mutating test).

Also add the infected-repo counterpart (never cached):

```rust
    #[test]
    fn infected_repo_is_never_cached() {
        let tmp = TempDir::new().unwrap();
        let cache_dir = tmp.path().join("cache");
        // (same ENV_LOCK guard as above)
        std::env::set_var("WORMWARD_CACHE_DIR", &cache_dir);
        let bare = make_infected_origin(&tmp);
        let make_host = || {
            CountingHost::new(GitFakeHost {
                repos: vec![RepoRef {
                    full_name: "me/dirty".into(),
                    clone_url: bare.to_string_lossy().to_string(),
                    default_branch: "main".into(),
                    fork: false,
                    size: 0,
                    pushed_at: Some("2026-08-17T00:00:00Z".into()),
                }],
            })
        };
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: false,
            push: false,
            yes: false,
            orgs: vec![],
        };
        let packs = builtin_packs();
        scan_pass(&opts, &make_host(), &packs, "").unwrap();
        let second = make_host();
        let scan2 = scan_pass(&opts, &second, &packs, "").unwrap();
        assert_eq!(scan2.infected_full_names(), vec!["me/dirty".to_string()]);
        assert!(second.branches.load(Ordering::Relaxed) > 0, "infected repo must always rescan");
        assert_eq!(scan2.skipped_unchanged(), 0);
        std::env::remove_var("WORMWARD_CACHE_DIR");
    }
```

Also add the cancelled-run guard (a partial run must never mark repos clean):

```rust
    #[test]
    fn cancelled_scan_writes_no_cache() {
        let tmp = TempDir::new().unwrap();
        let cache_dir = tmp.path().join("cache");
        // (same ENV_LOCK guard as above)
        std::env::set_var("WORMWARD_CACHE_DIR", &cache_dir);
        let bare = make_infected_origin(&tmp);
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/x".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
                size: 0,
                pushed_at: Some("2026-08-17T00:00:00Z".into()),
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
        let cancel = AtomicBool::new(true); // cancelled before the first repo
        let _ = scan_pass_with_progress_cancellable(&opts, &host, &builtin_packs(), "", &cancel, &|_| {});
        assert!(
            !cache_dir.join("github-scan-cache.json").exists(),
            "a cancelled run must not record 'clean' verdicts"
        );
        std::env::remove_var("WORMWARD_CACHE_DIR");
    }
```

- [ ] **Step 6: Run, verify RED**

Run: `cargo test -p wormward-github second_scan_skips_unchanged`
Expected: compile failure for `skipped_unchanged` → add the field/getter returning 0 and watch the second-scan assertion FAIL (branches > 0 on the second scan).

- [ ] **Step 7: Integrate into `scan_pass_with_progress_cancellable`**

- `ScanPass` gains `skipped_unchanged: usize` with getter `pub fn skipped_unchanged(&self) -> usize`.
- Before the parallel loop: `let fingerprint = scan_cache::packs_fingerprint(packs); let cache = scan_cache::ScanCache::load(&fingerprint);`
- Partition `repos` into `(skipped, to_scan)` via `cache.is_clean_unchanged(&r.full_name, r.pushed_at.as_deref())`. For each skipped repo: emit a `ScannedRepo` with empty findings, no error, `auto_fixable: false`, `branch_fixable: false`, and fire the progress callback (they count toward `total`).
- Scan `to_scan` exactly as today.
- After a SUCCESSFUL collect (`Ok`) AND `!cancel.load(...)`: rebuild the cache — start from the loaded cache, `record_clean` every scanned repo with `findings.is_empty() && error.is_none()` and a `Some(pushed_at)`, and also re-record the skipped repos (they are still clean and unchanged); then `save()`. On `Err` or cancel: do not save.
- Merge skipped + scanned repos into the returned `ScanPass` (order does not matter to callers; keep it deterministic by appending scanned after skipped or sorting as the existing code does), set `skipped_unchanged: skipped.len()`.

- [ ] **Step 8: Run, verify GREEN; run the crate**

Run: `cargo test -p wormward-github`
Expected: all pass, including all pre-existing scan tests (their fixtures have `pushed_at: None` → never skipped, and `WORMWARD_CACHE_DIR` unset means the real `~/.wormward` could be touched by them — verify: repos with `pushed_at: None` are never RECORDED either (record only `Some`), so pre-existing tests write nothing; state that check in the report).

- [ ] **Step 9: CLI skip-count print**

In `crates/wormward-cli/src/main.rs`, in the `Command::Github` arm right after the scan pass completes and before rendering (near the `scan_result` handling): when text output (not JSON/SARIF) and `scan.skipped_unchanged() > 0`, print:

```rust
            if scan.skipped_unchanged() > 0 {
                eprintln!(
                    "{} unchanged repo(s) skipped (clean last scan; cache: ~/.wormward)",
                    scan.skipped_unchanged()
                );
            }
```

(Use `eprintln!` so JSON stdout consumers are unaffected regardless of format; then the format gate is unnecessary — simpler. Match the surrounding code's naming for the scan variable.)

- [ ] **Step 10: Run CLI tests and commit**

Run: `cargo test -p wormward-cli && cargo test -p wormward-github`
Expected: all pass.

```bash
git add crates/wormward-github/src/scan_cache.rs crates/wormward-github/src/lib.rs crates/wormward-github/src/pipeline.rs crates/wormward-cli/src/main.rs
git add -u
git commit -m "feat(github): clean-repo rescan cache keyed on pushed_at and pack fingerprint"
```

---

### Task 6: Full verification sweep

**Files:** none (verification only)

- [ ] **Step 1:** `cargo test --workspace` — all pass.
- [ ] **Step 2:** `cd apps/desktop/src-tauri && cargo test` — all pass.
- [ ] **Step 3:** `cd apps/desktop && npm run check && npm test` — 0 errors, all pass.
- [ ] **Step 4:** `cargo clippy --workspace 2>&1 | grep -c "^warning"` — no more than main's baseline (2). Do NOT run `cargo fmt`.
