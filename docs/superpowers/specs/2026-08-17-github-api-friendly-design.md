# GitHub scan: API-friendly traffic

**Date:** 2026-08-17
**Status:** Approved

## Problem

An account scan spends REST quota like a scraper: per repo one `list_branches`, then per
branch tip one `get_tree` plus up to 300 individual `get_blob` calls — thousands of calls
per scan, repeated in full on every retry. This burst-heavy, blob-enumerating signature
tripped GitHub's anti-abuse enforcement on a real account (403 "scraping" refusals with the
counted quota showing near-zero use). The surfaced error also guesses ("wait a few
minutes") when the backend already holds the actual reset time.

## Goal

Cut REST usage by orders of magnitude, smooth what remains, make retries nearly free, and
tell the truth in the error messages. No detection-coverage regression: every repo is still
scanned by the same detectors.

## Non-goals

- No GraphQL client; no conditional-request/ETag layer.
- No change to detection logic or the fix pipeline.
- No new consent gates or UI surfaces beyond message copy.

## Design

### A. Clone-first scanning (`wormward-github`)

- `RepoRef` gains `size: u64` (KB) and `pushed_at: Option<String>`, serde-defaulted, parsed
  from the repo listing GitHub already returns — zero extra calls. `GitFakeHost` fixtures
  set them explicitly.
- In `api_scan_repo`, before `list_branches`: if `repo.size > CLONE_SIZE_KB` (const, 64),
  return `fallback_clone_scan(repo, packs, token)` directly. A big repo then costs zero
  REST calls; the shallow clone rides git smart-HTTP, which does not draw on the REST core
  quota. The existing `tree_needs_clone` gate stays as the second net for repos that are
  small on disk but have many files.
- Coverage parity: `fallback_clone_scan` already runs `scan_repo` + `deep_scan_repo` and
  computes `auto_fixable` and `branch_fixable`, so routing changes cost, not coverage.

### B. Honest rate-limit messages

- In `call`'s two give-up paths (immediate far-off reset, and retries exhausted), append
  `"; limited for ~N min"` to the `RateLimited` detail when a `Retry-After` or
  `x-ratelimit-reset` hint is available (N = minutes until the hint, rounded up, minimum 1
  — a duration needs no timezone handling, unlike a wall-clock time). No hint → detail
  unchanged.
- Desktop `errors.ts`: extract `limited for ~N min` from the raw error and surface it —
  "GitHub rate limit reached — wormward paused and retried, but it's still limited for
  about N more minutes. Wait and try again." When the raw error contains GitHub's
  anti-scraping wording (`scraping`), say instead: "GitHub has temporarily flagged this
  account's API traffic. Wait about N minutes, then scan fewer repos or orgs at once."
  Both fall back to the current copy when no duration is present. `errors.test.ts` updated
  for all three shapes.

### C. Pacing + circuit breaker

- `GitHubHost` gains a global pacer: request starts are spaced at least
  `MIN_REQUEST_SPACING_MS` (150) apart across all threads (a `Mutex<Instant>` holding the
  next allowed start; each `call` sleeps to its slot). Smooth ~6 req/s replaces 8 workers
  bursting.
- `RepoHost` gains `fn throttle_hint(&self) -> bool { false }` (default). `GitHubHost`
  returns true after any request observed a secondary limit (403/429 with `Retry-After`),
  sticky for the host's lifetime. `scan_pass_with_progress_cancellable` checks the hint
  before each repo; once true, the remaining repos are scanned under a global serialization
  mutex (concurrency collapses to 1 for the rest of the run).

### D. Clean-repo rescan cache

- New module `wormward-github/src/scan_cache.rs`. JSON file at
  `~/.wormward/github-scan-cache.json`; directory overridable via `WORMWARD_CACHE_DIR`
  (tests use a tempdir). Shape:
  `{ "packs_fingerprint": "<hex>", "repos": { "<full_name>": { "pushed_at": "...", "scanned_at": <epoch> } } }`.
- Only repos that finished a scan **clean** (no findings, no error) in a **completed** run
  (not cancelled, not rate-aborted) are recorded. Infected repos are never cached.
- On scan start: load the cache; if `packs_fingerprint` differs from the current packs'
  fingerprint (hash over each pack's id + signature/artifact/ioc counts), ignore the cache
  entirely. A repo whose listing `pushed_at` equals its cache entry is skipped without any
  per-repo API call and reported clean; everything else scans normally. Repos with
  `pushed_at: None` are never cached or skipped.
- Invalidation is inherent: any push (including wormward's own fixes) changes `pushed_at`;
  pack updates change the fingerprint.
- Failures are non-fatal in both directions: unreadable cache → scan everything; write
  failure → ignore. The CLI prints `N unchanged repos skipped (cache)` when N > 0; the
  desktop needs no UI change.

## Edge cases

- Repo with `size: 0` (empty or metadata-missing): stays on the REST path; the existing
  empty-branches early return handles it.
- Cancelled or rate-aborted run: cache is not written (a partial run must not mark repos
  clean).
- Fork of a large repo with `include_forks`: routed to clone like any large repo.
- Secondary limit on the very first request: breaker trips; whole run proceeds serially.

## Testing (offline)

1. Counting mock host: a repo with `size` above the threshold produces zero
   `list_branches`/`get_tree`/`get_blob` calls and is scanned via clone (findings present).
2. A repo at/below the threshold keeps the REST path (calls observed).
3. Message suffix: mock-server rate-limit test asserts `limited until` appears when a reset
   hint exists, and is absent otherwise. `errors.test.ts` covers plain-limited,
   limited-with-time, and scraping-flagged shapes.
4. Pacer: pure spacing computation unit-tested; no timing-flaky assertions.
5. Breaker: mock host with `throttle_hint() == true` → scan completes serially (behavioral:
   completes with correct results; the serialization mutex path is exercised).
6. Cache: round-trip; `pushed_at` mismatch rescans; fingerprint mismatch ignores cache;
   cached-clean repo produces zero per-repo calls on a counting host; infected repo is
   never written to the cache; cancelled run writes nothing.
