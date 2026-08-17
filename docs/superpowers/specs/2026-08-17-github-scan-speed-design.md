# GitHub scan: speed rebalance

**Date:** 2026-08-17
**Status:** Approved

## Problem

The API-friendly changes overshot on wall-clock: `CLONE_SIZE_KB = 64` routes nearly every
repo to a clone that downloads every blob at every branch tip (assets included), and the
150 ms global pacing throttles all REST traffic even when GitHub has signaled nothing.
First-scan wall-clock regressed badly; the user reports the scan is "so slow".

## Goal

Restore near-original scan speed while keeping every anti-flagging protection and all
detection coverage. Quota usage stays at the new (near-zero) level.

## Non-goals

- No change to the fix pipeline's clones (blobless / full logic there is untouched).
- No change to the rescan cache, breaker semantics, or message copy.
- No re-raising of REST usage (CLONE_SIZE_KB stays 64).

## Design

### A. Adaptive pacing (`wormward-github/src/lib.rs`)

- `GitHubHost` gains `pace_engaged: AtomicBool` (false at construction). `call` applies the
  150 ms `pace_slot` spacing ONLY while engaged.
- Engagement is sticky and set in the existing rate-limit match arm (any 429, or 403 with
  `retry-after`/`x-ratelimit-remaining: 0`) — before the retry sleep, so the retried
  request is already paced. Healthy accounts scan at full 8-way parallel speed; the first
  warning from GitHub smooths all subsequent traffic; the secondary-limit breaker
  (serialization) still layers on top unchanged.
- Test: the existing mock-server rate-limit test additionally asserts engagement flips
  (via a `#[cfg(test)]` accessor); the paginated success-path test asserts it stays off.
  `pace_slot` and its unit test are unchanged.

### B. Clone diet (scan clones only)

- `clone_repo`'s `blobless: bool` parameter becomes a three-way `CloneShape` enum:
  `Blobless` (`--filter=blob:none`; fix path, default-branch-only fixes), `Full` (no
  filter; fix path with branch cleans), and `ScanDiet`
  (`--filter=blob:limit=<MAX_CONTENT_BYTES> --no-checkout`; scan path, combined with the
  existing `--depth=1 --no-single-branch`). `MAX_CONTENT_BYTES` (5 MiB) is exported as a
  `pub const` from `wormward-core` so the filter and the scanner's skip threshold cannot
  drift apart — the scanner never reads files above it, so those blobs are dead weight in
  a scan transfer.
- `fallback_clone_scan` is restructured for the checkout-less clone:
  - The default tip is scanned as a git tree: resolve `HEAD` (`rev-parse` works without a
    checkout), build `GitTree::new(&dest, &head)`, run `scan_tree` with `git_ref: None`.
    This is exact parity with the API scan path (whose docs already state the
    `.git/hooks` and reflog passes are working-tree-only and legitimately absent).
  - `deep_scan_repo` runs unchanged (it reads via `cat-file`, which needs no checkout;
    blobs above the filter limit that a pass does try to read lazy-fetch individually —
    rare by construction, since the scanner skips oversized files).
  - `is_auto_fixable`'s read closure reads via the `GitTree` instead of `std::fs`.
- **Coverage preservation — selective materialization.** Two detection passes are
  filesystem-only and previously ran over the clone's checkout: the STRICT build-output
  hidden-payload pass (`dist`/`.nuxt`/`vendor`/…) and the installed-`node_modules` sweep.
  After the clone, list HEAD's top-level entries (`git ls-tree`); if any scanned-on-disk
  surface dir (`node_modules` or a build-output dir from the core exclusion list) is
  committed, materialize exactly those dirs (`git checkout HEAD -- <dirs>`) and run
  `scan_build_output` + `scan_node_modules` over them as today. Most repos commit none of
  these, so the common case pays zero checkout cost; repos that do commit them keep
  today's detection exactly.
- Fix-path behavior, backup/push logic, and the rescan cache are untouched.

## Edge cases

- Empty repo / unborn HEAD in the clone: `rev-parse HEAD` fails → report the repo scanned
  with no findings (same as the API path's empty-branches early return), no crash.
- A >5 MiB text file that a pass does attempt to read: lazily fetched, scanned or skipped
  exactly as before — correctness unchanged, only that file's transfer is deferred.
- Repos with committed `node_modules`/build dirs: materialized and scanned as today (test
  below); everything else never touches the working tree.

## Testing (offline; local bare fixtures, no network)

1. Adaptive pacing: engagement off on healthy calls, sticky-on after a rate-limited call
   (mock server); no timing-based assertions.
2. Clone-path repo (size > threshold) with a payload in a committed `dist/` file is still
   detected (guards the selective materialization + build-output pass).
3. Clone-path repo with a committed `node_modules/<bad>/` payload is still detected
   (guards the node_modules sweep).
4. Clone-path repo with a working-tree-strippable payload still reports `auto_fixable`
   (guards the GitTree-based read closure) — and the scan leaves no checkout behind apart
   from any materialized surface dirs.
5. All existing clone-routing, truncated-tree, cache, breaker, and fix-path tests stay
   green unchanged.
