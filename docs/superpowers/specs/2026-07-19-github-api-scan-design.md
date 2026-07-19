# GitHub API-Based Scanning (Clone-Free Scan Phase)

**Date:** 2026-07-19
**Status:** Approved

## Problem

GitHub mode (`wormward github`, desktop GUI) currently clones **every** repo in the
account (`git clone --no-single-branch`) just to run a read-only scan, then reuses
those clones in the fix phase. For accounts with many repos this is slow, heavy on
bandwidth/disk, and unnecessary: the scanner only ever reads a handful of
pack-targeted files per branch tip.

## Goal

Scan an entire GitHub account **without cloning anything**, preserving today's
detection coverage (default branch + every branch tip). Clone on demand only the
repos actually selected for fixing.

## Non-Goals

- The local filesystem scan (`wormward scan <path>`) is unchanged.
- The reflog amended-commit check is dropped from GitHub mode. It is
  corroborative-only, and a fresh clone has no meaningful reflog, so GitHub mode
  never truly benefited from it.
- No new rate-limit backoff machinery beyond fail-fast (see Error Handling).

## Design

### Key insight

`wormward-core`'s scanner is already abstracted over the `RepoFiles` trait
(`paths()` / `read()` / `exists()` in `crates/wormward-core/src/repo_files.rs`),
and campaign analyzers operate on in-memory `ScannedFile` content. Everything the
scan does — content signatures, artifact filenames, `.gitignore` tampering, npm
dependency checks, analyzers — flows through that trait. Only the reflog check
touches git state directly.

### Scan phase (no clones)

`RepoHost` (in `crates/wormward-github/src/lib.rs`) grows three methods beside
`list_repos`:

```rust
fn list_branches(&self, full_name: &str) -> Result<Vec<Branch>, GithubError>;
// Branch { name: String, commit_sha: String }
fn get_tree(&self, full_name: &str, commit_sha: &str) -> Result<Tree, GithubError>;
// Tree { entries: Vec<(PathBuf, String /* blob sha */)>, truncated: bool }
fn get_blob(&self, full_name: &str, blob_sha: &str) -> Result<Option<String>, GithubError>;
// Ok(None) for binary / non-UTF-8 blobs (mirrors GitTree::read)
```

Endpoints: `GET /repos/{o}/{r}/branches` (paginated), `GET
/repos/{o}/{r}/git/trees/{sha}?recursive=1`, `GET /repos/{o}/{r}/git/blobs/{sha}`
(base64). All three reuse the existing infrastructure: bearer token sent only to
the configured API authority (foreign-`next`-link guard), `MAX_PAGES` pagination
cap, token redaction in error strings.

A new `ApiTree` struct in `wormward-github` implements `RepoFiles`:

- `paths()` — from the tree listing.
- `read()` — lazy blob fetch through a shared `sha → Option<String>` cache
  (a file identical across N branches is fetched once). Packs only `read()`
  files matching their target globs, so this is a few blobs per branch.
- Fetch failures are recorded internally (see Error Handling).

Per repo, the scan mirrors `scan_repo` + `deep_scan_repo` semantics:

1. Scan the default-branch tip via `scan_files` with **no** `git_ref` — these
   findings are remediable, exactly like working-tree findings today.
2. Scan every other branch tip, deduplicated by commit SHA (skipping tips equal
   to the default tip), with `git_ref = branch name` — routed to `manual` by
   `plan_remediation`, exactly like deep-scan findings today.
3. Empty repos (no branches) produce no findings.

**Truncated-tree fallback:** the Trees API truncates around 100k entries. If
`truncated` is set for any tip, fall back to a full clone-and-scan for that one
repo, so coverage never silently degrades. The fallback clone is temporary and
deleted after scanning; if the repo is later selected for fixing, the fix phase
re-clones it like any other repo (keeps `ScannedRepo` clone-free and uniform).

### Fix phase (clone on demand)

- `ScannedRepo` loses `dest`; `ScanPass` loses its held `TempDir` — the scan
  result becomes pure findings.
- `fix_pass` clones **only selected repos** (authenticated, as today) into
  `opts.clone_dir` or a temp dir it owns and cleans up.
- After cloning, it re-runs the local `scan_repo` on the fresh clone and plans
  remediation from those local findings. This handles repos that changed between
  scan and fix, and makes remediation paths line up with the working tree
  naturally. Apply / commit / backup-push / force-push logic is unchanged.
- Clean repos never touch disk.

### Call-site impact

`scan_pass` / `fix_pass` signatures are unchanged, so:

- `crates/wormward-cli/src/main.rs` (github subcommand): trivial updates only.
- `apps/desktop/src-tauri/src/lib.rs`: the cached `ScanPass` state no longer
  holds live clones (just findings + token); the "keep clones alive between
  phases" and "clear clones after" bookkeeping goes away since the fix phase
  owns its own temp dir.

## Error Handling

- Per-repo failures remain non-fatal and land in `ScannedRepo.error` /
  `RepoOutcome.error`, as today.
- **Silent-clean hazard:** `RepoFiles::read()` has no error channel, so a
  transient HTTP failure could read as "file absent" → false clean. `ApiTree`
  records fetch failures; the scan promotes any failure into
  `ScannedRepo.error` ("scan incomplete") instead of reporting the repo clean.
- HTTP 403/429 (rate limit) aborts the run with a clear message rather than
  burning through every remaining repo.

## Rate-Limit Budget

Per repo ≈ 1 branches call + 1 tree call per unique branch tip + a few blob
fetches (SHA cache dedupes across branches). A 200-repo account with ~3 branches
each lands near ~1k requests against the 5,000/hour authenticated limit.

## Testing

- **HTTP layer (`httpmock`):** branches/trees/blobs happy paths and pagination;
  the foreign-host token guard on every new endpoint; truncated-tree detection;
  blob-fetch failure → repo error, not clean.
- **Pipeline:** the `FakeHost` test doubles implement the three new methods by
  shelling out to `git ls-tree` / `git cat-file` against the local bare
  fixtures, so the existing end-to-end tests (fix, dry-run, push+backup,
  branch-only detection, selection) keep passing under the new flow.
- **New invariant test:** a clean repo produces **zero clone directories** on
  disk after a full scan + fix pass.
