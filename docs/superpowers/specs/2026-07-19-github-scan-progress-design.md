# GitHub Scan Progress Reporting

**Date:** 2026-07-19
**Status:** Approved

## Problem

The API-based GitHub scan (`scan_pass`) fans out over all repos with rayon and
returns only when every repo is done. Until then the CLI prints nothing and the
desktop GUI shows a static "Scanning repositories…" line. On accounts with many
repos there is no sign of life or of how much work remains.

## Goal

Live per-repo progress ("X of Y, currently owner/repo") in both the CLI and the
desktop GUI, fed by one mechanism in the pipeline.

## Non-Goals

- No per-branch or per-blob granularity (too noisy; repo-level only).
- No streaming of per-repo findings (results still arrive at the end).
- No progress for the fix phase (it typically touches 0–2 repos).

## Design

### Pipeline (`crates/wormward-github/src/pipeline.rs`)

```rust
/// A completed repo during a scan pass. Events arrive in COMPLETION order,
/// not input order (rayon); consumers should render "latest done/total".
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanProgress {
    pub done: usize,
    pub total: usize,
    /// full_name of the repo that just finished.
    pub repo: String,
}

pub fn scan_pass_with_progress(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
    on_progress: &(dyn Fn(ScanProgress) + Sync),
) -> Result<ScanPass, GithubError>;
```

`scan_pass_with_progress` contains the current `scan_pass` body plus an
`AtomicUsize`. After each repo's `api_scan_repo` returns — success or per-repo
error alike — it increments the counter and invokes `on_progress` with
`done = fetch_add(1, Relaxed) + 1`, `total = repos.len()`, and the repo's
`full_name`. A rate-limit abort stops the scan (and therefore the events);
callbacks are `Fn` with no `Result`, so progress can never fail a scan.

`scan_pass` keeps its exact current signature and becomes a one-line wrapper:
`scan_pass_with_progress(opts, host, packs, token, &|_| {})`. No existing
caller changes.

### CLI (`crates/wormward-cli/src/main.rs`, github subcommand)

Pass a closure that rewrites a single stderr line:
`\r  scanning {done}/{total} {full_name}…` (padded/truncated so a shorter line
does not leave residue). Emit ONLY when stderr is a TTY (reuse the
`select::stdio_is_tty` pattern) so JSON mode, pipes, and CI logs stay clean.
Print one `\n` to stderr after the scan finishes if any progress was drawn.

### GUI

- `apps/desktop/src-tauri/src/lib.rs`: `github_scan` gains a
  `window: tauri::Window` parameter and passes a closure that does
  `let _ = window.emit("github-scan-progress", &p);` — emit failures ignored
  (progress is best-effort by design).
- `apps/desktop/src/routes/GitHub.svelte`: register
  `listen("github-scan-progress", ...)` BEFORE `invoke("github_scan")`,
  unlisten when the invoke settles (success or error). While scanning, render
  "Scanning {done} of {total} — {repo}" in place of the current static line
  (static line remains until the first event arrives).

## Error Handling

- Progress is fire-and-forget everywhere: no callback error channel, emit
  errors swallowed, TTY detection failure means simply no CLI progress.
- Unordered event arrival is documented on `ScanProgress`; consumers render
  the latest values only.

## Testing

- Pipeline: `GitFakeHost` with 3 repos + a `Mutex<Vec<ScanProgress>>`
  collector. Assert 3 events, each `total == 3`, `done` values are a
  permutation of 1..=3, every `full_name` appears exactly once, and the last
  event has `done == total`.
- Existing `scan_pass` tests keep passing unchanged (wrapper preserves
  behavior).
- CLI/GUI wiring is thin glue: verified by `cargo build --workspace`, the
  existing suites, and `pnpm check` (svelte-check) for the frontend change.
