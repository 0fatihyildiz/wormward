# Local scan: live progress + cancel (GUI)

## Problem

The desktop **local folder scan** (Scan tab) is now async (no longer freezes the UI, fixed
upstream), but it still shows nothing while running and cannot be stopped. Upstream added
per-repo progress streaming and a `ScanProgress` type for the **GitHub account scan** only
(`scan_pass_with_progress` → `github-scan-progress` event). This spec brings the same
live-progress + a Stop button to the local folder scan.

## Requirements

- While a local scan runs, the Scan tab shows a **live log** — one line per repo as it is
  scanned ("✓ /path/repo — N findings") plus a running `done/total` counter.
- A **Stop** button cancels the run. Cancellation takes effect at the next repo boundary
  (sub-second for normal repos); a partial report is returned for what was scanned.
- The existing CLI `scan`/`scan_deep` (parallel) are unchanged. This is GUI-only.

## Design

### Core — `wormward-core/src/scanner.rs`

New public function, sequential and cancellable:

```rust
pub fn scan_streaming(
    roots: &[PathBuf],
    packs: &[Pack],
    deep: bool,
    cancel: &AtomicBool,
    on_repo: &dyn Fn(usize, usize, &Path),   // (done, total, repo)
) -> ScanReport
```

- Discovers repos under `roots` (sorted, deduped) → `total`.
- For each repo: check `cancel` **before** scanning → break early if set. Scan with
  `scan_repo` (+ `deep_scan_repo` when `deep`). After each, call `on_repo(done, total, repo)`.
- `repos_scanned` reflects the number actually scanned (partial on cancel).
- Runs **sequentially** (not rayon) so progress order and cancellation are deterministic and
  immediate at repo boundaries. `scan`/`scan_deep` stay parallel for the CLI.

Exported from `lib.rs`.

### Desktop — `apps/desktop/src-tauri/src/lib.rs`

- Managed state: `type ScanCancel = Arc<AtomicBool>` (registered via `.manage(...)`).
- `scan` command gains `window: tauri::Window` and `cancel: State<ScanCancel>`. It resets the
  flag to `false`, then runs `scan_streaming(...)` with a callback that emits a
  `local-scan-progress` event `{ done, total, repo }` per repo (mirrors `github-scan-progress`).
  Returns the existing `ScanResult { report, warnings }` (report is partial on cancel).
- New `cancel_scan` command sets the flag to `true`. It runs as a separate async task, so it
  can flip the atomic while `scan` is mid-run (no shared lock).

### Frontend — `apps/desktop/src/routes/Scan.svelte` + `state.svelte.ts`

- State: `scanLog: string[]`, `scanProgress: { done: number; total: number } | null`.
- On scan: clear log, `listen('local-scan-progress', e => { append line; update progress })`,
  then `invoke('scan', ...)`. On resolve/reject: unlisten; navigate to Results.
- While `app.scanning`: show the live log panel + a **Durdur** button that calls
  `invoke('cancel_scan')`. Reuse the `ScanProgress` TS type.

## Testing

- **Core:** `scan_streaming` invokes `on_repo` once per repo with correct `(done, total)`; a
  callback that sets `cancel` after the first repo leaves `repos_scanned == 1` (deterministic
  cancellation). Verified with real temp repos.
- **Desktop:** compiles; `cancel_scan` plumbing exercised via the command signature. Event
  emission is not unit-tested (Tauri runtime), but the core streaming logic is.
- **Frontend:** `svelte-check` passes.

## Out of scope

- Mid-repo cancellation for a single gigantic monorepo (would thread `cancel` through
  `scan_repo`/`scan_tree`/`scan_files`/`scan_capabilities`). Repo-boundary cancel is enough
  for the common many-repos case; revisit only if needed.
- CLI progress/cancel (Ctrl-C already stops the process).
