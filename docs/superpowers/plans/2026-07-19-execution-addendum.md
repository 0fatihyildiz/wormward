# Execution Addendum — reconciled with origin/main

Date: 2026-07-19

After rebasing onto `origin/main`, local remediation already exists (the `clean` /
`restore` commands). This addendum supersedes the original plan where they conflict.

## Status of original plan phases

- **Phase 1 (faster search engine)** — NOT done. Proceed as written (Tasks 1-4).
- **Phase 2 (local remediation `fix`)** — OBSOLETE. Already implemented on main as
  `clean`/`restore`. Do NOT build `fix`, `plan`, `apply_working_tree`, `PlannedAction`,
  `ActionOutcome`. Use the EXISTING APIs instead (see "Existing APIs" below).
- **Phase 3 (cross-branch rewrite)** — REVISED. Integrate into the existing `clean`
  command; make it actually clean non-default branches (the user's core ask).
- **Phase 4 (GitHub account mode)** — proceed, but consume the EXISTING remediation
  APIs, not the obsolete Phase 2 names.

## Existing APIs (in `wormward-core`, use these verbatim)

Remediation (`remediate.rs`):
- `plan_remediation(findings: &[Finding], packs: &[Pack]) -> RemediationPlan`
  where `RemediationPlan { actions: Vec<RemediationAction>, manual: Vec<Finding> }`.
- `RemediationAction` = `StripPayload { file, markers } | DeleteFile { file } | RemoveGitignoreLine { file, line }`; `.target() -> &Path`.
- `apply(repo: &Path, actions: &[RemediationAction], backup: bool) -> RemediationResult`
  where `RemediationResult { applied, skipped: Vec<(RemediationAction, String)>, backup_dir: Option<PathBuf> }`. Backups go to `<repo>/.wormward-backup/<ts>/`.
- `restore(repo: &Path) -> RestoreResult`.

Git (`git.rs`):
- `commit_paths(repo, message, paths) -> Result<(), String>`
- `amend_head(repo, paths) -> Result<(), String>`
- `push(repo) -> Result<(), String>`
- `force_push_with_lease(repo) -> Result<(), String>`

Scanning: `scan_repo(repo, packs)`, `deep_scan_repo(repo, packs)`, `discover_repos(root)`.

Note: `plan_remediation` currently routes any finding with `git_ref.is_some()` (deep-scan,
other branch) into `manual`. Cross-branch cleaning (Phase 3) is what changes that.

## Wave structure (isolated worktrees, merge to main after review)

**Wave 1 — parallel, file-disjoint:**
- **W1-A: Phase 1 faster engine** — `SignatureEngine` (aho-corasick + RegexSet + sha256),
  rewrite `scan_files` onto it with binary/size skip, move walker to the `ignore` crate
  (ignore rules disabled). Files: `crates/wormward-core/src/{engine.rs,scanner.rs,walk.rs,lib.rs}`,
  `crates/wormward-core/Cargo.toml`, workspace `Cargo.toml` (`[workspace.dependencies]`).
  Must keep all existing tests green (behavior-preserving). Original plan Tasks 1-4.
- **W1-B: Phase 4 GitHub mode** — new crate `wormward-github` (`resolve_token`, `RepoRef`,
  `RepoHost`/`GitHubHost` with pagination, `pipeline::run` clone→scan(deep)→remediate→push
  reusing the Existing APIs) + `github` subcommand in `main.rs` + renderers in `report.rs`.
  Files: `crates/wormward-github/**` (new), `crates/wormward-cli/src/{main.rs,report.rs}`,
  `crates/wormward-cli/Cargo.toml`, workspace `Cargo.toml` (`[workspace] members`).
  Original plan Tasks 10-13, but calling `plan_remediation`/`apply`/`force_push_with_lease`.

Wave 1 collision check: W1-A touches `wormward-core` + workspace deps section; W1-B touches
new crate + `wormward-cli` + workspace members section. Disjoint except the workspace
`Cargo.toml` (different sections) — worktrees isolate; merge W1-A then W1-B, re-run tests.

**Wave 2 — after Wave 1 merged:**
- **W2-C: Phase 3 cross-branch cleaning** — extend `clean` with a `--deep`/`--all-branches`
  path that, for each infected non-default branch, rewrites history to strip the payload
  (via `git filter-repo` blob-callback generated from pack markers; backup ref
  `refs/wormward-backup/<branch>-<ts>` first; skip-with-message if filter-repo absent),
  and with `--push --yes` force-pushes the cleaned branches. Files: `crates/wormward-core/src/rewrite.rs`
  (new), `crates/wormward-cli/src/main.rs` (`Clean` arm), `report.rs`. Original plan Tasks 8-9,
  integrated into `clean` rather than a separate `fix`.

## Review gate after each wave

Run `cargo test --workspace` + `cargo clippy --workspace --all-targets`; confirm existing
`scan`/`clean`/`restore` behavior unchanged; then request code review before merging.
