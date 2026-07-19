# Wormward: Remediation, GitHub Mode, and Faster Search — Design

Date: 2026-07-19
Status: Approved (design)

## Summary

Extend Wormward from a detection-only tool into one that also **remediates**
supply-chain worm infections and can operate across an entire GitHub account,
while making the scan engine faster. Three additions, one refactor:

1. **Faster search engine** — single-pass multi-signature matching (Aho-Corasick
   + `RegexSet`), binary/large-file skipping, and the `ignore` crate's parallel
   walker configured to *not* filter gitignored/hidden files.
2. **Local remediation** — a new `fix` subcommand that cleans infected working
   trees (strip payloads, delete artifacts, un-inject `.gitignore`), dry-run by
   default, with an opt-in `--rewrite-branches` flag for cross-branch history
   rewriting.
3. **GitHub account mode** — a new `github` subcommand that enumerates the
   logged-in user's repos, clones them, scans all branches, and (opt-in)
   remediates and force-pushes the fixes back.

`scan` remains read-only and unchanged. Detection findings and the pack schema
are reused as-is; the `Remediation`/`PayloadStrip` scaffolding already present in
`pack.rs` becomes live.

## Goals / Non-goals

**Goals**
- Automatically remove detected worm payloads from local repos, safely by default.
- Optionally rewrite infected non-default branches' history.
- Scan and (optionally) remediate every repo on the logged-in GitHub account.
- Make scanning faster, especially with many signatures/files and in deep/GitHub
  modes.

**Non-goals (cut for YAGNI)**
- Organization-wide or arbitrary-user scanning (only the logged-in user's own repos).
- Opening PRs/issues as a remediation channel (force-push path was chosen instead).
- Replacing `git` blob access with gitoxide object scanning.
- Auto-editing `package.json` dependencies (npm findings stay manual-review).

## Safety model

Destructive operations are layered behind explicit flags and default to dry-run:

| Operation | Gate | Default |
|-----------|------|---------|
| Read-only scan (`scan`) | none | runs |
| Working-tree fix (`fix`, `github --fix`) | `--yes` to apply | dry-run prints plan |
| Cross-branch history rewrite | `--rewrite-branches` **and** `--yes` | dry-run |
| Remote force-push (`github --push`) | `--push` **and** `--yes` | dry-run |

Before any history rewrite, a backup ref `refs/wormward-backup/<branch>-<timestamp>`
is created locally. Before any remote force-push, backup branches are pushed to a
`wormward-backup/*` namespace on the remote first. Per-repo errors in GitHub mode
are collected and reported; one failing repo never aborts the run.

## Architecture

Data flow:

```
packs ──► SignatureEngine (built once)
              │
              ▼
        scan (RepoFiles: WorkingTree | GitTree) ──► findings
              │
              ▼
   remediate::plan(findings, packs) ──► Vec<PlannedAction>
              │
     ┌────────┼───────────────┐
     ▼        ▼               ▼
apply_working_tree   rewrite (filter-repo)   github push
```

Crates:
- `wormward-core` — gains `SignatureEngine`, `remediate`, `rewrite` modules;
  `walk`/`scanner` refactored onto the new engine and walker.
- `wormward-github` — **new** crate: GitHub REST enumeration + per-repo clone/
  scan/fix/push orchestration. Depends on `wormward-core` + `wormward-packs`,
  reuses `ureq` + `serde_json`.
- `wormward-cli` — gains `fix` and `github` subcommands.

## Component 1: Faster search engine

### Problem
`scan_files` currently calls `signature_matches(sig, content)` once per signature
per file — O(files × signatures) substring/regex scans, recompiling regexes each
call.

### Design
A `SignatureEngine` compiled **once** from all active packs:

- **Literal signatures** → one `aho_corasick::AhoCorasick` automaton over every
  literal value across all packs. A parallel index maps each pattern id back to
  its `(pack_id, signature_id, severity, kind)`. One `find_iter`/`is_match` pass
  per file yields all literal hits.
- **Regex signatures** → one `regex::RegexSet`; `matches()` gives the set of
  matching pattern indices in a single pass, mapped back to their signatures.
- **Sha256 signatures** → hash the file content once; compare against a
  `HashMap<digest, signature>`.

API sketch:

```rust
pub struct SignatureEngine { /* automata + index tables */ }

pub struct SigHit {
    pub pack_id: String,
    pub signature_id: String,
    pub severity: Severity,
}

impl SignatureEngine {
    pub fn build(packs: &[Pack]) -> Self;
    /// All signature hits for one file's content, across all packs.
    pub fn scan_content(&self, content: &str) -> Vec<SigHit>;
}
```

`scan_files` is rewritten to: for each file, decide relevance via the existing
per-pack `target_files` globset (unchanged), read content once, run the engine
once, and turn `SigHit`s into `Finding`s. IOC-domain, analyzer, artifact,
`.gitignore`, and npm checks are unchanged in behavior; the analyzer still runs
per matched target file.

Note: `target_files` gating is per-pack, but a literal automaton is global. The
engine returns which pack each hit belongs to, so a hit is only emitted when the
file is a target of *that* hit's pack — preserving the current "signature only
counts in a target file" rule (see the `non_target_file_ignored` test).

### File filtering
- **Binary skip**: if the first ~8 KB contains a NUL byte, skip content signature
  matching (payloads are text). Artifact/path checks still apply.
- **Size cap**: skip files larger than a cap (default 5 MB) for content matching;
  config payloads are small. Cap is a constant, not yet user-configurable (YAGNI).

### Walker
Replace `walkdir` with `ignore::WalkBuilder` in `walk.rs`, configured to walk
fast **without** honoring ignore rules:

```rust
WalkBuilder::new(root)
    .git_ignore(false).git_exclude(false).git_global(false)
    .ignore(false).hidden(false).parents(false)
    .filter_entry(|e| !is_pruned_dir(e))   // still prune .git, node_modules
    .build_parallel()
```

Rationale: the worm injects entries into `.gitignore` to hide `config.bat`; a
gitignore-aware walk would skip exactly the artifacts we hunt. `discover_repos`
and `walk_repo_files` both move to `ignore`. Public signatures
(`discover_repos -> Vec<PathBuf>`, `walk_repo_files -> Vec<PathBuf>`) are
preserved; results remain sorted/deduped where they were.

### Dependencies
Add to `wormward-core`: `aho-corasick`, `ignore` (added to workspace deps too).

### Testing
- Parity: on the existing fixtures, the engine yields the same set of findings as
  the current `signature_matches` loop (keep a reference path in tests).
- Binary/large files are skipped for content matching but not for artifact checks.
- Walker still finds files under injected-`.gitignore` entries and still prunes
  `.git`/`node_modules`. Existing `walk` tests continue to pass.

## Component 2: Local remediation (`fix`)

### Module `wormward-core::remediate`
Pure planning separated from side effects.

```rust
pub enum ActionKind {
    StripPayload { markers: Vec<String> }, // strip_after_marker
    DeleteFile,
    RemoveGitignoreLine { line: String },
    ManualReview { reason: String },       // non-remediable findings
}

pub struct PlannedAction {
    pub repo: PathBuf,
    pub file: Option<PathBuf>,
    pub campaign: String,
    pub kind: ActionKind,
}

pub fn plan(findings: &[Finding], packs: &[Pack]) -> Vec<PlannedAction>;
```

Mapping from finding kind → action:

| FindingKind | Action |
|-------------|--------|
| `ContentSignature`, `Analyzer` | `StripPayload` using the pack's `remediation.config_payload` markers |
| `Artifact` | `DeleteFile` |
| `GitignoreInjection` | `RemoveGitignoreLine` |
| `NpmPackage`, `IocDomain`, `GitReflog` | `ManualReview` |

`StripPayload` semantics (`strip_after_marker`): find the byte offset of the
first occurrence of any marker in the file; truncate from that offset to EOF;
trim a trailing newline run so the file ends cleanly. If **no** marker is present
(e.g. a rotated payload the strip rule doesn't cover), downgrade that action to
`ManualReview` rather than guess — never blank a file.

Actions are deduplicated per `(repo, file, kind)` so multiple signature hits in
one file produce a single strip/delete.

### Apply
```rust
pub struct ActionOutcome { pub action: PlannedAction, pub status: ApplyStatus }
pub enum ApplyStatus { Planned, Applied, Skipped(String), Failed(String) }

pub fn apply_working_tree(plan: &[PlannedAction], dry_run: bool) -> Vec<ActionOutcome>;
```

- Writes are atomic (write temp file in the same dir, then rename); deletes use
  `std::fs::remove_file`.
- `dry_run` records `Planned` and touches nothing.
- After a non-dry-run apply that changed ≥1 file in a repo, stage and commit:
  `git -C <repo> add -A && git commit -m "wormward: remove <campaign> payload"`.
  Commit failures are surfaced as `Failed` but do not roll back the file edits
  (the working tree is already clean; the user can commit manually).

### CLI: `fix`
```
wormward fix [dirs] [--deep] [--rewrite-branches] [--yes] [--format text|json]
```
- Runs `scan` (or `scan_deep` when `--deep` or `--rewrite-branches` is set),
  builds the plan, prints it (text or JSON).
- Applies working-tree actions only with `--yes`.
- Exit codes: 0 = clean or fully remediated, 1 = infections found (dry-run) or
  remaining after apply, 2 = error.

## Component 3: Cross-branch rewrite (`--rewrite-branches`)

Gated behind `--rewrite-branches`; still dry-run unless `--yes`.

For each infected branch (deep-scan findings whose `git_ref` is set and whose
kind is payload-strippable):

1. **Backup**: `git branch refs/wormward-backup/<branch>-<timestamp> <branch>`
   (created before any rewrite; never overwritten).
2. **Rewrite**: invoke `git filter-repo --refs <branch> --blob-callback <py>`,
   where `<py>` is a Python snippet generated from the pack's `strip_after_marker`
   markers that truncates each matching blob at the first marker. `git filter-repo`
   is the modern, well-tested history rewriter; delegating avoids hand-rolled
   history surgery.
3. **Absent tool**: if `git filter-repo` is not on `PATH`, skip branch rewrite
   with a clear message listing the affected branches and install instructions;
   the working-tree fix still applies. Dry-run prints the branch list and the
   generated callback without executing.

```rust
pub struct BranchRewritePlan {
    pub repo: PathBuf,
    pub branch: String,
    pub backup_ref: String,
    pub blob_callback: String,
}
pub fn plan_branch_rewrites(findings: &[Finding], packs: &[Pack]) -> Vec<BranchRewritePlan>;
pub fn apply_branch_rewrites(plans: &[BranchRewritePlan], dry_run: bool) -> Vec<ActionOutcome>;
```

### Testing
- Backup-ref name generation and `plan_branch_rewrites` selection logic
  (unit-tested against synthesized deep-scan findings).
- Blob-callback string generation from markers.
- `apply` dry-run creates no refs and executes nothing.
- If `git filter-repo` is available in CI, an end-to-end rewrite test on a temp
  repo asserts the payload is gone from history and the backup ref points at the
  original tip; otherwise this test is skipped with a logged notice.

## Component 4: GitHub account mode (`github`)

New crate `wormward-github`.

### Auth
Resolve a token in order: `--token`, `GITHUB_TOKEN`, `GH_TOKEN`, then
`gh auth token` (shell out). If none, exit 2 with guidance.

### Enumerate
`GET https://api.github.com/user/repos?affiliation=owner&per_page=100`, following
`Link: rel="next"` pagination (`ureq`). Parse into `RepoRef { full_name, clone_url,
default_branch, fork }`. `--include-forks` (default off) controls whether forks
are kept.

```rust
pub trait RepoHost {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError>;
}
pub struct GitHubHost { token: String, base_url: String } // base_url injectable for tests
```

### Per-repo pipeline
Bounded-parallel (a small pool, e.g. 4) over enumerated repos. For each:

1. **Clone** all branches into `--clone-dir`/temp:
   `git clone --no-single-branch <clone_url> <dest>`; remote branches land under
   `refs/remotes/origin/*`, which `deep_scan_repo` already scans.
2. **Scan**: `scan_repo` (default-branch working tree) + `deep_scan_repo`
   (all branch tips).
3. **`--fix`**: `remediate::apply_working_tree`; with `--rewrite-branches`,
   `apply_branch_rewrites`.
4. **`--push --yes`**: push backups to `wormward-backup/*` on origin first, then
   force-push the cleaned branches (`git push --force-with-lease`).

```rust
pub struct RepoOutcome {
    pub repo: RepoRef,
    pub findings: Vec<Finding>,
    pub actions: Vec<ActionOutcome>,
    pub error: Option<String>,
}
pub fn run(opts: &GithubRunOpts, host: &dyn RepoHost, packs: &[Pack]) -> Vec<RepoOutcome>;
```

Errors per repo are captured in `RepoOutcome.error`; the run continues.

### CLI: `github`
```
wormward github [--token T] [--clone-dir D] [--include-forks]
                [--fix] [--rewrite-branches] [--push] [--yes]
                [--format text|json]
```
- Dry-run default (enumerate + scan + print intended actions).
- `--fix` needs `--yes` to write locally; `--push` needs `--yes` to force-push.
- Aggregate exit code: 0 all clean/remediated, 1 infections found or remaining,
  2 error (auth/enumeration failure).

### Testing
- `list_repos` pagination + fork filtering parsed against `httpmock` (dev-dep).
- `run` pipeline exercised with a fake `RepoHost` and a temp local "origin" repo
  (`git init --bare`), so clone/scan/fix/push run without real network:
  asserts detection, working-tree fix, backup-branch push, and force-push.
- Auth resolution order unit-tested (env vars; `gh` shell-out mocked or skipped).

## CLI summary

```
wormward scan   [dirs] [--deep] [--online] [--format]              # unchanged, read-only
wormward fix    [dirs] [--deep] [--rewrite-branches] [--yes] [--format]
wormward github [--token T] [--clone-dir D] [--include-forks]
                [--fix] [--rewrite-branches] [--push] [--yes] [--format]
wormward list-packs                                                # unchanged
wormward check  ...                                                # unchanged
```

Exit codes across all commands: `0` clean/remediated, `1` infections found or
remaining, `2` error.

## Error handling

- Missing `git filter-repo` → branch rewrite skipped with install guidance;
  working-tree fix still applied.
- Missing GitHub token → exit 2 with instructions.
- Per-repo failure in `github` mode → recorded in `RepoOutcome.error`, run continues.
- Strip with no marker present → `ManualReview`, file untouched.
- All git invocations check exit status; failures become `Failed` outcomes, never
  silent.

## Rollout / compatibility

- `scan`, `list-packs`, `check`, and the JSON `Finding` shape are unchanged.
- The engine refactor is behavior-preserving, guarded by parity tests.
- New deps: `aho-corasick`, `ignore` (core); new crate `wormward-github`.
