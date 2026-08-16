# GitHub fix: clean infected branch tips

**Date:** 2026-08-17
**Status:** Approved

## Problem

The GitHub account scan reports infected branch tips (`git_ref`-stamped findings), but the
GitHub fix pipeline only remediates the default branch's working tree. A repo whose infection
is branch-only is marked `manual_review` and is not even selectable for fixing — the product
says "this branch is infected" and then refuses to act on it. Users must clone locally and use
the local branch cleaner by hand.

## Goal

`wormward github --fix --push` (and the desktop GitHub fix) also rewrites infected branch tips
clean and force-pushes them, with the old tip preserved on the remote. Branch-only repos become
selectable/fixable. No new consent gates: `--yes` / the desktop confirm modal already consent to
force-pushed history rewrites; copy is updated to name branch tips explicitly.

## Non-goals

- No GitHub-API-side rewriting (trees/commits/refs over REST). The strip-and-verify logic
  stays single-sourced in the local branch-clean machinery.
- No deep-history rewrite; like the local cleaner, this rewrites branch TIPS (one clean commit
  on top).
- No change to the local scan flow (it already offers branch cleaning).

## Design

### Pipeline (`fix_scanned` in `wormward-github/src/pipeline.rs`)

1. **Clone shape.** If the repo's findings include any `git_ref` finding, clone full
   (`blobless = false`) — branch cleaning reads branch blobs, and a blobless clone would
   lazily re-fetch each one over the network. Repos with only working-tree findings keep the
   existing blobless clone.
2. **Default-branch fix unchanged**, including the residual-scan safety revert and the
   remote `wormward-backup/<default>-<ts>` backup push.
3. **Branch cleans** run after the default-branch remediation, and only when `opts.push` is
   true (cleaning tips in a throwaway clone that never pushes accomplishes nothing; without
   `--push`, branch-only repos keep today's `manual_review` reporting):
   - Re-derive plans locally: `deep_scan_repo(&dest)` → `plan_branch_cleans` — the same
     "re-scan at fix time" philosophy the default-branch path uses.
   - **Exclude `origin/<default_branch>`** from the plans: after the default-branch commit,
     the stale remote-tracking ref would otherwise be planned as an "infected tip" and
     redundantly cleaned next to the default-branch force-push.
   - **Remote backups:** before applying each plan, push the old tip to the remote as
     `refs/heads/wormward-backup/<leaf>-<ts>` (leaf = branch name without the `origin/`
     prefix). The clone is deleted after the run, so a local backup ref would be a lie.
     A failed backup push skips that branch (mirrors the default-branch behavior).
   - Apply via `apply_branch_cleans(plans, dry_run=false, push=true, packs)` — isolated
     worktrees, per-branch `--force-with-lease`, all reused as-is. In a fresh clone every
     planned branch is a remote-tracking ref, which `apply_branch_cleans` pushes to the
     remote's real branch. `apply_branch_cleans` now also strip-and-VERIFIES: after applying
     the actions in the worktree and before committing, it re-scans the worktree
     (`scan_repo(wt, packs)`) — the same residual-verify safety property the default-branch
     path has always had. A signature sitting before the strip marker (surviving
     `strip_after_marker`, which cuts from the marker onward) makes the worktree scan
     non-empty; the clean then reports `BranchCleanStatus::Failed(...)` and neither commits
     nor pushes. The already-created backup ref is left in place (create-only, harmless).
4. **Reporting** reuses `RepoOutcome`'s existing fields: cleaned branches append to `actions`
   (human-readable "cleaned branch origin/evil: …" lines) and their leaf names to `pushed`;
   the first branch failure goes to `error`. Unplannable branch findings
   (`branch_manual_findings`) keep the repo `manual_review`. No JSON schema churn.

### Fixability / selectability

- `ScannedRepo` gains `branch_fixable: bool` — any finding with `git_ref` set and
  `remediable` true (the scan already computed strip applicability against that tip's actual
  content). Set in both `api_scan_repo` and `fallback_clone_scan`.
- Desktop: a repo is selectable when `auto_fixable || branch_fixable`; the GitHub card copy
  reflects that fixing may rewrite branches. CLI: the "branch-only repos are reported, not
  selectable" special case is removed.

### Dry run (`--fix` without `--yes`)

Derive branch plans from the API findings via `plan_branch_cleans` (no clone) and list them as
"would clean branch <name>: …" lines. Cosmetic note: dry-run branch names come from the API
(`evil`), the real fix names come from the clone's remote-tracking refs (`origin/evil`).

### Consent / UI

- CLI: no new flag; branch cleaning is part of `--fix --push --yes`.
- Desktop: the existing GitHub confirm modal's copy is extended — infected branch tips are
  also rewritten and force-pushed, old tips kept as `wormward-backup/…` branches on the
  remote.

## Edge cases

- Repo with both working-tree and branch infections: both are fixed in one pass.
- Branch tip sharing the default branch's payload: covered — the deep scan replays HEAD-tree
  findings per branch (fixed earlier this session); after the default-branch fix commits,
  the tip also differs from the new clean HEAD and is scanned directly.
- Multiple branches at one commit: deep scan dedupes by commit; one plan cleans the ref it
  names, the same behavior the local cleaner has today.
- `opts.push` false, or dry run: no branch mutation of any kind.

## Testing (TDD, pipeline-level, no network)

Local bare repo as "remote", file-URL clones, mock `RepoHost` (follow the existing pipeline
test harness):

1. Scan pass marks a branch-only repo `branch_fixable`.
2. Fix with push rewrites the remote's infected tip (payload gone on the remote branch) and
   creates the remote `wormward-backup/<leaf>-<ts>` branch pointing at the old tip.
3. Fix without push leaves every branch untouched; repo reports `manual_review`.
4. Repo with working-tree + branch infections: default branch and branch tip both clean on
   the remote afterwards.
5. `origin/<default_branch>` is never double-cleaned as a "branch".
6. Dry run lists "would clean branch …" lines and touches nothing.
