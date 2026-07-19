//! Cross-branch cleaning: remove worm payloads from the tips of infected branches other
//! than the one currently checked out.
//!
//! Each branch is cleaned in an isolated temporary worktree so the user's working tree and
//! HEAD are never disturbed. Before rewriting a branch tip we snapshot it into a
//! `refs/wormward-backup/...` ref (cheap, instant rollback via `git update-ref`/reset).
//!
//! Uses stock git only — no `git filter-repo`. This rewrites the branch TIP (a new clean
//! commit on top), not deep history.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::finding::Finding;
use crate::pack::Pack;
use crate::remediate::{self, action_for, RemediationAction};

/// A plan to clean one branch's tip: the actions to apply and where its old tip is backed up.
#[derive(Debug, Clone, PartialEq)]
pub struct BranchCleanPlan {
    pub repo: PathBuf,
    pub branch: String,
    pub backup_ref: String,
    pub actions: Vec<RemediationAction>,
}

/// Outcome of attempting to apply a single `BranchCleanPlan`.
#[derive(Debug, Clone, PartialEq)]
pub enum BranchCleanStatus {
    /// Dry run — nothing was changed.
    Planned,
    /// Branch tip rewritten; old tip preserved at `backup_ref`.
    Cleaned { backup_ref: String },
    /// Nothing to do (e.g. no action actually applied to this branch's tree).
    Skipped(String),
    /// An error occurred; the backup ref (if created) still allows recovery.
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct BranchCleanOutcome {
    pub plan: BranchCleanPlan,
    pub status: BranchCleanStatus,
}

/// Seconds since the UNIX epoch (used to make backup refs / worktree paths unique).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build one `BranchCleanPlan` per infected (repo, branch). Only findings carrying a
/// `git_ref` are considered (working-tree findings are handled by `plan_remediation`).
/// The kind→action mapping is shared with `remediate` via `action_for` (DRY); findings
/// that map to no action (npm, ioc, reflog, unconfigured strip …) are skipped. Actions are
/// deduped within a branch.
pub fn plan_branch_cleans(findings: &[Finding], packs: &[Pack], timestamp: u64) -> Vec<BranchCleanPlan> {
    // Preserve first-seen ordering of (repo, branch) groups.
    let mut order: Vec<(PathBuf, String)> = Vec::new();
    let mut actions_by_group: std::collections::HashMap<(PathBuf, String), Vec<RemediationAction>> =
        std::collections::HashMap::new();

    for f in findings {
        let branch = match &f.git_ref {
            Some(b) => b.clone(),
            None => continue,
        };
        let action = match action_for(f, packs) {
            Some(a) => a,
            None => continue,
        };
        let key = (f.repo.clone(), branch);
        let entry = actions_by_group.entry(key.clone()).or_default();
        // Dedup per (file, kind): identical actions collapse to one.
        if !entry.contains(&action) {
            entry.push(action);
        }
        if !order.contains(&key) {
            order.push(key);
        }
    }

    order
        .into_iter()
        .map(|key| {
            let actions = actions_by_group.remove(&key).unwrap_or_default();
            let (repo, branch) = key;
            let backup_ref = format!("refs/wormward-backup/{branch}-{timestamp}");
            BranchCleanPlan { repo, branch, backup_ref, actions }
        })
        .collect()
}

static WT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temp path for an isolated worktree. Uniqueness matters because a single run may
/// clean several branches sharing one timestamp.
fn unique_worktree_path() -> PathBuf {
    let n = WT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("wormward-wt-{}-{ts}-{n}", std::process::id()))
}

/// Apply branch-clean plans. When `dry_run`, every plan reports `Planned` and nothing is
/// touched. Otherwise, for each plan: back up the tip ref, add a temp worktree on the
/// branch, run the working-tree remediation there, commit, optionally force-push (scoped to
/// that branch), and ALWAYS tear the worktree down.
pub fn apply_branch_cleans(
    plans: &[BranchCleanPlan],
    dry_run: bool,
    push: bool,
) -> Vec<BranchCleanOutcome> {
    plans
        .iter()
        .map(|plan| {
            let status = if dry_run {
                BranchCleanStatus::Planned
            } else {
                clean_branch(plan, push)
            };
            BranchCleanOutcome { plan: plan.clone(), status }
        })
        .collect()
}

fn clean_branch(plan: &BranchCleanPlan, push: bool) -> BranchCleanStatus {
    let repo = &plan.repo;
    let branch = &plan.branch;

    // Snapshot the current tip so the rewrite is reversible.
    let old_oid = match crate::git::rev_parse(repo, branch) {
        Some(o) => o,
        None => return BranchCleanStatus::Failed(format!("cannot resolve branch '{branch}'")),
    };
    if let Err(e) = crate::git::update_ref(repo, &plan.backup_ref, &old_oid) {
        return BranchCleanStatus::Failed(format!("could not create backup ref: {e}"));
    }

    // Classify the ref. A local branch (refs/heads/<branch>) is checked out directly and its
    // ref advances in place. A remote-tracking ref (e.g. `origin/evil`) has no local branch,
    // so we materialize a local branch from it, clean that, and force-push the specific
    // remote branch. Local branches are checked first so a local branch named like a remote
    // one is never misclassified.
    let is_local = crate::git::verify_ref(repo, &format!("refs/heads/{branch}"));
    let is_remote_tracking =
        !is_local && crate::git::verify_ref(repo, &format!("refs/remotes/{branch}"));

    // (local branch name to check out, Some(remote) if this is a remote-tracking clean)
    let (local_name, remote): (String, Option<String>) = if is_local {
        (branch.clone(), None)
    } else if is_remote_tracking {
        match branch.split_once('/') {
            // refs/remotes/<remote>/<name>: first component is the remote, rest is the branch
            // (which may itself contain slashes, e.g. origin/feature/x).
            Some((r, n)) => (n.to_string(), Some(r.to_string())),
            None => {
                return BranchCleanStatus::Failed(format!(
                    "remote-tracking ref '{branch}' has no '/' separator"
                ))
            }
        }
    } else {
        return BranchCleanStatus::Failed(format!(
            "branch '{branch}' is neither a local nor a remote-tracking ref"
        ));
    };

    let wt = unique_worktree_path();
    let add = if is_local {
        crate::git::worktree_add(repo, &wt, branch)
    } else {
        crate::git::worktree_add_new_branch(repo, &wt, &local_name, branch)
    };
    if let Err(e) = add {
        return BranchCleanStatus::Failed(format!("worktree add failed: {e}"));
    }

    let status = clean_in_worktree(&wt, plan, push, remote.as_deref(), &local_name);

    // Always tear the worktree down, even on error.
    let _ = crate::git::worktree_remove(repo, &wt);
    let _ = std::fs::remove_dir_all(&wt);

    status
}

fn clean_in_worktree(
    wt: &std::path::Path,
    plan: &BranchCleanPlan,
    push: bool,
    remote: Option<&str>,
    local_name: &str,
) -> BranchCleanStatus {
    // The backup ref already covers rollback, so skip the on-disk backup dir.
    let res = remediate::apply(wt, &plan.actions, false);
    if res.applied.is_empty() {
        return BranchCleanStatus::Skipped("no actions applied to branch tip".into());
    }
    let paths: Vec<PathBuf> = res.applied.iter().map(|a| a.target().to_path_buf()).collect();
    let msg = format!("wormward: clean {}", plan.branch);
    if let Err(e) = crate::git::commit_paths(wt, &msg, &paths) {
        return BranchCleanStatus::Failed(format!("commit failed: {e}"));
    }
    if push {
        let pushed = match remote {
            // Remote-tracking clean: push exactly this branch to its remote.
            Some(r) => crate::git::force_push_with_lease_to(wt, r, local_name),
            // Local branch: the worktree's current branch pushes to its own upstream.
            None => crate::git::force_push_with_lease(wt),
        };
        if let Err(e) = pushed {
            return BranchCleanStatus::Failed(format!("push failed: {e}"));
        }
    }
    BranchCleanStatus::Cleaned { backup_ref: plan.backup_ref.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{FindingKind, Severity};
    use crate::matchers::{ContentSignature, SignatureKind};
    use crate::pack::{PackManifest, PayloadStrip, Remediation};
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;

    fn strip_pack() -> Pack {
        let manifest = PackManifest {
            id: "polinrider".into(),
            name: "PolinRider".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec!["postcss.config.mjs".into()],
            content_signatures: vec![ContentSignature {
                id: "primary".into(),
                kind: SignatureKind::Literal,
                value: "rmcej%otb%".into(),
            }],
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            ioc_domains: vec![],
            analyzer: None,
            remediation: Some(Remediation {
                config_payload: Some(PayloadStrip {
                    strategy: "strip_after_marker".into(),
                    markers: vec!["global['!']=".into()],
                }),
            }),
        };
        Pack { manifest, analyzer: None }
    }

    fn finding(repo: &str, branch: Option<&str>, kind: FindingKind, file: Option<&str>, sig: &str) -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: Severity::Critical,
            repo: PathBuf::from(repo),
            file: file.map(PathBuf::from),
            signature_id: sig.into(),
            kind,
            evidence: "e".into(),
            remediable: true,
            online: None,
            git_ref: branch.map(String::from),
        }
    }

    #[test]
    fn only_git_ref_findings_are_considered() {
        // A working-tree finding (git_ref = None) must not produce a branch plan.
        let plans = plan_branch_cleans(
            &[finding("/r", None, FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary")],
            &[strip_pack()],
            42,
        );
        assert!(plans.is_empty());
    }

    #[test]
    fn groups_by_branch_with_backup_ref_naming() {
        let plans = plan_branch_cleans(
            &[
                finding("/r", Some("evil"), FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary"),
                finding("/r", Some("nasty"), FindingKind::Artifact, Some("temp_auto_push.bat"), "artifact:temp_auto_push.bat"),
            ],
            &[strip_pack()],
            99,
        );
        assert_eq!(plans.len(), 2);
        let evil = plans.iter().find(|p| p.branch == "evil").unwrap();
        assert_eq!(evil.backup_ref, "refs/wormward-backup/evil-99");
        assert_eq!(
            evil.actions,
            vec![RemediationAction::StripPayload {
                file: PathBuf::from("postcss.config.mjs"),
                markers: vec!["global['!']=".into()],
            }]
        );
        let nasty = plans.iter().find(|p| p.branch == "nasty").unwrap();
        assert_eq!(nasty.backup_ref, "refs/wormward-backup/nasty-99");
        assert_eq!(nasty.actions, vec![RemediationAction::DeleteFile { file: PathBuf::from("temp_auto_push.bat") }]);
    }

    #[test]
    fn dedups_actions_within_a_branch() {
        let plans = plan_branch_cleans(
            &[
                finding("/r", Some("evil"), FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary"),
                finding("/r", Some("evil"), FindingKind::ContentSignature, Some("postcss.config.mjs"), "xor-key"),
            ],
            &[strip_pack()],
            1,
        );
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].actions.len(), 1);
    }

    #[test]
    fn non_remediable_kinds_are_skipped() {
        let mut npm = finding("/r", Some("evil"), FindingKind::NpmPackage, Some("package.json"), "npm:x");
        npm.remediable = false;
        let ioc = finding("/r", Some("evil"), FindingKind::IocDomain, Some("postcss.config.mjs"), "ioc-domain:x");
        // A ContentSignature whose campaign has no strip strategy also maps to no action.
        let mut no_strategy = finding("/r", Some("evil"), FindingKind::ContentSignature, Some("f.js"), "x");
        no_strategy.campaign = "shai-hulud".into();
        let plans = plan_branch_cleans(&[npm, ioc, no_strategy], &[strip_pack()], 1);
        assert!(plans.is_empty());
    }

    fn git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn git_stdout(repo: &Path, args: &[&str]) -> String {
        let out = Command::new("git").arg("-C").arg(repo).args(args).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn cleans_infected_branch_tip_and_leaves_checkout_untouched() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("postcss.config.mjs"), "export default {};\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "clean"]);

        // Infected 'evil' branch tip. Payload uses rmcej%otb% + global['!']=, NOT _$_...=,
        // so the global pre-commit hook does not block the fixture commit.
        git(&repo, &["checkout", "-q", "-b", "evil"]);
        std::fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8';var x='rmcej%otb%';",
        )
        .unwrap();
        git(&repo, &["commit", "-q", "-am", "payload"]);
        let infected_oid = git_stdout(&repo, &["rev-parse", "evil"]);
        git(&repo, &["checkout", "-q", "main"]);

        // Deep scan flags the 'evil' tip; build and apply the branch-clean plan.
        let packs = [strip_pack()];
        let deep = crate::scanner::deep_scan_repo(&repo, &packs);
        assert!(deep.iter().any(|f| f.git_ref.as_deref() == Some("evil")));
        let plans = plan_branch_cleans(&deep, &packs, 12345);
        assert_eq!(plans.len(), 1);

        let outcomes = apply_branch_cleans(&plans, false, false);
        assert_eq!(outcomes.len(), 1);
        assert!(
            matches!(outcomes[0].status, BranchCleanStatus::Cleaned { .. }),
            "expected Cleaned, got {:?}",
            outcomes[0].status
        );

        // The 'evil' tip no longer matches on a fresh deep scan.
        let re = crate::scanner::deep_scan_repo(&repo, &packs);
        assert!(!re.iter().any(|f| f.git_ref.as_deref() == Some("evil")));

        // Backup ref exists and still points at the old infected commit.
        let backup = git_stdout(&repo, &["rev-parse", "refs/wormward-backup/evil-12345"]);
        assert_eq!(backup, infected_oid);

        // User's checkout is undisturbed: still on main, working tree clean.
        let head = git_stdout(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]);
        assert_eq!(head, "main");
        // Normalize line endings: git may re-materialize with CRLF under core.autocrlf.
        let main_content =
            std::fs::read_to_string(repo.join("postcss.config.mjs")).unwrap().replace("\r\n", "\n");
        assert_eq!(main_content, "export default {};\n");
        assert!(!main_content.contains("rmcej%otb%"));
        let statusz = git_stdout(&repo, &["status", "--porcelain"]);
        assert!(statusz.is_empty(), "working tree should be clean: {statusz}");
    }
}
