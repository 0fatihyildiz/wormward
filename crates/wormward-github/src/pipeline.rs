use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use rayon::prelude::*;
use serde::Serialize;
use wormward_core::{
    apply, commit_paths, deep_scan_repo, force_push_with_lease, plan_remediation, scan_repo, Finding,
    Pack, RemediationAction,
};

use crate::{GithubError, RepoHost, RepoRef};

#[derive(Debug, Clone)]
pub struct GithubRunOpts {
    pub clone_dir: Option<PathBuf>,
    pub include_forks: bool,
    pub fix: bool,
    pub push: bool,
    pub yes: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoOutcome {
    pub repo: RepoRef,
    pub findings: Vec<Finding>,
    /// Human-readable descriptions of the remediation actions (planned in a dry run,
    /// applied when `--yes`).
    pub actions: Vec<String>,
    /// Branches force-pushed back to origin.
    pub pushed: Vec<String>,
    pub error: Option<String>,
}

fn describe_action(a: &RemediationAction) -> String {
    match a {
        RemediationAction::StripPayload { file, .. } => {
            format!("strip payload from {}", file.display())
        }
        RemediationAction::DeleteFile { file } => format!("delete {}", file.display()),
        RemediationAction::RemoveGitignoreLine { file, line } => {
            format!("remove '{line}' from {}", file.display())
        }
    }
}

fn git(dir: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn process_repo(repo: &RepoRef, opts: &GithubRunOpts, packs: &[Pack], base: &Path) -> RepoOutcome {
    let mut outcome = RepoOutcome {
        repo: repo.clone(),
        findings: Vec::new(),
        actions: Vec::new(),
        pushed: Vec::new(),
        error: None,
    };
    let dest = base.join(repo.full_name.replace('/', "__"));

    // Clone all branches so the deep scan can inspect every branch tip.
    let clone = Command::new("git")
        .args(["clone", "--no-single-branch", "-q"])
        .arg(&repo.clone_url)
        .arg(&dest)
        .output();
    match clone {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            outcome.error =
                Some(format!("clone: {}", String::from_utf8_lossy(&out.stderr).trim()));
            return outcome;
        }
        Err(e) => {
            outcome.error = Some(format!("clone: {e}"));
            return outcome;
        }
    }

    // Scan the working tree + every branch tip (read-only).
    let mut findings = scan_repo(&dest, packs);
    findings.extend(deep_scan_repo(&dest, packs));
    outcome.findings = findings.clone();

    if !opts.fix || findings.is_empty() {
        return outcome;
    }

    let plan = plan_remediation(&findings, packs);
    if plan.actions.is_empty() {
        return outcome;
    }

    // Dry run: report the actions that WOULD be applied without touching the tree.
    if !opts.yes {
        outcome.actions = plan.actions.iter().map(describe_action).collect();
        return outcome;
    }

    // Apply to the working tree (backups land in <repo>/.wormward-backup/<ts>/).
    let res = apply(&dest, &plan.actions, true);
    outcome.actions = res.applied.iter().map(describe_action).collect();
    if res.applied.is_empty() {
        return outcome;
    }

    let paths: Vec<PathBuf> = res.applied.iter().map(|a| a.target().to_path_buf()).collect();
    let campaigns = {
        let mut c: Vec<&str> = findings.iter().map(|f| f.campaign.as_str()).collect();
        c.sort();
        c.dedup();
        c.join(", ")
    };
    if let Err(e) =
        commit_paths(&dest, &format!("wormward: remediate {campaigns}"), &paths)
    {
        outcome.error = Some(format!("commit: {e}"));
        return outcome;
    }

    // Force-push the cleaned default branch, backing up the pre-clean tip first.
    if opts.push {
        let ts = now_secs();
        let backup = format!(
            "refs/remotes/origin/{b}:refs/heads/wormward-backup/{b}-{ts}",
            b = repo.default_branch
        );
        if let Err(e) = git(&dest, &["push", "origin", &backup]) {
            outcome.error = Some(format!("backup push: {e}"));
            return outcome;
        }
        match force_push_with_lease(&dest) {
            Ok(()) => outcome.pushed.push(repo.default_branch.clone()),
            Err(e) => outcome.error = Some(format!("force-push: {e}")),
        }
    }

    outcome
}

/// Enumerate the account's repos and process each one (bounded-parallel via rayon).
/// Per-repo failures are captured in `RepoOutcome.error`; the run never aborts.
pub fn run(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
) -> Result<Vec<RepoOutcome>, GithubError> {
    let repos = host.list_repos(opts.include_forks)?;

    // Resolve a base clone directory (temp dir kept alive for the whole run).
    let tmp_guard;
    let base: PathBuf = match &opts.clone_dir {
        Some(d) => {
            std::fs::create_dir_all(d).map_err(|e| GithubError::Http(e.to_string()))?;
            d.clone()
        }
        None => {
            tmp_guard = tempfile::TempDir::new().map_err(|e| GithubError::Http(e.to_string()))?;
            tmp_guard.path().to_path_buf()
        }
    };

    let outcomes: Vec<RepoOutcome> = repos
        .par_iter()
        .map(|repo| process_repo(repo, opts, packs, &base))
        .collect();
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;
    use wormward_packs::builtin_packs;

    fn git_ok(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status()
            .unwrap();
        assert!(status.success());
    }

    struct FakeHost {
        repo: RepoRef,
    }
    impl RepoHost for FakeHost {
        fn list_repos(&self, _include_forks: bool) -> Result<Vec<RepoRef>, GithubError> {
            Ok(vec![self.repo.clone()])
        }
    }

    fn make_infected_origin(tmp: &TempDir) -> PathBuf {
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        // Content signature ("rmcej%otb%") gives the finding; the strip marker
        // ("global['!']=") drives the StripPayload remediation.
        std::fs::write(
            src.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';\n(\"rmcej%otb%\",2857687)\n",
        )
        .unwrap();
        git_ok(&src, &["add", "."]);
        // --no-verify: this machine's git template installs a worm-scanning pre-commit
        // hook; the fixture deliberately commits an infected file for the test.
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "infected"]);

        let bare = tmp.path().join("origin.git");
        // -b main so the bare HEAD tracks main; otherwise a clone checks out an
        // unborn default branch and lands an empty working tree.
        Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&bare)
            .status()
            .unwrap();
        git_ok(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git_ok(&src, &["push", "-q", "origin", "main"]);
        bare
    }

    #[test]
    fn fixes_infected_repo_end_to_end() {
        let tmp = TempDir::new().unwrap();
        let bare = make_infected_origin(&tmp);
        let clone_dir = tmp.path().join("work");
        let host = FakeHost {
            repo: RepoRef {
                full_name: "me/proj".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            },
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir),
            include_forks: false,
            fix: true,
            push: false,
            yes: true,
        };

        let outcomes = run(&opts, &host, &builtin_packs()).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].error.is_none(), "unexpected error: {:?}", outcomes[0].error);
        assert!(!outcomes[0].findings.is_empty());
        assert!(!outcomes[0].actions.is_empty());
    }

    #[test]
    fn dry_run_reports_actions_without_writing() {
        let tmp = TempDir::new().unwrap();
        let bare = make_infected_origin(&tmp);
        let clone_dir = tmp.path().join("work");
        let host = FakeHost {
            repo: RepoRef {
                full_name: "me/proj".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            },
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir.clone()),
            include_forks: false,
            fix: true,
            push: false,
            yes: false,
        };

        let outcomes = run(&opts, &host, &builtin_packs()).unwrap();
        assert!(!outcomes[0].actions.is_empty());
        assert!(outcomes[0].pushed.is_empty());
        // The infected file in the working tree must be untouched by a dry run.
        let cloned = clone_dir.join("me__proj").join("postcss.config.mjs");
        assert!(std::fs::read_to_string(&cloned).unwrap().contains("rmcej%otb%"));
    }

    #[test]
    fn fix_and_push_force_pushes_and_backs_up() {
        let tmp = TempDir::new().unwrap();
        let bare = make_infected_origin(&tmp);
        let clone_dir = tmp.path().join("work");
        let host = FakeHost {
            repo: RepoRef {
                full_name: "me/proj".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            },
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir),
            include_forks: false,
            fix: true,
            push: true,
            yes: true,
        };

        let outcomes = run(&opts, &host, &builtin_packs()).unwrap();
        assert!(outcomes[0].error.is_none(), "unexpected error: {:?}", outcomes[0].error);
        assert_eq!(outcomes[0].pushed, vec!["main".to_string()]);

        // The bare origin's main tip is now clean.
        let show = Command::new("git")
            .arg("-C")
            .arg(&bare)
            .args(["show", "main:postcss.config.mjs"])
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&show.stdout).contains("rmcej%otb%"));

        // A backup branch of the pre-clean tip exists on origin.
        let branches = Command::new("git")
            .arg("-C")
            .arg(&bare)
            .args(["branch", "--list", "wormward-backup/*"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&branches.stdout).contains("wormward-backup/main-"));
    }
}
