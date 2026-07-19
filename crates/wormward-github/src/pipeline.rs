use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use rayon::prelude::*;
use serde::Serialize;
use wormward_core::{
    apply, commit_paths, deep_scan_repo, force_push_with_lease_to, now_secs, plan_remediation,
    scan_repo, Finding, Pack, RemediationAction,
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
        // Fail fast instead of blocking a rayon worker on an interactive auth prompt.
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Inject the token into an https GitHub clone URL so private repos clone/push. The
/// resulting `origin` carries auth for later backup/force-push too. Non-https URLs
/// (e.g. local paths used in tests) and empty tokens are returned unchanged.
fn authed_url(clone_url: &str, token: &str) -> String {
    match clone_url.strip_prefix("https://") {
        Some(rest) if !token.is_empty() => format!("https://x-access-token:{token}@{rest}"),
        _ => clone_url.to_string(),
    }
}

/// Redact the token from any captured git output before it lands in an error string
/// (git can echo the credentialed remote URL on failure). Never log the raw token.
fn redact(msg: String, token: &str) -> String {
    if token.is_empty() {
        msg
    } else {
        msg.replace(token, "x-access-token:***")
    }
}

/// True when there are staged changes to commit. Used to avoid a "nothing to commit"
/// failure when an applied remediation left the file byte-identical.
fn has_staged_changes(dir: &Path) -> bool {
    // `git diff --cached --quiet` exits 0 when nothing is staged, 1 when staged changes
    // exist. Treat a spawn failure as "no changes" so we skip the commit rather than error.
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["diff", "--cached", "--quiet"])
        .status()
        .map(|s| !s.success())
        .unwrap_or(false)
}

/// Turn a repo `full_name` (e.g. `owner/name`) into a single safe directory component.
/// Both `/` and `\` path separators AND any `..` are neutralized so a hostile or malformed
/// `full_name` cannot escape the clone base dir via path traversal.
fn sanitize_full_name(full_name: &str) -> String {
    full_name.replace(['/', '\\'], "__").replace("..", "__")
}

/// A repo cloned and scanned in phase one. The clone on disk at `dest` is reused by the
/// fix phase — we never re-clone.
pub struct ScannedRepo {
    pub repo: RepoRef,
    /// Working-tree path of the clone (empty/unused when `error` is set).
    pub dest: PathBuf,
    pub findings: Vec<Finding>,
    /// Clone failure, if any. A scanned-but-errored repo carries no findings.
    pub error: Option<String>,
}

impl ScannedRepo {
    /// A repo is "infected" (a fix candidate) when the read-only scan found anything.
    pub fn is_infected(&self) -> bool {
        self.error.is_none() && !self.findings.is_empty()
    }
}

/// Result of phase one: every repo cloned + scanned, with the clones kept alive on disk
/// (via `_tmp` when a temp dir was used) so the fix phase can reuse them.
pub struct ScanPass {
    repos: Vec<ScannedRepo>,
    // Held to keep the temp clone directory alive until the fix phase has run. `None`
    // when the caller supplied an explicit `clone_dir`.
    _tmp: Option<tempfile::TempDir>,
}

impl ScanPass {
    /// The repos cloned + scanned in phase one, for callers (e.g. a GUI) that need to
    /// build their own per-repo view from the raw scan results.
    pub fn repos(&self) -> &[ScannedRepo] {
        &self.repos
    }

    /// `full_name`s of every infected repo (working-tree OR branch-only), for reporting.
    pub fn infected_full_names(&self) -> Vec<String> {
        self.repos
            .iter()
            .filter(|r| r.is_infected())
            .map(|r| r.repo.full_name.clone())
            .collect()
    }

    /// `full_name`s of infected repos whose *default working tree* has at least one
    /// applicable remediation action — the only repos `fix_scanned` can actually fix, and
    /// therefore the only sensible candidates for interactive selection.
    ///
    /// A repo infected solely on a non-default branch has findings but no working-tree
    /// action (`plan_remediation` routes branch-tip findings, which carry a `git_ref`, to
    /// `manual`), so it is excluded here even though it remains in the scan results/output.
    pub fn fixable_full_names(&self, packs: &[Pack]) -> Vec<String> {
        self.repos
            .iter()
            .filter(|r| r.is_infected())
            .filter(|r| !plan_remediation(&r.findings, packs).actions.is_empty())
            .map(|r| r.repo.full_name.clone())
            .collect()
    }
}

/// Clone (all branches, authenticated) and read-only scan a single repo. No fixes.
fn clone_and_scan(repo: &RepoRef, base: &Path, packs: &[Pack], token: &str) -> ScannedRepo {
    let dest = base.join(sanitize_full_name(&repo.full_name));

    // Clone all branches so the deep scan can inspect every branch tip. Authenticate via
    // the token so private repos clone (and the resulting origin can be pushed to), and
    // disable the terminal prompt so an auth failure fails fast rather than hanging a
    // rayon worker on an interactive prompt.
    let clone = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["clone", "--no-single-branch", "-q"])
        .arg(authed_url(&repo.clone_url, token))
        .arg(&dest)
        .output();
    match clone {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return ScannedRepo {
                repo: repo.clone(),
                dest,
                findings: Vec::new(),
                error: Some(redact(
                    format!("clone: {}", String::from_utf8_lossy(&out.stderr).trim()),
                    token,
                )),
            };
        }
        Err(e) => {
            return ScannedRepo {
                repo: repo.clone(),
                dest,
                findings: Vec::new(),
                error: Some(redact(format!("clone: {e}"), token)),
            };
        }
    }

    // Scan the working tree + every branch tip (read-only).
    let mut findings = scan_repo(&dest, packs);
    findings.extend(deep_scan_repo(&dest, packs));
    ScannedRepo { repo: repo.clone(), dest, findings, error: None }
}

/// Phase one: enumerate the account's repos, then clone + scan each (bounded-parallel via
/// rayon). No repo is fixed here. Per-repo clone failures are captured, never fatal.
pub fn scan_pass(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
) -> Result<ScanPass, GithubError> {
    let repos = host.list_repos(opts.include_forks)?;

    // Resolve a base clone directory (temp dir kept alive inside the returned ScanPass).
    let mut tmp = None;
    let base: PathBuf = match &opts.clone_dir {
        Some(d) => {
            std::fs::create_dir_all(d).map_err(|e| GithubError::Http(e.to_string()))?;
            d.clone()
        }
        None => {
            let dir = tempfile::TempDir::new().map_err(|e| GithubError::Http(e.to_string()))?;
            let p = dir.path().to_path_buf();
            tmp = Some(dir);
            p
        }
    };

    let scanned: Vec<ScannedRepo> = repos
        .par_iter()
        .map(|repo| clone_and_scan(repo, &base, packs, token))
        .collect();
    Ok(ScanPass { repos: scanned, _tmp: tmp })
}

/// Remediate one already-cloned repo, reusing its working tree. When `do_fix` is false
/// the repo is only reported (findings preserved, no writes) — this is how deselected
/// repos and clean/errored repos are passed through.
fn fix_scanned(sr: &ScannedRepo, opts: &GithubRunOpts, packs: &[Pack], token: &str, do_fix: bool) -> RepoOutcome {
    let mut outcome = RepoOutcome {
        repo: sr.repo.clone(),
        findings: sr.findings.clone(),
        actions: Vec::new(),
        pushed: Vec::new(),
        error: sr.error.clone(),
    };

    if !do_fix || sr.error.is_some() || sr.findings.is_empty() {
        return outcome;
    }

    let dest = &sr.dest;
    let plan = plan_remediation(&sr.findings, packs);
    if plan.actions.is_empty() {
        return outcome;
    }

    // Dry run: report the actions that WOULD be applied without touching the tree.
    if !opts.yes {
        outcome.actions = plan.actions.iter().map(describe_action).collect();
        return outcome;
    }

    // Apply to the working tree (backups land in <repo>/.wormward-backup/<ts>/).
    let res = apply(dest, &plan.actions, true);
    outcome.actions = res.applied.iter().map(describe_action).collect();
    if res.applied.is_empty() {
        return outcome;
    }

    let paths: Vec<PathBuf> = res.applied.iter().map(|a| a.target().to_path_buf()).collect();
    let campaigns = {
        let mut c: Vec<&str> = sr.findings.iter().map(|f| f.campaign.as_str()).collect();
        c.sort();
        c.dedup();
        c.join(", ")
    };
    // Stage the applied paths first, then only commit if something is actually staged.
    // A remediation that leaves a file byte-identical stages nothing, and `git commit`
    // would fail with "nothing to commit" — treat that as a no-op success, not an error.
    for p in &paths {
        let s = p.to_string_lossy();
        let _ = git(dest, &["add", "-A", "--", s.as_ref()]);
    }
    if has_staged_changes(dest) {
        if let Err(e) = commit_paths(dest, &format!("wormward: remediate {campaigns}"), &paths) {
            outcome.error = Some(redact(format!("commit: {e}"), token));
            return outcome;
        }
    } else {
        // Nothing changed on disk; skip the commit (and the push below has nothing to do).
        return outcome;
    }

    // Force-push the cleaned default branch, backing up the pre-clean tip first.
    if opts.push {
        let ts = now_secs();
        let backup = format!(
            "refs/remotes/origin/{b}:refs/heads/wormward-backup/{b}-{ts}",
            b = sr.repo.default_branch
        );
        if let Err(e) = git(dest, &["push", "origin", "--", &backup]) {
            outcome.error = Some(redact(format!("backup push: {e}"), token));
            return outcome;
        }
        // Push EXACTLY the cleaned default branch via an explicit refspec, never a bare
        // `--force-with-lease` (which under push.default=matching would push every branch).
        let refspec = format!("HEAD:refs/heads/{}", sr.repo.default_branch);
        match force_push_with_lease_to(dest, "origin", &refspec) {
            Ok(()) => outcome.pushed.push(sr.repo.default_branch.clone()),
            Err(e) => outcome.error = Some(redact(format!("force-push: {e}"), token)),
        }
    }

    outcome
}

/// Phase two: remediate the scanned repos, reusing their clones (no re-clone). When
/// `selected` is `Some`, only repos whose `full_name` is in the set are fixed; every
/// other repo is reported unchanged. `None` fixes all infected repos (subject to
/// `opts.fix`). Per-repo failures are captured in `RepoOutcome.error`; the run never
/// aborts.
pub fn fix_pass(
    scan: &ScanPass,
    opts: &GithubRunOpts,
    packs: &[Pack],
    token: &str,
    selected: Option<&HashSet<String>>,
) -> Vec<RepoOutcome> {
    scan.repos
        .par_iter()
        .map(|sr| {
            let chosen = selected.is_none_or(|s| s.contains(&sr.repo.full_name));
            fix_scanned(sr, opts, packs, token, opts.fix && chosen)
        })
        .collect()
}

/// Enumerate the account's repos and process each one: clone + scan, then fix all
/// infected repos (no interactive selection). Per-repo failures are captured in
/// `RepoOutcome.error`; the run never aborts.
pub fn run(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
) -> Result<Vec<RepoOutcome>, GithubError> {
    let scan = scan_pass(opts, host, packs, token)?;
    Ok(fix_pass(&scan, opts, packs, token, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Branch, Tree, TreeEntry};
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

    /// Serves list/branches/tree/blob straight from local bare fixture repos via git,
    /// so the pipeline is exercised end-to-end without any HTTP. `clone_url` doubles
    /// as the filesystem path of the bare repo.
    struct GitFakeHost {
        repos: Vec<RepoRef>,
    }

    impl GitFakeHost {
        fn bare_path(&self, full_name: &str) -> PathBuf {
            PathBuf::from(
                &self.repos.iter().find(|r| r.full_name == full_name).unwrap().clone_url,
            )
        }
        fn git(&self, full_name: &str, args: &[&str]) -> Result<Vec<u8>, GithubError> {
            let out = Command::new("git")
                .arg("-C")
                .arg(self.bare_path(full_name))
                .args(args)
                .output()
                .map_err(|e| GithubError::Http(e.to_string()))?;
            if !out.status.success() {
                return Err(GithubError::Http(
                    String::from_utf8_lossy(&out.stderr).into_owned(),
                ));
            }
            Ok(out.stdout)
        }
    }

    impl RepoHost for GitFakeHost {
        fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError> {
            Ok(self.repos.iter().filter(|r| include_forks || !r.fork).cloned().collect())
        }
        fn list_branches(&self, full_name: &str) -> Result<Vec<Branch>, GithubError> {
            let out = self.git(
                full_name,
                &["for-each-ref", "--format=%(objectname) %(refname:short)", "refs/heads"],
            )?;
            Ok(String::from_utf8_lossy(&out)
                .lines()
                .filter_map(|l| {
                    let (sha, name) = l.split_once(' ')?;
                    Some(Branch { name: name.into(), commit_sha: sha.into() })
                })
                .collect())
        }
        fn get_tree(&self, full_name: &str, commit_sha: &str) -> Result<Tree, GithubError> {
            let out = self.git(full_name, &["ls-tree", "-r", "-z", commit_sha])?;
            let entries = String::from_utf8_lossy(&out)
                .split('\0')
                .filter(|s| !s.is_empty())
                .filter_map(|line| {
                    // "<mode> <type> <sha>\t<path>"
                    let (meta, path) = line.split_once('\t')?;
                    let mut parts = meta.split_whitespace();
                    let _mode = parts.next()?;
                    let kind = parts.next()?;
                    let sha = parts.next()?;
                    (kind == "blob")
                        .then(|| TreeEntry { path: PathBuf::from(path), sha: sha.into() })
                })
                .collect();
            Ok(Tree { entries, truncated: false })
        }
        fn get_blob(&self, full_name: &str, blob_sha: &str) -> Result<Option<String>, GithubError> {
            let out = self.git(full_name, &["cat-file", "blob", blob_sha])?;
            Ok(String::from_utf8(out).ok())
        }
    }

    /// Build an infected bare origin under `tmp` in a uniquely-named subdir so several
    /// can coexist in one test.
    fn make_infected_origin_named(tmp: &TempDir, name: &str) -> PathBuf {
        let src = tmp.path().join(format!("{name}-src"));
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(
            src.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';\n(\"rmcej%otb%\",2857687)\n",
        )
        .unwrap();
        git_ok(&src, &["add", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "infected"]);

        let bare = tmp.path().join(format!("{name}.git"));
        Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&bare)
            .status()
            .unwrap();
        git_ok(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git_ok(&src, &["push", "-q", "origin", "main"]);
        bare
    }

    /// Build a bare origin whose default branch (`main`) is CLEAN but a non-default
    /// branch (`evil`) carries the payload. A deep scan flags it (branch-only), yet its
    /// default working tree has no remediation action.
    fn make_branch_only_infected_origin(tmp: &TempDir, name: &str) -> PathBuf {
        let src = tmp.path().join(format!("{name}-src"));
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(src.join("postcss.config.mjs"), "export default {};\n").unwrap();
        git_ok(&src, &["add", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "clean"]);
        // Infect only a non-default branch.
        git_ok(&src, &["checkout", "-q", "-b", "evil"]);
        std::fs::write(
            src.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';\n(\"rmcej%otb%\",2857687)\n",
        )
        .unwrap();
        git_ok(&src, &["commit", "-q", "--no-verify", "-am", "payload"]);
        git_ok(&src, &["checkout", "-q", "main"]);

        let bare = tmp.path().join(format!("{name}.git"));
        Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&bare)
            .status()
            .unwrap();
        git_ok(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git_ok(&src, &["push", "-q", "origin", "main"]);
        git_ok(&src, &["push", "-q", "origin", "evil"]);
        bare
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
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/proj".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir),
            include_forks: false,
            fix: true,
            push: false,
            yes: true,
        };

        let outcomes = run(&opts, &host, &builtin_packs(), "").unwrap();
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
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/proj".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir.clone()),
            include_forks: false,
            fix: true,
            push: false,
            yes: false,
        };

        let outcomes = run(&opts, &host, &builtin_packs(), "").unwrap();
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
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/proj".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir),
            include_forks: false,
            fix: true,
            push: true,
            yes: true,
        };

        let outcomes = run(&opts, &host, &builtin_packs(), "").unwrap();
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

    #[test]
    fn branch_only_infection_is_reported_but_not_a_fix_candidate() {
        // Two infected repos: one infected only on a non-default branch, one infected in
        // its default working tree. Both must appear in the scan results (infected list),
        // but only the working-tree one is a fixable-selection candidate — offering the
        // branch-only repo would be a no-op since fix_scanned only touches the default tree.
        let tmp = TempDir::new().unwrap();
        let bare_branch_only = make_branch_only_infected_origin(&tmp, "branchonly");
        let bare_working_tree = make_infected_origin_named(&tmp, "wt");
        let clone_dir = tmp.path().join("work");
        let host = GitFakeHost {
            repos: vec![
                RepoRef {
                    full_name: "me/branchonly".into(),
                    clone_url: bare_branch_only.to_string_lossy().to_string(),
                    default_branch: "main".into(),
                    fork: false,
                },
                RepoRef {
                    full_name: "me/wt".into(),
                    clone_url: bare_working_tree.to_string_lossy().to_string(),
                    default_branch: "main".into(),
                    fork: false,
                },
            ],
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir),
            include_forks: false,
            fix: true,
            push: false,
            yes: true,
        };

        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();

        // Both repos are detected as infected (branch-only via deep scan, wt via working tree).
        let mut infected = scan.infected_full_names();
        infected.sort();
        assert_eq!(infected, vec!["me/branchonly".to_string(), "me/wt".to_string()]);

        // ...but only the working-tree-infected repo is a fixable-selection candidate.
        let fixable = scan.fixable_full_names(&builtin_packs());
        assert_eq!(
            fixable,
            vec!["me/wt".to_string()],
            "branch-only infection must not be offered as a fixable candidate"
        );
    }

    #[test]
    fn fix_pass_honors_selected_set() {
        // Two infected repos are scanned; only one is selected for fixing. The selected
        // repo gets remediation actions; the deselected one keeps its findings but is
        // left untouched (no actions). Clones from the scan pass are reused — no re-clone.
        let tmp = TempDir::new().unwrap();
        let bare_a = make_infected_origin_named(&tmp, "a");
        let bare_b = make_infected_origin_named(&tmp, "b");
        let clone_dir = tmp.path().join("work");
        let host = GitFakeHost {
            repos: vec![
                RepoRef {
                    full_name: "me/a".into(),
                    clone_url: bare_a.to_string_lossy().to_string(),
                    default_branch: "main".into(),
                    fork: false,
                },
                RepoRef {
                    full_name: "me/b".into(),
                    clone_url: bare_b.to_string_lossy().to_string(),
                    default_branch: "main".into(),
                    fork: false,
                },
            ],
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir.clone()),
            include_forks: false,
            fix: true,
            push: false,
            yes: true,
        };

        let scan = scan_pass(&opts, &host, &builtin_packs(), "").unwrap();
        let mut infected = scan.infected_full_names();
        infected.sort();
        assert_eq!(infected, vec!["me/a".to_string(), "me/b".to_string()]);

        // Select only me/a.
        let selected: HashSet<String> = ["me/a".to_string()].into_iter().collect();
        let outcomes = fix_pass(&scan, &opts, &builtin_packs(), "", Some(&selected));

        let by = |name: &str| outcomes.iter().find(|o| o.repo.full_name == name).unwrap();
        // Both repos are reported with their findings...
        assert!(!by("me/a").findings.is_empty());
        assert!(!by("me/b").findings.is_empty());
        // ...but only the selected one was fixed.
        assert!(!by("me/a").actions.is_empty(), "selected repo should be fixed");
        assert!(by("me/b").actions.is_empty(), "deselected repo must be left alone");
        assert!(by("me/a").error.is_none());
        assert!(by("me/b").error.is_none());

        // The deselected clone's working tree is still infected on disk (never remediated).
        let b_file = clone_dir.join("me__b").join("postcss.config.mjs");
        assert!(std::fs::read_to_string(&b_file).unwrap().contains("rmcej%otb%"));
    }
}
