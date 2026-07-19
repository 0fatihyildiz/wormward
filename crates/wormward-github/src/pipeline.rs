use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use serde::Serialize;
use wormward_core::{
    apply, commit_paths, deep_scan_repo, force_push_with_lease_to, now_secs, plan_remediation,
    scan_files, scan_repo, Finding, Pack, RemediationAction,
};

use crate::api_tree::{ApiTree, BlobCache};
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

/// A repo scanned via the API in phase one. No clone exists; the fix phase clones
/// on demand for the repos actually selected.
#[derive(Debug)]
pub struct ScannedRepo {
    pub repo: RepoRef,
    pub findings: Vec<Finding>,
    /// Scan failure, if any. An errored repo carries no findings and must never be
    /// treated as clean.
    pub error: Option<String>,
}

impl ScannedRepo {
    /// A repo is "infected" (a fix candidate) when the read-only scan found anything.
    pub fn is_infected(&self) -> bool {
        self.error.is_none() && !self.findings.is_empty()
    }
}

/// Result of phase one: every repo scanned via the API. No clones exist on disk.
#[derive(Debug)]
pub struct ScanPass {
    repos: Vec<ScannedRepo>,
}

impl ScanPass {
    /// The repos scanned in phase one, for callers (e.g. a GUI) that need to build
    /// their own per-repo view from the raw scan results.
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

/// A repo that just finished scanning. Events arrive in COMPLETION order, not
/// input order (rayon) — consumers should render the latest done/total only.
#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub done: usize,
    pub total: usize,
    /// `full_name` of the repo that just finished.
    pub repo: String,
}

/// Clone all branches of `repo` into `dest`, authenticated via the token so private
/// repos work (and the resulting origin can be pushed to). GIT_TERMINAL_PROMPT=0 so
/// an auth failure fails fast instead of hanging a rayon worker. Errors are redacted.
fn clone_repo(repo: &RepoRef, dest: &Path, token: &str) -> Result<(), String> {
    let out = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["clone", "--no-single-branch", "-q"])
        .arg(authed_url(&repo.clone_url, token))
        .arg(dest)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(redact(
            format!("clone: {}", String::from_utf8_lossy(&o.stderr).trim()),
            token,
        )),
        Err(e) => Err(redact(format!("clone: {e}"), token)),
    }
}

/// Full local clone + scan for repos whose tree the API refuses to enumerate
/// (`truncated`, ~100k+ entries) — coverage must never silently degrade. The temp
/// clone is deleted on return; a later fix re-clones like any other repo.
fn fallback_clone_scan(repo: &RepoRef, packs: &[Pack], token: &str) -> ScannedRepo {
    let mut out = ScannedRepo { repo: repo.clone(), findings: Vec::new(), error: None };
    let tmp = match tempfile::TempDir::new() {
        Ok(t) => t,
        Err(e) => {
            out.error = Some(format!("tempdir: {e}"));
            return out;
        }
    };
    let dest = tmp.path().join(sanitize_full_name(&repo.full_name));
    if let Err(e) = clone_repo(repo, &dest, token) {
        out.error = Some(e);
        return out;
    }
    let mut findings = scan_repo(&dest, packs);
    findings.extend(deep_scan_repo(&dest, packs));
    // Re-label onto the virtual repo path: the temp clone path would dangle.
    let label = PathBuf::from(&repo.full_name);
    for f in &mut findings {
        f.repo = label.clone();
    }
    out.findings = findings;
    out
}

/// Scan one repo entirely through the API: default-branch tip first (findings stay
/// remediable, like a working tree), then every other branch tip deduped by commit
/// sha with `git_ref` stamped (routed to manual by plan_remediation, like deep scan).
/// Mirrors scan_repo + deep_scan_repo minus the reflog check (local-only, and
/// meaningless on a fresh clone anyway). Err ONLY on rate limiting, which aborts the
/// whole run; anything else is a per-repo error.
fn api_scan_repo(
    repo: &RepoRef,
    host: &dyn RepoHost,
    packs: &[Pack],
    cache: &BlobCache,
    token: &str,
) -> Result<ScannedRepo, GithubError> {
    let mut out = ScannedRepo { repo: repo.clone(), findings: Vec::new(), error: None };

    let branches = match host.list_branches(&repo.full_name) {
        Ok(b) => b,
        Err(e @ GithubError::RateLimited(_)) => return Err(e),
        Err(e) => {
            out.error = Some(e.to_string());
            return Ok(out);
        }
    };
    if branches.is_empty() {
        return Ok(out); // empty repo / unborn default branch: nothing to scan
    }

    // Normally the default-branch tip is scanned like a working tree (findings stay
    // remediable, `git_ref = None`) and every other tip is `git_ref`-stamped. When the
    // default branch is NOT among the returned branches (stale metadata, a rename race,
    // or a serde-defaulted empty `default_branch`), we cannot tell which tip is the
    // working tree — so we scan EVERY tip `git_ref`-stamped. Detection coverage is
    // preserved, but nothing is offered as working-tree-fixable, which is correct: we do
    // not know the default branch to remediate/force-push, so all findings route to manual.
    let mut tips: Vec<(String, Option<String>)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(default) = branches.iter().find(|b| b.name == repo.default_branch) {
        seen.insert(default.commit_sha.clone());
        tips.push((default.commit_sha.clone(), None));
    }
    for b in &branches {
        if seen.insert(b.commit_sha.clone()) {
            tips.push((b.commit_sha.clone(), Some(b.name.clone())));
        }
    }

    let label = PathBuf::from(&repo.full_name);
    for (sha, git_ref) in tips {
        let tree = match host.get_tree(&repo.full_name, &sha) {
            Ok(t) => t,
            Err(e @ GithubError::RateLimited(_)) => return Err(e),
            Err(e) => {
                out.error = Some(e.to_string());
                return Ok(out);
            }
        };
        if tree.truncated {
            return Ok(fallback_clone_scan(repo, packs, token));
        }
        let files = ApiTree::new(host, &repo.full_name, &tree, cache);
        let mut findings = scan_files(&label, &files, packs);
        if let Some(name) = &git_ref {
            for f in &mut findings {
                f.git_ref = Some(name.clone());
            }
        }
        let mut errors = files.take_errors();
        if let Some(pos) = errors.iter().position(|e| matches!(e, GithubError::RateLimited(_))) {
            return Err(errors.swap_remove(pos));
        }
        if let Some(e) = errors.first() {
            // A failed blob fetch must not read as "clean".
            out.error = Some(format!("scan incomplete: {e}"));
            out.findings.clear();
            return Ok(out);
        }
        out.findings.extend(findings);
    }
    Ok(out)
}

/// Phase one: enumerate the account's repos, then scan each entirely via the API
/// (bounded-parallel via rayon) — nothing is cloned. Per-repo failures are captured,
/// never fatal; only rate limiting aborts the run (finishing the sweep would just
/// burn the remaining quota on guaranteed failures).
pub fn scan_pass(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
) -> Result<ScanPass, GithubError> {
    scan_pass_with_progress(opts, host, packs, token, &|_| {})
}

/// `scan_pass` with a progress callback, invoked once per repo as it finishes
/// (success or per-repo error alike — the repo is done either way). The callback
/// is infallible by design: progress must never be able to fail a scan.
pub fn scan_pass_with_progress(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
    on_progress: &(dyn Fn(ScanProgress) + Sync),
) -> Result<ScanPass, GithubError> {
    let repos = host.list_repos(opts.include_forks)?;
    let total = repos.len();
    let cache = BlobCache::new();
    let done_counter = AtomicUsize::new(0);
    // `collect::<Result<Vec<_>, _>>()` lets rayon short-circuit cooperatively on the
    // first Err (a rate limit) instead of scanning every repo before propagating it.
    let scanned = repos
        .par_iter()
        .map(|repo| {
            let result = api_scan_repo(repo, host, packs, &cache, token);
            let done = done_counter.fetch_add(1, Ordering::Relaxed) + 1;
            on_progress(ScanProgress { done, total, repo: repo.full_name.clone() });
            result
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ScanPass { repos: scanned })
}

/// Remediate one scanned repo. Dry runs (`!opts.yes`) plan from the API-scan
/// findings and touch nothing — not even a clone. A real fix clones the repo fresh,
/// re-scans it locally (the repo may have changed since the API scan, and local
/// findings make remediation paths line up with the working tree), then plans,
/// applies, commits and optionally pushes exactly as before.
fn fix_scanned(
    sr: &ScannedRepo,
    opts: &GithubRunOpts,
    packs: &[Pack],
    token: &str,
    do_fix: bool,
    base: Option<&Path>,
) -> RepoOutcome {
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

    // Branch-only infections have no working-tree action; nothing to do here.
    let preview = plan_remediation(&sr.findings, packs);
    if preview.actions.is_empty() {
        return outcome;
    }

    // Dry run: report the actions that WOULD be applied. No clone, no writes.
    if !opts.yes {
        outcome.actions = preview.actions.iter().map(describe_action).collect();
        return outcome;
    }

    let Some(base) = base else {
        outcome.error = Some("no clone directory available".into());
        return outcome;
    };
    let dest = base.join(sanitize_full_name(&sr.repo.full_name));
    if let Err(e) = clone_repo(&sr.repo, &dest, token) {
        outcome.error = Some(e);
        return outcome;
    }

    let local = scan_repo(&dest, packs);
    let plan = plan_remediation(&local, packs);
    if plan.actions.is_empty() {
        return outcome; // repo changed since the scan; nothing fixable remains
    }

    // Apply to the working tree (backups land in <repo>/.wormward-backup/<ts>/).
    let res = apply(&dest, &plan.actions, true);
    outcome.actions = res.applied.iter().map(describe_action).collect();
    if res.applied.is_empty() {
        return outcome;
    }

    let paths: Vec<PathBuf> = res.applied.iter().map(|a| a.target().to_path_buf()).collect();
    let campaigns = {
        let mut c: Vec<&str> = local.iter().map(|f| f.campaign.as_str()).collect();
        c.sort();
        c.dedup();
        c.join(", ")
    };
    // Stage the applied paths first, then only commit if something is actually staged.
    // A remediation that leaves a file byte-identical stages nothing, and `git commit`
    // would fail with "nothing to commit" — treat that as a no-op success, not an error.
    for p in &paths {
        let s = p.to_string_lossy();
        let _ = git(&dest, &["add", "-A", "--", s.as_ref()]);
    }
    if has_staged_changes(&dest) {
        if let Err(e) = commit_paths(&dest, &format!("wormward: remediate {campaigns}"), &paths) {
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
        if let Err(e) = git(&dest, &["push", "origin", "--", &backup]) {
            outcome.error = Some(redact(format!("backup push: {e}"), token));
            return outcome;
        }
        // Push EXACTLY the cleaned default branch via an explicit refspec, never a bare
        // `--force-with-lease` (which under push.default=matching would push every branch).
        let refspec = format!("HEAD:refs/heads/{}", sr.repo.default_branch);
        match force_push_with_lease_to(&dest, "origin", &refspec) {
            Ok(()) => outcome.pushed.push(sr.repo.default_branch.clone()),
            Err(e) => outcome.error = Some(redact(format!("force-push: {e}"), token)),
        }
    }

    outcome
}

/// Phase two: remediate the scanned repos, cloning ON DEMAND only the repos being
/// fixed. When `selected` is `Some`, only repos whose `full_name` is in the set are
/// fixed; every other repo is reported unchanged. The temp clone dir (when no
/// explicit `clone_dir` is given) is dropped at the end of this function, deleting
/// the credentialed clones. Per-repo failures are captured; the run never aborts.
pub fn fix_pass(
    scan: &ScanPass,
    opts: &GithubRunOpts,
    packs: &[Pack],
    token: &str,
    selected: Option<&HashSet<String>>,
) -> Vec<RepoOutcome> {
    // A clone base is only needed when something will actually be written.
    let mut _tmp = None;
    let base: Option<PathBuf> = if opts.fix && opts.yes {
        match &opts.clone_dir {
            Some(d) => std::fs::create_dir_all(d).ok().map(|_| d.clone()),
            None => tempfile::TempDir::new().ok().map(|t| {
                let p = t.path().to_path_buf();
                _tmp = Some(t);
                p
            }),
        }
    } else {
        None
    };

    scan.repos
        .par_iter()
        .map(|sr| {
            let chosen = selected.is_none_or(|s| s.contains(&sr.repo.full_name));
            fix_scanned(sr, opts, packs, token, opts.fix && chosen, base.as_deref())
        })
        .collect()
}

/// Enumerate the account's repos and process each one: API-scan, then fix (cloned on
/// demand) all infected repos (no interactive selection). Per-repo failures are captured
/// in `RepoOutcome.error`; the run never aborts.
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
        // The fix cloned on demand into clone_dir.
        assert!(tmp.path().join("work").join("me__proj").exists());
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
        // A dry run touches nothing: no clone is created and the origin keeps the payload.
        assert!(!clone_dir.exists(), "dry run must not clone anything");
        let show = Command::new("git")
            .arg("-C")
            .arg(&bare)
            .args(["show", "main:postcss.config.mjs"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&show.stdout).contains("rmcej%otb%"));
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
    fn missing_default_branch_scans_all_tips_git_ref_stamped() {
        // The repo's declared `default_branch` ("trunk") does not exist among the returned
        // branches (stale metadata / rename race / serde-defaulted name). The infected tip
        // ("evil") must still be detected, every finding must carry a `git_ref` (nothing
        // treated as the working tree), and the repo must NOT be a fixable candidate.
        let tmp = TempDir::new().unwrap();
        let bare = make_branch_only_infected_origin(&tmp, "renamed");
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/renamed".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "trunk".into(), // does not exist; real branches are main + evil
                fork: false,
            }],
        };

        let scan = scan_pass(&scan_only_opts(), &host, &builtin_packs(), "").unwrap();
        let sr = &scan.repos()[0];
        assert!(sr.error.is_none(), "unexpected error: {:?}", sr.error);
        assert!(sr.is_infected(), "infected tip must still be detected");
        assert!(
            sr.findings.iter().all(|f| f.git_ref.is_some()),
            "every finding must be git_ref-stamped when the default branch is unknown"
        );
        // Detection is preserved but nothing is working-tree-fixable.
        assert_eq!(scan.infected_full_names(), vec!["me/renamed".to_string()]);
        assert!(
            !scan.fixable_full_names(&builtin_packs()).contains(&"me/renamed".to_string()),
            "a repo with an unknown default branch must not be a fixable candidate"
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

        // The deselected repo was never cloned, and its origin is still infected.
        assert!(!clone_dir.join("me__b").exists(), "deselected repo must not be cloned");
        let show = Command::new("git")
            .arg("-C")
            .arg(&bare_b)
            .args(["show", "main:postcss.config.mjs"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&show.stdout).contains("rmcej%otb%"));
    }

    #[test]
    fn clean_repos_never_touch_disk() {
        // A clean account scans and "fixes" without a single clone directory appearing.
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("clean-src");
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(src.join("postcss.config.mjs"), "export default {};\n").unwrap();
        git_ok(&src, &["add", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "clean"]);
        let bare = tmp.path().join("clean.git");
        Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&bare)
            .status()
            .unwrap();
        git_ok(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git_ok(&src, &["push", "-q", "origin", "main"]);

        let clone_dir = tmp.path().join("work");
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/clean".into(),
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
            yes: true,
        };
        let outcomes = run(&opts, &host, &builtin_packs(), "").unwrap();
        assert!(outcomes[0].findings.is_empty());
        assert!(outcomes[0].error.is_none());
        assert!(
            !clone_dir.join("me__clean").exists(),
            "clean repo must never be cloned"
        );
    }

    /// Wraps GitFakeHost but reports every tree as truncated, forcing the
    /// clone-and-scan fallback.
    struct TruncatedHost(GitFakeHost);
    impl RepoHost for TruncatedHost {
        fn list_repos(&self, f: bool) -> Result<Vec<RepoRef>, GithubError> {
            self.0.list_repos(f)
        }
        fn list_branches(&self, n: &str) -> Result<Vec<Branch>, GithubError> {
            self.0.list_branches(n)
        }
        fn get_tree(&self, n: &str, s: &str) -> Result<Tree, GithubError> {
            self.0.get_tree(n, s).map(|t| Tree { truncated: true, ..t })
        }
        fn get_blob(&self, n: &str, s: &str) -> Result<Option<String>, GithubError> {
            self.0.get_blob(n, s)
        }
    }

    /// Wraps GitFakeHost but fails every blob fetch.
    struct BrokenBlobHost(GitFakeHost);
    impl RepoHost for BrokenBlobHost {
        fn list_repos(&self, f: bool) -> Result<Vec<RepoRef>, GithubError> {
            self.0.list_repos(f)
        }
        fn list_branches(&self, n: &str) -> Result<Vec<Branch>, GithubError> {
            self.0.list_branches(n)
        }
        fn get_tree(&self, n: &str, s: &str) -> Result<Tree, GithubError> {
            self.0.get_tree(n, s)
        }
        fn get_blob(&self, _: &str, _: &str) -> Result<Option<String>, GithubError> {
            Err(GithubError::Http("connection reset".into()))
        }
    }

    /// Rate-limited from the very first per-repo call.
    struct RateLimitedHost(GitFakeHost);
    impl RepoHost for RateLimitedHost {
        fn list_repos(&self, f: bool) -> Result<Vec<RepoRef>, GithubError> {
            self.0.list_repos(f)
        }
        fn list_branches(&self, _: &str) -> Result<Vec<Branch>, GithubError> {
            Err(GithubError::RateLimited("HTTP 429".into()))
        }
        fn get_tree(&self, n: &str, s: &str) -> Result<Tree, GithubError> {
            self.0.get_tree(n, s)
        }
        fn get_blob(&self, n: &str, s: &str) -> Result<Option<String>, GithubError> {
            self.0.get_blob(n, s)
        }
    }

    fn one_repo_host(tmp: &TempDir, name: &str) -> GitFakeHost {
        let bare = make_infected_origin_named(tmp, name);
        GitFakeHost {
            repos: vec![RepoRef {
                full_name: format!("me/{name}"),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        }
    }

    fn scan_only_opts() -> GithubRunOpts {
        GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: false,
            push: false,
            yes: false,
        }
    }

    #[test]
    fn truncated_tree_falls_back_to_clone_scan() {
        let tmp = TempDir::new().unwrap();
        let host = TruncatedHost(one_repo_host(&tmp, "big"));
        let scan = scan_pass(&scan_only_opts(), &host, &builtin_packs(), "").unwrap();
        let sr = &scan.repos()[0];
        assert!(sr.error.is_none(), "fallback should succeed: {:?}", sr.error);
        assert!(sr.is_infected(), "fallback clone-scan must still find the payload");
        // Findings are labeled with the virtual repo name, not a dangling temp path.
        assert_eq!(sr.findings[0].repo, PathBuf::from("me/big"));
    }

    #[test]
    fn blob_fetch_failure_marks_scan_incomplete_not_clean() {
        let tmp = TempDir::new().unwrap();
        let host = BrokenBlobHost(one_repo_host(&tmp, "flaky"));
        let scan = scan_pass(&scan_only_opts(), &host, &builtin_packs(), "").unwrap();
        let sr = &scan.repos()[0];
        assert!(sr.error.as_deref().unwrap_or("").contains("scan incomplete"));
        assert!(!sr.is_infected(), "errored repo is not 'infected'");
        assert!(sr.findings.is_empty(), "incomplete findings must not be reported");
    }

    #[test]
    fn rate_limit_aborts_the_scan() {
        let tmp = TempDir::new().unwrap();
        let host = RateLimitedHost(one_repo_host(&tmp, "limited"));
        let result = scan_pass(&scan_only_opts(), &host, &builtin_packs(), "");
        assert!(matches!(result, Err(GithubError::RateLimited(_))), "got {result:?}");
    }

    #[test]
    fn scan_progress_reports_each_repo_once() {
        use std::sync::Mutex;
        let tmp = TempDir::new().unwrap();
        let mut repos = Vec::new();
        for name in ["a", "b", "c"] {
            let bare = make_infected_origin_named(&tmp, name);
            repos.push(RepoRef {
                full_name: format!("me/{name}"),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            });
        }
        let host = GitFakeHost { repos };
        let events: Mutex<Vec<ScanProgress>> = Mutex::new(Vec::new());

        let scan = scan_pass_with_progress(
            &scan_only_opts(),
            &host,
            &builtin_packs(),
            "",
            &|p| events.lock().unwrap().push(p),
        )
        .unwrap();

        assert_eq!(scan.repos().len(), 3);
        let ev = events.into_inner().unwrap();
        assert_eq!(ev.len(), 3, "exactly one event per repo");
        assert!(ev.iter().all(|p| p.total == 3));
        // Completion order is nondeterministic; done values must be 1..=3 in some order.
        let mut dones: Vec<usize> = ev.iter().map(|p| p.done).collect();
        dones.sort();
        assert_eq!(dones, vec![1, 2, 3]);
        let mut names: Vec<&str> = ev.iter().map(|p| p.repo.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["me/a", "me/b", "me/c"]);
    }
}
