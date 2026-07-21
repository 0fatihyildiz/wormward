use std::path::{Path, PathBuf};

pub fn reflog_has_amend(repo: &Path) -> bool {
    let output = crate::proc::git()
        .arg("-C")
        .arg(repo)
        .arg("reflog")
        .output();
    match output {
        Ok(out) if out.status.success() => {
            // Match the reflog action token `commit (amend):`, not any commit
            // message that happens to contain the word "amend".
            String::from_utf8_lossy(&out.stdout).contains("(amend)")
        }
        _ => false,
    }
}

fn run_git(repo: &Path, args: &[&str]) -> Result<(), String> {
    let out = crate::proc::git()
        .arg("-C")
        .arg(repo)
        // Hardening: disable repo hooks so a malicious hook planted in a scanned repo cannot
        // execute when wormward stages/commits/pushes its remediation. `-c` must precede the
        // subcommand. Paired with GIT_CONFIG_NOSYSTEM below (ignore a hostile /etc/gitconfig).
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .args(args)
        // Never block on an interactive credential prompt (e.g. force-push to a private
        // remote without cached auth); fail fast with an error instead.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "wormward")
        .env("GIT_AUTHOR_EMAIL", "wormward@localhost")
        .env("GIT_COMMITTER_NAME", "wormward")
        .env("GIT_COMMITTER_EMAIL", "wormward@localhost")
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Stage ONLY the given remediation paths (best-effort per path; ignores a path with
/// nothing to stage, e.g. an untracked file that was deleted). Critically it never uses
/// `add -A` on the whole tree, so it never stages the `.wormward-backup/` directory (which
/// holds the removed payloads) nor unrelated working-tree changes.
fn stage_paths(repo: &Path, paths: &[PathBuf]) {
    for p in paths {
        let s = p.to_string_lossy();
        let _ = run_git(repo, &["add", "-A", "--", s.as_ref()]);
    }
}

/// Stage the given remediation paths and commit them.
pub fn commit_paths(repo: &Path, message: &str, paths: &[PathBuf]) -> Result<(), String> {
    stage_paths(repo, paths);
    run_git(repo, &["commit", "--no-verify", "-m", message])
}

/// Stage the given remediation paths and amend HEAD — rewrites the latest commit in place
/// (HEAD only, no deeper history rewrite). `--amend --no-edit` (no `--reset-author`) re-stamps
/// the *committer* to the identity running wormward but PRESERVES the original author, so the
/// forensic record of who introduced the commit is not lost.
pub fn amend_head(repo: &Path, paths: &[PathBuf]) -> Result<(), String> {
    stage_paths(repo, paths);
    run_git(repo, &["commit", "--amend", "--no-edit", "--no-verify"])
}

/// `git push`.
pub fn push(repo: &Path) -> Result<(), String> {
    run_git(repo, &["push", "--no-verify"])
}

/// `git push --force-with-lease` (safe force-push; fails if the remote moved).
pub fn force_push_with_lease(repo: &Path) -> Result<(), String> {
    run_git(repo, &["push", "--force-with-lease", "--no-verify"])
}

/// `git push --force-with-lease <remote> <branch>` — a force-push scoped to exactly one
/// branch. Used when cleaning a remote-tracking tip (e.g. `origin/evil`), where the temp
/// worktree's local branch has no upstream configured for a bare `push`.
pub fn force_push_with_lease_to(repo: &Path, remote: &str, branch: &str) -> Result<(), String> {
    // `--` ends option parsing so a refspec/branch beginning with `-` cannot be read as a flag.
    run_git(repo, &["push", "--force-with-lease", "--no-verify", remote, "--", branch])
}

/// Run git and capture trimmed stdout on success.
fn run_git_stdout(repo: &Path, args: &[&str]) -> Option<String> {
    let out = crate::proc::git()
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

/// Resolve a revision to its full commit oid (`git rev-parse <rev>`).
pub fn rev_parse(repo: &Path, rev: &str) -> Option<String> {
    run_git_stdout(repo, &["rev-parse", rev])
}

/// Whether a ref resolves (`git rev-parse --verify --quiet <refname>`).
pub fn verify_ref(repo: &Path, refname: &str) -> bool {
    run_git(repo, &["rev-parse", "--verify", "--quiet", refname]).is_ok()
}

/// Point a ref at a value (`git update-ref <name> <value>`). Used to snapshot a branch tip
/// into `refs/wormward-backup/...` before rewriting it.
pub fn update_ref(repo: &Path, name: &str, value: &str) -> Result<(), String> {
    // `--` guards against a ref name beginning with `-` being parsed as an option.
    run_git(repo, &["update-ref", "--", name, value])
}

/// The all-zero oid: `git update-ref <name> <new> <old>` with this as `<old>` means
/// "only create; fail if the ref already exists".
const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// Create a ref *only if it does not already exist* (`git update-ref <name> <value> <zero>`).
/// Fails (non-zero) if the ref is already present, so a same-second rerun cannot clobber an
/// existing backup ref and destroy its rollback target.
pub fn create_ref(repo: &Path, name: &str, value: &str) -> Result<(), String> {
    // `--` guards against a ref name beginning with `-` being parsed as an option.
    run_git(repo, &["update-ref", "--", name, value, ZERO_OID])
}

/// The configured remote for a local branch (`git config --get branch.<branch>.remote`),
/// e.g. `origin`. `None` when the branch has no upstream remote configured.
pub fn branch_remote(repo: &Path, branch: &str) -> Option<String> {
    run_git_stdout(repo, &["config", "--get", &format!("branch.{branch}.remote")])
        .filter(|s| !s.is_empty())
}

/// The current branch name (`git rev-parse --abbrev-ref HEAD`), or `None` on a detached HEAD.
/// Used to scope a force-push to exactly the checked-out branch, never a bare push that could
/// touch every branch under `push.default=matching`.
pub fn current_branch(repo: &Path) -> Option<String> {
    run_git_stdout(repo, &["rev-parse", "--abbrev-ref", "HEAD"]).filter(|b| b != "HEAD")
}

/// `git worktree prune` — drop stale administrative worktree entries under
/// `.git/worktrees/` (used as a fallback when a worktree dir vanished without a clean remove).
pub fn worktree_prune(repo: &Path) -> Result<(), String> {
    run_git(repo, &["worktree", "prune"])
}

/// `git branch -D <name>` — force-delete a local branch. Used to remove the throwaway branch
/// created for a remote-tracking clean so no real-named local branch is left behind.
pub fn delete_branch(repo: &Path, name: &str) -> Result<(), String> {
    // `--` guards against a branch name beginning with `-` being parsed as an option.
    run_git(repo, &["branch", "-D", "--", name])
}

/// `git worktree add <path> <branch>` — check out an existing local branch into an isolated
/// worktree so its tip can be cleaned without disturbing the user's checkout.
pub fn worktree_add(repo: &Path, path: &Path, branch: &str) -> Result<(), String> {
    let p = path.to_string_lossy();
    // `--` ends option parsing so a branch beginning with `-` is not read as a flag.
    run_git(repo, &["worktree", "add", p.as_ref(), "--", branch])
}

/// `git worktree add <path> -b <new_branch> <start>` — create a fresh local branch from a
/// start-point (e.g. a remote-tracking ref) in an isolated worktree.
pub fn worktree_add_new_branch(
    repo: &Path,
    path: &Path,
    new_branch: &str,
    start: &str,
) -> Result<(), String> {
    let p = path.to_string_lossy();
    // `--` ends option parsing so a start-point beginning with `-` is not read as a flag.
    run_git(repo, &["worktree", "add", p.as_ref(), "-b", new_branch, "--", start])
}

/// `git worktree remove --force <path>` — always run after a branch clean, success or not.
pub fn worktree_remove(repo: &Path, path: &Path) -> Result<(), String> {
    let p = path.to_string_lossy();
    run_git(repo, &["worktree", "remove", "--force", p.as_ref()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_TEMPLATE_DIR", "")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn current_branch_reports_checked_out_branch() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("f.txt"), "a").unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "c"]);
        assert_eq!(current_branch(repo), Some("main".to_string()));
        git(repo, &["checkout", "-q", "-b", "feature"]);
        assert_eq!(current_branch(repo), Some("feature".to_string()));
    }

    #[test]
    fn detects_amend_in_reflog() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q"]);
        std::fs::write(repo.join("f.txt"), "a").unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "first"]);
        std::fs::write(repo.join("f.txt"), "b").unwrap();
        git(repo, &["commit", "-q", "-a", "--amend", "-m", "first-amended"]);

        assert!(reflog_has_amend(repo));
    }

    #[test]
    fn no_amend_when_none() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q"]);
        std::fs::write(repo.join("f.txt"), "a").unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "first"]);
        assert!(!reflog_has_amend(repo));
    }

    #[test]
    fn commit_and_push_to_bare_remote() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        let remote = tmp.path().join("remote.git");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        Command::new("git").args(["init", "--bare", "-q"]).env("GIT_TEMPLATE_DIR", "").arg(&remote).status().unwrap();
        std::fs::write(repo.join("a.txt"), "one").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "init"]);
        git(&repo, &["remote", "add", "origin", remote.to_str().unwrap()]);
        git(&repo, &["push", "-q", "-u", "origin", "main"]);

        std::fs::write(repo.join("a.txt"), "two").unwrap();
        commit_paths(&repo, "wormward: remediate", &[PathBuf::from("a.txt")]).unwrap();
        push(&repo).unwrap();

        let show = Command::new("git").arg("-C").arg(&remote).args(["show", "main:a.txt"]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&show.stdout), "two");
    }

    #[test]
    fn amend_and_force_push_with_lease() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("repo");
        let remote = tmp.path().join("remote.git");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        Command::new("git").args(["init", "--bare", "-q"]).env("GIT_TEMPLATE_DIR", "").arg(&remote).status().unwrap();
        std::fs::write(repo.join("a.txt"), "payload").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "c"]);
        git(&repo, &["remote", "add", "origin", remote.to_str().unwrap()]);
        git(&repo, &["push", "-q", "-u", "origin", "main"]);

        std::fs::write(repo.join("a.txt"), "clean").unwrap();
        amend_head(&repo, &[PathBuf::from("a.txt")]).unwrap();
        force_push_with_lease(&repo).unwrap();

        let show = Command::new("git").arg("-C").arg(&remote).args(["show", "main:a.txt"]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&show.stdout), "clean");
        let count = Command::new("git").arg("-C").arg(&remote).args(["rev-list", "--count", "main"]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&count.stdout).trim(), "1");
    }

    #[test]
    fn commit_paths_stages_only_given_paths() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("seed.txt"), "s").unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "seed"]);
        // A cleaned file plus an UNRELATED untracked file that must NOT be committed.
        std::fs::write(repo.join("cleaned.txt"), "ok").unwrap();
        std::fs::write(repo.join("unrelated-secret.txt"), "SECRET").unwrap();
        commit_paths(repo, "wormward: remediate", &[PathBuf::from("cleaned.txt")]).unwrap();

        let files = Command::new("git").arg("-C").arg(repo).args(["show", "--name-only", "--format=", "HEAD"]).output().unwrap();
        let out = String::from_utf8_lossy(&files.stdout);
        assert!(out.contains("cleaned.txt"));
        assert!(!out.contains("unrelated-secret.txt"));
    }

    #[test]
    fn create_ref_is_create_only() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("f.txt"), "a").unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "c"]);
        let oid = rev_parse(repo, "HEAD").unwrap();

        let name = "refs/wormward-backup/x-1";
        create_ref(repo, name, &oid).unwrap();
        // A second create-only attempt must FAIL rather than clobber the existing ref.
        assert!(create_ref(repo, name, &oid).is_err());
        assert_eq!(rev_parse(repo, name).unwrap(), oid);
    }

    #[test]
    fn force_push_with_lease_rejects_when_remote_moved() {
        let tmp = TempDir::new().unwrap();
        let remote = tmp.path().join("remote.git");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        // -b main so the bare HEAD tracks main even when init.defaultBranch=master.
        Command::new("git").args(["init", "--bare", "-q", "-b", "main"]).env("GIT_TEMPLATE_DIR", "").arg(&remote).status().unwrap();
        std::fs::create_dir_all(&a).unwrap();
        git(&a, &["init", "-q", "-b", "main"]);
        std::fs::write(a.join("f.txt"), "1").unwrap();
        git(&a, &["add", "."]);
        git(&a, &["commit", "-q", "-m", "c1"]);
        git(&a, &["remote", "add", "origin", remote.to_str().unwrap()]);
        git(&a, &["push", "-q", "-u", "origin", "main"]);
        // Clone B advances the remote underneath A.
        Command::new("git").args(["clone", "-q"]).env("GIT_TEMPLATE_DIR", "").arg(&remote).arg(&b).status().unwrap();
        std::fs::write(b.join("f.txt"), "2").unwrap();
        git(&b, &["add", "."]);
        git(&b, &["commit", "-q", "-m", "c2"]);
        git(&b, &["push", "-q", "origin", "main"]);
        // A is stale; the lease must reject the force-push.
        std::fs::write(a.join("f.txt"), "3").unwrap();
        amend_head(&a, &[PathBuf::from("f.txt")]).unwrap();
        assert!(force_push_with_lease(&a).is_err());
    }
}
