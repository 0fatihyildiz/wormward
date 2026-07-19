use std::path::{Path, PathBuf};
use std::process::Command;

pub fn reflog_has_amend(repo: &Path) -> bool {
    let output = Command::new("git")
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
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
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
    run_git(repo, &["commit", "-m", message])
}

/// Stage the given remediation paths and amend HEAD — rewrites the latest commit in place
/// (HEAD only, no deeper history rewrite) and reattributes its authorship to wormward.
pub fn amend_head(repo: &Path, paths: &[PathBuf]) -> Result<(), String> {
    stage_paths(repo, paths);
    run_git(repo, &["commit", "--amend", "--no-edit"])
}

/// `git push`.
pub fn push(repo: &Path) -> Result<(), String> {
    run_git(repo, &["push"])
}

/// `git push --force-with-lease` (safe force-push; fails if the remote moved).
pub fn force_push_with_lease(repo: &Path) -> Result<(), String> {
    run_git(repo, &["push", "--force-with-lease"])
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
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status()
            .unwrap();
        assert!(status.success());
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
        Command::new("git").args(["init", "--bare", "-q"]).arg(&remote).status().unwrap();
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
        Command::new("git").args(["init", "--bare", "-q"]).arg(&remote).status().unwrap();
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
    fn force_push_with_lease_rejects_when_remote_moved() {
        let tmp = TempDir::new().unwrap();
        let remote = tmp.path().join("remote.git");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        Command::new("git").args(["init", "--bare", "-q"]).arg(&remote).status().unwrap();
        std::fs::create_dir_all(&a).unwrap();
        git(&a, &["init", "-q", "-b", "main"]);
        std::fs::write(a.join("f.txt"), "1").unwrap();
        git(&a, &["add", "."]);
        git(&a, &["commit", "-q", "-m", "c1"]);
        git(&a, &["remote", "add", "origin", remote.to_str().unwrap()]);
        git(&a, &["push", "-q", "-u", "origin", "main"]);
        // Clone B advances the remote underneath A.
        Command::new("git").args(["clone", "-q"]).arg(&remote).arg(&b).status().unwrap();
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
