use std::path::Path;
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

/// `git add -A && git commit -m <message>`.
pub fn commit_all(repo: &Path, message: &str) -> Result<(), String> {
    run_git(repo, &["add", "-A"])?;
    run_git(repo, &["commit", "-m", message])
}

/// `git add -A && git commit --amend --no-edit` (rewrites HEAD to include cleaned files).
pub fn amend_head(repo: &Path) -> Result<(), String> {
    run_git(repo, &["add", "-A"])?;
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
        commit_all(&repo, "wormward: remediate").unwrap();
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
        amend_head(&repo).unwrap();
        force_push_with_lease(&repo).unwrap();

        let show = Command::new("git").arg("-C").arg(&remote).args(["show", "main:a.txt"]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&show.stdout), "clean");
        let count = Command::new("git").arg("-C").arg(&remote).args(["rev-list", "--count", "main"]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&count.stdout).trim(), "1");
    }
}
