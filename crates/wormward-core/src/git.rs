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
}
