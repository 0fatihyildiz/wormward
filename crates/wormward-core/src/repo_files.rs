use std::path::{Path, PathBuf};
use std::process::Command;

use crate::walk::walk_repo_files;

/// A source of repo-relative files to scan (a working tree or a git tree).
pub trait RepoFiles {
    fn paths(&self) -> &[PathBuf];
    fn read(&self, rel: &Path) -> Option<String>;
    /// Whether a specific file is present. Default = membership in `paths()`;
    /// `WorkingTree` overrides to follow symlinks like the previous `is_file()` check.
    fn exists(&self, rel: &Path) -> bool {
        self.paths().iter().any(|p| p == rel)
    }
}

pub struct WorkingTree {
    repo: PathBuf,
    paths: Vec<PathBuf>,
}

impl WorkingTree {
    pub fn new(repo: &Path) -> Self {
        let paths = walk_repo_files(repo)
            .into_iter()
            .map(|p| p.strip_prefix(repo).map(Path::to_path_buf).unwrap_or(p))
            .collect();
        WorkingTree { repo: repo.to_path_buf(), paths }
    }
}

impl RepoFiles for WorkingTree {
    fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
    fn read(&self, rel: &Path) -> Option<String> {
        std::fs::read_to_string(self.repo.join(rel)).ok()
    }
    fn exists(&self, rel: &Path) -> bool {
        self.repo.join(rel).is_file()
    }
}

pub struct GitTree {
    repo: PathBuf,
    commit: String,
    paths: Vec<PathBuf>,
}

impl GitTree {
    /// Build a file source for a commit's tree, reading blobs via git (no checkout).
    pub fn new(repo: &Path, commit: &str) -> Option<Self> {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            // -z: NUL-separated, and disables git's C-quoting of non-ASCII/special
            // paths so filenames on branch tips are matched and read correctly.
            .args(["ls-tree", "-r", "-z", "--name-only", commit])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let paths = String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        Some(GitTree { repo: repo.to_path_buf(), commit: commit.to_string(), paths })
    }
}

impl RepoFiles for GitTree {
    fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
    fn read(&self, rel: &Path) -> Option<String> {
        let spec = format!("{}:{}", self.commit, rel.to_string_lossy());
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(["show", &spec])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout).ok() // None for non-utf8 (binary) blobs
    }
}
