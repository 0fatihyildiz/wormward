use std::path::{Path, PathBuf};

use crate::walk::walk_repo_files;

/// A source of repo-relative files to scan (a working tree or a git tree).
pub trait RepoFiles {
    fn paths(&self) -> &[PathBuf];
    fn read(&self, rel: &Path) -> Option<String>;
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
}
