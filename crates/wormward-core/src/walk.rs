use std::path::{Path, PathBuf};

use walkdir::WalkDir;

fn is_pruned_dir(name: &str) -> bool {
    name == ".git" || name == "node_modules"
}

pub fn discover_repos(root: &Path) -> Vec<PathBuf> {
    let mut repos = Vec::new();
    let mut it = WalkDir::new(root).into_iter();
    while let Some(entry) = it.next() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.file_type().is_dir() && entry.file_name() == ".git" {
            if let Some(parent) = entry.path().parent() {
                repos.push(parent.to_path_buf());
            }
            it.skip_current_dir(); // do not descend into .git internals
        }
    }
    repos.sort();
    repos.dedup();
    repos
}

pub fn walk_repo_files(repo: &Path) -> Vec<PathBuf> {
    WalkDir::new(repo)
        .into_iter()
        .filter_entry(|e| {
            !(e.file_type().is_dir()
                && e.depth() > 0
                && is_pruned_dir(&e.file_name().to_string_lossy()))
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, "x").unwrap();
    }

    #[test]
    fn discovers_git_repos() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("a/.git")).unwrap();
        fs::create_dir_all(root.join("b/c/.git")).unwrap();
        fs::create_dir_all(root.join("d")).unwrap(); // no .git

        let mut repos = discover_repos(root);
        repos.sort();
        assert_eq!(repos, vec![root.join("a"), root.join("b/c")]);
    }

    #[test]
    fn walk_skips_git_and_node_modules() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        touch(&repo.join("postcss.config.mjs"));
        touch(&repo.join("src/index.js"));
        touch(&repo.join(".git/config"));
        touch(&repo.join("node_modules/pkg/index.js"));

        let files = walk_repo_files(repo);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(repo).unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(names.contains(&"postcss.config.mjs".to_string()));
        assert!(names.contains(&"src/index.js".to_string()));
        assert!(!names.iter().any(|n| n.starts_with(".git/")));
        assert!(!names.iter().any(|n| n.starts_with("node_modules/")));
    }
}
