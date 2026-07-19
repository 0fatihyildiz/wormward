use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ignore::{WalkBuilder, WalkState};

fn is_pruned_dir(name: &str) -> bool {
    name == ".git" || name == "node_modules"
}

fn base_builder(root: &Path) -> WalkBuilder {
    let mut b = WalkBuilder::new(root);
    // Walk everything: the worm hides artifacts via .gitignore, so ignore rules
    // must NOT filter our view. We only use `ignore` for its fast parallel walker.
    b.git_ignore(false)
        .git_exclude(false)
        .git_global(false)
        .ignore(false)
        .hidden(false)
        .parents(false)
        .standard_filters(false);
    b
}

pub fn discover_repos(root: &Path) -> Vec<PathBuf> {
    let found = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let mut b = base_builder(root);
    // Prune node_modules (never a repo root we care about); detect .git in-callback.
    b.filter_entry(|e| e.file_name() != "node_modules");
    b.build_parallel().run(|| {
        let found = Arc::clone(&found);
        Box::new(move |res| {
            if let Ok(entry) = res {
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                if is_dir && entry.file_name() == ".git" {
                    if let Some(parent) = entry.path().parent() {
                        found.lock().unwrap().push(parent.to_path_buf());
                    }
                    return WalkState::Skip; // do not descend into .git internals
                }
            }
            WalkState::Continue
        })
    });
    let mut repos = Arc::try_unwrap(found).unwrap().into_inner().unwrap();
    repos.sort();
    repos.dedup();
    repos
}

pub fn walk_repo_files(repo: &Path) -> Vec<PathBuf> {
    let files = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let mut b = base_builder(repo);
    b.filter_entry(|e| {
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        !(is_dir && e.depth() > 0 && is_pruned_dir(&e.file_name().to_string_lossy()))
    });
    b.build_parallel().run(|| {
        let files = Arc::clone(&files);
        Box::new(move |res| {
            if let Ok(entry) = res {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    files.lock().unwrap().push(entry.into_path());
                }
            }
            WalkState::Continue
        })
    });
    Arc::try_unwrap(files).unwrap().into_inner().unwrap()
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

    #[test]
    fn walk_includes_gitignored_files() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        touch(&repo.join(".gitignore"));
        fs::write(repo.join(".gitignore"), "config.bat\n").unwrap();
        touch(&repo.join("config.bat")); // hidden by .gitignore, must still be walked
        touch(&repo.join(".git/config"));

        let files = walk_repo_files(repo);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(repo).unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(names.contains(&"config.bat".to_string()));
        assert!(!names.iter().any(|n| n.starts_with(".git/")));
    }
}
