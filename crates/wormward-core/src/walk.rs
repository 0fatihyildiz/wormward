use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ignore::{WalkBuilder, WalkState};

/// A never-set cancel flag, so the non-cancellable public walkers can delegate to the
/// cancellable ones without every caller threading a flag.
static NEVER: AtomicBool = AtomicBool::new(false);

fn is_pruned_dir(name: &str) -> bool {
    // `.wormward-backup` holds pristine copies of removed payloads — never rescan it,
    // or every scan after a `clean` would re-flag the backed-up originals.
    name == ".git" || name == "node_modules" || name == ".wormward-backup"
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
    discover_repos_cancellable(root, &NEVER)
}

/// Cancellable variant of [`discover_repos`]. The parallel walk quits as soon as `cancel` is
/// set, so a Stop during the discovery phase — which descends into node_modules and can be the
/// slowest part of scanning a large monorepo — is honored instead of running the whole tree to
/// completion first.
pub fn discover_repos_cancellable(root: &Path, cancel: &AtomicBool) -> Vec<PathBuf> {
    let found = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let b = base_builder(root);
    // Descend everywhere (including node_modules): the worm can vendor an infected
    // repo at node_modules/<pkg>/.git, so we must still discover it. We only avoid
    // descending into .git internals, via WalkState::Skip in the callback below.
    b.build_parallel().run(|| {
        let found = Arc::clone(&found);
        Box::new(move |res| {
            if cancel.load(Ordering::Relaxed) {
                return WalkState::Quit; // Stop requested: abandon the whole walk.
            }
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
    walk_repo_files_cancellable(repo, &NEVER)
}

/// Cancellable variant of [`walk_repo_files`]. Quits the parallel walk as soon as `cancel` is
/// set, so a Stop lands even before the per-file scan loop starts on a huge working tree.
pub fn walk_repo_files_cancellable(repo: &Path, cancel: &AtomicBool) -> Vec<PathBuf> {
    let files = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let mut b = base_builder(repo);
    // The per-repo scan runs under an outer rayon parallelism across repos, and the scan itself
    // is sequential per repo — so a multi-threaded walk here only oversubscribes the CPU (up to
    // cores² threads, which thrashes and heats). One walker thread per repo keeps total threads
    // ≈ cores. Discovery stays parallel: it runs standalone, before the repo loop.
    b.threads(1);
    b.filter_entry(|e| {
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        !(is_dir && e.depth() > 0 && is_pruned_dir(&e.file_name().to_string_lossy()))
    });
    b.build_parallel().run(|| {
        let files = Arc::clone(&files);
        Box::new(move |res| {
            if cancel.load(Ordering::Relaxed) {
                return WalkState::Quit; // Stop requested: abandon the walk.
            }
            if let Ok(entry) = res {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    files.lock().unwrap().push(entry.into_path());
                }
            }
            WalkState::Continue
        })
    });
    let mut files = Arc::try_unwrap(files).unwrap().into_inner().unwrap();
    // The parallel walker yields files in nondeterministic order; sort so findings
    // (and reflog attribution via findings[0]) are deterministic across runs.
    files.sort();
    files
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
    fn discover_repos_cancellable_bails_when_flag_set() {
        use std::sync::atomic::AtomicBool;
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("a/.git")).unwrap();
        // Not cancelled: finds the repo.
        let live = discover_repos_cancellable(root, &AtomicBool::new(false));
        assert!(live.contains(&root.join("a")));
        // Pre-cancelled: the parallel walk quits before discovering anything, so a Stop during
        // the discovery phase is honored instead of running the whole tree to completion.
        let cancelled = discover_repos_cancellable(root, &AtomicBool::new(true));
        assert!(cancelled.is_empty(), "cancelled discovery must return no repos, got {cancelled:?}");
    }

    #[test]
    fn walk_repo_files_cancellable_bails_when_flag_set() {
        use std::sync::atomic::AtomicBool;
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        touch(&repo.join("src/a.rs"));
        touch(&repo.join("src/b.rs"));
        // Not cancelled: walks the files.
        let live = walk_repo_files_cancellable(repo, &AtomicBool::new(false));
        assert!(!live.is_empty());
        // Pre-cancelled: the walk quits immediately.
        let cancelled = walk_repo_files_cancellable(repo, &AtomicBool::new(true));
        assert!(cancelled.is_empty(), "cancelled walk must return no files, got {cancelled:?}");
    }

    #[test]
    fn discovers_repo_vendored_under_node_modules() {
        // The worm can vendor an infected repo at node_modules/<pkg>/.git; discover_repos
        // must descend into node_modules and still find it.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("app/.git")).unwrap();
        fs::create_dir_all(root.join("app/node_modules/evil-pkg/.git")).unwrap();

        let repos = discover_repos(root);
        assert!(repos.contains(&root.join("app")));
        assert!(repos.contains(&root.join("app/node_modules/evil-pkg")));
    }

    #[test]
    fn walk_skips_git_and_node_modules() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        touch(&repo.join("postcss.config.mjs"));
        touch(&repo.join("src/index.js"));
        touch(&repo.join(".git/config"));
        touch(&repo.join("node_modules/pkg/index.js"));
        touch(&repo.join(".wormward-backup/123/postcss.config.mjs"));

        let files = walk_repo_files(repo);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(repo).unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(names.contains(&"postcss.config.mjs".to_string()));
        assert!(names.contains(&"src/index.js".to_string()));
        assert!(!names.iter().any(|n| n.starts_with(".git/")));
        assert!(!names.iter().any(|n| n.starts_with("node_modules/")));
        assert!(!names.iter().any(|n| n.starts_with(".wormward-backup/")));
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
