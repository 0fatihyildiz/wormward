use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ignore::{WalkBuilder, WalkState};

/// A never-set cancel flag, so the non-cancellable public walkers can delegate to the
/// cancellable ones without every caller threading a flag.
static NEVER: AtomicBool = AtomicBool::new(false);

fn is_pruned_dir(name: &str) -> bool {
    // `.wormward-backup` (in EXCLUDED_DIRS) holds pristine copies of removed payloads — never
    // rescan it, or every scan after a `clean` would re-flag the backed-up originals.
    // EXCLUDED_DIRS as a whole (target/, dist/, .next/, …) is pruned because every scan pass
    // already skips those paths via is_excluded_path — enumerating a multi-GB build tree only
    // to discard each path is the walk's dominant wasted I/O.
    name == ".git" || crate::surface::EXCLUDED_DIRS.contains(&name)
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

/// Package-shaped node_modules descent for repo DISCOVERY. Inside a node_modules subtree, only
/// the places a vendored repo's `.git` can live at a package ROOT are entered: a direct child
/// (`<pkg>`, `@scope`, `.pnpm`), the second level for scoped / pnpm-virtual-store packages
/// (`@scope/<pkg>`, `.pnpm/<name>@<ver>`), plus `.git` and nested `node_modules` re-entry points
/// at any depth. A package's own internal file tree (thousands of entries per package) is never
/// enumerated — that enumeration was over half of total scan time on real trees. The worm vendors
/// at `node_modules/<pkg>/.git`, so coverage is unchanged where it matters; a `.git` buried
/// deeper inside a package's shipped sources is the accepted tradeoff.
fn node_modules_descent_allowed(path: &Path) -> bool {
    let comps: Vec<&std::ffi::OsStr> = path.components().map(|c| c.as_os_str()).collect();
    let last_nm = match comps.iter().rposition(|c| *c == "node_modules") {
        Some(i) => i,
        None => return true, // not inside node_modules — normal descent
    };
    let tail = &comps[last_nm + 1..];
    // `.git` (a vendored repo) and `node_modules` (a nested install tree) re-enter at any depth.
    if let Some(name) = tail.last() {
        if *name == ".git" || *name == "node_modules" {
            return true;
        }
    }
    match tail.len() {
        // node_modules itself, or a direct child: a package root, an @scope, or pnpm's .pnpm.
        0 | 1 => true,
        // One level deeper only for the two layouts whose package roots live there.
        2 => {
            let head = tail[0].to_string_lossy();
            head.starts_with('@') || head == ".pnpm"
        }
        _ => false,
    }
}

/// Cancellable variant of [`discover_repos`]. The parallel walk quits as soon as `cancel` is
/// set, so a Stop during the discovery phase — which descends into node_modules and can be the
/// slowest part of scanning a large monorepo — is honored instead of running the whole tree to
/// completion first.
pub fn discover_repos_cancellable(root: &Path, cancel: &AtomicBool) -> Vec<PathBuf> {
    let found = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
    let mut b = base_builder(root);
    // Descend into node_modules (the worm can vendor an infected repo at
    // node_modules/<pkg>/.git) but package-shaped: only package roots and re-entry points are
    // entered, never a package's internal file tree — see node_modules_descent_allowed. .git
    // internals are skipped via WalkState::Skip in the callback below.
    b.filter_entry(|e| node_modules_descent_allowed(e.path()));
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
    fn discovers_vendored_repos_at_every_package_root_shape() {
        // The node_modules descent is package-shaped (it must not enumerate every package's
        // internal file tree), so each place a PACKAGE ROOT can live must still be reached:
        // plain, @scoped, the pnpm virtual store, and a nested node_modules.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let nm = root.join("app/node_modules");
        fs::create_dir_all(root.join("app/.git")).unwrap();
        fs::create_dir_all(nm.join("@scope/evil/.git")).unwrap();
        fs::create_dir_all(nm.join(".pnpm/evil@1.0.0/node_modules/evil/.git")).unwrap();
        fs::create_dir_all(nm.join("host/node_modules/nested-evil/.git")).unwrap();

        let repos = discover_repos(root);
        assert!(repos.contains(&nm.join("@scope/evil")), "scoped package root: {repos:?}");
        assert!(
            repos.contains(&nm.join(".pnpm/evil@1.0.0/node_modules/evil")),
            "pnpm virtual-store package root: {repos:?}"
        );
        assert!(
            repos.contains(&nm.join("host/node_modules/nested-evil")),
            "nested node_modules package root: {repos:?}"
        );
    }

    #[test]
    fn discovery_skips_package_internals_under_node_modules() {
        // The accepted tradeoff of the package-shaped descent: a .git buried INSIDE a package's
        // source tree (not at a package root) is no longer discovered — the worm vendors at
        // node_modules/<pkg>/.git, and enumerating every package's internals cost more than half
        // of total scan time on real trees.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("app/.git")).unwrap();
        fs::create_dir_all(root.join("app/node_modules/pkg/src/deep/.git")).unwrap();

        let repos = discover_repos(root);
        assert!(repos.contains(&root.join("app")));
        assert!(
            !repos.contains(&root.join("app/node_modules/pkg/src/deep")),
            "package internals must not be walked: {repos:?}"
        );
    }

    #[test]
    fn walk_prunes_dirs_every_scan_pass_excludes() {
        // Build-output dirs (target/, dist/, .next/, …) are skipped by every scan pass via
        // is_excluded_path — enumerating them in the walk is pure wasted I/O (a Rust repo's
        // target/ alone can be 99% of its walked paths). They must be pruned at walk time.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        touch(&repo.join("src/index.js"));
        touch(&repo.join("target/debug/build/foo/out.rs"));
        touch(&repo.join("dist/index.js"));
        touch(&repo.join(".next/server/app.js"));
        touch(&repo.join("coverage/lcov.info"));

        let files = walk_repo_files(repo);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(repo).unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(names.contains(&"src/index.js".to_string()));
        for pruned in ["target/", "dist/", ".next/", "coverage/"] {
            assert!(
                !names.iter().any(|n| n.starts_with(pruned)),
                "{pruned} must be pruned from the walk, got {names:?}"
            );
        }
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
