use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::AtomicBool;

use crate::walk::walk_repo_files_cancellable;

/// A never-set cancel flag so `WorkingTree::new` can delegate to the cancellable builder.
static NEVER: AtomicBool = AtomicBool::new(false);

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
        Self::new_cancellable(repo, &NEVER)
    }

    /// Like [`WorkingTree::new`] but abandons the working-tree walk as soon as `cancel` is set,
    /// so a Stop request is honored before the (potentially large) file list is even built.
    pub fn new_cancellable(repo: &Path, cancel: &AtomicBool) -> Self {
        let paths = walk_repo_files_cancellable(repo, cancel)
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
    // One lazily-spawned `git cat-file --batch` process, reused for every blob read in this
    // tree. Deep scan reads config/manifest files across many branch tips; a shared reader turns
    // that from one `git show` subprocess per file into a single reader per tree — a large drop
    // in process churn (and CPU/heat) on repos with many branches.
    reader: RefCell<Option<CatFile>>,
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
        Some(GitTree {
            repo: repo.to_path_buf(),
            commit: commit.to_string(),
            paths,
            reader: RefCell::new(None),
        })
    }
}

impl RepoFiles for GitTree {
    fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
    fn read(&self, rel: &Path) -> Option<String> {
        let mut slot = self.reader.borrow_mut();
        if slot.is_none() {
            *slot = CatFile::spawn(&self.repo);
        }
        slot.as_mut()?.read_blob(&self.commit, rel)
    }
}

/// A persistent `git cat-file --batch` reader for one repo. Specs `<rev>:<path>` are written to
/// stdin; each reply is `<oid> <type> <size>\n<content>\n`, or `<spec> missing\n` when absent.
struct CatFile {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl CatFile {
    fn spawn(repo: &Path) -> Option<CatFile> {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let stdin = child.stdin.take()?;
        let stdout = BufReader::new(child.stdout.take()?);
        Some(CatFile { child, stdin, stdout })
    }

    /// Read one blob by `<commit>:<path>`. Returns None for a missing path or a non-utf8 (binary)
    /// blob. The stream is always advanced past the object, so subsequent reads stay in sync.
    fn read_blob(&mut self, commit: &str, rel: &Path) -> Option<String> {
        // cat-file --batch treats the whole input line as the spec, so paths with spaces work;
        // a literal newline in a path (astronomically rare) would break framing — accept that.
        let spec = format!("{}:{}\n", commit, rel.to_string_lossy());
        self.stdin.write_all(spec.as_bytes()).ok()?;
        self.stdin.flush().ok()?;

        let mut header = String::new();
        if self.stdout.read_line(&mut header).ok()? == 0 {
            return None; // reader exited
        }
        // "<oid> <type> <size>" on success; the last token is "missing" when absent.
        let size: usize = match header.trim_end().rsplit(' ').next() {
            Some("missing") | None => return None,
            Some(tok) => tok.parse().ok()?,
        };
        let mut buf = vec![0u8; size];
        self.stdout.read_exact(&mut buf).ok()?;
        let mut lf = [0u8; 1];
        self.stdout.read_exact(&mut lf).ok()?; // trailing LF after the content
        String::from_utf8(buf).ok() // None for non-utf8 (binary) blobs
    }
}

impl Drop for CatFile {
    fn drop(&mut self) {
        // Closing stdin lets `git cat-file --batch` exit; kill+wait reaps it promptly so a deep
        // scan of many trees never leaves a pile of lingering git processes.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn git(repo: &Path, args: &[&str]) {
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status()
            .unwrap();
    }

    fn head(repo: &Path) -> String {
        let out = Command::new("git").arg("-C").arg(repo).args(["rev-parse", "HEAD"]).output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn git_tree_reads_committed_blobs() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join("a.txt"), "hello\n").unwrap();
        fs::create_dir_all(repo.join("sub")).unwrap();
        fs::write(repo.join("sub/b.txt"), "world payload\n").unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "c"]);

        let tree = GitTree::new(repo, &head(repo)).unwrap();
        assert!(tree.paths().contains(&PathBuf::from("a.txt")));
        assert!(tree.paths().contains(&PathBuf::from("sub/b.txt")));
        // Several reads (should reuse one reader once batched); a repeated read still works.
        assert_eq!(tree.read(Path::new("a.txt")).as_deref(), Some("hello\n"));
        assert_eq!(tree.read(Path::new("sub/b.txt")).as_deref(), Some("world payload\n"));
        assert_eq!(tree.read(Path::new("a.txt")).as_deref(), Some("hello\n"));
        // A path not in the tree yields None.
        assert_eq!(tree.read(Path::new("nope.txt")), None);
    }

    #[test]
    fn git_tree_read_none_for_binary_keeps_stream_in_sync() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join("bin.dat"), [0u8, 159, 146, 150, 0, 255]).unwrap(); // invalid utf-8
        fs::write(repo.join("ok.txt"), "clean\n").unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "c"]);

        let tree = GitTree::new(repo, &head(repo)).unwrap();
        // Binary blob -> None, and the reader must stay synced so the next read still works.
        assert_eq!(tree.read(Path::new("bin.dat")), None);
        assert_eq!(tree.read(Path::new("ok.txt")).as_deref(), Some("clean\n"));
    }
}
