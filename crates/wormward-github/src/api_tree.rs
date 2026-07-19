use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use wormward_core::RepoFiles;

use crate::{GithubError, RepoHost, Tree};

/// Blob contents keyed by git sha, shared across all branches and repos of one scan
/// pass so an identical file is fetched at most once. `None` = fetched, binary.
pub struct BlobCache(Mutex<HashMap<String, Option<String>>>);

impl BlobCache {
    pub fn new() -> Self {
        BlobCache(Mutex::new(HashMap::new()))
    }
    fn get(&self, sha: &str) -> Option<Option<String>> {
        self.0.lock().ok()?.get(sha).cloned()
    }
    fn put(&self, sha: &str, content: Option<String>) {
        if let Ok(mut map) = self.0.lock() {
            map.insert(sha.to_string(), content);
        }
    }
}

impl Default for BlobCache {
    fn default() -> Self {
        Self::new()
    }
}

/// One branch tip's file listing served from the GitHub API, implementing the core
/// scanner's `RepoFiles`. Blob fetches are lazy: packs only read files matching
/// their target globs, so this touches a handful of blobs per branch.
pub struct ApiTree<'a> {
    host: &'a dyn RepoHost,
    full_name: &'a str,
    paths: Vec<PathBuf>,
    shas: HashMap<PathBuf, String>,
    cache: &'a BlobCache,
    // `read()` has no error channel (Option only); failures are recorded here so the
    // caller can refuse to report the repo as clean when a fetch failed.
    errors: Mutex<Vec<GithubError>>,
}

impl<'a> ApiTree<'a> {
    pub fn new(
        host: &'a dyn RepoHost,
        full_name: &'a str,
        tree: &Tree,
        cache: &'a BlobCache,
    ) -> Self {
        let paths: Vec<PathBuf> = tree.entries.iter().map(|e| e.path.clone()).collect();
        let shas = tree.entries.iter().map(|e| (e.path.clone(), e.sha.clone())).collect();
        ApiTree { host, full_name, paths, shas, cache, errors: Mutex::new(Vec::new()) }
    }

    /// Drain the fetch failures recorded during `read()`s. Non-empty means the scan
    /// of this tree is incomplete and must NOT be reported as clean.
    pub fn take_errors(&self) -> Vec<GithubError> {
        self.errors.lock().map(|mut v| std::mem::take(&mut *v)).unwrap_or_default()
    }
}

impl RepoFiles for ApiTree<'_> {
    fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
    fn read(&self, rel: &Path) -> Option<String> {
        let sha = self.shas.get(rel)?;
        if let Some(cached) = self.cache.get(sha) {
            return cached;
        }
        match self.host.get_blob(self.full_name, sha) {
            Ok(content) => {
                self.cache.put(sha, content.clone());
                content
            }
            Err(e) => {
                if let Ok(mut errs) = self.errors.lock() {
                    errs.push(e);
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Branch, RepoRef, TreeEntry};

    /// Serves blobs from an in-memory map, counting fetches per sha so tests can
    /// prove the cache dedupes.
    struct MapHost {
        blobs: HashMap<String, Option<String>>,
        fetches: Mutex<HashMap<String, usize>>,
        fail: bool,
    }
    impl MapHost {
        fn new(blobs: &[(&str, Option<&str>)]) -> Self {
            MapHost {
                blobs: blobs
                    .iter()
                    .map(|(sha, c)| (sha.to_string(), c.map(str::to_string)))
                    .collect(),
                fetches: Mutex::new(HashMap::new()),
                fail: false,
            }
        }
        fn fetch_count(&self, sha: &str) -> usize {
            *self.fetches.lock().unwrap().get(sha).unwrap_or(&0)
        }
    }
    impl RepoHost for MapHost {
        fn list_repos(&self, _: bool, _: &[String]) -> Result<Vec<RepoRef>, GithubError> {
            unimplemented!()
        }
        fn list_orgs(&self) -> Result<Vec<String>, GithubError> {
            unimplemented!()
        }
        fn list_branches(&self, _: &str) -> Result<Vec<Branch>, GithubError> {
            unimplemented!()
        }
        fn get_tree(&self, _: &str, _: &str) -> Result<Tree, GithubError> {
            unimplemented!()
        }
        fn get_blob(&self, _: &str, sha: &str) -> Result<Option<String>, GithubError> {
            *self.fetches.lock().unwrap().entry(sha.to_string()).or_insert(0) += 1;
            if self.fail {
                return Err(GithubError::Http("boom".into()));
            }
            Ok(self.blobs.get(sha).cloned().unwrap_or(None))
        }
    }

    fn tree(entries: &[(&str, &str)]) -> Tree {
        Tree {
            entries: entries
                .iter()
                .map(|(p, s)| TreeEntry { path: PathBuf::from(p), sha: s.to_string() })
                .collect(),
            truncated: false,
        }
    }

    #[test]
    fn paths_and_reads_come_from_tree_and_blobs() {
        let host = MapHost::new(&[("b1", Some("export default {};"))]);
        let cache = BlobCache::new();
        let t = tree(&[("postcss.config.mjs", "b1")]);
        let files = ApiTree::new(&host, "me/a", &t, &cache);
        assert_eq!(files.paths(), &[PathBuf::from("postcss.config.mjs")]);
        assert!(files.exists(Path::new("postcss.config.mjs")));
        assert!(!files.exists(Path::new("nope.js")));
        assert_eq!(
            files.read(Path::new("postcss.config.mjs")),
            Some("export default {};".to_string())
        );
        assert_eq!(files.read(Path::new("nope.js")), None);
        assert!(files.take_errors().is_empty());
    }

    #[test]
    fn identical_sha_across_trees_is_fetched_once() {
        let host = MapHost::new(&[("b1", Some("same"))]);
        let cache = BlobCache::new();
        let t1 = tree(&[("a.js", "b1")]);
        let t2 = tree(&[("b.js", "b1")]); // second branch, same content
        let f1 = ApiTree::new(&host, "me/a", &t1, &cache);
        let f2 = ApiTree::new(&host, "me/a", &t2, &cache);
        assert_eq!(f1.read(Path::new("a.js")), Some("same".to_string()));
        assert_eq!(f2.read(Path::new("b.js")), Some("same".to_string()));
        assert_eq!(host.fetch_count("b1"), 1);
    }

    #[test]
    fn binary_blob_reads_none_without_error() {
        let host = MapHost::new(&[("b1", None)]); // host says: valid blob, not UTF-8
        let cache = BlobCache::new();
        let t = tree(&[("logo.png", "b1")]);
        let files = ApiTree::new(&host, "me/a", &t, &cache);
        assert_eq!(files.read(Path::new("logo.png")), None);
        assert!(files.take_errors().is_empty());
    }

    #[test]
    fn fetch_failure_is_recorded_not_silent() {
        let mut host = MapHost::new(&[]);
        host.fail = true;
        let cache = BlobCache::new();
        let t = tree(&[("a.js", "b1")]);
        let files = ApiTree::new(&host, "me/a", &t, &cache);
        assert_eq!(files.read(Path::new("a.js")), None);
        let errors = files.take_errors();
        assert_eq!(errors.len(), 1);
        assert!(files.take_errors().is_empty(), "take_errors drains");
    }
}
