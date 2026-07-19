# Clone-Free GitHub API Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scan an entire GitHub account without cloning any repos, cloning on demand only the repos selected for fixing.

**Architecture:** The core scanner is already abstracted over the `RepoFiles` trait, so we add an `ApiTree` implementation backed by the GitHub Trees/Blobs API. `RepoHost` grows `list_branches`/`get_tree`/`get_blob`; `scan_pass` scans every branch tip via the API (default tip = fixable findings, other tips = `git_ref`-stamped manual findings, matching `scan_repo`/`deep_scan_repo` semantics); `fix_pass` clones only selected repos into a dir it owns and cleans up.

**Tech Stack:** Rust, ureq 2.x, serde, base64, rayon, httpmock (tests), git CLI (fix phase + test fakes).

**Spec:** `docs/superpowers/specs/2026-07-19-github-api-scan-design.md`

## Global Constraints

- The bearer token is only ever sent to the configured API authority (`GitHubHost.base_url`); every new endpoint must go through the guarded helper.
- Never log or return a raw token; redact via the existing `redact()` before any git output lands in an error string.
- Per-repo failures are non-fatal (captured in `ScannedRepo.error` / `RepoOutcome.error`); ONLY rate-limit errors (`GithubError::RateLimited`) abort the whole run.
- A failed blob fetch must NEVER read as "clean" — it becomes `ScannedRepo.error` ("scan incomplete").
- Public signatures of `scan_pass` / `fix_pass` are unchanged: `(opts, host, packs, token)` and `(scan, opts, packs, token, selected)`.
- The reflog check is intentionally absent from GitHub mode (spec Non-Goals).
- Workspace: run `cargo test` from the repo root for crates; the desktop app is its own workspace (`cd apps/desktop/src-tauri && cargo check`).
- Match existing code style: doc comments explain constraints, not mechanics; `thiserror` for errors; tests colocated in `#[cfg(test)] mod tests`.

---

### Task 1: HTTP layer — branches, trees, blobs on `RepoHost`

**Files:**
- Modify: `crates/wormward-github/Cargo.toml`
- Modify: `crates/wormward-github/src/lib.rs`
- Modify: `crates/wormward-github/src/pipeline.rs` (test doubles only — replace `FakeHost`/`FakeMultiHost` with `GitFakeHost` so the crate keeps compiling)

**Interfaces:**
- Produces (used by Tasks 2–4):

```rust
#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("github auth: {0}")] Auth(String),
    #[error("github http: {0}")] Http(String),
    #[error("github parse: {0}")] Parse(String),
    #[error("github rate limit: {0}")] RateLimited(String),   // NEW
}

#[derive(Debug, Clone, PartialEq)]
pub struct Branch { pub name: String, pub commit_sha: String }

#[derive(Debug, Clone, PartialEq)]
pub struct TreeEntry { pub path: std::path::PathBuf, pub sha: String }

#[derive(Debug, Clone, PartialEq)]
pub struct Tree { pub entries: Vec<TreeEntry>, pub truncated: bool }

pub trait RepoHost: Sync {                      // NEW: Sync bound (used from rayon)
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError>;
    fn list_branches(&self, full_name: &str) -> Result<Vec<Branch>, GithubError>;
    fn get_tree(&self, full_name: &str, commit_sha: &str) -> Result<Tree, GithubError>;
    /// Ok(None) for binary / non-UTF-8 blobs (mirrors GitTree::read).
    fn get_blob(&self, full_name: &str, blob_sha: &str) -> Result<Option<String>, GithubError>;
}
```

- [ ] **Step 1: Add the base64 dependency**

In `crates/wormward-github/Cargo.toml` under `[dependencies]` add:

```toml
base64 = "0.22"
```

(If the root `[workspace.dependencies]` already defines `base64`, use `base64 = { workspace = true }` instead.)

- [ ] **Step 2: Write the failing tests**

Append to the `tests` module in `crates/wormward-github/src/lib.rs`:

```rust
#[test]
fn lists_branches_across_pages() {
    let server = MockServer::start();
    let next = format!("<{}/repos/me/a/branches?page=2>; rel=\"next\"", server.base_url());
    server.mock(|when, then| {
        when.method(GET).path("/repos/me/a/branches").query_param_missing("page");
        then.status(200).header("Link", next.as_str()).json_body(serde_json::json!([
            {"name":"main","commit":{"sha":"aaa"}}
        ]));
    });
    server.mock(|when, then| {
        when.method(GET).path("/repos/me/a/branches").query_param("page", "2");
        then.status(200).json_body(serde_json::json!([
            {"name":"evil","commit":{"sha":"bbb"}}
        ]));
    });
    let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
    let branches = host.list_branches("me/a").unwrap();
    assert_eq!(
        branches,
        vec![
            Branch { name: "main".into(), commit_sha: "aaa".into() },
            Branch { name: "evil".into(), commit_sha: "bbb".into() },
        ]
    );
}

#[test]
fn gets_tree_blobs_only_and_truncated_flag() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/repos/me/a/git/trees/aaa").query_param("recursive", "1");
        then.status(200).json_body(serde_json::json!({
            "tree": [
                {"path":"postcss.config.mjs","type":"blob","sha":"b1"},
                {"path":"src","type":"tree","sha":"t1"},
                {"path":"src/x.js","type":"blob","sha":"b2"}
            ],
            "truncated": true
        }));
    });
    let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
    let tree = host.get_tree("me/a", "aaa").unwrap();
    assert!(tree.truncated);
    // Non-blob entries (type == "tree") are filtered out.
    assert_eq!(
        tree.entries,
        vec![
            TreeEntry { path: "postcss.config.mjs".into(), sha: "b1".into() },
            TreeEntry { path: "src/x.js".into(), sha: "b2".into() },
        ]
    );
}

#[test]
fn gets_blob_decoding_base64_and_none_for_binary() {
    use base64::Engine as _;
    let server = MockServer::start();
    // GitHub wraps base64 at 60 cols with newlines; include one to prove we strip it.
    let mut b64 = base64::engine::general_purpose::STANDARD.encode("hello world");
    b64.insert(4, '\n');
    server.mock(|when, then| {
        when.method(GET).path("/repos/me/a/git/blobs/b1");
        then.status(200).json_body(serde_json::json!({"content": b64, "encoding": "base64"}));
    });
    let bin = base64::engine::general_purpose::STANDARD.encode([0xffu8, 0xfe, 0x00]);
    server.mock(|when, then| {
        when.method(GET).path("/repos/me/a/git/blobs/b2");
        then.status(200).json_body(serde_json::json!({"content": bin, "encoding": "base64"}));
    });
    let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
    assert_eq!(host.get_blob("me/a", "b1").unwrap(), Some("hello world".to_string()));
    assert_eq!(host.get_blob("me/a", "b2").unwrap(), None); // non-UTF-8 → Ok(None)
}

#[test]
fn branches_refuse_foreign_next_link() {
    let api = MockServer::start();
    let attacker = MockServer::start();
    let evil_next = format!("<{}/repos/me/a/branches?page=2>; rel=\"next\"", attacker.base_url());
    api.mock(|when, then| {
        when.method(GET).path("/repos/me/a/branches");
        then.status(200).header("Link", evil_next.as_str())
            .json_body(serde_json::json!([{"name":"main","commit":{"sha":"aaa"}}]));
    });
    let attacker_mock = attacker.mock(|when, then| {
        when.method(GET).path("/repos/me/a/branches");
        then.status(200).json_body(serde_json::json!([]));
    });
    let host = GitHubHost { token: "secret".into(), base_url: api.base_url() };
    assert!(host.list_branches("me/a").is_err());
    attacker_mock.assert_hits(0);
}

#[test]
fn rate_limit_is_a_distinct_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/repos/me/a/branches");
        then.status(403).header("x-ratelimit-remaining", "0").body("{}");
    });
    let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
    assert!(matches!(host.list_branches("me/a"), Err(GithubError::RateLimited(_))));
}

#[test]
fn plain_403_is_not_rate_limited() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/repos/me/a/branches");
        then.status(403).header("x-ratelimit-remaining", "42").body("{}");
    });
    let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
    assert!(matches!(host.list_branches("me/a"), Err(GithubError::Http(_))));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p wormward-github lists_branches 2>&1 | tail -20`
Expected: COMPILE ERROR — `list_branches`, `Branch`, etc. not defined.

- [ ] **Step 4: Implement in `crates/wormward-github/src/lib.rs`**

Add `RateLimited` to `GithubError`:

```rust
    #[error("github rate limit: {0}")]
    RateLimited(String),
```

Add the public types after `RepoRef`:

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct Branch {
    pub name: String,
    pub commit_sha: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TreeEntry {
    pub path: std::path::PathBuf,
    pub sha: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
    pub truncated: bool,
}
```

Replace the `RepoHost` trait:

```rust
/// A source of repos + their trees/blobs. `Sync` because the scan fans out over
/// repos with rayon while sharing one host.
pub trait RepoHost: Sync {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError>;
    fn list_branches(&self, full_name: &str) -> Result<Vec<Branch>, GithubError>;
    fn get_tree(&self, full_name: &str, commit_sha: &str) -> Result<Tree, GithubError>;
    /// `Ok(None)` for binary / non-UTF-8 blobs (mirrors `GitTree::read`).
    fn get_blob(&self, full_name: &str, blob_sha: &str) -> Result<Option<String>, GithubError>;
}
```

Add private wire-format structs and the guarded GET helper to `impl GitHubHost` (this factors the guard/header logic out of `list_repos`):

```rust
#[derive(serde::Deserialize)]
struct ApiBranch {
    name: String,
    commit: ApiCommit,
}
#[derive(serde::Deserialize)]
struct ApiCommit {
    sha: String,
}
#[derive(serde::Deserialize)]
struct ApiTreeResp {
    tree: Vec<ApiTreeEntry>,
    #[serde(default)]
    truncated: bool,
}
#[derive(serde::Deserialize)]
struct ApiTreeEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}
#[derive(serde::Deserialize)]
struct ApiBlob {
    content: String,
}

impl GitHubHost {
    pub fn new(token: String) -> Self {
        GitHubHost { token, base_url: "https://api.github.com".into() }
    }

    /// GET `url` with auth headers. Only ever sends the bearer token to the configured
    /// API authority — a malicious or buggy URL pointing elsewhere must not receive our
    /// credentials. Distinguishes rate limiting (fatal for the run) from other HTTP
    /// failures (per-repo).
    fn get(&self, url: &str) -> Result<(Option<String>, String), GithubError> {
        let base_authority = url_authority(&self.base_url)
            .ok_or_else(|| GithubError::Http(format!("invalid base_url: {}", self.base_url)))?;
        if url_authority(url) != Some(base_authority) {
            return Err(GithubError::Http(format!(
                "refusing to send token to unexpected host: {url}"
            )));
        }
        match ureq::get(url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("User-Agent", "wormward")
            .set("Accept", "application/vnd.github+json")
            .call()
        {
            Ok(resp) => {
                let link = resp.header("Link").map(|s| s.to_string());
                let body = resp.into_string().map_err(|e| GithubError::Http(e.to_string()))?;
                Ok((link, body))
            }
            // 429, or 403 with the quota actually exhausted, is a rate limit — fatal for
            // the run. A plain 403 (permissions) stays a per-repo Http error.
            Err(ureq::Error::Status(code, resp))
                if code == 429
                    || (code == 403 && resp.header("x-ratelimit-remaining") == Some("0")) =>
            {
                Err(GithubError::RateLimited(format!("HTTP {code} from {url}")))
            }
            Err(e) => Err(GithubError::Http(e.to_string())),
        }
    }

    /// Follow Link: rel="next" pagination, bounded by MAX_PAGES.
    fn get_paginated<T: serde::de::DeserializeOwned>(
        &self,
        first_url: String,
    ) -> Result<Vec<T>, GithubError> {
        let mut url = first_url;
        let mut all = Vec::new();
        for _ in 0..MAX_PAGES {
            let (link, body) = self.get(&url)?;
            let page: Vec<T> =
                serde_json::from_str(&body).map_err(|e| GithubError::Parse(e.to_string()))?;
            all.extend(page);
            match link.as_deref().and_then(next_link) {
                Some(next) => url = next,
                None => break,
            }
        }
        Ok(all)
    }
}
```

Replace the `impl RepoHost for GitHubHost` block (the old inline `list_repos` body moves onto the helpers; behavior is identical):

```rust
impl RepoHost for GitHubHost {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError> {
        let url = format!("{}/user/repos?affiliation=owner&per_page=100", self.base_url);
        let mut all: Vec<RepoRef> = self.get_paginated(url)?;
        if !include_forks {
            all.retain(|r| !r.fork);
        }
        Ok(all)
    }

    fn list_branches(&self, full_name: &str) -> Result<Vec<Branch>, GithubError> {
        let url = format!("{}/repos/{full_name}/branches?per_page=100", self.base_url);
        let branches: Vec<ApiBranch> = self.get_paginated(url)?;
        Ok(branches
            .into_iter()
            .map(|b| Branch { name: b.name, commit_sha: b.commit.sha })
            .collect())
    }

    fn get_tree(&self, full_name: &str, commit_sha: &str) -> Result<Tree, GithubError> {
        let url = format!("{}/repos/{full_name}/git/trees/{commit_sha}?recursive=1", self.base_url);
        let (_, body) = self.get(&url)?;
        let resp: ApiTreeResp =
            serde_json::from_str(&body).map_err(|e| GithubError::Parse(e.to_string()))?;
        let entries = resp
            .tree
            .into_iter()
            .filter(|e| e.kind == "blob")
            .map(|e| TreeEntry { path: std::path::PathBuf::from(e.path), sha: e.sha })
            .collect();
        Ok(Tree { entries, truncated: resp.truncated })
    }

    fn get_blob(&self, full_name: &str, blob_sha: &str) -> Result<Option<String>, GithubError> {
        use base64::Engine as _;
        let url = format!("{}/repos/{full_name}/git/blobs/{blob_sha}", self.base_url);
        let (_, body) = self.get(&url)?;
        let blob: ApiBlob =
            serde_json::from_str(&body).map_err(|e| GithubError::Parse(e.to_string()))?;
        // GitHub newline-wraps the base64 payload; strip all whitespace before decoding.
        let compact: String = blob.content.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|e| GithubError::Parse(format!("blob base64: {e}")))?;
        Ok(String::from_utf8(bytes).ok()) // None for binary blobs, like GitTree::read
    }
}
```

Note: the old `lists_repos_across_pages_and_filters_forks` and `refuses_to_follow_next_link_to_foreign_host` tests must still pass unchanged — the refactor preserves `list_repos` behavior, including the guard on the *first* request.

- [ ] **Step 5: Replace the pipeline test doubles so the crate compiles**

In `crates/wormward-github/src/pipeline.rs` tests, delete `FakeHost` and `FakeMultiHost` and add one fake that serves trees/blobs straight from the local bare fixtures via git (so pipeline tests exercise the API-scan path end-to-end without HTTP):

```rust
    /// Serves list/branches/tree/blob straight from local bare fixture repos via git,
    /// so the pipeline is exercised end-to-end without any HTTP. `clone_url` doubles
    /// as the filesystem path of the bare repo.
    struct GitFakeHost {
        repos: Vec<RepoRef>,
    }

    impl GitFakeHost {
        fn bare_path(&self, full_name: &str) -> PathBuf {
            PathBuf::from(
                &self.repos.iter().find(|r| r.full_name == full_name).unwrap().clone_url,
            )
        }
        fn git(&self, full_name: &str, args: &[&str]) -> Result<Vec<u8>, GithubError> {
            let out = Command::new("git")
                .arg("-C")
                .arg(self.bare_path(full_name))
                .args(args)
                .output()
                .map_err(|e| GithubError::Http(e.to_string()))?;
            if !out.status.success() {
                return Err(GithubError::Http(
                    String::from_utf8_lossy(&out.stderr).into_owned(),
                ));
            }
            Ok(out.stdout)
        }
    }

    impl RepoHost for GitFakeHost {
        fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError> {
            Ok(self.repos.iter().filter(|r| include_forks || !r.fork).cloned().collect())
        }
        fn list_branches(&self, full_name: &str) -> Result<Vec<Branch>, GithubError> {
            let out = self.git(
                full_name,
                &["for-each-ref", "--format=%(objectname) %(refname:short)", "refs/heads"],
            )?;
            Ok(String::from_utf8_lossy(&out)
                .lines()
                .filter_map(|l| {
                    let (sha, name) = l.split_once(' ')?;
                    Some(Branch { name: name.into(), commit_sha: sha.into() })
                })
                .collect())
        }
        fn get_tree(&self, full_name: &str, commit_sha: &str) -> Result<Tree, GithubError> {
            let out = self.git(full_name, &["ls-tree", "-r", "-z", commit_sha])?;
            let entries = String::from_utf8_lossy(&out)
                .split('\0')
                .filter(|s| !s.is_empty())
                .filter_map(|line| {
                    // "<mode> <type> <sha>\t<path>"
                    let (meta, path) = line.split_once('\t')?;
                    let mut parts = meta.split_whitespace();
                    let _mode = parts.next()?;
                    let kind = parts.next()?;
                    let sha = parts.next()?;
                    (kind == "blob")
                        .then(|| TreeEntry { path: PathBuf::from(path), sha: sha.into() })
                })
                .collect();
            Ok(Tree { entries, truncated: false })
        }
        fn get_blob(&self, full_name: &str, blob_sha: &str) -> Result<Option<String>, GithubError> {
            let out = self.git(full_name, &["cat-file", "blob", blob_sha])?;
            Ok(String::from_utf8(out).ok())
        }
    }
```

Update the tests that used the old fakes (`FakeHost { repo: X }` → `GitFakeHost { repos: vec![X] }`, `FakeMultiHost { repos }` → `GitFakeHost { repos }`) and add `use crate::{Branch, Tree, TreeEntry};` to the test module imports. Do NOT change test assertions in this task — the pipeline itself is unchanged until Task 3; `GitFakeHost`'s extra methods are simply unused yet.

- [ ] **Step 6: Run the full crate test suite**

Run: `cargo test -p wormward-github 2>&1 | tail -15`
Expected: PASS (all new + all pre-existing tests).

- [ ] **Step 7: Commit**

```bash
git add crates/wormward-github/Cargo.toml crates/wormward-github/src/lib.rs crates/wormward-github/src/pipeline.rs
git commit -m "Add branches/trees/blobs endpoints and rate-limit error to RepoHost"
```

---

### Task 2: `ApiTree` — `RepoFiles` over the API with a shared blob cache

**Files:**
- Create: `crates/wormward-github/src/api_tree.rs`
- Modify: `crates/wormward-github/src/lib.rs` (add `pub mod api_tree;`)

**Interfaces:**
- Consumes: `RepoHost::get_blob`, `Tree`/`TreeEntry` (Task 1); `wormward_core::RepoFiles`.
- Produces (used by Task 3):

```rust
pub struct BlobCache { /* Mutex<HashMap<String /*sha*/, Option<String>>> */ }
impl BlobCache { pub fn new() -> Self; }
impl Default for BlobCache { fn default() -> Self; }

pub struct ApiTree<'a> { /* host, full_name, paths, sha map, cache, fetch errors */ }
impl<'a> ApiTree<'a> {
    pub fn new(host: &'a dyn RepoHost, full_name: &'a str, tree: &Tree, cache: &'a BlobCache) -> Self;
    /// Fetch failures recorded during read()s; non-empty ⇒ the scan is incomplete.
    pub fn take_errors(&self) -> Vec<GithubError>;
}
impl wormward_core::RepoFiles for ApiTree<'_> { /* paths / read / default exists */ }
```

- [ ] **Step 1: Write the failing tests**

Create `crates/wormward-github/src/api_tree.rs` with the tests first (module skeleton so it compiles as a target):

```rust
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use wormward_core::RepoFiles;

use crate::{GithubError, RepoHost, Tree};

// (implementation added in Step 3)

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
        fn list_repos(&self, _: bool) -> Result<Vec<RepoRef>, GithubError> {
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
```

Add to `crates/wormward-github/src/lib.rs` after `pub mod pipeline;`:

```rust
pub mod api_tree;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p wormward-github api_tree 2>&1 | tail -10`
Expected: COMPILE ERROR — `BlobCache`, `ApiTree` not defined.

- [ ] **Step 3: Implement**

Above the tests in `api_tree.rs`:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p wormward-github api_tree 2>&1 | tail -10`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-github/src/api_tree.rs crates/wormward-github/src/lib.rs
git commit -m "Add ApiTree: RepoFiles over the GitHub API with shared blob cache"
```

---

### Task 3: Pipeline switch — clone-free scan, clone-on-demand fix

**Files:**
- Modify: `crates/wormward-github/src/pipeline.rs`

**Interfaces:**
- Consumes: `ApiTree`, `BlobCache` (Task 2); `Branch`/`Tree`/`GithubError::RateLimited` (Task 1); `wormward_core::{scan_files, scan_repo, deep_scan_repo, plan_remediation, apply, commit_paths, force_push_with_lease_to, now_secs}`.
- Produces (relied on by Tasks 4–5 and existing call sites):

```rust
pub struct ScannedRepo {           // `dest` REMOVED
    pub repo: RepoRef,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
}
pub struct ScanPass { /* repos only; TempDir field REMOVED */ }
// Unchanged: ScanPass::{repos, infected_full_names, fixable_full_names},
// ScannedRepo::is_infected, scan_pass(...), fix_pass(...), run(...), GithubRunOpts,
// RepoOutcome.
```

- [ ] **Step 1: Update imports and structs**

In `crates/wormward-github/src/pipeline.rs`:

```rust
use crate::api_tree::{ApiTree, BlobCache};
use crate::{GithubError, RepoHost, RepoRef};
```

and extend the wormward_core import with `scan_files`:

```rust
use wormward_core::{
    apply, commit_paths, deep_scan_repo, force_push_with_lease_to, now_secs, plan_remediation,
    scan_files, scan_repo, Finding, Pack, RemediationAction,
};
```

Replace `ScannedRepo` and `ScanPass`:

```rust
/// A repo scanned via the API in phase one. No clone exists; the fix phase clones
/// on demand for the repos actually selected.
pub struct ScannedRepo {
    pub repo: RepoRef,
    pub findings: Vec<Finding>,
    /// Scan failure, if any. An errored repo carries no findings and must never be
    /// treated as clean.
    pub error: Option<String>,
}
```

`ScanPass` keeps only `repos: Vec<ScannedRepo>` (delete `_tmp` and its doc comment; the accessor methods are unchanged). Update `ScanPass`'s `repos()` doc comment to drop the "cloned" wording.

- [ ] **Step 2: Extract `clone_repo` from `clone_and_scan` and add the API scan**

Replace `clone_and_scan` with:

```rust
/// Clone all branches of `repo` into `dest`, authenticated via the token so private
/// repos work (and the resulting origin can be pushed to). GIT_TERMINAL_PROMPT=0 so
/// an auth failure fails fast instead of hanging a rayon worker. Errors are redacted.
fn clone_repo(repo: &RepoRef, dest: &Path, token: &str) -> Result<(), String> {
    let out = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["clone", "--no-single-branch", "-q"])
        .arg(authed_url(&repo.clone_url, token))
        .arg(dest)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(redact(
            format!("clone: {}", String::from_utf8_lossy(&o.stderr).trim()),
            token,
        )),
        Err(e) => Err(redact(format!("clone: {e}"), token)),
    }
}

/// Full local clone + scan for repos whose tree the API refuses to enumerate
/// (`truncated`, ~100k+ entries) — coverage must never silently degrade. The temp
/// clone is deleted on return; a later fix re-clones like any other repo.
fn fallback_clone_scan(repo: &RepoRef, packs: &[Pack], token: &str) -> ScannedRepo {
    let mut out = ScannedRepo { repo: repo.clone(), findings: Vec::new(), error: None };
    let tmp = match tempfile::TempDir::new() {
        Ok(t) => t,
        Err(e) => {
            out.error = Some(format!("tempdir: {e}"));
            return out;
        }
    };
    let dest = tmp.path().join(sanitize_full_name(&repo.full_name));
    if let Err(e) = clone_repo(repo, &dest, token) {
        out.error = Some(e);
        return out;
    }
    let mut findings = scan_repo(&dest, packs);
    findings.extend(deep_scan_repo(&dest, packs));
    // Re-label onto the virtual repo path: the temp clone path would dangle.
    let label = PathBuf::from(&repo.full_name);
    for f in &mut findings {
        f.repo = label.clone();
    }
    out.findings = findings;
    out
}

/// Scan one repo entirely through the API: default-branch tip first (findings stay
/// remediable, like a working tree), then every other branch tip deduped by commit
/// sha with `git_ref` stamped (routed to manual by plan_remediation, like deep scan).
/// Mirrors scan_repo + deep_scan_repo minus the reflog check (local-only, and
/// meaningless on a fresh clone anyway). Err ONLY on rate limiting, which aborts the
/// whole run; anything else is a per-repo error.
fn api_scan_repo(
    repo: &RepoRef,
    host: &dyn RepoHost,
    packs: &[Pack],
    cache: &BlobCache,
    token: &str,
) -> Result<ScannedRepo, GithubError> {
    let mut out = ScannedRepo { repo: repo.clone(), findings: Vec::new(), error: None };

    let branches = match host.list_branches(&repo.full_name) {
        Ok(b) => b,
        Err(e @ GithubError::RateLimited(_)) => return Err(e),
        Err(e) => {
            out.error = Some(e.to_string());
            return Ok(out);
        }
    };
    let Some(default) = branches.iter().find(|b| b.name == repo.default_branch) else {
        return Ok(out); // empty repo / unborn default branch: nothing to scan
    };

    let mut tips: Vec<(String, Option<String>)> = vec![(default.commit_sha.clone(), None)];
    let mut seen: HashSet<String> = [default.commit_sha.clone()].into_iter().collect();
    for b in &branches {
        if seen.insert(b.commit_sha.clone()) {
            tips.push((b.commit_sha.clone(), Some(b.name.clone())));
        }
    }

    let label = PathBuf::from(&repo.full_name);
    for (sha, git_ref) in tips {
        let tree = match host.get_tree(&repo.full_name, &sha) {
            Ok(t) => t,
            Err(e @ GithubError::RateLimited(_)) => return Err(e),
            Err(e) => {
                out.error = Some(e.to_string());
                return Ok(out);
            }
        };
        if tree.truncated {
            return Ok(fallback_clone_scan(repo, packs, token));
        }
        let files = ApiTree::new(host, &repo.full_name, &tree, cache);
        let mut findings = scan_files(&label, &files, packs);
        if let Some(name) = &git_ref {
            for f in &mut findings {
                f.git_ref = Some(name.clone());
            }
        }
        let mut errors = files.take_errors();
        if let Some(pos) = errors.iter().position(|e| matches!(e, GithubError::RateLimited(_))) {
            return Err(errors.swap_remove(pos));
        }
        if let Some(e) = errors.first() {
            // A failed blob fetch must not read as "clean".
            out.error = Some(format!("scan incomplete: {e}"));
            out.findings.clear();
            return Ok(out);
        }
        out.findings.extend(findings);
    }
    Ok(out)
}
```

- [ ] **Step 3: Rewrite `scan_pass`**

```rust
/// Phase one: enumerate the account's repos, then scan each entirely via the API
/// (bounded-parallel via rayon) — nothing is cloned. Per-repo failures are captured,
/// never fatal; only rate limiting aborts the run (finishing the sweep would just
/// burn the remaining quota on guaranteed failures).
pub fn scan_pass(
    opts: &GithubRunOpts,
    host: &dyn RepoHost,
    packs: &[Pack],
    token: &str,
) -> Result<ScanPass, GithubError> {
    let repos = host.list_repos(opts.include_forks)?;
    let cache = BlobCache::new();
    let results: Vec<Result<ScannedRepo, GithubError>> = repos
        .par_iter()
        .map(|repo| api_scan_repo(repo, host, packs, &cache, token))
        .collect();
    let mut scanned = Vec::with_capacity(results.len());
    for r in results {
        scanned.push(r?);
    }
    Ok(ScanPass { repos: scanned })
}
```

(`opts.clone_dir` is no longer read here — it now belongs to the fix phase only.)

- [ ] **Step 4: Rewrite `fix_scanned` and `fix_pass`**

```rust
/// Remediate one scanned repo. Dry runs (`!opts.yes`) plan from the API-scan
/// findings and touch nothing — not even a clone. A real fix clones the repo fresh,
/// re-scans it locally (the repo may have changed since the API scan, and local
/// findings make remediation paths line up with the working tree), then plans,
/// applies, commits and optionally pushes exactly as before.
fn fix_scanned(
    sr: &ScannedRepo,
    opts: &GithubRunOpts,
    packs: &[Pack],
    token: &str,
    do_fix: bool,
    base: Option<&Path>,
) -> RepoOutcome {
    let mut outcome = RepoOutcome {
        repo: sr.repo.clone(),
        findings: sr.findings.clone(),
        actions: Vec::new(),
        pushed: Vec::new(),
        error: sr.error.clone(),
    };

    if !do_fix || sr.error.is_some() || sr.findings.is_empty() {
        return outcome;
    }

    // Branch-only infections have no working-tree action; nothing to do here.
    let preview = plan_remediation(&sr.findings, packs);
    if preview.actions.is_empty() {
        return outcome;
    }

    // Dry run: report the actions that WOULD be applied. No clone, no writes.
    if !opts.yes {
        outcome.actions = preview.actions.iter().map(describe_action).collect();
        return outcome;
    }

    let Some(base) = base else {
        outcome.error = Some("no clone directory available".into());
        return outcome;
    };
    let dest = base.join(sanitize_full_name(&sr.repo.full_name));
    if let Err(e) = clone_repo(&sr.repo, &dest, token) {
        outcome.error = Some(e);
        return outcome;
    }

    let local = scan_repo(&dest, packs);
    let plan = plan_remediation(&local, packs);
    if plan.actions.is_empty() {
        return outcome; // repo changed since the scan; nothing fixable remains
    }

    // Apply to the working tree (backups land in <repo>/.wormward-backup/<ts>/).
    let res = apply(&dest, &plan.actions, true);
    outcome.actions = res.applied.iter().map(describe_action).collect();
    if res.applied.is_empty() {
        return outcome;
    }

    let paths: Vec<PathBuf> = res.applied.iter().map(|a| a.target().to_path_buf()).collect();
    let campaigns = {
        let mut c: Vec<&str> = local.iter().map(|f| f.campaign.as_str()).collect();
        c.sort();
        c.dedup();
        c.join(", ")
    };
    // Stage the applied paths first, then only commit if something is actually staged.
    // A remediation that leaves a file byte-identical stages nothing, and `git commit`
    // would fail with "nothing to commit" — treat that as a no-op success, not an error.
    for p in &paths {
        let s = p.to_string_lossy();
        let _ = git(&dest, &["add", "-A", "--", s.as_ref()]);
    }
    if has_staged_changes(&dest) {
        if let Err(e) = commit_paths(&dest, &format!("wormward: remediate {campaigns}"), &paths) {
            outcome.error = Some(redact(format!("commit: {e}"), token));
            return outcome;
        }
    } else {
        // Nothing changed on disk; skip the commit (and the push below has nothing to do).
        return outcome;
    }

    // Force-push the cleaned default branch, backing up the pre-clean tip first.
    if opts.push {
        let ts = now_secs();
        let backup = format!(
            "refs/remotes/origin/{b}:refs/heads/wormward-backup/{b}-{ts}",
            b = sr.repo.default_branch
        );
        if let Err(e) = git(&dest, &["push", "origin", "--", &backup]) {
            outcome.error = Some(redact(format!("backup push: {e}"), token));
            return outcome;
        }
        // Push EXACTLY the cleaned default branch via an explicit refspec, never a bare
        // `--force-with-lease` (which under push.default=matching would push every branch).
        let refspec = format!("HEAD:refs/heads/{}", sr.repo.default_branch);
        match force_push_with_lease_to(&dest, "origin", &refspec) {
            Ok(()) => outcome.pushed.push(sr.repo.default_branch.clone()),
            Err(e) => outcome.error = Some(redact(format!("force-push: {e}"), token)),
        }
    }

    outcome
}

/// Phase two: remediate the scanned repos, cloning ON DEMAND only the repos being
/// fixed. When `selected` is `Some`, only repos whose `full_name` is in the set are
/// fixed; every other repo is reported unchanged. The temp clone dir (when no
/// explicit `clone_dir` is given) is dropped at the end of this function, deleting
/// the credentialed clones. Per-repo failures are captured; the run never aborts.
pub fn fix_pass(
    scan: &ScanPass,
    opts: &GithubRunOpts,
    packs: &[Pack],
    token: &str,
    selected: Option<&HashSet<String>>,
) -> Vec<RepoOutcome> {
    // A clone base is only needed when something will actually be written.
    let mut _tmp = None;
    let base: Option<PathBuf> = if opts.fix && opts.yes {
        match &opts.clone_dir {
            Some(d) => std::fs::create_dir_all(d).ok().map(|_| d.clone()),
            None => tempfile::TempDir::new().ok().map(|t| {
                let p = t.path().to_path_buf();
                _tmp = Some(t);
                p
            }),
        }
    } else {
        None
    };

    scan.repos
        .par_iter()
        .map(|sr| {
            let chosen = selected.is_none_or(|s| s.contains(&sr.repo.full_name));
            fix_scanned(sr, opts, packs, token, opts.fix && chosen, base.as_deref())
        })
        .collect()
}
```

NOTE for the `# (see current ...)` marker above: that block is the existing code at pipeline.rs lines 275–319 (from `let paths: Vec<PathBuf> = ...` through the force-push match). Copy it as-is with two mechanical substitutions: the campaigns iterator reads `local.iter()` instead of `sr.findings.iter()`, and every `dest` becomes `&dest` where a `&Path` is expected. `run()` needs no changes.

- [ ] **Step 5: Update the pipeline tests**

All fixture builders (`make_infected_origin*`, `make_branch_only_infected_origin`) stay as-is. Update tests:

1. `fixes_infected_repo_end_to_end` — swap host to `GitFakeHost { repos: vec![...] }`. Assertions unchanged. Add at the end (fix happened via on-demand clone into `clone_dir`):

```rust
        // The fix cloned on demand into clone_dir.
        assert!(tmp.path().join("work").join("me__proj").exists());
```

2. `dry_run_reports_actions_without_writing` — swap host. Replace the final two assertions (the old ones read the scan-phase clone, which no longer exists) with:

```rust
        // A dry run touches nothing: no clone is created and the origin keeps the payload.
        assert!(!clone_dir.exists(), "dry run must not clone anything");
        let show = Command::new("git")
            .arg("-C")
            .arg(&bare)
            .args(["show", "main:postcss.config.mjs"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&show.stdout).contains("rmcej%otb%"));
```

3. `fix_and_push_force_pushes_and_backs_up` — swap host. Assertions unchanged.

4. `branch_only_infection_is_reported_but_not_a_fix_candidate` — swap host (one `GitFakeHost` with both repos). Assertions unchanged. IMPORTANT semantic check this test now exercises: the API scan stamps `git_ref` with the branch name for non-default tips, so `fixable_full_names` still excludes `me/branchonly`.

5. `fix_pass_honors_selected_set` — swap host. Replace the final on-disk assertion (deselected clone no longer exists) with:

```rust
        // The deselected repo was never cloned, and its origin is still infected.
        assert!(!clone_dir.join("me__b").exists(), "deselected repo must not be cloned");
        let show = Command::new("git")
            .arg("-C")
            .arg(&bare_b)
            .args(["show", "main:postcss.config.mjs"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&show.stdout).contains("rmcej%otb%"));
```

   Note: this test runs `fix_pass` with `push: false` and an explicit `clone_dir`, so the selected repo's remediation lands in `clone_dir/me__a` — same observable behavior as before.

6. NEW test — the headline invariant:

```rust
    #[test]
    fn clean_repos_never_touch_disk() {
        // A clean account scans and "fixes" without a single clone directory appearing.
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("clean-src");
        std::fs::create_dir_all(&src).unwrap();
        git_ok(&src, &["init", "-q", "-b", "main"]);
        std::fs::write(src.join("postcss.config.mjs"), "export default {};\n").unwrap();
        git_ok(&src, &["add", "."]);
        git_ok(&src, &["commit", "-q", "--no-verify", "-m", "clean"]);
        let bare = tmp.path().join("clean.git");
        Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&bare)
            .status()
            .unwrap();
        git_ok(&src, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git_ok(&src, &["push", "-q", "origin", "main"]);

        let clone_dir = tmp.path().join("work");
        let host = GitFakeHost {
            repos: vec![RepoRef {
                full_name: "me/clean".into(),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        };
        let opts = GithubRunOpts {
            clone_dir: Some(clone_dir.clone()),
            include_forks: false,
            fix: true,
            push: false,
            yes: true,
        };
        let outcomes = run(&opts, &host, &builtin_packs(), "").unwrap();
        assert!(outcomes[0].findings.is_empty());
        assert!(outcomes[0].error.is_none());
        assert!(
            !clone_dir.join("me__clean").exists(),
            "clean repo must never be cloned"
        );
    }
```

- [ ] **Step 6: Run the crate tests**

Run: `cargo test -p wormward-github 2>&1 | tail -15`
Expected: PASS. If `branch_only_infection...` fails, check the `git_ref` stamping in `api_scan_repo` (non-default tips must carry the branch name).

- [ ] **Step 7: Verify dependent crates still compile**

Run: `cargo build --workspace 2>&1 | tail -5`
Expected: success — `scan_pass`/`fix_pass` signatures are unchanged, and neither the CLI nor (root-workspace) crates reference `ScannedRepo.dest`.

- [ ] **Step 8: Commit**

```bash
git add crates/wormward-github/src/pipeline.rs
git commit -m "Scan GitHub repos via the API without cloning; clone on demand for fixes"
```

---

### Task 4: Edge cases — truncated fallback, fetch failure, rate-limit abort

**Files:**
- Modify: `crates/wormward-github/src/pipeline.rs` (tests only, unless a test flushes out a fix)

**Interfaces:**
- Consumes: everything from Task 3. No new public API.

- [ ] **Step 1: Write the failing tests**

Add to the pipeline tests module:

```rust
    /// Wraps GitFakeHost but reports every tree as truncated, forcing the
    /// clone-and-scan fallback.
    struct TruncatedHost(GitFakeHost);
    impl RepoHost for TruncatedHost {
        fn list_repos(&self, f: bool) -> Result<Vec<RepoRef>, GithubError> {
            self.0.list_repos(f)
        }
        fn list_branches(&self, n: &str) -> Result<Vec<Branch>, GithubError> {
            self.0.list_branches(n)
        }
        fn get_tree(&self, n: &str, s: &str) -> Result<Tree, GithubError> {
            self.0.get_tree(n, s).map(|t| Tree { truncated: true, ..t })
        }
        fn get_blob(&self, n: &str, s: &str) -> Result<Option<String>, GithubError> {
            self.0.get_blob(n, s)
        }
    }

    /// Wraps GitFakeHost but fails every blob fetch.
    struct BrokenBlobHost(GitFakeHost);
    impl RepoHost for BrokenBlobHost {
        fn list_repos(&self, f: bool) -> Result<Vec<RepoRef>, GithubError> {
            self.0.list_repos(f)
        }
        fn list_branches(&self, n: &str) -> Result<Vec<Branch>, GithubError> {
            self.0.list_branches(n)
        }
        fn get_tree(&self, n: &str, s: &str) -> Result<Tree, GithubError> {
            self.0.get_tree(n, s)
        }
        fn get_blob(&self, _: &str, _: &str) -> Result<Option<String>, GithubError> {
            Err(GithubError::Http("connection reset".into()))
        }
    }

    /// Rate-limited from the very first per-repo call.
    struct RateLimitedHost(GitFakeHost);
    impl RepoHost for RateLimitedHost {
        fn list_repos(&self, f: bool) -> Result<Vec<RepoRef>, GithubError> {
            self.0.list_repos(f)
        }
        fn list_branches(&self, _: &str) -> Result<Vec<Branch>, GithubError> {
            Err(GithubError::RateLimited("HTTP 429".into()))
        }
        fn get_tree(&self, n: &str, s: &str) -> Result<Tree, GithubError> {
            self.0.get_tree(n, s)
        }
        fn get_blob(&self, n: &str, s: &str) -> Result<Option<String>, GithubError> {
            self.0.get_blob(n, s)
        }
    }

    fn one_repo_host(tmp: &TempDir, name: &str) -> GitFakeHost {
        let bare = make_infected_origin_named(tmp, name);
        GitFakeHost {
            repos: vec![RepoRef {
                full_name: format!("me/{name}"),
                clone_url: bare.to_string_lossy().to_string(),
                default_branch: "main".into(),
                fork: false,
            }],
        }
    }

    fn scan_only_opts() -> GithubRunOpts {
        GithubRunOpts {
            clone_dir: None,
            include_forks: false,
            fix: false,
            push: false,
            yes: false,
        }
    }

    #[test]
    fn truncated_tree_falls_back_to_clone_scan() {
        let tmp = TempDir::new().unwrap();
        let host = TruncatedHost(one_repo_host(&tmp, "big"));
        let scan = scan_pass(&scan_only_opts(), &host, &builtin_packs(), "").unwrap();
        let sr = &scan.repos()[0];
        assert!(sr.error.is_none(), "fallback should succeed: {:?}", sr.error);
        assert!(sr.is_infected(), "fallback clone-scan must still find the payload");
        // Findings are labeled with the virtual repo name, not a dangling temp path.
        assert_eq!(sr.findings[0].repo, PathBuf::from("me/big"));
    }

    #[test]
    fn blob_fetch_failure_marks_scan_incomplete_not_clean() {
        let tmp = TempDir::new().unwrap();
        let host = BrokenBlobHost(one_repo_host(&tmp, "flaky"));
        let scan = scan_pass(&scan_only_opts(), &host, &builtin_packs(), "").unwrap();
        let sr = &scan.repos()[0];
        assert!(sr.error.as_deref().unwrap_or("").contains("scan incomplete"));
        assert!(!sr.is_infected(), "errored repo is not 'infected'");
        assert!(sr.findings.is_empty(), "incomplete findings must not be reported");
    }

    #[test]
    fn rate_limit_aborts_the_scan() {
        let tmp = TempDir::new().unwrap();
        let host = RateLimitedHost(one_repo_host(&tmp, "limited"));
        let result = scan_pass(&scan_only_opts(), &host, &builtin_packs(), "");
        assert!(matches!(result, Err(GithubError::RateLimited(_))), "got {result:?}");
    }
```

- [ ] **Step 2: Run the new tests**

Run: `cargo test -p wormward-github truncated_tree blob_fetch rate_limit_aborts 2>&1 | tail -10`
Expected: PASS if Task 3 was implemented exactly as written; otherwise fix `api_scan_repo` (not the tests) until they pass. Note `Tree { truncated: true, ..t }` requires `Tree` to be a plain struct with public fields — it is (Task 1).

- [ ] **Step 3: Run the whole crate**

Run: `cargo test -p wormward-github 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/wormward-github/src/pipeline.rs
git commit -m "Cover truncated-tree fallback, incomplete-scan, and rate-limit abort"
```

---

### Task 5: Call sites — CLI/GUI doc updates and full verification

**Files:**
- Modify: `crates/wormward-cli/src/main.rs` (comments/help text only)
- Modify: `apps/desktop/src-tauri/src/lib.rs` (comments only)

**Interfaces:**
- Consumes: unchanged `scan_pass`/`fix_pass`. No behavior changes in this task.

- [ ] **Step 1: Update stale CLI wording**

In `crates/wormward-cli/src/main.rs` (github subcommand, ~line 548): change the phase-1 comment to

```rust
            // Phase 1: enumerate → API-scan every branch tip (no clones), to learn
            // which repos are infected.
```

and the phase-2 comment (~line 584) to

```rust
            // Phase 2: fix only the selected repos (cloned on demand by fix_pass).
```

Also `grep -n "clone" crates/wormward-cli/src/main.rs` and update any `--clone-dir`/github help strings that claim scanning clones (e.g. reword to "directory where repos selected for fixing are cloned"). The "--fix without --push or --clone-dir cannot persist changes" downgrade logic is still correct — leave it.

- [ ] **Step 2: Update stale GUI wording**

In `apps/desktop/src-tauri/src/lib.rs`:

- `GithubScanCache` doc (lines 16–20): the scan no longer produces clones; the token is stored so the fix phase clones/pushes with the same secret that gets redacted. Replace with:

```rust
/// The findings from a GitHub `scan_pass` (API-based, no clones), plus the exact token
/// resolved at scan time. The fix phase reuses this stored token for its on-demand
/// clones and pushes so the secret it redacts is the one it actually used.
```

- `GithubScanState` type comment (lines 26–28): replace with:

```rust
/// Managed Tauri state holding the findings from a GitHub `scan_pass` between the scan
/// and fix phases. Lightweight: no clones exist until a fix is requested.
```

- `github_scan` doc (line ~341): "Enumerate + clone + scan" → "Enumerate + API-scan (no clones)".
- `github_fix` doc (line ~383) and the state-clearing comment (lines ~421–423): fixes now clone on demand inside `fix_pass` and the clones are deleted when it returns; the state reset just drops stale findings + token. Replace the trailing comment with:

```rust
    // fix_pass's on-demand clones are already gone (its temp dir is dropped on return).
    // Reset the state so a stale token/finding set can't be reused; the frontend
    // re-scans before any subsequent fix.
```

- [ ] **Step 3: Full verification**

```bash
cargo test --workspace 2>&1 | tail -10
cd apps/desktop/src-tauri && cargo check 2>&1 | tail -3 && cd ../../..
```

Expected: all tests pass; desktop crate checks clean.

- [ ] **Step 4: Manual smoke test note**

If a real token is available (`gh auth token`), optionally run `cargo run -p wormward-cli -- github` against the actual account and confirm: no clone activity (fast, no temp git dirs), findings (if any) reported per repo. This is a judgment check, not a gate.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-cli/src/main.rs apps/desktop/src-tauri/src/lib.rs
git commit -m "Update CLI/GUI docs for clone-free GitHub scanning"
```
