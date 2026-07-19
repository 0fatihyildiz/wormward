use std::process::Command;

use serde::{Deserialize, Serialize};

pub mod pipeline;

// Serialize is required because RepoOutcome (pipeline) serializes an embedded RepoRef.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoRef {
    pub full_name: String,
    pub clone_url: String,
    #[serde(default)]
    pub default_branch: String,
    #[serde(default)]
    pub fork: bool,
}

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

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("github auth: {0}")]
    Auth(String),
    #[error("github http: {0}")]
    Http(String),
    #[error("github parse: {0}")]
    Parse(String),
    #[error("github rate limit: {0}")]
    RateLimited(String),
}

/// Resolve a GitHub token: explicit non-empty wins, then GITHUB_TOKEN, then GH_TOKEN,
/// then `gh auth token`.
pub fn resolve_token(explicit: Option<&str>) -> Result<String, GithubError> {
    if let Some(t) = explicit {
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(t) = std::env::var(var) {
            if !t.is_empty() {
                return Ok(t);
            }
        }
    }
    // Fall back to the gh CLI.
    if let Ok(out) = Command::new("gh").args(["auth", "token"]).output() {
        if out.status.success() {
            let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !t.is_empty() {
                return Ok(t);
            }
        }
    }
    Err(GithubError::Auth(
        "no token: pass --token, set GITHUB_TOKEN/GH_TOKEN, or run `gh auth login`".into(),
    ))
}

/// A source of repos + their trees/blobs. `Sync` because the scan fans out over
/// repos with rayon while sharing one host.
pub trait RepoHost: Sync {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError>;
    fn list_branches(&self, full_name: &str) -> Result<Vec<Branch>, GithubError>;
    fn get_tree(&self, full_name: &str, commit_sha: &str) -> Result<Tree, GithubError>;
    /// `Ok(None)` for binary / non-UTF-8 blobs (mirrors `GitTree::read`).
    fn get_blob(&self, full_name: &str, blob_sha: &str) -> Result<Option<String>, GithubError>;
}

pub struct GitHubHost {
    pub token: String,
    pub base_url: String,
}

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

/// Extract the URL for rel="next" from a GitHub Link header, if present.
fn next_link(link_header: &str) -> Option<String> {
    for part in link_header.split(',') {
        let seg = part.trim();
        if seg.contains("rel=\"next\"") {
            let start = seg.find('<')?;
            let end = seg.find('>')?;
            return Some(seg[start + 1..end].to_string());
        }
    }
    None
}

/// The authority (host[:port]) of an absolute URL, for comparing whether two URLs
/// address the same host before we send a bearer token to a paginated `next` link.
fn url_authority(url: &str) -> Option<&str> {
    let (_scheme, rest) = url.split_once("://")?;
    Some(rest.split(['/', '?', '#']).next().unwrap_or(rest))
}

/// Cap on paginated requests to bound the loop even if a host keeps advertising a next link.
const MAX_PAGES: usize = 1000;

impl RepoHost for GitHubHost {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError> {
        let url = format!("{}/user/repos?affiliation=owner&per_page=100&page=1", self.base_url);
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

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[test]
    fn explicit_token_wins() {
        let t = resolve_token(Some("tok_explicit")).unwrap();
        assert_eq!(t, "tok_explicit");
    }

    #[test]
    fn env_token_used_when_no_explicit() {
        // SAFETY: single-threaded test.
        std::env::set_var("GITHUB_TOKEN", "tok_env");
        let t = resolve_token(None).unwrap();
        assert_eq!(t, "tok_env");
        std::env::remove_var("GITHUB_TOKEN");
    }

    #[test]
    fn lists_repos_across_pages_and_filters_forks() {
        let server = MockServer::start();
        let next = format!("<{}/user/repos?page=2>; rel=\"next\"", server.base_url());
        server.mock(|when, then| {
            when.method(GET).path("/user/repos").query_param("page", "1");
            then.status(200)
                .header("Link", next.as_str())
                .json_body(serde_json::json!([
                    {"full_name":"me/a","clone_url":"https://x/a.git","default_branch":"main","fork":false},
                    {"full_name":"me/forked","clone_url":"https://x/f.git","default_branch":"main","fork":true}
                ]));
        });
        server.mock(|when, then| {
            when.method(GET).path("/user/repos").query_param("page", "2");
            then.status(200).json_body(serde_json::json!([
                {"full_name":"me/b","clone_url":"https://x/b.git","default_branch":"dev","fork":false}
            ]));
        });

        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        let repos = host.list_repos(false).unwrap();
        let names: Vec<&str> = repos.iter().map(|r| r.full_name.as_str()).collect();
        assert_eq!(names, vec!["me/a", "me/b"]); // fork filtered out, both pages merged
    }

    #[test]
    fn refuses_to_follow_next_link_to_foreign_host() {
        // The API host returns a `next` link pointing at an attacker-controlled host.
        // We must NOT send the bearer token there: the run errors and the foreign host
        // receives zero requests.
        let api = MockServer::start();
        let attacker = MockServer::start();
        let evil_next = format!("<{}/user/repos?page=2>; rel=\"next\"", attacker.base_url());
        api.mock(|when, then| {
            when.method(GET).path("/user/repos").query_param("page", "1");
            then.status(200).header("Link", evil_next.as_str()).json_body(serde_json::json!([
                {"full_name":"me/a","clone_url":"https://x/a.git","default_branch":"main","fork":false}
            ]));
        });
        let attacker_mock = attacker.mock(|when, then| {
            when.method(GET).path("/user/repos");
            then.status(200).json_body(serde_json::json!([]));
        });

        let host = GitHubHost { token: "secret".into(), base_url: api.base_url() };
        let result = host.list_repos(false);
        assert!(result.is_err(), "expected an error, got {result:?}");
        attacker_mock.assert_hits(0); // token never sent to the foreign host
    }

    #[test]
    fn url_authority_extracts_host_and_port() {
        assert_eq!(url_authority("https://api.github.com/user/repos?x=1"), Some("api.github.com"));
        assert_eq!(url_authority("http://127.0.0.1:8080/p"), Some("127.0.0.1:8080"));
        assert_eq!(url_authority("not-a-url"), None);
    }

    #[test]
    fn lists_branches_across_pages() {
        let server = MockServer::start();
        let next = format!("<{}/repos/me/a/branches?page=2>; rel=\"next\"", server.base_url());
        server.mock(|when, then| {
            when.method(GET).path("/repos/me/a/branches").query_param("per_page", "100");
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
}
