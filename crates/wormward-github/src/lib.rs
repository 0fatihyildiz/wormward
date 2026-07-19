use std::collections::HashSet;
use std::process::Command;

use serde::{Deserialize, Serialize};

pub mod audit;
pub mod pipeline;
pub mod api_tree;

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
    /// List repos to scan. Personal repos (yours) are always included. When `orgs` is
    /// empty, org-member repos across ALL your orgs are included too (single call); when
    /// `orgs` is non-empty, only those named orgs' repos are added to your personal repos.
    fn list_repos(&self, include_forks: bool, orgs: &[String]) -> Result<Vec<RepoRef>, GithubError>;
    /// The login names of the orgs the token owner belongs to (for the GUI org picker).
    fn list_orgs(&self) -> Result<Vec<String>, GithubError>;
    fn list_branches(&self, full_name: &str) -> Result<Vec<Branch>, GithubError>;
    fn get_tree(&self, full_name: &str, commit_sha: &str) -> Result<Tree, GithubError>;
    /// `Ok(None)` for binary / non-UTF-8 blobs (mirrors `GitTree::read`).
    fn get_blob(&self, full_name: &str, blob_sha: &str) -> Result<Option<String>, GithubError>;
}

// ---- Account-audit host abstraction (read-only) ----------------------------------------

/// An SSH / GPG / deploy key on the account or a repo.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountKey {
    pub id: String,
    pub title: String,
    pub created_at: Option<String>,
    /// Deploy keys only: whether the key is read-only (a writable deploy key is a stronger tell).
    pub read_only: Option<bool>,
}

/// A repository webhook.
#[derive(Debug, Clone, PartialEq)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub active: bool,
}

/// A self-hosted Actions runner.
#[derive(Debug, Clone, PartialEq)]
pub struct Runner {
    pub id: String,
    pub name: String,
    pub os: String,
}

/// A GitHub App installed on the account.
#[derive(Debug, Clone, PartialEq)]
pub struct Installation {
    pub app_slug: String,
    pub id: String,
}

/// Read-only account-persistence surface: the artifacts a supply-chain backdoor leaves behind.
/// Separate from [`RepoHost`] (repo scanning) so each stays focused; `GitHubHost` implements both.
/// Every method may fail independently — the audit degrades gracefully, never sending the token
/// anywhere but the configured API host.
pub trait AccountHost: Sync {
    /// The classic scopes of the token in use (from the `X-OAuth-Scopes` response header). An
    /// empty vec means the header was absent — typically a fine-grained token with no classic scopes.
    fn token_scopes(&self) -> Result<Vec<String>, GithubError>;
    fn list_ssh_keys(&self) -> Result<Vec<AccountKey>, GithubError>;
    fn list_gpg_keys(&self) -> Result<Vec<AccountKey>, GithubError>;
    fn list_installations(&self) -> Result<Vec<Installation>, GithubError>;
    fn list_repo_webhooks(&self, full_name: &str) -> Result<Vec<Webhook>, GithubError>;
    fn list_repo_deploy_keys(&self, full_name: &str) -> Result<Vec<AccountKey>, GithubError>;
    fn list_repo_runners(&self, full_name: &str) -> Result<Vec<Runner>, GithubError>;
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
#[derive(serde::Deserialize)]
struct ApiOrg {
    login: String,
}

impl GitHubHost {
    pub fn new(token: String) -> Self {
        GitHubHost { token, base_url: "https://api.github.com".into() }
    }

    /// GET `url` with auth headers. Only ever sends the bearer token to the configured
    /// API authority — a malicious or buggy URL pointing elsewhere must not receive our
    /// credentials. Distinguishes rate limiting (fatal for the run) from other HTTP
    /// failures (per-repo).
    /// GET `url` with auth headers, returning the raw response (headers intact) so callers can
    /// read `Link`, `X-OAuth-Scopes`, etc. Only ever sends the bearer token to the configured
    /// API authority+scheme; distinguishes rate limiting (fatal) from other HTTP failures.
    fn call(&self, url: &str) -> Result<ureq::Response, GithubError> {
        let base_authority = url_authority(&self.base_url)
            .ok_or_else(|| GithubError::Http(format!("invalid base_url: {}", self.base_url)))?;
        // Match SCHEME as well as authority: an `http://` next-link to the same host must
        // not receive the bearer token over plaintext. We compare against base_url's own
        // scheme (not https-only) so the httpmock http://127.0.0.1 test servers still work.
        if url_authority(url) != Some(base_authority)
            || url_scheme(url) != url_scheme(&self.base_url)
        {
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
            Ok(resp) => Ok(resp),
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

    fn get(&self, url: &str) -> Result<(Option<String>, String), GithubError> {
        let resp = self.call(url)?;
        let link = resp.header("Link").map(|s| s.to_string());
        let body = resp.into_string().map_err(|e| GithubError::Http(e.to_string()))?;
        Ok((link, body))
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

/// The scheme (e.g. `https`) of an absolute URL, so the token guard can reject a
/// `next` link that swaps the scheme (e.g. plaintext http) to the same authority.
fn url_scheme(url: &str) -> Option<&str> {
    url.split_once("://").map(|(scheme, _)| scheme)
}

/// Cap on paginated requests to bound the loop even if a host keeps advertising a next link.
const MAX_PAGES: usize = 1000;

impl RepoHost for GitHubHost {
    fn list_orgs(&self) -> Result<Vec<String>, GithubError> {
        let url = format!("{}/user/orgs?per_page=100&page=1", self.base_url);
        let orgs: Vec<ApiOrg> = self.get_paginated(url)?;
        Ok(orgs.into_iter().map(|o| o.login).collect())
    }

    fn list_repos(&self, include_forks: bool, orgs: &[String]) -> Result<Vec<RepoRef>, GithubError> {
        let mut all: Vec<RepoRef> = if orgs.is_empty() {
            // No org selection: include repos in ALL orgs the user belongs to, not just
            // owned repos, so an org's infected repos are scanned too. `organization_member`
            // covers "org repos I'm a part of"; `owner` keeps personal repos.
            // Outside-collaborator repos are intentionally excluded (narrower).
            let url = format!(
                "{}/user/repos?affiliation=owner,organization_member&per_page=100&page=1",
                self.base_url
            );
            self.get_paginated(url)?
        } else {
            // Org selection narrows only the org set: your personal repos are ALWAYS
            // scanned (affiliation=owner), plus each named org's repos. Merge and dedup by
            // `full_name` (an org repo you also own would otherwise appear twice).
            let url =
                format!("{}/user/repos?affiliation=owner&per_page=100&page=1", self.base_url);
            let mut repos: Vec<RepoRef> = self.get_paginated(url)?;
            for login in orgs {
                let url = format!("{}/orgs/{login}/repos?per_page=100&page=1", self.base_url);
                match self.get_paginated::<RepoRef>(url) {
                    Ok(mut org_repos) => repos.append(&mut org_repos),
                    // Rate limiting is fatal for the run; propagate to abort.
                    Err(e @ GithubError::RateLimited(_)) => return Err(e),
                    // Any other per-org failure fails fast WITH the org named — never
                    // silently skip an org the user asked to scan.
                    Err(e) => return Err(GithubError::Http(format!("org '{login}': {e}"))),
                }
            }
            let mut seen = HashSet::new();
            repos.retain(|r| seen.insert(r.full_name.clone()));
            repos
        };
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

#[derive(serde::Deserialize)]
struct ApiSshKey {
    id: i64,
    #[serde(default)]
    title: String,
    #[serde(default)]
    created_at: Option<String>,
}
#[derive(serde::Deserialize)]
struct ApiGpgKey {
    id: i64,
    #[serde(default)]
    key_id: String,
    #[serde(default)]
    created_at: Option<String>,
}
#[derive(serde::Deserialize)]
struct ApiDeployKey {
    id: i64,
    #[serde(default)]
    title: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    read_only: Option<bool>,
}
#[derive(serde::Deserialize)]
struct ApiHookConfig {
    #[serde(default)]
    url: String,
}
#[derive(serde::Deserialize)]
struct ApiHook {
    id: i64,
    #[serde(default)]
    active: bool,
    #[serde(default)]
    events: Vec<String>,
    config: ApiHookConfig,
}
#[derive(serde::Deserialize)]
struct ApiRunner {
    id: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    os: String,
}
#[derive(serde::Deserialize)]
struct ApiRunnersResp {
    #[serde(default)]
    runners: Vec<ApiRunner>,
}
#[derive(serde::Deserialize)]
struct ApiInstallation {
    id: i64,
    #[serde(default)]
    app_slug: String,
}
#[derive(serde::Deserialize)]
struct ApiInstallationsResp {
    #[serde(default)]
    installations: Vec<ApiInstallation>,
}

impl AccountHost for GitHubHost {
    fn token_scopes(&self) -> Result<Vec<String>, GithubError> {
        // The classic scopes are advertised on any authenticated response header.
        let resp = self.call(&format!("{}/user", self.base_url))?;
        let raw = resp.header("X-OAuth-Scopes").unwrap_or("").to_string();
        Ok(raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    }

    fn list_ssh_keys(&self) -> Result<Vec<AccountKey>, GithubError> {
        let keys: Vec<ApiSshKey> =
            self.get_paginated(format!("{}/user/keys?per_page=100&page=1", self.base_url))?;
        Ok(keys
            .into_iter()
            .map(|k| AccountKey {
                id: k.id.to_string(),
                title: k.title,
                created_at: k.created_at,
                read_only: None,
            })
            .collect())
    }

    fn list_gpg_keys(&self) -> Result<Vec<AccountKey>, GithubError> {
        let keys: Vec<ApiGpgKey> =
            self.get_paginated(format!("{}/user/gpg_keys?per_page=100&page=1", self.base_url))?;
        Ok(keys
            .into_iter()
            .map(|k| AccountKey {
                id: k.id.to_string(),
                title: k.key_id,
                created_at: k.created_at,
                read_only: None,
            })
            .collect())
    }

    fn list_installations(&self) -> Result<Vec<Installation>, GithubError> {
        // `/user/installations` wraps the array in an object; a single page suffices for the audit.
        let (_, body) = self.get(&format!("{}/user/installations?per_page=100", self.base_url))?;
        let resp: ApiInstallationsResp =
            serde_json::from_str(&body).map_err(|e| GithubError::Parse(e.to_string()))?;
        Ok(resp
            .installations
            .into_iter()
            .map(|i| Installation { app_slug: i.app_slug, id: i.id.to_string() })
            .collect())
    }

    fn list_repo_webhooks(&self, full_name: &str) -> Result<Vec<Webhook>, GithubError> {
        let hooks: Vec<ApiHook> = self
            .get_paginated(format!("{}/repos/{full_name}/hooks?per_page=100&page=1", self.base_url))?;
        Ok(hooks
            .into_iter()
            .map(|h| Webhook {
                id: h.id.to_string(),
                url: h.config.url,
                events: h.events,
                active: h.active,
            })
            .collect())
    }

    fn list_repo_deploy_keys(&self, full_name: &str) -> Result<Vec<AccountKey>, GithubError> {
        let keys: Vec<ApiDeployKey> = self
            .get_paginated(format!("{}/repos/{full_name}/keys?per_page=100&page=1", self.base_url))?;
        Ok(keys
            .into_iter()
            .map(|k| AccountKey {
                id: k.id.to_string(),
                title: k.title,
                created_at: k.created_at,
                read_only: k.read_only,
            })
            .collect())
    }

    fn list_repo_runners(&self, full_name: &str) -> Result<Vec<Runner>, GithubError> {
        // `/actions/runners` wraps the array in an object; a single page suffices for the audit.
        let (_, body) =
            self.get(&format!("{}/repos/{full_name}/actions/runners?per_page=100", self.base_url))?;
        let resp: ApiRunnersResp =
            serde_json::from_str(&body).map_err(|e| GithubError::Parse(e.to_string()))?;
        Ok(resp
            .runners
            .into_iter()
            .map(|r| Runner { id: r.id.to_string(), name: r.name, os: r.os })
            .collect())
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
            // Assert the first request asks for owned AND org-member repos, not owner-only.
            when.method(GET)
                .path("/user/repos")
                .query_param("page", "1")
                .query_param("affiliation", "owner,organization_member");
            then.status(200)
                .header("Link", next.as_str())
                .json_body(serde_json::json!([
                    {"full_name":"me/a","clone_url":"https://x/a.git","default_branch":"main","fork":false},
                    {"full_name":"org/repo","clone_url":"https://x/o.git","default_branch":"main","fork":false},
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
        let repos = host.list_repos(false, &[]).unwrap();
        let names: Vec<&str> = repos.iter().map(|r| r.full_name.as_str()).collect();
        // owned + org-member repos across both pages; the fork is filtered out.
        assert_eq!(names, vec!["me/a", "org/repo", "me/b"]);
    }

    #[test]
    fn list_orgs_parses_logins() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/user/orgs");
            then.status(200).json_body(serde_json::json!([
                {"login":"acme"},
                {"login":"foo"}
            ]));
        });
        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        assert_eq!(host.list_orgs().unwrap(), vec!["acme".to_string(), "foo".to_string()]);
    }

    #[test]
    fn list_repos_with_orgs_fetches_owner_plus_each_org() {
        let server = MockServer::start();
        // Personal repos: affiliation=owner (NOT organization_member).
        server.mock(|when, then| {
            when.method(GET)
                .path("/user/repos")
                .query_param("affiliation", "owner");
            then.status(200).json_body(serde_json::json!([
                {"full_name":"me/a","clone_url":"https://x/a.git","default_branch":"main","fork":false},
                {"full_name":"me/forked","clone_url":"https://x/f.git","default_branch":"main","fork":true}
            ]));
        });
        // Selected org's repos.
        server.mock(|when, then| {
            when.method(GET).path("/orgs/acme/repos");
            then.status(200).json_body(serde_json::json!([
                {"full_name":"acme/x","clone_url":"https://x/x.git","default_branch":"main","fork":false}
            ]));
        });
        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        let repos = host.list_repos(false, &["acme".into()]).unwrap();
        let names: Vec<&str> = repos.iter().map(|r| r.full_name.as_str()).collect();
        // personal (owner) + the org's repos; the personal fork is filtered out.
        assert_eq!(names, vec!["me/a", "acme/x"]);
    }

    #[test]
    fn list_repos_with_bad_org_errors_named() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/user/repos")
                .query_param("affiliation", "owner");
            then.status(200).json_body(serde_json::json!([
                {"full_name":"me/a","clone_url":"https://x/a.git","default_branch":"main","fork":false}
            ]));
        });
        server.mock(|when, then| {
            when.method(GET).path("/orgs/bad/repos");
            then.status(404).body("{}");
        });
        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        let result = host.list_repos(false, &["bad".into()]);
        match result {
            Err(e) => assert!(e.to_string().contains("bad"), "error should name the org: {e}"),
            Ok(_) => panic!("expected an error for the bad org"),
        }
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
        let result = host.list_repos(false, &[]);
        assert!(result.is_err(), "expected an error, got {result:?}");
        attacker_mock.assert_hits(0); // token never sent to the foreign host
    }

    #[test]
    fn refuses_to_follow_next_link_with_swapped_scheme() {
        // The API host (http) returns a `next` link to the SAME authority but over https.
        // The token must not go out over a different scheme, so the run errors before any
        // second request. We can't mock the https side; asserting the Err is sufficient
        // because the guard rejects before issuing a request.
        let api = MockServer::start();
        let evil_next = format!(
            "<{}/user/repos?page=2>; rel=\"next\"",
            api.base_url().replace("http://", "https://")
        );
        api.mock(|when, then| {
            when.method(GET).path("/user/repos").query_param("page", "1");
            then.status(200).header("Link", evil_next.as_str()).json_body(serde_json::json!([
                {"full_name":"me/a","clone_url":"https://x/a.git","default_branch":"main","fork":false}
            ]));
        });
        let host = GitHubHost { token: "secret".into(), base_url: api.base_url() };
        let result = host.list_repos(false, &[]);
        assert!(result.is_err(), "expected an error, got {result:?}");
    }

    #[test]
    fn url_scheme_extracts_scheme() {
        assert_eq!(url_scheme("https://api.github.com/x"), Some("https"));
        assert_eq!(url_scheme("http://127.0.0.1:8080/p"), Some("http"));
        assert_eq!(url_scheme("not-a-url"), None);
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

    // ---- account audit host ----
    #[test]
    fn token_scopes_parsed_from_header() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/user");
            then.status(200)
                .header("X-OAuth-Scopes", "repo, admin:public_key, workflow")
                .json_body(serde_json::json!({"login": "me"}));
        });
        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        assert_eq!(
            host.token_scopes().unwrap(),
            vec!["repo".to_string(), "admin:public_key".into(), "workflow".into()]
        );
    }

    #[test]
    fn token_scopes_empty_when_header_absent() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/user");
            then.status(200).json_body(serde_json::json!({"login": "me"}));
        });
        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        assert!(host.token_scopes().unwrap().is_empty());
    }

    #[test]
    fn lists_ssh_keys() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/user/keys");
            then.status(200).json_body(serde_json::json!([
                {"id": 1, "title": "laptop", "key": "ssh-ed25519 AAAA", "created_at": "2020-01-01T00:00:00Z"},
                {"id": 2, "title": "backdoor", "key": "ssh-rsa BBBB"}
            ]));
        });
        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        let keys = host.list_ssh_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, "1");
        assert_eq!(keys[0].title, "laptop");
        assert_eq!(keys[0].created_at.as_deref(), Some("2020-01-01T00:00:00Z"));
        assert_eq!(keys[1].created_at, None);
    }

    #[test]
    fn lists_repo_runners_from_wrapped_object() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/repos/me/a/actions/runners");
            then.status(200).json_body(serde_json::json!({
                "total_count": 1,
                "runners": [{"id": 7, "name": "SHA1HULUD", "os": "Linux"}]
            }));
        });
        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        assert_eq!(
            host.list_repo_runners("me/a").unwrap(),
            vec![Runner { id: "7".into(), name: "SHA1HULUD".into(), os: "Linux".into() }]
        );
    }

    #[test]
    fn lists_repo_webhooks_with_config_url() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/repos/me/a/hooks");
            then.status(200).json_body(serde_json::json!([
                {"id": 5, "active": true, "events": ["push"], "config": {"url": "https://evil.host/collect"}}
            ]));
        });
        let host = GitHubHost { token: "t".into(), base_url: server.base_url() };
        assert_eq!(
            host.list_repo_webhooks("me/a").unwrap(),
            vec![Webhook {
                id: "5".into(),
                url: "https://evil.host/collect".into(),
                events: vec!["push".into()],
                active: true,
            }]
        );
    }
}
