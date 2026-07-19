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

#[derive(Debug, thiserror::Error)]
pub enum GithubError {
    #[error("github auth: {0}")]
    Auth(String),
    #[error("github http: {0}")]
    Http(String),
    #[error("github parse: {0}")]
    Parse(String),
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

pub trait RepoHost {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError>;
}

pub struct GitHubHost {
    pub token: String,
    pub base_url: String,
}

impl GitHubHost {
    pub fn new(token: String) -> Self {
        GitHubHost { token, base_url: "https://api.github.com".into() }
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

impl RepoHost for GitHubHost {
    fn list_repos(&self, include_forks: bool) -> Result<Vec<RepoRef>, GithubError> {
        let mut url =
            format!("{}/user/repos?affiliation=owner&per_page=100&page=1", self.base_url);
        let mut all: Vec<RepoRef> = Vec::new();
        loop {
            let resp = ureq::get(&url)
                .set("Authorization", &format!("Bearer {}", self.token))
                .set("User-Agent", "wormward")
                .set("Accept", "application/vnd.github+json")
                .call()
                .map_err(|e| GithubError::Http(e.to_string()))?;
            let link = resp.header("Link").map(|s| s.to_string());
            let body = resp.into_string().map_err(|e| GithubError::Http(e.to_string()))?;
            let page: Vec<RepoRef> =
                serde_json::from_str(&body).map_err(|e| GithubError::Parse(e.to_string()))?;
            all.extend(page);
            match link.as_deref().and_then(next_link) {
                Some(next) => url = next,
                None => break,
            }
        }
        if !include_forks {
            all.retain(|r| !r.fork);
        }
        Ok(all)
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
}
