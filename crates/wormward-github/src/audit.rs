//! Read-only account-persistence audit. Supply-chain worms don't just infect repo files —
//! they steal a credential and plant persistence (an over-privileged token, an injected SSH
//! key, a rogue self-hosted Actions runner, an exfil webhook). Cleaning the repo while that
//! persistence lives re-infects you. This surfaces the backdoor and feeds the rotate-first
//! gate. It NEVER changes account settings — findings are advisory (`remediable = false`).

use std::path::PathBuf;

use wormward_core::{Finding, FindingKind, Severity};

use crate::{AccountHost, GithubError, RepoRef};

/// Token scopes that a *fix* credential should never carry — they grant account-level
/// persistence powers (SSH/GPG key management, org admin, repo deletion). A token bearing one
/// of these is over-privileged for cleaning repos and, if stolen, is the re-infection vector.
const DANGEROUS_SCOPES: &[&str] = &[
    "admin:public_key",
    "write:public_key",
    "admin:ssh_signing_key",
    "admin:gpg_key",
    "admin:org",
    "admin:org_hook",
    "admin:repo_hook",
    "delete_repo",
    "admin:enterprise",
    "site_admin",
];

/// Case-insensitive substrings identifying a KNOWN-bad self-hosted runner (the Shai-Hulud worm
/// registers a "SHA1HULUD" runner). Only known-bad names BLOCK; other self-hosted runners are
/// surfaced for review (legitimate projects run their own runners).
const BAD_RUNNER_MARKERS: &[&str] = &["sha1hulud", "shai-hulud", "shai_hulud"];

/// Outcome of the account audit: advisory findings, plus whether a high-confidence persistence
/// tell should BLOCK a push (fail-closed rotate-first gate).
pub struct AccountAudit {
    pub findings: Vec<Finding>,
    pub blocked: bool,
}

fn finding(repo: &str, sev: Severity, sig: &str, evidence: String) -> Finding {
    Finding {
        campaign: "account-audit".into(),
        severity: sev,
        repo: PathBuf::from(format!("github:{repo}")),
        file: None,
        signature_id: format!("account:{sig}"),
        kind: FindingKind::AccountAudit,
        evidence,
        remediable: false, // advisory only — wormward never touches account settings
        online: None,
        git_ref: None,
        excerpt: None,
    }
}

/// A check failed (usually the token lacks the read scope). Surface it as an Info note rather
/// than aborting the whole audit — graceful degradation, and we never request more scopes.
fn skipped(what: &str, e: &GithubError) -> Finding {
    finding("account", Severity::Info, "check-skipped", format!("could not audit {what}: {e}"))
}

/// Run the read-only account audit. `repos` are the repositories to check per-repo persistence
/// on (typically the infected ones) — keeps the API cost proportional and targeted.
pub fn audit_account(host: &dyn AccountHost, repos: &[RepoRef]) -> AccountAudit {
    let mut findings = Vec::new();
    let mut blocked = false;

    // --- token scopes (blocking) ---
    match host.token_scopes() {
        Ok(scopes) => {
            let dangerous: Vec<&String> =
                scopes.iter().filter(|s| DANGEROUS_SCOPES.contains(&s.as_str())).collect();
            if !dangerous.is_empty() {
                blocked = true;
                let list = dangerous.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                findings.push(finding(
                    "account",
                    Severity::High,
                    "token-scope",
                    format!(
                        "the token in use carries over-privileged scopes ({list}). A repo fix \
                         needs only `repo` (or fine-grained contents:write). If this token was \
                         stolen it is a re-infection vector — rotate it and re-auth with a \
                         minimal-scope token before pushing."
                    ),
                ));
            }
        }
        Err(e) => findings.push(skipped("token scopes", &e)),
    }

    // --- account keys / apps (surface for review, non-blocking) ---
    match host.list_ssh_keys() {
        Ok(keys) if !keys.is_empty() => findings.push(finding(
            "account",
            Severity::Medium,
            "ssh-keys",
            format!(
                "{} SSH key(s) on the account — review and revoke any you do not recognize \
                 (an injected key is a persistent re-entry backdoor): {}",
                keys.len(),
                keys.iter().map(describe_key).collect::<Vec<_>>().join("; ")
            ),
        )),
        Ok(_) => {}
        Err(e) => findings.push(skipped("SSH keys", &e)),
    }
    match host.list_gpg_keys() {
        Ok(keys) if !keys.is_empty() => findings.push(finding(
            "account",
            Severity::Medium,
            "gpg-keys",
            format!(
                "{} GPG key(s) on the account — review for any you do not recognize: {}",
                keys.len(),
                keys.iter().map(describe_key).collect::<Vec<_>>().join("; ")
            ),
        )),
        Ok(_) => {}
        Err(e) => findings.push(skipped("GPG keys", &e)),
    }
    match host.list_installations() {
        Ok(apps) if !apps.is_empty() => findings.push(finding(
            "account",
            Severity::Medium,
            "app-installations",
            format!(
                "{} GitHub App installation(s) — review and remove any you do not recognize: {}",
                apps.len(),
                apps.iter().map(|a| a.app_slug.as_str()).collect::<Vec<_>>().join(", ")
            ),
        )),
        Ok(_) => {}
        Err(e) => findings.push(skipped("app installations", &e)),
    }

    // --- per-repo persistence (runners block on a known-bad name; rest surfaced) ---
    for repo in repos {
        let name = &repo.full_name;
        match host.list_repo_runners(name) {
            Ok(runners) => {
                for r in &runners {
                    let low = r.name.to_lowercase();
                    if BAD_RUNNER_MARKERS.iter().any(|m| low.contains(m)) {
                        blocked = true;
                        findings.push(finding(
                            name,
                            Severity::High,
                            "rogue-runner",
                            format!(
                                "self-hosted Actions runner '{}' matches a known worm runner \
                                 (Shai-Hulud). Remove it — it can execute attacker code on every \
                                 workflow run.",
                                r.name
                            ),
                        ));
                    }
                }
                let benign: Vec<&str> = runners
                    .iter()
                    .filter(|r| {
                        let low = r.name.to_lowercase();
                        !BAD_RUNNER_MARKERS.iter().any(|m| low.contains(m))
                    })
                    .map(|r| r.name.as_str())
                    .collect();
                if !benign.is_empty() {
                    findings.push(finding(
                        name,
                        Severity::Medium,
                        "self-hosted-runner",
                        format!(
                            "self-hosted runner(s) on {name} — confirm they are yours: {}",
                            benign.join(", ")
                        ),
                    ));
                }
            }
            Err(e) => findings.push(skipped(&format!("runners on {name}"), &e)),
        }
        match host.list_repo_webhooks(name) {
            Ok(hooks) if !hooks.is_empty() => findings.push(finding(
                name,
                Severity::Medium,
                "webhooks",
                format!(
                    "{} webhook(s) on {name} — review the delivery URLs for exfiltration \
                     endpoints: {}",
                    hooks.len(),
                    hooks.iter().map(|h| h.url.as_str()).collect::<Vec<_>>().join(", ")
                ),
            )),
            Ok(_) => {}
            Err(e) => findings.push(skipped(&format!("webhooks on {name}"), &e)),
        }
        match host.list_repo_deploy_keys(name) {
            Ok(keys) => {
                let writable = keys.iter().filter(|k| k.read_only == Some(false)).count();
                if writable > 0 {
                    findings.push(finding(
                        name,
                        Severity::Medium,
                        "deploy-keys",
                        format!(
                            "{writable} writable deploy key(s) on {name} — a writable deploy key \
                             is a push backdoor; revoke any you do not recognize."
                        ),
                    ));
                }
            }
            Err(e) => findings.push(skipped(&format!("deploy keys on {name}"), &e)),
        }
    }

    // --- guided manual (not API-listable) ---
    findings.push(finding(
        "account",
        Severity::Info,
        "manual-review",
        "Not checkable via the API — review manually: authorized OAuth apps at \
         github.com/settings/applications (revoke anything with admin/key/repo powers you did \
         not grant), personal access tokens at github.com/settings/tokens (delete unknown \
         tokens), and the security log at github.com/settings/security-log for \
         oauth_authorization / key.create events."
            .into(),
    ));

    AccountAudit { findings, blocked }
}

fn describe_key(k: &crate::AccountKey) -> String {
    match &k.created_at {
        Some(t) => format!("{} (added {t})", k.title),
        None => k.title.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountKey, Installation, Runner, Webhook};

    #[derive(Default)]
    struct FakeAccount {
        scopes: Vec<String>,
        scopes_err: bool,
        ssh: Vec<AccountKey>,
        gpg: Vec<AccountKey>,
        apps: Vec<Installation>,
        runners: Vec<Runner>,
        webhooks: Vec<Webhook>,
        deploy_keys: Vec<AccountKey>,
    }

    impl AccountHost for FakeAccount {
        fn token_scopes(&self) -> Result<Vec<String>, GithubError> {
            if self.scopes_err {
                Err(GithubError::Http("403".into()))
            } else {
                Ok(self.scopes.clone())
            }
        }
        fn list_ssh_keys(&self) -> Result<Vec<AccountKey>, GithubError> {
            Ok(self.ssh.clone())
        }
        fn list_gpg_keys(&self) -> Result<Vec<AccountKey>, GithubError> {
            Ok(self.gpg.clone())
        }
        fn list_installations(&self) -> Result<Vec<Installation>, GithubError> {
            Ok(self.apps.clone())
        }
        fn list_repo_webhooks(&self, _: &str) -> Result<Vec<Webhook>, GithubError> {
            Ok(self.webhooks.clone())
        }
        fn list_repo_deploy_keys(&self, _: &str) -> Result<Vec<AccountKey>, GithubError> {
            Ok(self.deploy_keys.clone())
        }
        fn list_repo_runners(&self, _: &str) -> Result<Vec<Runner>, GithubError> {
            Ok(self.runners.clone())
        }
    }

    fn repo(name: &str) -> RepoRef {
        RepoRef {
            full_name: name.into(),
            clone_url: String::new(),
            default_branch: "main".into(),
            fork: false,
        }
    }

    #[test]
    fn dangerous_token_scope_blocks() {
        let host = FakeAccount { scopes: vec!["repo".into(), "admin:public_key".into()], ..Default::default() };
        let audit = audit_account(&host, &[]);
        assert!(audit.blocked, "an over-privileged token must block the push");
        assert!(audit
            .findings
            .iter()
            .any(|f| f.signature_id == "account:token-scope" && f.severity == Severity::High));
    }

    #[test]
    fn minimal_token_and_clean_account_does_not_block() {
        let host = FakeAccount { scopes: vec!["repo".into()], ..Default::default() };
        let audit = audit_account(&host, &[repo("me/a")]);
        assert!(!audit.blocked, "a minimal token with no persistence artifacts must not block");
        // Still emits the guided-manual note.
        assert!(audit.findings.iter().any(|f| f.signature_id == "account:manual-review"));
    }

    #[test]
    fn known_bad_runner_blocks() {
        let host = FakeAccount {
            scopes: vec!["repo".into()],
            runners: vec![Runner { id: "1".into(), name: "SHA1HULUD".into(), os: "Linux".into() }],
            ..Default::default()
        };
        let audit = audit_account(&host, &[repo("me/a")]);
        assert!(audit.blocked, "a Shai-Hulud runner must block");
        assert!(audit.findings.iter().any(|f| f.signature_id == "account:rogue-runner"));
    }

    #[test]
    fn benign_self_hosted_runner_surfaced_not_blocking() {
        let host = FakeAccount {
            scopes: vec!["repo".into()],
            runners: vec![Runner { id: "1".into(), name: "my-ci-box".into(), os: "Linux".into() }],
            ..Default::default()
        };
        let audit = audit_account(&host, &[repo("me/a")]);
        assert!(!audit.blocked, "a legit self-hosted runner must not block");
        assert!(audit
            .findings
            .iter()
            .any(|f| f.signature_id == "account:self-hosted-runner" && f.severity == Severity::Medium));
    }

    #[test]
    fn ssh_keys_surfaced_for_review() {
        let host = FakeAccount {
            scopes: vec!["repo".into()],
            ssh: vec![AccountKey {
                id: "1".into(),
                title: "backdoor".into(),
                created_at: Some("2025-01-01T00:00:00Z".into()),
                read_only: None,
            }],
            ..Default::default()
        };
        let audit = audit_account(&host, &[]);
        let f = audit.findings.iter().find(|f| f.signature_id == "account:ssh-keys").unwrap();
        assert!(f.evidence.contains("backdoor"));
        assert!(!audit.blocked);
    }

    #[test]
    fn writable_deploy_key_surfaced() {
        let host = FakeAccount {
            scopes: vec!["repo".into()],
            deploy_keys: vec![AccountKey {
                id: "1".into(),
                title: "dk".into(),
                created_at: None,
                read_only: Some(false),
            }],
            ..Default::default()
        };
        let audit = audit_account(&host, &[repo("me/a")]);
        assert!(audit.findings.iter().any(|f| f.signature_id == "account:deploy-keys"));
    }

    #[test]
    fn failed_scope_check_degrades_gracefully() {
        let host = FakeAccount { scopes_err: true, ..Default::default() };
        let audit = audit_account(&host, &[]);
        // The audit still completes and notes the skipped check.
        assert!(audit.findings.iter().any(|f| f.signature_id == "account:check-skipped"));
        assert!(!audit.blocked);
    }
}
