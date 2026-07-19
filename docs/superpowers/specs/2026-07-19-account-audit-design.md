# Account-persistence audit + rotate-first gate

## Problem

wormward cleans infected repo **files**, but the supply-chain worm's real payoff is a
**stolen credential + account persistence** (a god-mode OAuth app, an injected SSH key, a
PAT, a rogue self-hosted Actions runner, an exfil webhook). Cleaning the repo while the
attacker still holds the token / persistence re-infects you — and `wormward github --push`
with the same stolen token is itself part of the re-infection loop. The audit surfaces the
persistence backdoor and **refuses to push until credentials are rotated** (fail-closed).

## Scope reality (honest)

The GitHub REST API **cannot** list a user's OAuth-app authorizations (the Authorizations
API was removed in 2020) nor their classic PATs. So the audit:
- **Automatically checks** the artifacts a backdoor leaves behind (all API-listable).
- **Guides a manual check** for OAuth apps + PATs (direct settings links + what to look for).

We never ask the user to grant MORE scopes for the audit (ironic for a security tool): each
check degrades gracefully when the existing token can't perform it.

## Design

### Host abstraction — new `AccountHost` trait (wormward-github/lib.rs)

Separate from `RepoHost` (repo/tree/blob scanning) so the scan trait stays clean.
`GitHubHost` implements both; the test fake implements `AccountHost` with canned data.

```rust
pub struct AccountKey { pub id: String, pub title: String, pub created_at: Option<String>, pub read_only: Option<bool> }
pub struct Webhook    { pub id: String, pub url: String, pub events: Vec<String>, pub active: bool }
pub struct Runner     { pub id: String, pub name: String, pub os: String }
pub struct Installation { pub app_slug: String, pub id: String }

pub trait AccountHost: Sync {
    /// Scopes of the token in use (from the `X-OAuth-Scopes` response header). Empty vec = a
    /// fine-grained token (no classic scopes) — reported as "unknown, likely fine-grained".
    fn token_scopes(&self) -> Result<Vec<String>, GithubError>;
    fn list_ssh_keys(&self) -> Result<Vec<AccountKey>, GithubError>;      // GET /user/keys
    fn list_gpg_keys(&self) -> Result<Vec<AccountKey>, GithubError>;      // GET /user/gpg_keys
    fn list_installations(&self) -> Result<Vec<Installation>, GithubError>; // GET /user/installations
    fn list_repo_webhooks(&self, full_name: &str) -> Result<Vec<Webhook>, GithubError>;   // /repos/{}/hooks
    fn list_repo_deploy_keys(&self, full_name: &str) -> Result<Vec<AccountKey>, GithubError>; // /repos/{}/keys
    fn list_repo_runners(&self, full_name: &str) -> Result<Vec<Runner>, GithubError>;     // /repos/{}/actions/runners
}
```

`GitHubHost::get()` gains header access: extend it (or add `get_headers`) to also return
`X-OAuth-Scopes`. The existing token-to-host guard and rate-limit handling are reused.

### Audit logic — `wormward-github/src/audit.rs`

`pub fn audit_account(host: &dyn AccountHost, repos: &[RepoRef]) -> AccountAudit` where
`AccountAudit { findings: Vec<Finding>, blocked: bool }`. Each check is independent and
**catches its own error** → on failure emits an Info "check skipped: <reason>" finding
rather than aborting the audit (graceful degradation).

Findings use a new `FindingKind::AccountAudit`, `campaign = "account-audit"`,
`remediable = false` (READ-ONLY + advisory — wormward never deletes keys / revokes apps;
the user rotates/revokes). `repo` carries `github:<owner-or-repo>`; the fix action lives in
`evidence`.

| Check | Severity | Feeds gate `blocked`? |
|---|---|---|
| Token has a **dangerous scope** (`admin:public_key`, `write:public_key`, `admin:org`, `delete_repo`, `admin:org_hook`, `admin:repo_hook`, `admin:gpg_key`, `admin:enterprise`, or any `admin:*` beyond `repo`) | High | **Yes** |
| **Self-hosted runner** present (e.g. `SHA1HULUD`) | High | **Yes** |
| **Webhook** to a non-GitHub / unusual host | High | **Yes** |
| SSH / GPG keys (surface for review; flag recently-added) | Medium | No |
| Deploy keys with write access | Medium | No |
| App installations (surface unrecognized) | Medium | No |
| OAuth apps + PATs — **guided manual** (settings links + checklist) | Info | No |

### Fail-closed rotate-first gate — pipeline.rs

Before `fix_pass` pushes anything (`opts.fix && opts.yes && opts.push`), run
`audit_account`. If `blocked` is true (dangerous token scope OR active-persistence artifact)
and the user did NOT pass `--i-rotated`, **refuse to push**: emit the audit findings, mark
each repo outcome not-pushed / manual, and surface a clear message —
> "Refusing to push: your token or account shows persistence risk. Rotate your GitHub token
> (revoke the old one), review the flagged keys/runners/webhooks, then re-run with a fresh
> minimal-scope token — or pass --i-rotated to override."

`--i-rotated` is the explicit override (wormward can't verify rotation; it requires the
user's assertion). The audit is always shown; only the push is gated.

### CLI — wormward-cli

- `wormward github --audit` — run the account audit standalone (read-only), render findings.
- `--fix --yes --push` auto-runs the audit as the gate; `--i-rotated` overrides the block.
- Text + JSON via the existing report renderer (AccountAudit findings render like any other).

### Rendering — report.rs

`FindingKind::AccountAudit` gets a label; `remediable=false` so it always routes to the
"manual" / advisory section. The guided-manual finding's evidence includes the settings URLs.

## Testing

Extend the httpmock pattern (like `GitHubHost`'s tests) and add a fake `AccountHost` (canned
scopes/keys/hooks/runners) for the audit + gate logic:
- Dangerous scope (`admin:public_key`) → High finding + `blocked` true → push refused;
  `--i-rotated` overrides.
- Minimal token (`repo`) + no artifacts → not blocked → push proceeds.
- Self-hosted runner named `SHA1HULUD` → flagged + blocks.
- Webhook to `https://evil.host` → flagged + blocks; a github.com webhook does not.
- A check returning 403 (missing scope) → "check skipped" Info finding, audit still completes.
- `GitHubHost` header parse: `X-OAuth-Scopes: repo, admin:public_key` → `["repo","admin:public_key"]`.

## Out of scope

- Auto-remediation of account settings (deleting keys, revoking apps) — too dangerous;
  advisory only.
- OAuth-app / PAT enumeration — not API-listable; guided manual only.
- On-chain C2 follow (separate nice-to-have).
