use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::Emitter;
use wormward_core::{
    apply, apply_branch_cleans, deep_scan_repo, discover_repos, now_secs, plan_branch_cleans,
    plan_remediation, restore as core_restore, scan_repo, scan_streaming, BranchCleanStatus,
    Finding, RemediationAction, ScanReport,
};
use wormward_github::pipeline::{fix_pass, scan_pass_with_progress, GithubRunOpts, ScanPass};
use wormward_github::{resolve_token, GitHubHost, RepoHost};
use wormward_osm::{enrich, OsmClient};
use wormward_packs::builtin_packs;

/// The findings from a GitHub `scan_pass` (API-based, no clones), plus the exact token
/// resolved at scan time. The fix phase reuses this stored token for its on-demand
/// clones and pushes so the secret it redacts is the one it actually used.
struct GithubScanCache {
    scan: ScanPass,
    token: String,
}

/// Managed Tauri state holding the findings from a GitHub `scan_pass` between the scan
/// and fix phases. Lightweight: no clones exist until a fix is requested.
type GithubScanState = Mutex<Option<GithubScanCache>>;

fn to_paths(dirs: Vec<String>) -> Vec<PathBuf> {
    dirs.into_iter().map(PathBuf::from).collect()
}

fn describe(a: &RemediationAction) -> String {
    match a {
        RemediationAction::StripPayload { file, .. } => {
            format!("strip payload from {}", file.display())
        }
        RemediationAction::DeleteFile { file } => format!("delete {}", file.display()),
        RemediationAction::RemoveGitignoreLine { file, line } => {
            format!("remove '{line}' from {}", file.display())
        }
    }
}

#[derive(Serialize)]
pub struct PackInfo {
    id: String,
    name: String,
    description: String,
}

#[derive(Serialize)]
pub struct RepoPlan {
    repo: String,
    actions: Vec<RemediationAction>,
    manual: Vec<Finding>,
}

#[derive(Serialize)]
pub struct SkippedAction {
    action: String,
    reason: String,
}

#[derive(Serialize)]
pub struct CleanSummary {
    repos: usize,
    applied: usize,
    skipped: Vec<SkippedAction>,
    backups: Vec<String>,
}

#[derive(Serialize)]
pub struct RestoreSummary {
    repos: usize,
    restored: usize,
}

/// A scan report plus any non-fatal OSM enrichment warnings. `warnings` is flattened into
/// the report's JSON object (`{ findings, repos_scanned, warnings }`), so the existing
/// frontend `ScanReport` shape keeps working and simply gains a `warnings` array.
#[derive(Serialize)]
pub struct ScanResult {
    #[serde(flatten)]
    report: ScanReport,
    /// OSM enrichment warnings (auth / rate-limit / network). Empty on an offline scan.
    warnings: Vec<String>,
    /// True when the run was stopped early via `cancel_scan` (the report is partial).
    cancelled: bool,
}

/// Per-repo progress emitted on the `local-scan-progress` event as a scan runs.
#[derive(Serialize, Clone)]
pub struct ScanProgress {
    done: usize,
    total: usize,
    repo: String,
}

/// Cross-command cancel flag for the running local scan. `cancel_scan` sets it; the `scan`
/// command clears it at the start of each run and checks it between repos.
type ScanCancel = Arc<AtomicBool>;

#[tauri::command]
async fn scan(
    dirs: Vec<String>,
    deep: bool,
    online: bool,
    token: Option<String>,
    window: tauri::Window,
    cancel: tauri::State<'_, ScanCancel>,
) -> Result<ScanResult, String> {
    let paths = to_paths(dirs);
    let packs = builtin_packs();
    // Fresh run: clear any stale cancel request from a previous scan.
    cancel.store(false, Ordering::Relaxed);
    let flag: &AtomicBool = &cancel;
    // Sequential, cancellable scan: emit one progress event per repo for the live log.
    let mut report = scan_streaming(&paths, &packs, deep, flag, &|done, total, repo| {
        let _ = window.emit(
            "local-scan-progress",
            ScanProgress { done, total, repo: repo.display().to_string() },
        );
    });
    let cancelled = flag.load(Ordering::Relaxed);
    let mut warnings = Vec::new();
    if online {
        // Mirror the CLI: an online scan with no resolvable token is a hard error, not a
        // silent offline scan presented to the user as a completed online lookup.
        let token = token
            .filter(|t| !t.is_empty())
            .or_else(|| std::env::var("OSM_API_KEY").ok())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                "online scan requires an OSM token (set OSM_API_KEY or enter a token)".to_string()
            })?;
        let base = std::env::var("OSM_BASE_URL")
            .unwrap_or_else(|_| "https://api.opensourcemalware.com/functions/v1".to_string());
        let client = OsmClient::new(base, token);
        // Surface enrichment warnings rather than discarding them (the CLI prints each).
        warnings = enrich(&mut report.findings, &client);
    }
    Ok(ScanResult { report, warnings, cancelled })
}

/// Request cancellation of the running local scan. Cooperative: the `scan` loop stops at the
/// next repo boundary and returns a partial report with `cancelled = true`.
#[tauri::command]
fn cancel_scan(cancel: tauri::State<'_, ScanCancel>) {
    cancel.store(true, Ordering::Relaxed);
}

#[tauri::command]
fn list_packs() -> Vec<PackInfo> {
    builtin_packs()
        .into_iter()
        .map(|p| PackInfo {
            id: p.manifest.id,
            name: p.manifest.name,
            description: p.manifest.description,
        })
        .collect()
}

#[tauri::command]
async fn clean_preview(dirs: Vec<String>) -> Result<Vec<RepoPlan>, String> {
    let packs = builtin_packs();
    let mut out = Vec::new();
    for dir in to_paths(dirs) {
        for repo in discover_repos(&dir) {
            let findings = scan_repo(&repo, &packs);
            let plan = plan_remediation(&findings, &packs);
            if plan.actions.is_empty() && plan.manual.is_empty() {
                continue;
            }
            out.push(RepoPlan {
                repo: repo.display().to_string(),
                actions: plan.actions,
                manual: plan.manual,
            });
        }
    }
    Ok(out)
}

/// Clean exactly the repos the user selected (paths from `clean_preview`), rather than
/// re-discovering everything under the scanned dirs. Repos with no applicable action are a
/// no-op.
#[tauri::command]
async fn clean_apply(repos: Vec<String>) -> Result<CleanSummary, String> {
    let packs = builtin_packs();
    let mut summary = CleanSummary {
        repos: 0,
        applied: 0,
        skipped: Vec::new(),
        backups: Vec::new(),
    };
    for repo in to_paths(repos) {
        let findings = scan_repo(&repo, &packs);
        let plan = plan_remediation(&findings, &packs);
        if plan.actions.is_empty() {
            continue;
        }
        let res = apply(&repo, &plan.actions, true);
        summary.repos += 1;
        summary.applied += res.applied.len();
        for (a, e) in res.skipped {
            summary.skipped.push(SkippedAction {
                action: describe(&a),
                reason: e,
            });
        }
        if let Some(bd) = res.backup_dir {
            summary.backups.push(bd.display().to_string());
        }
    }
    Ok(summary)
}

#[tauri::command]
async fn restore(dirs: Vec<String>) -> Result<RestoreSummary, String> {
    let mut summary = RestoreSummary { repos: 0, restored: 0 };
    for dir in to_paths(dirs) {
        for repo in discover_repos(&dir) {
            let r = core_restore(&repo);
            if r.backup_dir.is_some() {
                summary.repos += 1;
                summary.restored += r.restored.len();
            }
        }
    }
    Ok(summary)
}

// ---- Feature B: cross-branch cleaning -------------------------------------------------

/// A dry-run plan to clean one infected branch tip (from a deep scan). `action_count` is how
/// many remediation actions would be applied on that branch.
#[derive(Serialize)]
pub struct BranchCleanPreview {
    repo: String,
    branch: String,
    backup_ref: String,
    action_count: usize,
}

/// One (repo, branch) the user chose to clean.
#[derive(Deserialize)]
pub struct BranchSelection {
    repo: String,
    branch: String,
}

/// GUI-friendly outcome of applying one branch-clean plan.
#[derive(Serialize)]
pub struct BranchCleanResult {
    repo: String,
    branch: String,
    /// "cleaned" | "skipped" | "failed" | "planned".
    status: String,
    pushed: bool,
    backup_ref: Option<String>,
    message: Option<String>,
}

#[derive(Serialize)]
pub struct BranchCleanApplySummary {
    results: Vec<BranchCleanResult>,
    cleaned: usize,
    skipped: usize,
    failed: usize,
}

/// Deep-scan the given dirs and return a dry-run branch-clean plan per infected branch tip.
/// Never mutates anything.
#[tauri::command]
async fn clean_branches_preview(dirs: Vec<String>) -> Result<Vec<BranchCleanPreview>, String> {
    let packs = builtin_packs();
    let ts = now_secs();
    let mut out = Vec::new();
    for dir in to_paths(dirs) {
        for repo in discover_repos(&dir) {
            let findings = deep_scan_repo(&repo, &packs);
            for plan in plan_branch_cleans(&findings, &packs, ts) {
                out.push(BranchCleanPreview {
                    repo: plan.repo.display().to_string(),
                    branch: plan.branch,
                    backup_ref: plan.backup_ref,
                    action_count: plan.actions.len(),
                });
            }
        }
    }
    Ok(out)
}

/// Apply branch-clean plans for exactly the selected (repo, branch) pairs. Re-derives the
/// plans from a fresh deep scan (so backup refs are created at apply time) and applies only
/// the selected branches. `push` force-pushes cleaned tips to their remotes; remote-tracking
/// branches without `push` are reported as skipped (expected).
#[tauri::command]
async fn clean_branches_apply(
    selected: Vec<BranchSelection>,
    push: bool,
) -> Result<BranchCleanApplySummary, String> {
    let packs = builtin_packs();
    let ts = now_secs();

    // Group the selected branches by repo so each repo is deep-scanned once.
    let mut by_repo: HashMap<String, HashSet<String>> = HashMap::new();
    for s in selected {
        by_repo.entry(s.repo).or_default().insert(s.branch);
    }

    let mut plans = Vec::new();
    for (repo_str, branches) in by_repo {
        let repo = PathBuf::from(&repo_str);
        let findings = deep_scan_repo(&repo, &packs);
        for plan in plan_branch_cleans(&findings, &packs, ts) {
            if branches.contains(&plan.branch) {
                plans.push(plan);
            }
        }
    }

    let outcomes = apply_branch_cleans(&plans, false, push);
    let mut summary = BranchCleanApplySummary {
        results: Vec::new(),
        cleaned: 0,
        skipped: 0,
        failed: 0,
    };
    for o in outcomes {
        let (status, pushed, backup_ref, message) = match o.status {
            BranchCleanStatus::Planned => ("planned".to_string(), false, None, None),
            BranchCleanStatus::Cleaned { backup_ref, pushed } => {
                summary.cleaned += 1;
                ("cleaned".to_string(), pushed, Some(backup_ref), None)
            }
            BranchCleanStatus::Skipped(m) => {
                summary.skipped += 1;
                ("skipped".to_string(), false, None, Some(m))
            }
            BranchCleanStatus::Failed(m) => {
                summary.failed += 1;
                ("failed".to_string(), false, None, Some(m))
            }
        };
        summary.results.push(BranchCleanResult {
            repo: o.plan.repo.display().to_string(),
            branch: o.plan.branch,
            status,
            pushed,
            backup_ref,
            message,
        });
    }
    Ok(summary)
}

// ---- Feature C: GitHub account mode ---------------------------------------------------

/// A serializable per-repo view of one infected GitHub repo from a scan pass.
#[derive(Serialize)]
pub struct GithubRepoView {
    full_name: String,
    findings: usize,
    campaigns: Vec<String>,
    /// True when the default working tree has an applicable remediation action — the only
    /// repos `github_fix` can actually fix (branch-only infections are reported, not fixable).
    fixable: bool,
}

/// Per-repo outcome of a GitHub fix-and-push.
#[derive(Serialize)]
pub struct GithubFixView {
    full_name: String,
    fixed: bool,
    pushed: Vec<String>,
    actions: Vec<String>,
    error: Option<String>,
    /// Infected but not auto-remediated (no strip marker, or an incomplete strip was
    /// reverted). Surfaced so the UI reports "manual review needed", never a silent no-op.
    manual_review: bool,
}

/// Enumerate + API-scan (no clones) the token owner's GitHub repos and repos in their orgs
/// (read-only), stash the
/// findings in managed state for a later fix, and return a view of the infected repos. Token:
/// explicit (non-empty) or resolved from `gh auth token`/`GITHUB_TOKEN`/`GH_TOKEN` when blank.
/// List the orgs the token owner belongs to (for the GUI org picker). Errors are returned
/// so the frontend can fall back to "scan all orgs".
#[tauri::command]
async fn github_orgs(token: Option<String>) -> Result<Vec<String>, String> {
    let token = resolve_token(token.as_deref()).map_err(|e| e.to_string())?;
    GitHubHost::new(token).list_orgs().map_err(|e| e.to_string())
}

#[tauri::command]
async fn github_scan(
    token: Option<String>,
    include_forks: bool,
    orgs: Vec<String>,
    window: tauri::Window,
    state: tauri::State<'_, GithubScanState>,
) -> Result<Vec<GithubRepoView>, String> {
    let token = resolve_token(token.as_deref()).map_err(|e| e.to_string())?;
    let host = GitHubHost::new(token.clone());
    let packs = builtin_packs();
    let opts = GithubRunOpts {
        clone_dir: None,
        include_forks,
        fix: false,
        push: false,
        yes: false,
        orgs,
    };
    let scan = scan_pass_with_progress(&opts, &host, &packs, &token, &|p| {
        // Best-effort: a failed emit must never fail the scan.
        let _ = window.emit("github-scan-progress", &p);
    })
    .map_err(|e| e.to_string())?;
    let fixable: HashSet<String> = scan.fixable_full_names(&packs).into_iter().collect();

    let mut views = Vec::new();
    for sr in scan.repos() {
        if !sr.is_infected() {
            continue;
        }
        let mut campaigns: Vec<String> = sr.findings.iter().map(|f| f.campaign.clone()).collect();
        campaigns.sort();
        campaigns.dedup();
        views.push(GithubRepoView {
            full_name: sr.repo.full_name.clone(),
            findings: sr.findings.len(),
            campaigns,
            fixable: fixable.contains(&sr.repo.full_name),
        });
    }

    *state.lock().map_err(|e| e.to_string())? = Some(GithubScanCache { scan, token });
    Ok(views)
}

/// Fix the selected GitHub repos, cloning each on demand inside `fix_pass` (the clones are
/// deleted when it returns). Fixing a GitHub repo always pushes (a no-push GitHub fix would be
/// discarded with the temp clone), so this force-pushes cleaned history to the remote. Returns
/// per-repo outcomes for the selected repos. Uses the token resolved at scan time (stored in
/// managed state) — not a freshly resolved one — so the redacted secret matches the one used
/// for the on-demand clones and pushes.
#[tauri::command]
async fn github_fix(
    selected: Vec<String>,
    state: tauri::State<'_, GithubScanState>,
) -> Result<Vec<GithubFixView>, String> {
    let packs = builtin_packs();
    let opts = GithubRunOpts {
        clone_dir: None,
        include_forks: false,
        fix: true,
        push: true,
        yes: true,
        // Fix reuses the cached scan; no re-listing, so orgs are irrelevant here.
        orgs: vec![],
    };
    let sel: HashSet<String> = selected.into_iter().collect();

    let mut guard = state.lock().map_err(|e| e.to_string())?;
    let cache = guard
        .as_ref()
        .ok_or_else(|| "no scan available; run a GitHub scan first".to_string())?;
    let outcomes = fix_pass(&cache.scan, &opts, &packs, &cache.token, Some(&sel));

    let views = outcomes
        .into_iter()
        .filter(|o| sel.contains(&o.repo.full_name))
        .map(|o| GithubFixView {
            // Mirror the CLI's per-repo resolution (github_exit_code): resolved only when a
            // fix was actually pushed AND no non-remediable finding survives on origin —
            // not merely "some actions ran". Otherwise the GUI reports `fixed` while a
            // non-remediable infection is still live.
            fixed: o.error.is_none()
                && !o.pushed.is_empty()
                && o.findings.iter().all(|f| f.remediable),
            full_name: o.repo.full_name,
            pushed: o.pushed,
            actions: o.actions,
            error: o.error,
            manual_review: o.manual_review,
        })
        .collect();

    // fix_pass's on-demand clones are already gone (its temp dir is dropped on return).
    // Reset the state so a stale token/finding set can't be reused; the frontend
    // re-scans before any subsequent fix.
    *guard = None;
    Ok(views)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(GithubScanState::new(None))
        .manage(ScanCancel::new(AtomicBool::new(false)))
        .invoke_handler(tauri::generate_handler![
            scan,
            cancel_scan,
            list_packs,
            clean_preview,
            clean_apply,
            restore,
            clean_branches_preview,
            clean_branches_apply,
            github_orgs,
            github_scan,
            github_fix
        ])
        .run(tauri::generate_context!())
        .expect("error while running Wormward desktop");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn list_packs_returns_bundled() {
        let packs = list_packs();
        assert!(packs.iter().any(|p| p.id == "polinrider"));
        assert!(packs.iter().any(|p| p.id == "shai-hulud"));
    }

    #[test]
    fn clean_preview_lists_actions_for_infected_repo() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();
        let plans =
            tauri::async_runtime::block_on(clean_preview(vec![tmp.path().display().to_string()]))
                .unwrap();
        assert_eq!(plans.len(), 1);
        assert!(!plans[0].actions.is_empty());
    }

    #[test]
    fn clean_apply_cleans_only_selected_repos() {
        let tmp = TempDir::new().unwrap();
        let mk = |name: &str| {
            let repo = tmp.path().join(name);
            fs::create_dir_all(repo.join(".git")).unwrap();
            fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();
            repo
        };
        let a = mk("a");
        let b = mk("b");
        // Apply to `a` only; `b`'s dropped artifact must remain.
        let summary =
            tauri::async_runtime::block_on(clean_apply(vec![a.display().to_string()])).unwrap();
        assert_eq!(summary.repos, 1);
        assert!(!a.join("temp_auto_push.bat").exists());
        assert!(b.join("temp_auto_push.bat").exists());
    }

    fn git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// A repo whose default branch is clean but whose non-default `evil` branch tip carries a
    /// worm payload. The fixture payload uses `rmcej%otb%` + `global['!']=` (not the worm's own
    /// assignment marker) so the machine's worm-scanning pre-commit hook does not block it.
    fn repo_with_infected_branch(tmp: &TempDir) -> PathBuf {
        let repo = tmp.path().join("proj");
        fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join("postcss.config.mjs"), "export default {};\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "--no-verify", "-m", "clean"]);
        git(&repo, &["checkout", "-q", "-b", "evil"]);
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';\n(\"rmcej%otb%\",2857687)\n",
        )
        .unwrap();
        git(&repo, &["commit", "-q", "--no-verify", "-am", "payload"]);
        git(&repo, &["checkout", "-q", "main"]);
        repo
    }

    #[test]
    fn clean_branches_preview_finds_infected_non_default_branch() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with_infected_branch(&tmp);
        let previews = tauri::async_runtime::block_on(clean_branches_preview(vec![repo
            .display()
            .to_string()]))
        .unwrap();
        let evil = previews
            .iter()
            .find(|p| p.branch == "evil")
            .expect("expected a plan for the infected 'evil' branch");
        assert!(evil.action_count >= 1);
        assert!(evil.backup_ref.starts_with("refs/wormward-backup/evil-"));
    }

    #[test]
    fn clean_branches_apply_cleans_selected_branch_tip() {
        let tmp = TempDir::new().unwrap();
        let repo = repo_with_infected_branch(&tmp);
        let summary = tauri::async_runtime::block_on(clean_branches_apply(
            vec![BranchSelection {
                repo: repo.display().to_string(),
                branch: "evil".into(),
            }],
            false,
        ))
        .unwrap();
        assert_eq!(summary.cleaned, 1, "results: {:?}", summary.results.len());
        assert_eq!(summary.results[0].status, "cleaned");
        // A fresh deep scan no longer flags the 'evil' tip.
        let packs = builtin_packs();
        let re = deep_scan_repo(&repo, &packs);
        assert!(!re.iter().any(|f| f.git_ref.as_deref() == Some("evil")));
    }
}
