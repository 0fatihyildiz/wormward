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
use wormward_github::pipeline::{
    fix_pass, scan_pass_with_progress_cancellable, GithubRunOpts, ScanPass,
};
use wormward_github::{resolve_token, GitHubHost, RepoHost};
use wormward_osm::{check_npm_package, enrich, OsmClient, PackageCheck};
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

/// Per-repo progress emitted on the `local-scan-progress` event as a scan runs. `phase` is
/// "scanning" (a repo just started) or "scanned" (finished; `findings` is its result count).
#[derive(Serialize, Clone)]
pub struct ScanProgress {
    phase: &'static str,
    done: usize,
    total: usize,
    repo: String,
    findings: usize,
}

/// Cross-command cancel flag for the running local scan. `cancel_scan` sets it; the `scan`
/// command clears it at the start of each run. It is polled between repos and per file within
/// a repo, so Stop is honored even in the middle of one large repository.
type ScanCancel = Arc<AtomicBool>;

/// Cross-command cancel flag for a running GitHub account scan. `cancel_github_scan` sets it;
/// `github_scan` clears it at the start and skips the remaining repos once it's set. A distinct
/// newtype (not a bare `Arc<AtomicBool>` alias) so Tauri's type-keyed state doesn't collide with
/// `ScanCancel`.
struct GithubScanCancel(Arc<AtomicBool>);

#[tauri::command]
async fn scan(
    dirs: Vec<String>,
    deep: bool,
    online: bool,
    token: Option<String>,
    history: bool,
    include_community: bool,
    osv: bool,
    window: tauri::Window,
    cancel: tauri::State<'_, ScanCancel>,
) -> Result<ScanResult, String> {
    let paths = to_paths(dirs);
    // Fresh run: clear any stale cancel request from a previous scan.
    cancel.store(false, Ordering::Relaxed);
    let flag = cancel.inner().clone(); // Arc<AtomicBool> shared with `cancel_scan`

    // Run the CPU-bound scan on a BLOCKING thread so this async command yields the executor.
    // Otherwise the synchronous scan loop pins the async worker and the `cancel_scan` command
    // can't run concurrently — the Stop button would set the flag only after the scan finished.
    let scan_flag = flag.clone();
    let scan_window = window.clone();
    let (mut report, osv_skipped) = tauri::async_runtime::spawn_blocking(move || {
        let packs = builtin_packs();
        // Parallel, cancellable scan: emit a "scanning" event when a repo starts and a
        // "scanned" event (with its finding count) when it finishes, for the live log.
        let mut report =
            scan_streaming(&paths, &packs, deep, &scan_flag, &|e: wormward_core::RepoScanEvent| {
                let phase = match e.phase {
                    wormward_core::ScanPhase::Scanning => "scanning",
                    wormward_core::ScanPhase::Scanned => "scanned",
                };
                let _ = scan_window.emit(
                    "local-scan-progress",
                    ScanProgress {
                        phase,
                        done: e.done,
                        total: e.total,
                        repo: e.repo.display().to_string(),
                        findings: e.findings,
                    },
                );
            });
        // Opt-in extra passes (mirror the CLI's `--history`/`--osv`/`--include-community`). Skip
        // when the user has already cancelled the main scan, and poll the flag between repos so a
        // long history pickaxe still honors Stop.
        if history && !scan_flag.load(Ordering::Relaxed) {
            for dir in &paths {
                for repo in discover_repos(dir) {
                    if scan_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    report.findings.extend(wormward_core::scan_history(&repo, &packs));
                    report.findings.extend(wormward_core::scan_date_skew(&repo));
                }
            }
        }
        // Community-sourced leads carry a `pkg-community:` id and are low-confidence; drop them
        // unless the user opted in, so a single-source list never inflates the default verdict.
        if !include_community {
            report.findings.retain(|f| !f.signature_id.starts_with("pkg-community:"));
        }
        // OSV lockfile gating via the external `osv-scanner`, when requested and installed.
        let mut osv_skipped = false;
        if osv && !scan_flag.load(Ordering::Relaxed) {
            if wormward_core::osv_available() {
                for dir in &paths {
                    for hit in wormward_core::osv_scan(dir) {
                        report.findings.push(wormward_core::Finding {
                            campaign: "osv".into(),
                            severity: wormward_core::Severity::High,
                            repo: dir.clone(),
                            file: None,
                            signature_id: format!("osv:{}", hit.advisory),
                            kind: wormward_core::FindingKind::NpmPackage,
                            evidence: format!(
                                "OSV malicious-package advisory {} for '{}'",
                                hit.advisory, hit.package
                            ),
                            remediable: false,
                            online: None,
                            git_ref: None,
                        });
                    }
                }
            } else {
                osv_skipped = true;
            }
        }
        (report, osv_skipped)
    })
    .await
    .map_err(|e| e.to_string())?;

    let cancelled = flag.load(Ordering::Relaxed);
    let mut warnings = Vec::new();
    if osv_skipped {
        warnings
            .push("osv-scanner is not installed — lockfile (OSV) checks were skipped.".to_string());
    }
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
/// next file (or repo boundary) and returns a partial report with `cancelled = true`.
#[tauri::command]
fn cancel_scan(cancel: tauri::State<'_, ScanCancel>) {
    cancel.store(true, Ordering::Relaxed);
}

/// Request cancellation of a running GitHub account scan. Cooperative: the remaining repos are
/// skipped (reported clean) and the partial result returns.
#[tauri::command]
fn cancel_github_scan(cancel: tauri::State<'_, GithubScanCancel>) {
    cancel.0.store(true, Ordering::Relaxed);
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

/// Export takedown-ready IOCs from the loaded packs as a machine-readable feed (`list`), an npm
/// abuse-report draft (`npm-report`), or a STIX 2.1 bundle (`stix`).
#[tauri::command]
fn export_iocs(format: String) -> String {
    let packs = builtin_packs();
    match format.as_str() {
        "npm-report" => wormward_core::to_npm_report(&packs),
        "stix" => wormward_core::to_stix(&packs),
        _ => wormward_core::to_ioc_list(&packs),
    }
}

/// Pre-install delivery-vector check: fetch an npm package's metadata + entry (no install, no
/// execution) and flag dropper behaviour before it ever runs.
#[tauri::command]
fn check_package(name: String) -> Result<PackageCheck, String> {
    check_npm_package(name.trim()).map_err(|e| e.to_string())
}

#[tauri::command]
async fn clean_preview(dirs: Vec<String>) -> Result<Vec<RepoPlan>, String> {
    // spawn_blocking + rayon: the preview re-scan is as CPU/I/O-heavy as a full scan, so it
    // must neither pin the async executor nor run repo-by-repo sequentially (it used to do
    // both, which made "Clean" take a multiple of the scan the user had just watched).
    tauri::async_runtime::spawn_blocking(move || {
        use rayon::prelude::*;
        let packs = builtin_packs();
        let mut repos: Vec<PathBuf> = Vec::new();
        for dir in to_paths(dirs) {
            repos.extend(discover_repos(&dir));
        }
        repos.sort();
        repos.dedup();
        let mut out: Vec<RepoPlan> = repos
            .par_iter()
            .filter_map(|repo| {
                let findings = scan_repo(repo, &packs);
                let plan = plan_remediation(&findings, &packs);
                if plan.actions.is_empty() && plan.manual.is_empty() {
                    return None;
                }
                Some(RepoPlan {
                    repo: repo.display().to_string(),
                    actions: plan.actions,
                    manual: plan.manual,
                })
            })
            .collect();
        // Parallel collection order is nondeterministic; keep the list stable for the UI.
        out.sort_by(|a, b| a.repo.cmp(&b.repo));
        out
    })
    .await
    .map_err(|e| e.to_string())
}

/// Clean exactly the repos the user selected (paths from `clean_preview`), rather than
/// re-discovering everything under the scanned dirs. Repos with no applicable action are a
/// no-op.
#[tauri::command]
async fn clean_apply(repos: Vec<String>) -> Result<CleanSummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use rayon::prelude::*;
        let packs = builtin_packs();
        // The freshness re-scan before writing (repos may have changed since the preview) runs
        // per selected repo in parallel; each repo's apply is independent (its own working tree
        // and backup dir), so the whole per-repo unit parallelizes safely.
        let results: Vec<_> = to_paths(repos)
            .par_iter()
            .filter_map(|repo| {
                let findings = scan_repo(repo, &packs);
                let plan = plan_remediation(&findings, &packs);
                if plan.actions.is_empty() {
                    return None;
                }
                Some(apply(repo, &plan.actions, true))
            })
            .collect();
        let mut summary = CleanSummary {
            repos: 0,
            applied: 0,
            skipped: Vec::new(),
            backups: Vec::new(),
        };
        for res in results {
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
        summary
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn restore(dirs: Vec<String>) -> Result<RestoreSummary, String> {
    // spawn_blocking: rediscovery walks the whole tree; don't pin the async executor.
    tauri::async_runtime::spawn_blocking(move || {
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
        summary
    })
    .await
    .map_err(|e| e.to_string())
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
    // spawn_blocking + rayon: a deep scan per repo is the heaviest scan there is; run repos in
    // parallel and keep the async executor free (this used to be a sequential loop on it).
    tauri::async_runtime::spawn_blocking(move || {
        use rayon::prelude::*;
        let packs = builtin_packs();
        let ts = now_secs();
        let mut repos: Vec<PathBuf> = Vec::new();
        for dir in to_paths(dirs) {
            repos.extend(discover_repos(&dir));
        }
        repos.sort();
        repos.dedup();
        let mut out: Vec<BranchCleanPreview> = repos
            .par_iter()
            .flat_map(|repo| {
                let findings = deep_scan_repo(repo, &packs);
                plan_branch_cleans(&findings, &packs, ts)
                    .into_iter()
                    .map(|plan| BranchCleanPreview {
                        repo: plan.repo.display().to_string(),
                        branch: plan.branch,
                        backup_ref: plan.backup_ref,
                        action_count: plan.actions.len(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        out.sort_by(|a, b| (&a.repo, &a.branch).cmp(&(&b.repo, &b.branch)));
        out
    })
    .await
    .map_err(|e| e.to_string())
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
    let outcomes = tauri::async_runtime::spawn_blocking(move || {
        use rayon::prelude::*;
        let packs = builtin_packs();
        let ts = now_secs();

        // Group the selected branches by repo so each repo is deep-scanned once; the per-repo
        // deep scans run in parallel (they only read git objects, no working-tree writes).
        let mut by_repo: HashMap<String, HashSet<String>> = HashMap::new();
        for s in selected {
            by_repo.entry(s.repo).or_default().insert(s.branch);
        }

        let plans: Vec<_> = by_repo
            .into_par_iter()
            .flat_map(|(repo_str, branches)| {
                let repo = PathBuf::from(&repo_str);
                let findings = deep_scan_repo(&repo, &packs);
                plan_branch_cleans(&findings, &packs, ts)
                    .into_iter()
                    .filter(|plan| branches.contains(&plan.branch))
                    .collect::<Vec<_>>()
            })
            .collect();

        apply_branch_cleans(&plans, false, push)
    })
    .await
    .map_err(|e| e.to_string())?;
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
    // Network call (and possibly a `gh auth token` subprocess) — keep it off the async executor.
    tauri::async_runtime::spawn_blocking(move || {
        let token = resolve_token(token.as_deref()).map_err(|e| e.to_string())?;
        GitHubHost::new(token).list_orgs().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn github_scan(
    token: Option<String>,
    include_forks: bool,
    orgs: Vec<String>,
    window: tauri::Window,
    state: tauri::State<'_, GithubScanState>,
    cancel: tauri::State<'_, GithubScanCancel>,
) -> Result<Vec<GithubRepoView>, String> {
    let token = resolve_token(token.as_deref()).map_err(|e| e.to_string())?;
    // Fresh run: clear any stale cancel request from a previous scan.
    cancel.0.store(false, Ordering::Relaxed);
    let flag: Arc<AtomicBool> = cancel.0.clone();
    // The account scan is long, network-bound work; run it on a blocking thread so the async
    // executor stays free — otherwise the Stop command queues behind the scan (the same bug the
    // local `scan` command fixed with spawn_blocking) and the UI stutters for its whole duration.
    let scan_token = token.clone();
    let scan = tauri::async_runtime::spawn_blocking(move || {
        let host = GitHubHost::new(scan_token.clone());
        let packs = builtin_packs();
        let opts = GithubRunOpts {
            clone_dir: None,
            include_forks,
            fix: false,
            push: false,
            yes: false,
            orgs,
        };
        scan_pass_with_progress_cancellable(&opts, &host, &packs, &scan_token, &flag, &|p| {
            // Best-effort: a failed emit must never fail the scan.
            let _ = window.emit("github-scan-progress", &p);
        })
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    let packs = builtin_packs();
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
    let sel: HashSet<String> = selected.into_iter().collect();

    // Take the cache out of managed state up front: the state resets whether the fix succeeds
    // or not (a stale token/finding set must never be reused; the frontend re-scans before any
    // subsequent fix), and taking ownership lets the clone-heavy fix run on a blocking thread
    // without holding the state mutex across it.
    let cache = state
        .lock()
        .map_err(|e| e.to_string())?
        .take()
        .ok_or_else(|| "no scan available; run a GitHub scan first".to_string())?;

    tauri::async_runtime::spawn_blocking(move || {
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
        let outcomes = fix_pass(&cache.scan, &opts, &packs, &cache.token, Some(&sel));

        // fix_pass's on-demand clones are already gone (its temp dir is dropped on return).
        outcomes
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
            .collect()
    })
    .await
    .map_err(|e| e.to_string())
}

/// Machine-level PolinRider check (running loader, tainted caches, trigger paths). Runs on a
/// blocking thread since it shells out to `ps`/`npm`.
#[tauri::command]
async fn doctor() -> Result<wormward_doctor::DoctorReport, String> {
    tauri::async_runtime::spawn_blocking(wormward_doctor::check)
        .await
        .map_err(|e| e.to_string())
}

/// Delete a tainted toolchain cache directory. Guarded: only known cache targets are removable,
/// so the frontend can never be tricked into deleting an arbitrary path.
#[tauri::command]
fn doctor_clear_cache(dir: String) -> Result<(), String> {
    let path = std::path::PathBuf::from(&dir);
    if !wormward_doctor::cache_targets().contains(&path) {
        return Err("refusing to delete a directory that is not a known toolchain cache".into());
    }
    // Regenerable caches are removed whole; global `node_modules` roots keep the user's packages
    // and only shed the tainted dropped files. Anything the app can't delete (e.g. a root-owned
    // /usr/local path) is reported with an actionable message instead of a raw errno.
    match wormward_doctor::clear_cache_dir(&path) {
        Ok(unremovable) if unremovable.is_empty() => Ok(()),
        Ok(unremovable) => {
            let paths = unremovable
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" ");
            Err(format!(
                "Removed what I could, but {} tainted file(s) under {} are owned by the system and \
                 need elevated permissions. Remove them with: sudo rm -f {paths}",
                unremovable.len(),
                path.display(),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(format!(
            "Can't remove {p} — it's owned by another user (likely root). Remove it manually with: \
             sudo rm -rf {p}",
            p = path.display(),
        )),
        Err(e) => Err(format!("Couldn't clean {}: {e}", path.display())),
    }
}

/// Apply the safe trigger hardening (npm/pnpm ignore-scripts=true). Returns a line per fix applied.
#[tauri::command]
async fn doctor_harden_triggers() -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(wormward_doctor::fix_triggers)
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(GithubScanState::new(None))
        .manage(ScanCancel::new(AtomicBool::new(false)))
        .manage(GithubScanCancel(Arc::new(AtomicBool::new(false))))
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
            github_fix,
            doctor,
            doctor_clear_cache,
            doctor_harden_triggers,
            cancel_github_scan,
            export_iocs,
            check_package
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
