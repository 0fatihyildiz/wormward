mod doctor;
mod report;
mod select;

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use wormward_core::{
    amend_head, apply, apply_branch_cleans, branch_remote, commit_paths, current_branch,
    deep_scan_repo, discover_repos, force_push_with_lease, force_push_with_lease_to, now_secs,
    plan_branch_cleans, plan_remediation, push, restore, scan, scan_deep, scan_repo,
    BranchCleanStatus,
};
use wormward_osm::OsmClient;
use wormward_packs::builtin_packs;

#[derive(Parser)]
#[command(name = "wormward", version, about = "Detect and remove supply-chain worms")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan directories for infections (read-only).
    Scan {
        /// Directories to scan (default: current directory).
        #[arg(default_value = ".")]
        dirs: Vec<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Cross-check npm-package and domain findings against the live OSM API.
        #[arg(long)]
        online: bool,
        /// OSM API token (else OSM_API_KEY env).
        #[arg(long)]
        osm_token: Option<String>,
        /// Also scan the tip of every local/remote branch (read-only, no checkout).
        #[arg(long)]
        deep: bool,
    },
    /// List the campaign packs compiled into this build.
    ListPacks,
    /// Check a single asset against the live OSM database.
    Check {
        /// report_type: package | repository | url | domain | ip | wallet | container
        #[arg(long = "type")]
        report_type: String,
        #[arg(long)]
        ecosystem: Option<String>,
        #[arg(long)]
        version: Option<String>,
        /// OSM API token (else OSM_API_KEY env).
        #[arg(long)]
        osm_token: Option<String>,
        identifier: String,
    },
    /// Remove detected infections from the working tree (dry-run unless --apply).
    Clean {
        #[arg(default_value = ".")]
        dirs: Vec<PathBuf>,
        /// Apply changes (default is a dry-run that only prints the plan).
        #[arg(long)]
        apply: bool,
        /// Disable the automatic backup taken before changes.
        #[arg(long)]
        no_backup: bool,
        /// After --apply, commit the cleaned files and push to the current branch.
        #[arg(long)]
        push: bool,
        /// With --push, amend HEAD instead of adding a commit, then push --force-with-lease.
        #[arg(long)]
        rewrite: bool,
        /// Also clean infected tips of branches other than the one checked out (via isolated
        /// worktrees). With --apply --push --yes, force-pushes each cleaned branch.
        #[arg(long = "all-branches")]
        all_branches: bool,
        /// Required confirmation for the destructive --push / --rewrite git operations.
        #[arg(long)]
        yes: bool,
        /// Fix every infected repo without the interactive selection prompt.
        #[arg(long)]
        all: bool,
    },
    /// Restore files from the latest wormward backup.
    Restore {
        #[arg(default_value = ".")]
        dirs: Vec<PathBuf>,
    },
    /// Scan (and optionally remediate) every repo you own or belong to via an organization.
    Github {
        /// GitHub token (else GITHUB_TOKEN/GH_TOKEN, else `gh auth token`).
        #[arg(long)]
        token: Option<String>,
        /// Directory where repos selected for fixing are cloned (default: a temp dir removed after the run).
        #[arg(long)]
        clone_dir: Option<PathBuf>,
        /// Include forks (default: skip them).
        #[arg(long)]
        include_forks: bool,
        /// Remediate infected working trees (requires --yes to write).
        #[arg(long)]
        fix: bool,
        /// Force-push cleaned default branches back to origin (backs up first; requires --yes).
        #[arg(long)]
        push: bool,
        /// Actually perform writes/pushes. Without this, only prints the plan.
        #[arg(long)]
        yes: bool,
        /// Fix every infected repo without the interactive selection prompt.
        #[arg(long)]
        all: bool,
        /// Restrict org scanning to these orgs (repeatable). Your own repos are always scanned.
        /// Omit to scan every org you belong to.
        #[arg(long = "org")]
        org: Vec<String>,
        /// Also run the read-only account-persistence audit (token scopes, SSH/GPG keys, app
        /// installations, per-repo webhooks/deploy-keys/runners). Runs automatically before a push.
        #[arg(long)]
        audit: bool,
        /// Assert you have rotated a potentially-stolen credential — overrides the fail-closed
        /// rotate-first gate that otherwise refuses to push when the audit flags a persistence risk.
        #[arg(long = "i-rotated")]
        i_rotated: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Machine-level PolinRider check (macOS): running loader processes (and later tainted
    /// caches + trigger paths). Complements the repo scan; read-only. Reuses the same
    /// obfuscation fingerprint as the file analyzer.
    Doctor {
        /// Poll for this many seconds (every 5s) to catch a loader that only respawns on a
        /// trigger — open your editor/projects during the window. Omit for a single snapshot.
        #[arg(long)]
        watch: Option<u64>,
        /// After the scan, delete tainted toolchain cache dirs (npx / TypeScript). Prompts
        /// first; the caches regenerate cleanly. Ignored with --watch.
        #[arg(long)]
        fix: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn osm_base_url() -> String {
    std::env::var("OSM_BASE_URL")
        .unwrap_or_else(|_| "https://api.opensourcemalware.com/functions/v1".to_string())
}

fn describe_action(a: &wormward_core::RemediationAction) -> String {
    use wormward_core::RemediationAction::*;
    match a {
        StripPayload { file, .. } => format!("strip payload from {}", file.display()),
        DeleteFile { file } => format!("delete {}", file.display()),
        RemoveGitignoreLine { file, line } => format!("remove '{line}' from {}", file.display()),
    }
}

/// Exit code for the `github` command, per the unified scan/clean/github convention:
///   0 — no findings, or every infected repo was actually remediated (fixed AND persisted).
///   1 — unresolved findings remain: a dry-run that found infections, a fix that failed or
///       could not persist (temp clone / no push), or manual/branch-only findings.
///   2 — a repo errored and no unresolved findings remain to take precedence over it.
/// A repo's findings only count as "resolved" when the cleaned default branch was actually
/// force-pushed back to origin with no error; a local-only clone or a dry-run leaves origin
/// infected, so it stays unresolved. (Auth/enumeration failures before the run are handled
/// separately and also exit 2.)
fn github_exit_code(outcomes: &[wormward_github::pipeline::RepoOutcome]) -> u8 {
    let mut any_unresolved = false;
    let mut any_error = false;
    for o in outcomes {
        if o.error.is_some() {
            any_error = true;
        }
        if !o.findings.is_empty() {
            // Resolved only if a fix was pushed AND no non-remediable finding survives.
            // Capability (campaign="generic"), npm, ioc and branch-only findings are never
            // auto-fixed, so a push alone must not mark the repo clean.
            let resolved =
                o.error.is_none() && !o.pushed.is_empty() && o.findings.iter().all(|f| f.remediable);
            if !resolved {
                any_unresolved = true;
            }
        }
    }
    if any_unresolved {
        1
    } else if any_error {
        2
    } else {
        0
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { dirs, format, online, osm_token, deep } => {
            for dir in &dirs {
                if !dir.exists() {
                    eprintln!("error: path does not exist: {}", dir.display());
                    return ExitCode::from(2);
                }
            }
            let mut report = if deep {
                scan_deep(&dirs, &builtin_packs())
            } else {
                scan(&dirs, &builtin_packs())
            };
            if online {
                let token = osm_token
                    .or_else(|| std::env::var("OSM_API_KEY").ok())
                    .filter(|t| !t.is_empty());
                let token = match token {
                    Some(t) => t,
                    None => {
                        eprintln!("error: --online requires an OSM token (--osm-token or OSM_API_KEY)");
                        return ExitCode::from(2);
                    }
                };
                let client = OsmClient::new(osm_base_url(), token);
                for w in wormward_osm::enrich(&mut report.findings, &client) {
                    eprintln!("warning: {w}");
                }
            }
            match format {
                OutputFormat::Text => print!("{}", report::render_text(&report)),
                OutputFormat::Json => println!("{}", report::render_json(&report)),
            }
            if report.findings.is_empty() {
                ExitCode::from(0)
            } else {
                ExitCode::from(1)
            }
        }
        Command::ListPacks => {
            for pack in builtin_packs() {
                println!("{} — {}", pack.manifest.id, pack.manifest.name);
            }
            ExitCode::from(0)
        }
        Command::Check { report_type, ecosystem, version, osm_token, identifier } => {
            let token = osm_token
                .or_else(|| std::env::var("OSM_API_KEY").ok())
                .filter(|t| !t.is_empty());
            let token = match token {
                Some(t) => t,
                None => {
                    eprintln!("error: check requires an OSM token (--osm-token or OSM_API_KEY)");
                    return ExitCode::from(2);
                }
            };
            let client = OsmClient::new(osm_base_url(), token);
            match client.check(&wormward_osm::CheckQuery {
                report_type,
                resource_identifier: identifier,
                ecosystem,
                version,
            }) {
                Ok(r) => {
                    println!("malicious: {}", r.malicious);
                    if !r.osm_url.is_empty() {
                        println!("osm_url: {}", r.osm_url);
                    }
                    if let Some(d) = r.details {
                        println!("threat: {} ({})", d.description, d.severity_level);
                    }
                    if r.malicious {
                        ExitCode::from(1)
                    } else {
                        ExitCode::from(0)
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Command::Clean {
            dirs,
            apply: do_apply,
            no_backup,
            push: do_push,
            rewrite,
            all_branches,
            yes,
            all,
        } => {
            for dir in &dirs {
                if !dir.exists() {
                    eprintln!("error: path does not exist: {}", dir.display());
                    return ExitCode::from(2);
                }
            }
            if do_push && !do_apply {
                eprintln!("error: --push requires --apply");
                return ExitCode::from(2);
            }
            if rewrite && !do_push {
                eprintln!("error: --rewrite requires --push");
                return ExitCode::from(2);
            }
            if (do_push || rewrite) && !yes {
                let op = if rewrite {
                    "amend HEAD and push --force-with-lease"
                } else {
                    "commit and push"
                };
                eprintln!("refusing to {op} without --yes (destructive). Re-run with --yes to confirm.");
                return ExitCode::from(2);
            }
            let packs = builtin_packs();

            // Phase 1: scan every repo and build its plan. Nothing is written here.
            struct RepoWork {
                repo: PathBuf,
                findings: Vec<wormward_core::Finding>,
                plan: wormward_core::RemediationPlan,
                branch_plans: Vec<wormward_core::BranchCleanPlan>,
                // Branch-tip findings that no clean action covers (non-remediable, e.g.
                // capability findings on a non-default branch) — surfaced, never cleaned.
                branch_manual: Vec<wormward_core::Finding>,
            }
            let mut works: Vec<RepoWork> = Vec::new();
            for dir in &dirs {
                for repo in discover_repos(dir) {
                    let findings = scan_repo(&repo, &packs);
                    let plan = plan_remediation(&findings, &packs);
                    // Cross-branch: plan cleans for infected tips of other branches.
                    let deep = if all_branches {
                        deep_scan_repo(&repo, &packs)
                    } else {
                        Vec::new()
                    };
                    let branch_plans = plan_branch_cleans(&deep, &packs, now_secs());
                    let branch_manual: Vec<wormward_core::Finding> = deep
                        .into_iter()
                        .filter(|f| f.git_ref.is_some() && !f.remediable)
                        .collect();
                    if plan.actions.is_empty()
                        && plan.manual.is_empty()
                        && branch_plans.is_empty()
                        && branch_manual.is_empty()
                    {
                        continue;
                    }
                    works.push(RepoWork { repo, findings, plan, branch_plans, branch_manual });
                }
            }

            // Print every repo's plan (the "would …" lines) up front, for both dry-run
            // and apply. total_actions drives the dry-run exit code.
            let mut total_actions = 0usize;
            for w in &works {
                println!("{}", w.repo.display());
                for a in &w.plan.actions {
                    println!("  would {}", describe_action(a));
                }
                for m in &w.plan.manual {
                    let file = m
                        .file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    let branch = m
                        .git_ref
                        .as_deref()
                        .map(|r| format!(" (branch: {r})"))
                        .unwrap_or_default();
                    println!("  manual: {} {}{} — {}", m.campaign, file, branch, m.evidence);
                }
                total_actions += w.plan.actions.len();
                for bp in &w.branch_plans {
                    println!("  branch {}:", bp.branch);
                    for a in &bp.actions {
                        println!("    would {}", describe_action(a));
                    }
                    total_actions += bp.actions.len();
                }
                for m in &w.branch_manual {
                    let file = m
                        .file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    let branch = m
                        .git_ref
                        .as_deref()
                        .map(|r| format!(" (branch: {r})"))
                        .unwrap_or_default();
                    println!("  manual: {} {}{} — {}", m.campaign, file, branch, m.evidence);
                }
            }

            // A pure dry-run lists the plan and never prompts or writes. Any findings at all —
            // auto-fixable, manual, or branch-tip — leave infections unresolved, so exit 1
            // whenever a repo made it into `works` (which only holds repos with findings).
            if !do_apply {
                if total_actions > 0 {
                    println!("\nDry run — re-run with --apply to make these changes.");
                }
                if works.is_empty() {
                    return ExitCode::from(0);
                }
                return ExitCode::from(1);
            }

            // Which repos have something to auto-fix (working-tree actions or branch cleans)?
            let fixable: Vec<usize> = works
                .iter()
                .enumerate()
                .filter(|(_, w)| !w.plan.actions.is_empty() || !w.branch_plans.is_empty())
                .map(|(i, _)| i)
                .collect();

            // With >1 infected repo, let the user deselect any they want left alone.
            // With 0 or 1, there is nothing to choose.
            let selected: HashSet<usize> = if fixable.len() >= 2 {
                let opts = select::SelectOpts {
                    bypass: all,
                    non_interactive: !select::stdio_is_tty(),
                };
                match select::select_repos(fixable, opts, |i| works[*i].repo.display().to_string()) {
                    Some(sel) => sel.into_iter().collect(),
                    // Aborted prompt (Ctrl-C / interrupt): fail closed — fix nothing. Fall
                    // through with an EMPTY selection so the unresolved-infection accounting
                    // below yields exit 1, exactly like deselecting every repo (exit-code
                    // contract: any infection remaining -> 1, never a clean 0).
                    None => {
                        eprintln!("selection aborted; no repos fixed");
                        HashSet::new()
                    }
                }
            } else {
                fixable.into_iter().collect()
            };

            // Phase 2: apply only to the selected repos. `total_unresolved` tracks infections
            // that remain after the run (deselected repos, manual findings, un-cleaned
            // branch tips) so the exit code is 1 whenever anything is left unfixed.
            let mut total_failed = 0usize;
            let mut total_unresolved = 0usize;
            for (i, w) in works.iter().enumerate() {
                if !selected.contains(&i) {
                    // Left alone by the user: its findings remain unresolved.
                    total_unresolved += 1;
                    continue;
                }
                let repo = &w.repo;
                // Findings that need manual handling are never auto-fixed — whether in the
                // working tree or on a non-default branch tip (e.g. capability findings).
                if !w.plan.manual.is_empty() || !w.branch_manual.is_empty() {
                    total_unresolved += 1;
                }
                let res = apply(repo, &w.plan.actions, !no_backup);
                for (a, e) in &res.skipped {
                    eprintln!("  skipped {}: {}", describe_action(a), e);
                }
                total_failed += res.skipped.len();
                if let Some(bd) = res.backup_dir {
                    println!("  backup: {}", bd.display());
                }
                if do_push && !res.applied.is_empty() {
                    // Stage ONLY the files wormward changed — never the backup dir
                    // or unrelated working-tree changes.
                    let paths: Vec<PathBuf> =
                        res.applied.iter().map(|a| a.target().to_path_buf()).collect();
                    let campaigns = {
                        let mut c: Vec<&str> =
                            w.findings.iter().map(|f| f.campaign.as_str()).collect();
                        c.sort();
                        c.dedup();
                        c.join(", ")
                    };
                    let git_result = if rewrite {
                        amend_head(repo, &paths).and_then(|_| match current_branch(repo) {
                            // Scope the force-push to exactly the checked-out branch — never a
                            // bare `push --force-with-lease`, which under push.default=matching
                            // would force EVERY matching branch, not just the remediated one.
                            Some(branch) => {
                                let remote = branch_remote(repo, &branch)
                                    .unwrap_or_else(|| "origin".to_string());
                                force_push_with_lease_to(
                                    repo,
                                    &remote,
                                    &format!("HEAD:refs/heads/{branch}"),
                                )
                            }
                            // Detached HEAD: no branch to scope to — fall back to the bare push.
                            None => force_push_with_lease(repo),
                        })
                    } else {
                        commit_paths(repo, &format!("wormward: remediate {campaigns}"), &paths)
                            .and_then(|_| push(repo))
                    };
                    match git_result {
                        Ok(()) => println!(
                            "  pushed{}",
                            if rewrite {
                                " (rewritten HEAD, force-with-lease)"
                            } else {
                                ""
                            }
                        ),
                        Err(e) => {
                            eprintln!("  git error: {e}");
                            eprintln!("  note: local changes were applied; run 'wormward restore' to revert, or fix git and retry");
                            total_failed += 1;
                        }
                    }
                }

                // Cross-branch cleaning of other infected branch tips.
                if !w.branch_plans.is_empty() {
                    // Cleaning a branch inherently COMMITS (it rewrites a ref), so it is
                    // destructive and gated behind --yes exactly like the working-tree
                    // commit/push path. Without --yes it runs as a dry-run (plan only,
                    // no commits/refs). Force-push only with BOTH --push and --yes.
                    let outcomes = apply_branch_cleans(&w.branch_plans, !yes, do_push && yes);
                    for o in &outcomes {
                        match &o.status {
                            BranchCleanStatus::Cleaned { backup_ref, pushed } => println!(
                                "  branch {}: cleaned{} (backup {})",
                                o.plan.branch,
                                if *pushed {
                                    ", pushed"
                                } else if do_push {
                                    ", not pushed (no upstream)"
                                } else {
                                    ""
                                },
                                backup_ref
                            ),
                            BranchCleanStatus::Skipped(why) => {
                                // e.g. a remote-tracking tip that needs --push: still infected.
                                println!("  branch {}: skipped — {why}", o.plan.branch);
                                total_unresolved += 1;
                            }
                            BranchCleanStatus::Failed(why) => {
                                eprintln!("  branch {}: failed — {why}", o.plan.branch);
                                total_failed += 1;
                            }
                            BranchCleanStatus::Planned => {
                                println!(
                                    "  branch {}: planned (re-run with --yes to clean and commit)",
                                    o.plan.branch
                                );
                                total_unresolved += 1;
                            }
                        }
                    }
                }
            }
            if total_failed > 0 || total_unresolved > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::from(0)
            }
        }
        Command::Restore { dirs } => {
            for dir in &dirs {
                for repo in discover_repos(dir) {
                    let r = restore(&repo);
                    if let Some(bd) = r.backup_dir {
                        println!(
                            "{}: restored {} file(s) from {}",
                            repo.display(),
                            r.restored.len(),
                            bd.display()
                        );
                    }
                }
            }
            ExitCode::from(0)
        }
        Command::Github {
            token,
            clone_dir,
            include_forks,
            fix,
            push,
            yes,
            all,
            org,
            audit,
            i_rotated,
            format,
        } => {
            // --push and --fix are destructive; require explicit --yes to write.
            if push && !yes {
                eprintln!("refusing to force-push without --yes (destructive). Re-run with --yes to confirm.");
                return ExitCode::from(2);
            }
            if fix && !yes {
                eprintln!("note: --fix without --yes is a dry-run; re-run with --yes to write.");
            }
            let token = match wormward_github::resolve_token(token.as_deref()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let host = wormward_github::GitHubHost::new(token.clone());
            let mut opts = wormward_github::pipeline::GithubRunOpts {
                clone_dir,
                include_forks,
                // Pushing implies remediating.
                fix: fix || push,
                push,
                yes,
                orgs: org,
            };

            // A fix only persists if it has somewhere to land: a push target OR an explicit
            // --clone-dir. Without either, remediation is applied+committed into a temp clone
            // that is dropped at end of run, so nothing survives. Downgrade to a dry-run
            // (report the plan, write nothing) so the outcome reflects reality rather than a
            // false "applied".
            let persistent_dest = opts.push || opts.clone_dir.is_some();
            if opts.fix && opts.yes && !persistent_dest {
                eprintln!(
                    "note: --fix without --push or --clone-dir cannot persist changes (the temp clone is discarded); running as a dry-run. Re-run with --clone-dir <dir> or --push to apply."
                );
                opts.yes = false;
            }
            let packs = builtin_packs();
            // Progress only when a human is watching: text mode with stderr on a TTY.
            // JSON mode, pipes and CI logs stay byte-identical.
            let show_progress = matches!(format, OutputFormat::Text)
                && std::io::IsTerminal::is_terminal(&std::io::stderr());
            // Phase 1: enumerate → API-scan every branch tip (no clones), to learn
            // which repos are infected.
            let scan_result = wormward_github::pipeline::scan_pass_with_progress(
                &opts,
                &host,
                &packs,
                &token,
                &|p: wormward_github::pipeline::ScanProgress| {
                    if show_progress {
                        // \r + width-clamped pad so a shorter repo name leaves no
                        // residue from the previous, longer line.
                        eprint!("\r  scanning {}/{} {:<60.60}", p.done, p.total, p.repo);
                    }
                },
            );
            if show_progress {
                eprintln!(); // finish the progress line before any other output
            }
            let scan = match scan_result {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };

            // Account-persistence audit + rotate-first gate. Run when --audit, or automatically
            // before any real push — a stolen credential plus account persistence (over-privileged
            // token, injected key, rogue runner) is the re-infection vector, so pushing a cleaned
            // repo with the same token just re-opens the loop.
            let will_push = opts.yes && opts.fix && opts.push;
            let account_audit = if audit || will_push {
                let infected: Vec<wormward_github::RepoRef> = scan
                    .repos()
                    .iter()
                    .filter(|sr| sr.is_infected())
                    .map(|sr| sr.repo.clone())
                    .collect();
                Some(wormward_github::audit::audit_account(&host, &infected))
            } else {
                None
            };
            // Fail-closed: a blocked audit refuses the push unless the user asserts --i-rotated.
            if let Some(a) = &account_audit {
                if will_push && a.blocked && !i_rotated {
                    eprintln!(
                        "\nRefusing to push: the account audit flagged a persistence risk (below).\n\
                         Rotate your GitHub token (revoke the old one), review the flagged keys/\n\
                         runners/webhooks, then re-run with a fresh minimal-scope token — or pass\n\
                         --i-rotated to override."
                    );
                    opts.yes = false; // downgrade to a dry-run: report, write nothing, push nothing
                }
            }

            // Selection only matters when we will actually write (fix/push + yes). A
            // dry-run never prompts. Only offer repos that `fix_pass` can actually
            // remediate (a working-tree action on the default branch); repos infected
            // only on other branches are still reported but not selectable. With >1 such
            // repo, let the user deselect any to leave alone; JSON output or no TTY keeps
            // all.
            // Reflect the post-downgrade reality: `opts.yes` is cleared above when a fix
            // cannot persist, so a non-persistent `--fix --yes` is treated as a dry-run here.
            let writes = opts.yes && opts.fix;
            let fixable = scan.fixable_full_names(&packs);
            let selected: Option<HashSet<String>> = if writes && fixable.len() >= 2 {
                let sel_opts = select::SelectOpts {
                    bypass: all,
                    non_interactive: matches!(format, OutputFormat::Json) || !select::stdio_is_tty(),
                };
                match select::select_repos(fixable, sel_opts, |n| n.clone()) {
                    Some(sel) => Some(sel.into_iter().collect()),
                    // Aborted prompt (Ctrl-C / interrupt): fail closed — fix nothing. Fall
                    // through with an EMPTY selection (NOT `None`, which fixes all) so
                    // github_exit_code sees the infections unremediated and returns 1.
                    None => {
                        eprintln!("selection aborted; no repos fixed");
                        Some(HashSet::new())
                    }
                }
            } else {
                None
            };

            // Phase 2: fix only the selected repos (cloned on demand by fix_pass).
            let outcomes = wormward_github::pipeline::fix_pass(
                &scan,
                &opts,
                &packs,
                &token,
                selected.as_ref(),
            );
            match format {
                OutputFormat::Text => {
                    print!("{}", report::render_github_text(&outcomes, writes));
                    if let Some(a) = &account_audit {
                        print!("{}", report::render_audit_text(&a.findings));
                    }
                }
                OutputFormat::Json => match &account_audit {
                    Some(a) => {
                        let v = serde_json::json!({ "repos": &outcomes, "account_audit": &a.findings });
                        println!("{}", serde_json::to_string_pretty(&v).unwrap());
                    }
                    None => println!("{}", report::render_github_json(&outcomes)),
                },
            }
            let audit_blocked = account_audit.as_ref().is_some_and(|a| a.blocked);
            ExitCode::from(github_exit_code(&outcomes).max(u8::from(audit_blocked)))
        }
        Command::Doctor { watch, fix, format } => match watch {
            None => {
                let report = doctor::check();
                match format {
                    OutputFormat::Text => print!("{}", doctor::render_text(&report)),
                    OutputFormat::Json => println!("{}", doctor::render_json(&report)),
                }
                if fix {
                    for dir in doctor::affected_cache_dirs(&report) {
                        let ok = dialoguer::Confirm::new()
                            .with_prompt(format!(
                                "Delete tainted cache dir {}? (regenerates cleanly)",
                                dir.display()
                            ))
                            .default(false)
                            .interact()
                            .unwrap_or(false);
                        if ok {
                            match std::fs::remove_dir_all(&dir) {
                                Ok(()) => println!("  removed {}", dir.display()),
                                Err(e) => eprintln!("  failed to remove {}: {e}", dir.display()),
                            }
                        }
                    }
                }
                ExitCode::from(u8::from(report.has_findings()))
            }
            Some(secs) => {
                let _ = fix; // --fix is a no-op in watch mode (process-focused)
                // Poll across the window so a loader that only fires on a trigger is caught.
                let interval = 5u64;
                let iters = (secs / interval).max(1);
                let mut ever = false;
                for i in 0..iters {
                    let report = doctor::check();
                    ever |= report.has_findings();
                    println!("poll {}/{}: {} loader process(es)", i + 1, iters, report.processes.len());
                    for h in &report.processes {
                        println!("  ✗ pid {} — {}", h.pid, h.reason);
                    }
                    if i + 1 < iters {
                        std::thread::sleep(std::time::Duration::from_secs(interval));
                    }
                }
                if !ever {
                    println!("✓ no loader seen across the {secs}s watch window");
                }
                ExitCode::from(u8::from(ever))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::github_exit_code;
    use std::path::PathBuf;
    use wormward_core::{Finding, FindingKind, Severity};
    use wormward_github::pipeline::RepoOutcome;
    use wormward_github::RepoRef;

    fn repo_ref(name: &str) -> RepoRef {
        RepoRef {
            full_name: name.into(),
            clone_url: "https://x/r.git".into(),
            default_branch: "main".into(),
            fork: false,
        }
    }

    fn finding() -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: Severity::Critical,
            repo: PathBuf::from("/r"),
            file: Some(PathBuf::from("postcss.config.mjs")),
            signature_id: "primary".into(),
            kind: FindingKind::ContentSignature,
            evidence: "content signature matched".into(),
            remediable: true,
            online: None,
            git_ref: None,
        }
    }

    fn outcome(findings: Vec<Finding>, error: Option<String>) -> RepoOutcome {
        RepoOutcome {
            repo: repo_ref("me/proj"),
            findings,
            actions: vec![],
            pushed: vec![],
            error,
            manual_review: false,
        }
    }

    #[test]
    fn findings_take_precedence_over_errors() {
        // One repo has a finding, another only errored → findings win (exit 1).
        let outcomes =
            vec![outcome(vec![finding()], None), outcome(vec![], Some("clone failed".into()))];
        assert_eq!(github_exit_code(&outcomes), 1);
    }

    #[test]
    fn finding_and_error_on_same_repo_exits_1() {
        let outcomes = vec![outcome(vec![finding()], Some("push failed".into()))];
        assert_eq!(github_exit_code(&outcomes), 1);
    }

    #[test]
    fn error_only_exits_2() {
        let outcomes = vec![outcome(vec![], Some("clone failed".into()))];
        assert_eq!(github_exit_code(&outcomes), 2);
    }

    #[test]
    fn clean_run_exits_0() {
        let outcomes = vec![outcome(vec![], None)];
        assert_eq!(github_exit_code(&outcomes), 0);
    }

    #[test]
    fn dry_run_with_findings_exits_1() {
        // Infections found but nothing was pushed (dry-run / no persistent destination):
        // the origin is still infected, so the findings are unresolved.
        let outcomes = vec![outcome(vec![finding()], None)];
        assert_eq!(github_exit_code(&outcomes), 1);
    }

    #[test]
    fn successful_fix_and_push_exits_0() {
        // Findings fixed AND persisted to origin (force-pushed) with no error → resolved.
        let mut o = outcome(vec![finding()], None);
        o.pushed = vec!["main".into()];
        assert_eq!(github_exit_code(&[o]), 0);
    }

    #[test]
    fn push_with_surviving_non_remediable_finding_exits_1() {
        // A remediable pack finding is fixed and pushed, but a non-remediable capability
        // finding survives on origin's default branch → NOT resolved (regression guard).
        let mut cap = finding();
        cap.kind = FindingKind::Capability;
        cap.campaign = "generic".into();
        cap.remediable = false;
        let mut o = outcome(vec![finding(), cap], None);
        o.pushed = vec!["main".into()];
        assert_eq!(github_exit_code(&[o]), 1);
    }

    #[test]
    fn per_repo_error_exits_2() {
        // A repo failed to process (e.g. clone/auth) and left no unresolved findings.
        let outcomes = vec![outcome(vec![], Some("clone failed".into()))];
        assert_eq!(github_exit_code(&outcomes), 2);
    }
}
