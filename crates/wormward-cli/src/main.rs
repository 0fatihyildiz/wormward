mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use wormward_core::{
    amend_head, apply, apply_branch_cleans, commit_paths, deep_scan_repo, discover_repos,
    force_push_with_lease, now_secs, plan_branch_cleans, plan_remediation, push, restore, scan,
    scan_deep, scan_repo, BranchCleanStatus,
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
    },
    /// Restore files from the latest wormward backup.
    Restore {
        #[arg(default_value = ".")]
        dirs: Vec<PathBuf>,
    },
    /// Scan (and optionally remediate) every repo on the logged-in GitHub account.
    Github {
        /// GitHub token (else GITHUB_TOKEN/GH_TOKEN, else `gh auth token`).
        #[arg(long)]
        token: Option<String>,
        /// Directory to clone into (default: a temp dir removed after the run).
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

/// Exit code for the `github` command. Findings take precedence over per-repo errors:
/// a detected infection must surface as exit 1 even if another repo failed to process.
/// Only a clean-but-errored run exits 2. (Auth/enumeration failures before `run` are
/// handled separately and also exit 2.)
fn github_exit_code(outcomes: &[wormward_github::pipeline::RepoOutcome]) -> u8 {
    let any_findings = outcomes.iter().any(|o| !o.findings.is_empty());
    let any_error = outcomes.iter().any(|o| o.error.is_some());
    if any_findings {
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
            let mut total_actions = 0usize;
            let mut total_failed = 0usize;
            for dir in &dirs {
                for repo in discover_repos(dir) {
                    let findings = scan_repo(&repo, &packs);
                    let plan = plan_remediation(&findings, &packs);
                    // Cross-branch: plan cleans for infected tips of other branches.
                    let branch_plans = if all_branches {
                        plan_branch_cleans(&deep_scan_repo(&repo, &packs), &packs, now_secs())
                    } else {
                        Vec::new()
                    };
                    if plan.actions.is_empty() && plan.manual.is_empty() && branch_plans.is_empty() {
                        continue;
                    }
                    println!("{}", repo.display());
                    for a in &plan.actions {
                        println!("  would {}", describe_action(a));
                    }
                    for m in &plan.manual {
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
                    total_actions += plan.actions.len();
                    if do_apply {
                        let res = apply(&repo, &plan.actions, !no_backup);
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
                                    findings.iter().map(|f| f.campaign.as_str()).collect();
                                c.sort();
                                c.dedup();
                                c.join(", ")
                            };
                            let git_result = if rewrite {
                                amend_head(&repo, &paths).and_then(|_| force_push_with_lease(&repo))
                            } else {
                                commit_paths(&repo, &format!("wormward: remediate {campaigns}"), &paths)
                                    .and_then(|_| push(&repo))
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
                    }

                    // Cross-branch cleaning of other infected branch tips.
                    for bp in &branch_plans {
                        println!("  branch {}:", bp.branch);
                        for a in &bp.actions {
                            println!("    would {}", describe_action(a));
                        }
                        total_actions += bp.actions.len();
                    }
                    if do_apply && !branch_plans.is_empty() {
                        // Cleaning a branch inherently COMMITS (it rewrites a ref), so it is
                        // destructive and gated behind --yes exactly like the working-tree
                        // commit/push path. Without --yes it runs as a dry-run (plan only,
                        // no commits/refs). Force-push only with BOTH --push and --yes.
                        let outcomes = apply_branch_cleans(&branch_plans, !yes, do_push && yes);
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
                                    println!("  branch {}: skipped — {why}", o.plan.branch)
                                }
                                BranchCleanStatus::Failed(why) => {
                                    eprintln!("  branch {}: failed — {why}", o.plan.branch);
                                    total_failed += 1;
                                }
                                BranchCleanStatus::Planned => println!(
                                    "  branch {}: planned (re-run with --yes to clean and commit)",
                                    o.plan.branch
                                ),
                            }
                        }
                    }
                }
            }
            if !do_apply && total_actions > 0 {
                println!("\nDry run — re-run with --apply to make these changes.");
                return ExitCode::from(1);
            }
            if total_failed > 0 {
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
        Command::Github { token, clone_dir, include_forks, fix, push, yes, format } => {
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
            let opts = wormward_github::pipeline::GithubRunOpts {
                clone_dir,
                include_forks,
                // Pushing implies remediating.
                fix: fix || push,
                push,
                yes,
            };
            let outcomes = match wormward_github::pipeline::run(&opts, &host, &builtin_packs(), &token)
            {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let writes = yes && (fix || push);
            match format {
                OutputFormat::Text => print!("{}", report::render_github_text(&outcomes, writes)),
                OutputFormat::Json => println!("{}", report::render_github_json(&outcomes)),
            }
            ExitCode::from(github_exit_code(&outcomes))
        }
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
}
