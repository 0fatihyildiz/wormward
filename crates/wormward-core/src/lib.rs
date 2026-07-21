pub mod capability;
pub mod engine;
pub mod finding;
pub mod git;
pub mod histrewrite;
pub mod hunt;
pub mod iocs;
pub mod lockfile;
pub mod matchers;
pub mod osv;
pub mod pack;
pub mod remediate;
pub mod repo_files;
pub mod rewrite;
pub mod rules;
pub mod sarif;
pub mod scanner;
pub mod surface;
pub mod typosquat;
pub mod walk;

pub use engine::{SigHit, SignatureEngine};
pub use finding::{Finding, FindingKind, OnlineVerdict, Severity};
pub use hunt::{baseline, extract_new_iocs, NewIocs};
pub use iocs::{collect_iocs, to_ioc_list, to_npm_report, to_stix, Iocs};
pub use histrewrite::{git_filter_repo_available, replace_text_expressions, rewrite_history};
pub use lockfile::{check_lockfiles, parse_lockfile, version_matches, LockEntry};
pub use osv::{osv_available, osv_scan, OsvHit};
pub use rules::{to_sigma, to_suricata, to_yara};
pub use sarif::to_sarif;
pub use git::{
    amend_head, branch_remote, commit_paths, create_ref, current_branch, delete_branch,
    force_push_with_lease, force_push_with_lease_to, push, reflog_has_amend, rev_parse, update_ref,
    verify_ref, worktree_add, worktree_add_new_branch, worktree_prune, worktree_remove,
};
pub use matchers::{shannon_entropy, sha256_hex, ContentSignature, SignatureKind};
pub use pack::{CampaignAnalyzer, Pack, PackError, PackManifest, ScannedFile};
pub use remediate::{
    action_for, apply, plan_remediation, restore, RemediationAction, RemediationPlan,
    RemediationResult, RestoreResult,
};
pub use repo_files::{GitTree, RepoFiles, WorkingTree};
pub use rewrite::{
    apply_branch_cleans, now_secs, plan_branch_cleans, BranchCleanOutcome, BranchCleanPlan,
    BranchCleanStatus,
};
pub use scanner::{
    deep_scan_repo, scan, scan_capabilities, scan_date_skew, scan_deep, scan_dependency_typosquats,
    scan_files, scan_history, scan_injection_structure,
    scan_node_modules, scan_repo, scan_streaming, scan_tree, RepoScanEvent, ScanPhase, ScanReport,
};
pub use walk::{
    discover_repos, discover_repos_cancellable, walk_repo_files, walk_repo_files_cancellable,
};
