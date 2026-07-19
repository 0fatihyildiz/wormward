pub mod engine;
pub mod finding;
pub mod git;
pub mod matchers;
pub mod pack;
pub mod remediate;
pub mod repo_files;
pub mod rewrite;
pub mod scanner;
pub mod walk;

pub use engine::{SigHit, SignatureEngine};
pub use finding::{Finding, FindingKind, OnlineVerdict, Severity};
pub use git::{
    amend_head, branch_remote, commit_paths, create_ref, delete_branch, force_push_with_lease,
    force_push_with_lease_to, push, reflog_has_amend, rev_parse, update_ref, verify_ref,
    worktree_add, worktree_add_new_branch, worktree_prune, worktree_remove,
};
pub use matchers::{sha256_hex, signature_matches, ContentSignature, SignatureKind};
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
pub use scanner::{deep_scan_repo, scan, scan_deep, scan_files, scan_repo, ScanReport};
pub use walk::{discover_repos, walk_repo_files};
