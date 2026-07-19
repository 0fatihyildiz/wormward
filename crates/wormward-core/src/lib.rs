pub mod capability;
pub mod finding;
pub mod git;
pub mod matchers;
pub mod pack;
pub mod remediate;
pub mod repo_files;
pub mod scanner;
pub mod surface;
pub mod walk;

pub use finding::{Finding, FindingKind, OnlineVerdict, Severity};
pub use git::{amend_head, commit_paths, force_push_with_lease, push, reflog_has_amend};
pub use matchers::{shannon_entropy, sha256_hex, signature_matches, ContentSignature, SignatureKind};
pub use pack::{CampaignAnalyzer, Pack, PackError, PackManifest, ScannedFile};
pub use remediate::{
    apply, plan_remediation, restore, RemediationAction, RemediationPlan, RemediationResult,
    RestoreResult,
};
pub use repo_files::{GitTree, RepoFiles, WorkingTree};
pub use scanner::{deep_scan_repo, scan, scan_deep, scan_files, scan_repo, ScanReport};
pub use walk::{discover_repos, walk_repo_files};
