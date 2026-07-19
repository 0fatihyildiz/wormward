pub mod finding;
pub mod git;
pub mod matchers;
pub mod pack;
pub mod repo_files;
pub mod scanner;
pub mod walk;

pub use finding::{Finding, FindingKind, OnlineVerdict, Severity};
pub use git::reflog_has_amend;
pub use matchers::{sha256_hex, signature_matches, ContentSignature, SignatureKind};
pub use pack::{CampaignAnalyzer, Pack, PackError, PackManifest, ScannedFile};
pub use repo_files::{RepoFiles, WorkingTree};
pub use scanner::{scan, scan_files, scan_repo, ScanReport};
pub use walk::{discover_repos, walk_repo_files};
