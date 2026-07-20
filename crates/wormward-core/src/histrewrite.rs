//! Guarded full-history rewrite via `git filter-repo`, for the enterprise case tip/worktree/branch
//! remediation can't reach: the payload was committed and force-pushed, so it survives in old
//! commits/tags reachable by `git checkout`.
//!
//! HIGH BLAST RADIUS — this rewrites history (new commit hashes, requires a force-push and every
//! clone to reset). It is **marker redaction**, not a surgical strip: every literal injection
//! marker string is removed from every blob, which neutralizes the decoder and clears detection,
//! but a from-a-known-clean-commit rebuild is still the gold standard. Dry-run by default; the
//! caller must pass `dry_run = false` (behind an explicit `--yes`) to actually rewrite.

use std::path::Path;
use std::process::Command;

use crate::matchers::SignatureKind;
use crate::pack::Pack;

/// True if `git filter-repo` is installed (it is a separate tool from git).
pub fn git_filter_repo_available() -> bool {
    Command::new("git")
        .args(["filter-repo", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build `git filter-repo --replace-text` expressions from a pack's literal markers. Each line is
/// `literal:<marker>==>` (replace the marker with empty). Hash/entropy signatures are skipped (no
/// literal to redact).
pub fn replace_text_expressions(packs: &[Pack]) -> String {
    let mut lines = Vec::new();
    for pack in packs {
        for sig in &pack.manifest.content_signatures {
            if sig.kind == SignatureKind::Literal && !sig.value.contains("==>") {
                lines.push(format!("literal:{}==>", sig.value));
            }
        }
    }
    if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    }
}

/// Rewrite `repo`'s full history to redact injection markers. Returns the tool's output on success.
/// `dry_run` (the default posture) passes `--dry-run` so filter-repo writes its plan to
/// `.git/filter-repo/` WITHOUT changing the repo. The caller is responsible for having a backup and
/// for the subsequent force-push.
pub fn rewrite_history(repo: &Path, packs: &[Pack], dry_run: bool) -> Result<String, String> {
    if !git_filter_repo_available() {
        return Err("git-filter-repo is not installed (see https://github.com/newren/git-filter-repo)".into());
    }
    let exprs = replace_text_expressions(packs);
    if exprs.is_empty() {
        return Err("no literal markers to redact".into());
    }
    let expr_file = repo.join(".wormward-filter-repo-exprs.txt");
    std::fs::write(&expr_file, exprs).map_err(|e| e.to_string())?;
    let expr_path = expr_file.to_string_lossy().into_owned();
    let mut args = vec!["-C", repo.to_str().unwrap_or("."), "filter-repo", "--replace-text", &expr_path, "--force"];
    if dry_run {
        args.push("--dry-run");
    }
    let out = Command::new("git").args(&args).output().map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&expr_file);
    let out = out?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::matchers::ContentSignature;
    use crate::pack::{Pack, PackManifest};

    fn pack() -> Pack {
        let manifest = PackManifest {
            id: "demo".into(),
            name: "Demo".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec![],
            content_signatures: vec![
                ContentSignature { id: "primary".into(), kind: SignatureKind::Literal, value: r#"("rmcej%otb%",2857687)"#.into() },
                ContentSignature { id: "hash".into(), kind: SignatureKind::Sha256, value: "deadbeef".into() },
            ],
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            bad_packages: Default::default(),
            ioc_domains: vec![],
            analyzer: None,
            remediation: None,
        };
        Pack { manifest, analyzer: None }
    }

    #[test]
    fn expressions_redact_literals_only() {
        let e = replace_text_expressions(&[pack()]);
        assert!(e.contains(r#"literal:("rmcej%otb%",2857687)==>"#));
        assert!(!e.contains("deadbeef"), "sha256 signature has no literal to redact");
    }

    #[test]
    fn empty_packs_yield_no_expressions() {
        assert!(replace_text_expressions(&[]).is_empty());
    }
}
