use std::path::{Path, PathBuf};
use std::process::Command;

use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;

use crate::finding::{Finding, FindingKind, Severity};
use crate::git::reflog_has_amend;
use crate::matchers::signature_matches;
use crate::pack::{Pack, ScannedFile};
use crate::repo_files::{GitTree, RepoFiles, WorkingTree};
use crate::walk::discover_repos;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub repos_scanned: usize,
}

fn build_globset(patterns: &[String]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
        // Bare filename patterns should also match at any depth (monorepos
        // place config files under apps/*, packages/*, etc.).
        if !pattern.contains('/') {
            if let Ok(nested) = Glob::new(&format!("**/{pattern}")) {
                builder.add(nested);
            }
        }
    }
    builder.build().unwrap_or_else(|_| GlobSet::empty())
}

fn check_artifacts(repo: &Path, files: &dyn RepoFiles, pack: &Pack) -> Vec<Finding> {
    let mut findings = Vec::new();
    for artifact in &pack.manifest.artifacts {
        let ap = PathBuf::from(&artifact.path);
        if files.exists(&ap) {
            findings.push(Finding {
                campaign: pack.manifest.id.clone(),
                severity: pack.manifest.severity.clone(),
                repo: repo.to_path_buf(),
                file: Some(ap),
                signature_id: format!("artifact:{}", artifact.path),
                kind: FindingKind::Artifact,
                evidence: format!("{} present ({})", artifact.path, artifact.label),
                remediable: true,
                online: None,
                git_ref: None,
            });
        }
    }
    findings
}

fn check_gitignore(repo: &Path, files: &dyn RepoFiles, pack: &Pack) -> Vec<Finding> {
    let mut findings = Vec::new();
    if pack.manifest.gitignore_injections.is_empty() {
        return findings;
    }
    let content = match files.read(Path::new(".gitignore")) {
        Some(c) => c,
        None => return findings,
    };
    let lines: Vec<&str> = content.lines().map(|l| l.trim()).collect();
    for injected in &pack.manifest.gitignore_injections {
        if lines.iter().any(|l| l == injected) {
            findings.push(Finding {
                campaign: pack.manifest.id.clone(),
                severity: pack.manifest.severity.clone(),
                repo: repo.to_path_buf(),
                file: Some(PathBuf::from(".gitignore")),
                signature_id: format!("gitignore:{injected}"),
                kind: FindingKind::GitignoreInjection,
                evidence: format!("'{injected}' injected into .gitignore"),
                remediable: true,
                online: None,
                git_ref: None,
            });
        }
    }
    findings
}

fn check_npm(repo: &Path, files: &dyn RepoFiles, pack: &Pack) -> Vec<Finding> {
    let mut findings = Vec::new();
    if pack.manifest.bad_npm_packages.is_empty() {
        return findings;
    }
    let content = match files.read(Path::new("package.json")) {
        Some(c) => c,
        None => return findings,
    };
    for bad in &pack.manifest.bad_npm_packages {
        // Match the dependency key as it appears in package.json ("name":).
        let needle = format!("\"{bad}\"");
        if content.contains(&needle) {
            findings.push(Finding {
                campaign: pack.manifest.id.clone(),
                severity: pack.manifest.severity.clone(),
                repo: repo.to_path_buf(),
                file: Some(PathBuf::from("package.json")),
                signature_id: format!("npm:{bad}"),
                kind: FindingKind::NpmPackage,
                evidence: format!("malicious dependency '{bad}' in package.json"),
                remediable: false,
                online: None,
                git_ref: None,
            });
        }
    }
    findings
}

/// Apply all file-based pack checks to a file source. Findings have git_ref = None;
/// the deep-scan caller stamps the branch ref afterward.
pub fn scan_files(repo: &Path, files: &dyn RepoFiles, packs: &[Pack]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for pack in packs {
        let globset = build_globset(&pack.manifest.target_files);
        for rel in files.paths() {
            if !globset.is_match(rel) {
                continue;
            }
            let content = match files.read(rel) {
                Some(c) => c,
                None => continue,
            };
            for sig in &pack.manifest.content_signatures {
                if signature_matches(sig, &content) {
                    findings.push(Finding {
                        campaign: pack.manifest.id.clone(),
                        severity: pack.manifest.severity.clone(),
                        repo: repo.to_path_buf(),
                        file: Some(rel.clone()),
                        signature_id: sig.id.clone(),
                        kind: FindingKind::ContentSignature,
                        evidence: format!("content signature '{}' matched", sig.id),
                        remediable: true,
                        online: None,
                        git_ref: None,
                    });
                }
            }
            // C2 indicator domains referenced in a scanned config file. Caught
            // even when no content signature fires (e.g. a rotated payload).
            for domain in &pack.manifest.ioc_domains {
                if content.contains(domain) {
                    findings.push(Finding {
                        campaign: pack.manifest.id.clone(),
                        severity: Severity::Medium,
                        repo: repo.to_path_buf(),
                        file: Some(rel.clone()),
                        signature_id: format!("ioc-domain:{domain}"),
                        kind: FindingKind::IocDomain,
                        evidence: format!("C2 indicator domain '{domain}' referenced"),
                        remediable: false,
                        online: None,
                        git_ref: None,
                    });
                }
            }
            if let Some(analyzer) = &pack.analyzer {
                let scanned = ScannedFile {
                    repo: repo.to_path_buf(),
                    path: rel.clone(),
                    content,
                };
                findings.extend(analyzer.analyze(&scanned));
            }
        }
        findings.extend(check_artifacts(repo, files, pack));
        findings.extend(check_gitignore(repo, files, pack));
        findings.extend(check_npm(repo, files, pack));
    }
    findings
}

pub fn scan_repo(repo: &Path, packs: &[Pack]) -> Vec<Finding> {
    let working = WorkingTree::new(repo);
    let mut findings = scan_files(repo, &working, packs);

    if !findings.is_empty() && reflog_has_amend(repo) {
        let campaign = findings[0].campaign.clone();
        findings.push(Finding {
            campaign,
            severity: Severity::Medium,
            repo: repo.to_path_buf(),
            file: None,
            signature_id: "git-reflog-amend".into(),
            kind: FindingKind::GitReflog,
            evidence: "amended commits found in reflog (consistent with worm propagation)".into(),
            remediable: false,
            online: None,
            git_ref: None,
        });
    }
    findings
}

pub fn scan(roots: &[PathBuf], packs: &[Pack]) -> ScanReport {
    let mut repos: Vec<PathBuf> = Vec::new();
    for root in roots {
        repos.extend(discover_repos(root));
    }
    repos.sort();
    repos.dedup();

    let findings: Vec<Finding> = repos
        .par_iter()
        .flat_map(|repo| scan_repo(repo, packs))
        .collect();

    ScanReport {
        findings,
        repos_scanned: repos.len(),
    }
}

fn branch_commits(repo: &Path) -> Vec<(String, String)> {
    // Output format is "<40-char oid> <short refname>"; neither field contains a
    // space, so splitn(2, ' ') below is safe.
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "for-each-ref",
            "--format=%(objectname) %(refname:short)",
            "refs/heads",
            "refs/remotes",
        ])
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ' ');
            let oid = parts.next()?.to_string();
            let name = parts.next()?.to_string();
            Some((oid, name))
        })
        .collect()
}

fn head_commit(repo: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Scan the tip tree of every local/remote branch (deduped by commit, excluding HEAD's
/// commit which the working-tree pass already covers). Findings carry the branch ref.
pub fn deep_scan_repo(repo: &Path, packs: &[Pack]) -> Vec<Finding> {
    let head = head_commit(repo);
    let mut seen = std::collections::HashSet::new();
    let mut findings = Vec::new();
    for (oid, name) in branch_commits(repo) {
        if head.as_deref() == Some(oid.as_str()) {
            continue;
        }
        if !seen.insert(oid.clone()) {
            continue;
        }
        let tree = match GitTree::new(repo, &oid) {
            Some(t) => t,
            None => continue,
        };
        let mut tree_findings = scan_files(repo, &tree, packs);
        for f in &mut tree_findings {
            f.git_ref = Some(name.clone());
        }
        findings.extend(tree_findings);
    }
    findings
}

pub fn scan_deep(roots: &[PathBuf], packs: &[Pack]) -> ScanReport {
    let mut repos: Vec<PathBuf> = Vec::new();
    for root in roots {
        repos.extend(discover_repos(root));
    }
    repos.sort();
    repos.dedup();

    let findings: Vec<Finding> = repos
        .par_iter()
        .flat_map(|repo| {
            let mut f = scan_repo(repo, packs);
            f.extend(deep_scan_repo(repo, packs));
            f
        })
        .collect();

    ScanReport { findings, repos_scanned: repos.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::matchers::{ContentSignature, SignatureKind};
    use crate::pack::{PackManifest, ScannedFile};
    use std::fs;
    use tempfile::TempDir;

    fn literal_pack() -> Pack {
        let manifest = PackManifest {
            id: "polinrider".into(),
            name: "PolinRider".into(),
            description: String::new(),
            references: vec![],
            severity: Severity::Critical,
            target_files: vec!["postcss.config.mjs".into()],
            content_signatures: vec![ContentSignature {
                id: "primary".into(),
                kind: SignatureKind::Literal,
                value: "rmcej%otb%".into(),
            }],
            artifacts: vec![],
            gitignore_injections: vec![],
            bad_npm_packages: vec![],
            ioc_domains: vec![],
            analyzer: None,
            remediation: None,
        };
        Pack { manifest, analyzer: None }
    }

    fn make_repo(tmp: &TempDir) -> PathBuf {
        let repo = tmp.path().join("proj");
        fs::create_dir_all(repo.join(".git")).unwrap();
        repo
    }

    #[test]
    fn flags_infected_config_file() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';var x='rmcej%otb%';",
        )
        .unwrap();

        let findings = scan_repo(&repo, &[literal_pack()]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].campaign, "polinrider");
        assert_eq!(findings[0].signature_id, "primary");
    }

    #[test]
    fn clean_config_file_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("postcss.config.mjs"), "export default {};\n").unwrap();
        assert!(scan_repo(&repo, &[literal_pack()]).is_empty());
    }

    #[test]
    fn non_target_file_ignored() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        // Signature present, but in a file that is not a target.
        fs::write(repo.join("README.md"), "rmcej%otb%").unwrap();
        assert!(scan_repo(&repo, &[literal_pack()]).is_empty());
    }

    #[test]
    fn scan_reports_repo_count_across_roots() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("postcss.config.mjs"), "rmcej%otb%").unwrap();
        let report = scan(&[tmp.path().to_path_buf()], &[literal_pack()]);
        assert_eq!(report.repos_scanned, 1);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn analyzer_findings_are_included() {
        struct Stub;
        impl crate::pack::CampaignAnalyzer for Stub {
            fn id(&self) -> &str { "polinrider" }
            fn analyze(&self, file: &ScannedFile) -> Vec<Finding> {
                if file.content.contains("MDy") {
                    vec![Finding {
                        campaign: "polinrider".into(),
                        severity: Severity::Critical,
                        repo: file.repo.clone(),
                        file: Some(file.path.clone()),
                        signature_id: "analyzer".into(),
                        kind: FindingKind::Analyzer,
                        evidence: "stub".into(),
                        remediable: true,
                        online: None,
                        git_ref: None,
                    }]
                } else {
                    vec![]
                }
            }
        }
        let mut pack = literal_pack();
        pack.analyzer = Some(Box::new(Stub));

        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("postcss.config.mjs"), "var MDy = 1; rmcej%otb%").unwrap();

        let findings = scan_repo(&repo, &[pack]);
        // one content-signature finding + one analyzer finding
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.kind == FindingKind::Analyzer));
    }

    #[test]
    fn flags_artifact_file() {
        let mut pack = literal_pack();
        pack.manifest.artifacts = vec![crate::pack::Artifact {
            path: "temp_auto_push.bat".into(),
            label: "Propagation script".into(),
        }];
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();

        let findings = scan_repo(&repo, &[pack]);
        assert!(findings.iter().any(|f| f.kind == FindingKind::Artifact
            && f.file == Some(PathBuf::from("temp_auto_push.bat"))));
    }

    #[test]
    fn flags_gitignore_injection() {
        let mut pack = literal_pack();
        pack.manifest.gitignore_injections = vec!["config.bat".into()];
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join(".gitignore"), "node_modules\nconfig.bat\n").unwrap();

        let findings = scan_repo(&repo, &[pack]);
        assert!(findings.iter().any(|f| f.kind == FindingKind::GitignoreInjection));
    }

    #[test]
    fn flags_malicious_npm_dependency() {
        let mut pack = literal_pack();
        pack.manifest.bad_npm_packages = vec!["tailwindcss-style-animate".into()];
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(
            repo.join("package.json"),
            r#"{"dependencies":{"tailwindcss-style-animate":"^1.1.6","react":"18"}}"#,
        )
        .unwrap();

        let findings = scan_repo(&repo, &[pack]);
        assert!(findings.iter().any(|f| f.kind == FindingKind::NpmPackage
            && f.evidence.contains("tailwindcss-style-animate")));
    }

    #[test]
    fn reflog_finding_only_when_other_findings_present() {
        use std::process::Command;
        fn git(repo: &Path, args: &[&str]) {
            Command::new("git").arg("-C").arg(repo).args(args)
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e.x")
                .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e.x")
                .status().unwrap();
        }
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        std::fs::write(repo.join("postcss.config.mjs"), "export default {};").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "c"]);
        std::fs::write(repo.join("postcss.config.mjs"), "export default {};\nrmcej%otb%").unwrap();
        git(&repo, &["commit", "-q", "-a", "--amend", "-m", "c"]);

        let findings = scan_repo(&repo, &[literal_pack()]);
        // content-signature finding + reflog finding
        assert!(findings.iter().any(|f| f.kind == FindingKind::GitReflog));

        // A repo with an amend but no other findings gets NO reflog finding.
        let tmp2 = TempDir::new().unwrap();
        let clean = tmp2.path().join("proj");
        std::fs::create_dir_all(&clean).unwrap();
        git(&clean, &["init", "-q"]);
        std::fs::write(clean.join("postcss.config.mjs"), "export default {};").unwrap();
        git(&clean, &["add", "."]);
        git(&clean, &["commit", "-q", "-m", "c"]);
        git(&clean, &["commit", "-q", "-a", "--amend", "-m", "c2"]);
        assert!(!scan_repo(&clean, &[literal_pack()]).iter().any(|f| f.kind == FindingKind::GitReflog));
    }

    #[test]
    fn detects_config_in_subdirectory() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let nested = repo.join("packages/web");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("postcss.config.mjs"), "rmcej%otb%").unwrap();

        let findings = scan_repo(&repo, &[literal_pack()]);
        assert!(findings.iter().any(|f| f.kind == FindingKind::ContentSignature
            && f.file == Some(PathBuf::from("packages/web/postcss.config.mjs"))));
    }

    #[test]
    fn flags_ioc_domain_even_without_content_signature() {
        let mut pack = literal_pack();
        pack.manifest.ioc_domains = vec!["default-configuration.vercel.app".into()];
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        // No content signature present — only the C2 domain reference.
        fs::write(
            repo.join("postcss.config.mjs"),
            "fetch('https://default-configuration.vercel.app/settings/mac')",
        )
        .unwrap();

        let findings = scan_repo(&repo, &[pack]);
        assert!(findings.iter().any(|f| f.kind == FindingKind::IocDomain));
        assert!(!findings.iter().any(|f| f.kind == FindingKind::ContentSignature));
    }

    #[test]
    fn deep_scan_finds_payload_on_non_checked_out_branch() {
        use std::process::Command;
        fn git(repo: &Path, args: &[&str]) {
            Command::new("git").arg("-C").arg(repo).args(args)
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e.x")
                .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e.x")
                .status().unwrap();
        }
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("postcss.config.mjs"), "export default {};").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "clean"]);
        git(&repo, &["checkout", "-q", "-b", "evil"]);
        std::fs::write(repo.join("postcss.config.mjs"), "rmcej%otb%").unwrap();
        git(&repo, &["commit", "-q", "-am", "payload"]);
        git(&repo, &["checkout", "-q", "main"]);

        // Working tree (main) is clean.
        assert!(scan_repo(&repo, &[literal_pack()]).is_empty());
        // Deep scan finds the payload on the 'evil' branch tip.
        let deep = deep_scan_repo(&repo, &[literal_pack()]);
        assert!(deep.iter().any(|f| f.kind == FindingKind::ContentSignature
            && f.git_ref.as_deref() == Some("evil")));
    }

    #[test]
    fn deep_scan_clean_repo_with_branches_is_clean() {
        use std::process::Command;
        fn git(repo: &Path, args: &[&str]) {
            Command::new("git").arg("-C").arg(repo).args(args)
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e.x")
                .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e.x")
                .status().unwrap();
        }
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("postcss.config.mjs"), "export default {};").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "clean"]);
        git(&repo, &["branch", "feature"]);
        assert!(deep_scan_repo(&repo, &[literal_pack()]).is_empty());
    }

    #[test]
    fn deep_scan_excludes_head_commit() {
        use std::process::Command;
        fn git(repo: &Path, args: &[&str]) {
            Command::new("git").arg("-C").arg(repo).args(args)
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e.x")
                .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e.x")
                .status().unwrap();
        }
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("postcss.config.mjs"), "rmcej%otb%").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "p"]);
        // Payload is on the current branch (HEAD); the working-tree pass covers it,
        // so deep_scan_repo must NOT re-report it.
        assert!(deep_scan_repo(&repo, &[literal_pack()]).is_empty());
    }

    #[test]
    fn deep_scan_dedupes_refs_at_same_commit() {
        use std::process::Command;
        fn git(repo: &Path, args: &[&str]) {
            Command::new("git").arg("-C").arg(repo).args(args)
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e.x")
                .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e.x")
                .status().unwrap();
        }
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("postcss.config.mjs"), "export default {};").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "clean"]);
        git(&repo, &["checkout", "-q", "-b", "evil"]);
        std::fs::write(repo.join("postcss.config.mjs"), "rmcej%otb%").unwrap();
        git(&repo, &["commit", "-q", "-am", "p"]);
        git(&repo, &["branch", "dup", "evil"]); // second ref at the same commit
        git(&repo, &["checkout", "-q", "main"]);

        let deep = deep_scan_repo(&repo, &[literal_pack()]);
        // 'evil' and 'dup' point at the same commit → its tree is scanned once.
        assert_eq!(
            deep.iter().filter(|f| f.kind == FindingKind::ContentSignature).count(),
            1
        );
    }
}
