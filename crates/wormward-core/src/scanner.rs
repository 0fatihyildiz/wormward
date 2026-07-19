use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;

use crate::capability::{gate, is_exfil_staging, score, CapabilityScore};
use crate::engine::SignatureEngine;
use crate::finding::{Finding, FindingKind, Severity};
use crate::git::reflog_has_amend;
use crate::pack::{Pack, ScannedFile};
use crate::repo_files::{GitTree, RepoFiles, WorkingTree};
use crate::surface::{classify, derived_targets, is_excluded_path, lifecycle_scripts, Surface};
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

const MAX_CONTENT_BYTES: usize = 5 * 1024 * 1024;

fn looks_binary(content: &str) -> bool {
    content.as_bytes().iter().take(8192).any(|&b| b == 0)
}

/// Apply all file-based pack checks to a file source. Findings have git_ref = None;
/// the deep-scan caller stamps the branch ref afterward.
pub fn scan_files(repo: &Path, files: &dyn RepoFiles, packs: &[Pack]) -> Vec<Finding> {
    let engine = SignatureEngine::build(packs);
    // Per-pack target globsets, indexed alongside `packs`.
    let globsets: Vec<GlobSet> =
        packs.iter().map(|p| build_globset(&p.manifest.target_files)).collect();

    let mut findings = Vec::new();

    for rel in files.paths() {
        // Which packs target this file?
        let targeting: Vec<usize> = globsets
            .iter()
            .enumerate()
            .filter(|(_, g)| g.is_match(rel))
            .map(|(i, _)| i)
            .collect();
        if targeting.is_empty() {
            continue;
        }
        let content = match files.read(rel) {
            Some(c) => c,
            None => continue,
        };
        if content.len() > MAX_CONTENT_BYTES || looks_binary(&content) {
            continue;
        }
        let targeting_ids: std::collections::HashSet<&str> =
            targeting.iter().map(|&i| packs[i].manifest.id.as_str()).collect();

        // Content signatures via the shared engine, gated by target membership.
        for hit in engine.scan_content(&content) {
            // Relies on pack ids being unique: a hit's pack_id must map to exactly one
            // pack, so this membership check correctly scopes hits to packs targeting
            // this file. Duplicate pack ids would misattribute or drop hits here.
            if !targeting_ids.contains(hit.pack_id.as_str()) {
                continue;
            }
            findings.push(Finding {
                campaign: hit.pack_id.clone(),
                severity: hit.severity.clone(),
                repo: repo.to_path_buf(),
                file: Some(rel.clone()),
                signature_id: hit.signature_id.clone(),
                kind: FindingKind::ContentSignature,
                evidence: format!("content signature '{}' matched", hit.signature_id),
                remediable: true,
                online: None,
                git_ref: None,
            });
        }

        // IOC domains + analyzer stay per-pack (small lists; not worth the engine).
        for &i in &targeting {
            let pack = &packs[i];
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
                    content: content.clone(),
                };
                findings.extend(analyzer.analyze(&scanned));
            }
        }
    }

    for pack in packs {
        findings.extend(check_artifacts(repo, files, pack));
        findings.extend(check_gitignore(repo, files, pack));
        findings.extend(check_npm(repo, files, pack));
    }
    findings
}

fn cap_finding(repo: &Path, file: PathBuf, surface: Surface, s: &CapabilityScore) -> Finding {
    let top = s.evidence.first().cloned().unwrap_or_else(|| "capability".into());
    Finding {
        campaign: "generic".into(),
        severity: Severity::Critical,
        repo: repo.to_path_buf(),
        file: Some(file),
        signature_id: format!("capability:{surface:?}:{top}"),
        kind: FindingKind::Capability,
        evidence: format!("auto-run {surface:?}: {}", s.evidence.join(" + ")),
        remediable: false,
        online: None,
        git_ref: None,
    }
}

fn push_if_gated(
    findings: &mut Vec<Finding>,
    repo: &Path,
    file: PathBuf,
    surface: Surface,
    content: &str,
) {
    let s = score(content, surface);
    if gate(surface, &s) {
        findings.push(cap_finding(repo, file, surface, &s));
    }
}

/// Promote local `node ./X.js` targets of an auto-run command to `DerivedScript`
/// units and score them (one hop). `scored` dedups against files already scored
/// under another surface, so a reachable file is never double-reported.
fn expand_derived(
    findings: &mut Vec<Finding>,
    repo: &Path,
    files: &dyn RepoFiles,
    scored: &mut HashSet<PathBuf>,
    command: &str,
) {
    for tgt in derived_targets(command) {
        let tp = PathBuf::from(&tgt);
        if is_excluded_path(&tp) || !scored.insert(tp.clone()) {
            continue;
        }
        if let Some(dc) = files.read(&tp) {
            if dc.len() <= MAX_CONTENT_BYTES && !looks_binary(&dc) {
                push_if_gated(findings, repo, tp, Surface::DerivedScript, &dc);
            }
        }
    }
}

/// Campaign-agnostic capability pass over an auto-run surface. Works on any
/// `RepoFiles` (working tree or a branch tip). The physical `.git/hooks` pass
/// is separate (`scan_git_hooks`) because it applies only to the working tree.
pub fn scan_capabilities(repo: &Path, files: &dyn RepoFiles) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Real file paths already scored under some surface — prevents a reachable
    // DerivedScript that is also a classified ConfigFile from double-reporting.
    let mut scored: HashSet<PathBuf> = HashSet::new();

    for rel in files.paths() {
        if is_excluded_path(rel) {
            continue;
        }
        // Read each file once; skip oversized/binary blobs (mirrors scan_files).
        let content = match files.read(rel) {
            Some(c) if c.len() <= MAX_CONTENT_BYTES && !looks_binary(&c) => c,
            _ => continue,
        };

        if let Some(surface) = classify(rel) {
            // A folderOpen precondition gates TasksJson (auto-runs on folder open only).
            let auto_run_ok = surface != Surface::TasksJson || {
                let low = content.to_lowercase();
                low.contains("folderopen") || low.contains("allowautomatictasks")
            };
            if auto_run_ok {
                if scored.insert(rel.clone()) {
                    push_if_gated(&mut findings, repo, rel.clone(), surface, &content);
                }
                if matches!(surface, Surface::WorkflowFile | Surface::TasksJson) {
                    expand_derived(&mut findings, repo, files, &mut scored, &content);
                }
            }
        }

        if rel.file_name().map(|n| n == "package.json").unwrap_or(false) {
            for (key, script) in lifecycle_scripts(&content) {
                let vfile = PathBuf::from(format!("{}#{}", rel.display(), key));
                push_if_gated(&mut findings, repo, vfile, Surface::LifecycleScript, &script);
                expand_derived(&mut findings, repo, files, &mut scored, &script);
            }
        }

        // ExfilStaging: root-level *.json holding a base64 credential blob.
        if rel.parent().map(|p| p.as_os_str().is_empty()).unwrap_or(true)
            && rel.extension().map(|e| e == "json").unwrap_or(false)
            && is_exfil_staging(&content)
        {
            findings.push(Finding {
                campaign: "generic".into(),
                severity: Severity::Critical,
                repo: repo.to_path_buf(),
                file: Some(rel.clone()),
                signature_id: "capability:exfil-staging".into(),
                kind: FindingKind::Capability,
                evidence: format!("exfil-staging: base64 credential blob ({})", rel.display()),
                remediable: false,
                online: None,
                git_ref: None,
            });
        }
    }

    findings
}

/// Physical `.git/hooks/*` (non-`.sample`) scan — working tree only; the hooks
/// dir is pruned from `walk_repo_files` and absent from a `GitTree`.
fn scan_git_hooks(repo: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let hooks_dir = repo.join(".git/hooks");
    if let Ok(entries) = std::fs::read_dir(&hooks_dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "sample").unwrap_or(false) {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&p) {
                let rel = p.strip_prefix(repo).unwrap_or(&p).to_path_buf();
                push_if_gated(&mut findings, repo, rel, Surface::GitHook, &content);
            }
        }
    }
    findings
}

/// When a campaign (pack) finding already covers a file, drop the additive generic
/// capability finding on that same file so the report shows the more actionable,
/// remediable, campaign-attributed finding rather than a duplicate.
fn dedup_capability_against_packs(findings: &mut Vec<Finding>) {
    let pack_files: HashSet<PathBuf> = findings
        .iter()
        .filter(|f| f.kind != FindingKind::Capability)
        .filter_map(|f| f.file.clone())
        .collect();
    findings.retain(|f| {
        f.kind != FindingKind::Capability
            || f.file.as_ref().map(|p| !pack_files.contains(p)).unwrap_or(true)
    });
}

pub fn scan_repo(repo: &Path, packs: &[Pack]) -> Vec<Finding> {
    let working = WorkingTree::new(repo);
    let mut findings = scan_files(repo, &working, packs);
    findings.extend(scan_capabilities(repo, &working));
    findings.extend(scan_git_hooks(repo));
    dedup_capability_against_packs(&mut findings);

    if !findings.is_empty() && reflog_has_amend(repo) {
        // Attribute the reflog corroboration to a campaign (pack) finding when one
        // exists; fall back to "generic" only if every finding is capability-only.
        let campaign = findings
            .iter()
            .map(|f| f.campaign.as_str())
            .find(|c| *c != "generic")
            .unwrap_or("generic")
            .to_string();
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
        tree_findings.extend(scan_capabilities(repo, &tree));
        dedup_capability_against_packs(&mut tree_findings);
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
    fn capability_flags_obfuscated_config_without_pack() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';var _$_1e42=[];require('https')",
        )
        .unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_capabilities(&repo, &files);
        assert!(f
            .iter()
            .any(|x| x.kind == FindingKind::Capability && x.campaign == "generic"));
    }

    #[test]
    fn capability_reaches_dropped_file() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("package.json"), r#"{"scripts":{"preinstall":"node setup_bun.js"}}"#)
            .unwrap();
        fs::write(
            repo.join("setup_bun.js"),
            "global['r']=require;const x=String.fromCharCode(1,2,3,4,5);process.env.NPM_TOKEN;fetch('http://x')",
        )
        .unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_capabilities(&repo, &files);
        assert!(f
            .iter()
            .any(|x| x.kind == FindingKind::Capability && x.file == Some(PathBuf::from("setup_bun.js"))));
    }

    #[test]
    fn capability_clean_repo_silent() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("postcss.config.mjs"), "export default { plugins: {} };\n").unwrap();
        fs::write(repo.join("package.json"), r#"{"scripts":{"build":"vite build"}}"#).unwrap();
        let files = WorkingTree::new(&repo);
        assert!(scan_capabilities(&repo, &files).is_empty());
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
    fn binary_file_is_not_content_matched() {
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        // Target-named file, signature present, but contains a NUL byte early.
        let mut bytes = b"\x00".to_vec();
        bytes.extend_from_slice(b"rmcej%otb%");
        std::fs::write(repo.join("postcss.config.mjs"), bytes).unwrap();
        assert!(scan_repo(&repo, &[literal_pack()]).is_empty());
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
                .env("GIT_TEMPLATE_DIR", "")
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
                .env("GIT_TEMPLATE_DIR", "")
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
                .env("GIT_TEMPLATE_DIR", "")
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
                .env("GIT_TEMPLATE_DIR", "")
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
                .env("GIT_TEMPLATE_DIR", "")
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
