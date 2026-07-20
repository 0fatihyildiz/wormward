use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::finding::{Finding, FindingKind};
use crate::pack::{Pack, PayloadStrip};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum RemediationAction {
    StripPayload { file: PathBuf, markers: Vec<String>, strip_lines: Vec<String> },
    DeleteFile { file: PathBuf },
    RemoveGitignoreLine { file: PathBuf, line: String },
}

impl RemediationAction {
    pub fn target(&self) -> &Path {
        match self {
            RemediationAction::StripPayload { file, .. } => file,
            RemediationAction::DeleteFile { file } => file,
            RemediationAction::RemoveGitignoreLine { file, .. } => file,
        }
    }
}

pub struct RemediationPlan {
    pub actions: Vec<RemediationAction>,
    pub manual: Vec<Finding>,
}

fn strip_config<'a>(campaign: &str, packs: &'a [Pack]) -> Option<&'a PayloadStrip> {
    let pack = packs.iter().find(|p| p.manifest.id == campaign)?;
    let payload = pack.manifest.remediation.as_ref()?.config_payload.as_ref()?;
    if payload.strategy == "strip_after_marker" && !payload.markers.is_empty() {
        Some(payload)
    } else {
        None
    }
}

/// Map a single finding to its auto-remediation action, or `None` if it cannot be
/// cleaned automatically (no file, unknown kind, or a strip with no configured marker).
///
/// This is the SINGLE source of the kind→action mapping. Both the working-tree planner
/// (`plan_remediation`) and the cross-branch planner (`rewrite::plan_branch_cleans`) call
/// it so the two paths never drift. It intentionally ignores `git_ref` — callers decide
/// how to route branch-tip findings.
pub fn action_for(finding: &Finding, packs: &[Pack]) -> Option<RemediationAction> {
    let file = finding.file.clone()?;
    match finding.kind {
        FindingKind::Artifact => Some(RemediationAction::DeleteFile { file }),
        FindingKind::GitignoreInjection => {
            let line = finding
                .signature_id
                .strip_prefix("gitignore:")
                .unwrap_or("")
                .to_string();
            Some(RemediationAction::RemoveGitignoreLine { file, line })
        }
        FindingKind::ContentSignature | FindingKind::Analyzer => {
            let cfg = strip_config(&finding.campaign, packs)?;
            Some(RemediationAction::StripPayload {
                file,
                markers: cfg.markers.clone(),
                strip_lines: cfg.strip_lines.clone(),
            })
        }
        _ => None,
    }
}

/// Derive remediation actions from findings. Working-tree findings only; auto-cleanable
/// kinds become actions (deduped by target), the rest are returned as `manual`.
pub fn plan_remediation(findings: &[Finding], packs: &[Pack]) -> RemediationPlan {
    let mut actions: Vec<RemediationAction> = Vec::new();
    let mut manual: Vec<Finding> = Vec::new();

    for f in findings {
        // Deep-scan findings live on other branches — cannot edit safely here.
        if f.git_ref.is_some() {
            manual.push(f.clone());
            continue;
        }
        match action_for(f, packs) {
            Some(a) => {
                if !actions.contains(&a) {
                    actions.push(a);
                }
            }
            None => manual.push(f.clone()),
        }
    }
    RemediationPlan { actions, manual }
}

pub struct RemediationResult {
    pub applied: Vec<RemediationAction>,
    pub skipped: Vec<(RemediationAction, String)>,
    pub backup_dir: Option<PathBuf>,
}

fn backup_file(repo: &Path, rel: &Path, backup_dir: &Path) {
    let src = repo.join(rel);
    if !src.is_file() {
        return;
    }
    let dst = backup_dir.join(rel);
    if let Some(parent) = dst.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::copy(&src, &dst);
}

/// Position of the earliest marker match in `content`. A marker written `re:<pattern>`
/// is matched as a regex; any other marker is matched as a literal substring. An
/// invalid regex is ignored (never matches) rather than panicking.
fn earliest_marker(content: &str, markers: &[String]) -> Option<usize> {
    markers
        .iter()
        .filter_map(|m| match m.strip_prefix("re:") {
            Some(pat) => regex::Regex::new(pat).ok()?.find(content).map(|mat| mat.start()),
            None => content.find(m),
        })
        .min()
}

/// True if any strip marker matches `content`. Same literal/`re:` semantics as
/// `earliest_marker`. Callers use it to decide whether a StripPayload will actually do
/// anything (fixability) before offering or attempting it.
pub fn strip_marker_matches(content: &str, markers: &[String]) -> bool {
    earliest_marker(content, markers).is_some()
}

/// Delete whole lines matching any `patterns` entry, used to excise injected lines the payload
/// cut leaves behind (e.g. the PolinRider `createRequire` ESM shim at the top of the file). Each
/// pattern is a `re:` regex or a literal substring, matched against the line; an invalid regex
/// never matches. A no-op when `patterns` is empty.
fn remove_matching_lines(content: &str, patterns: &[String]) -> String {
    if patterns.is_empty() {
        return content.to_string();
    }
    let matches = |line: &str| {
        patterns.iter().any(|p| match p.strip_prefix("re:") {
            Some(pat) => regex::Regex::new(pat).map(|re| re.is_match(line)).unwrap_or(false),
            None => line.contains(p.as_str()),
        })
    };
    let kept: Vec<&str> = content.lines().filter(|l| !matches(l)).collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

/// Apply actions in the working tree, backing up each target first (unless disabled).
pub fn apply(repo: &Path, actions: &[RemediationAction], backup: bool) -> RemediationResult {
    let backup_dir = if backup && !actions.is_empty() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = repo.join(".wormward-backup").join(ts.to_string());
        let _ = std::fs::create_dir_all(&dir);
        Some(dir)
    } else {
        None
    };

    let mut applied = Vec::new();
    let mut skipped = Vec::new();

    for action in actions {
        if let Some(bd) = &backup_dir {
            backup_file(repo, action.target(), bd);
        }
        let result: Result<(), String> = match action {
            RemediationAction::DeleteFile { file } => {
                std::fs::remove_file(repo.join(file)).map_err(|e| e.to_string())
            }
            RemediationAction::StripPayload { file, markers, strip_lines } => {
                let path = repo.join(file);
                match std::fs::read_to_string(&path) {
                    Ok(content) => match earliest_marker(&content, markers) {
                        Some(idx) => {
                            // Cut the appended payload at the earliest marker, then excise any
                            // injected lines (e.g. the createRequire shim) left in the prefix.
                            let prefix = format!("{}\n", content[..idx].trim_end());
                            let cleaned = remove_matching_lines(&prefix, strip_lines);
                            std::fs::write(&path, cleaned).map_err(|e| e.to_string())
                        }
                        None => Err("no strip marker found in file".to_string()),
                    },
                    Err(e) => Err(e.to_string()),
                }
            }
            RemediationAction::RemoveGitignoreLine { file, line } => {
                let path = repo.join(file);
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        let kept: Vec<&str> =
                            content.lines().filter(|l| l.trim() != line).collect();
                        let mut out = kept.join("\n");
                        if !out.is_empty() {
                            out.push('\n');
                        }
                        std::fs::write(&path, out).map_err(|e| e.to_string())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
        };
        match result {
            Ok(()) => applied.push(action.clone()),
            Err(e) => skipped.push((action.clone(), e)),
        }
    }
    RemediationResult { applied, skipped, backup_dir }
}

pub struct RestoreResult {
    pub restored: Vec<PathBuf>,
    pub backup_dir: Option<PathBuf>,
}

fn latest_backup_dir(repo: &Path) -> Option<PathBuf> {
    let root = repo.join(".wormward-backup");
    let mut best: Option<(u128, PathBuf)> = None;
    for entry in std::fs::read_dir(&root).ok()?.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        if let Ok(ts) = entry.file_name().to_string_lossy().parse::<u128>() {
            if best.as_ref().map(|(b, _)| ts > *b).unwrap_or(true) {
                best = Some((ts, entry.path()));
            }
        }
    }
    best.map(|(_, p)| p)
}

fn collect_files(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, base, out);
            } else if let Ok(rel) = path.strip_prefix(base) {
                out.push(rel.to_path_buf());
            }
        }
    }
}

/// Restore every file from the latest backup back into the repo (recreating deletions
/// and reverting modifications).
pub fn restore(repo: &Path) -> RestoreResult {
    let backup_dir = match latest_backup_dir(repo) {
        Some(d) => d,
        None => return RestoreResult { restored: Vec::new(), backup_dir: None },
    };
    let mut rels = Vec::new();
    collect_files(&backup_dir, &backup_dir, &mut rels);
    let mut restored = Vec::new();
    for rel in rels {
        let dst = repo.join(&rel);
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::copy(backup_dir.join(&rel), &dst).is_ok() {
            restored.push(rel);
        }
    }
    RestoreResult { restored, backup_dir: Some(backup_dir) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::matchers::{ContentSignature, SignatureKind};
    use crate::pack::{Pack, PackManifest, PayloadStrip, Remediation};
    use std::fs;
    use tempfile::TempDir;

    fn polinrider_pack() -> Pack {
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
            remediation: Some(Remediation {
                config_payload: Some(PayloadStrip {
                    strategy: "strip_after_marker".into(),
                    markers: vec!["global['!']=".into()],
                    strip_lines: vec![],                }),
            }),
        };
        Pack { manifest, analyzer: None }
    }

    fn finding(kind: FindingKind, file: Option<&str>, sig: &str) -> Finding {
        Finding {
            campaign: "polinrider".into(),
            severity: Severity::Critical,
            repo: PathBuf::from("/r"),
            file: file.map(PathBuf::from),
            signature_id: sig.into(),
            kind,
            evidence: "e".into(),
            remediable: true,
            online: None,
            git_ref: None,
        }
    }

    #[test]
    fn regex_marker_matches_bracket_global_of_any_key() {
        // Bracket-notation global assignment with an arbitrary key — the generalized
        // payload-start form. `re:` prefix = regex marker.
        let markers = vec![r"re:global\[('|\x22)[^'\x22]+('|\x22)\]\s*=".to_string()];
        let content = "export default {};\nglobal['xyz']=1;PAYLOAD";
        assert!(strip_marker_matches(content, &markers));
        assert_eq!(earliest_marker(content, &markers), Some(content.find("global[").unwrap()));
        // Dot-notation must NOT match (legit `global.x` collision risk).
        assert!(!strip_marker_matches("const a = global.foo;", &markers));
    }

    #[test]
    fn literal_and_regex_markers_take_earliest() {
        let markers = vec!["global['!']=".to_string(), r"re:_\$_[0-9a-f]{4,}".to_string()];
        // decoder pattern appears BEFORE the literal here → earliest wins.
        let content = "ok\n_$_1a2b=1;global['!']=2;";
        assert_eq!(earliest_marker(content, &markers), Some(content.find("_$_1a2b").unwrap()));
    }

    #[test]
    fn strip_marker_matches_false_when_absent() {
        assert!(!strip_marker_matches("clean config", &["global['!']=".to_string()]));
    }

    #[test]
    fn artifact_becomes_delete() {
        let plan = plan_remediation(
            &[finding(FindingKind::Artifact, Some("temp_auto_push.bat"), "artifact:temp_auto_push.bat")],
            &[polinrider_pack()],
        );
        assert_eq!(plan.actions, vec![RemediationAction::DeleteFile { file: PathBuf::from("temp_auto_push.bat") }]);
    }

    #[test]
    fn content_signature_becomes_strip_with_pack_markers() {
        let plan = plan_remediation(
            &[finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary")],
            &[polinrider_pack()],
        );
        assert_eq!(
            plan.actions,
            vec![RemediationAction::StripPayload {
                file: PathBuf::from("postcss.config.mjs"),
                markers: vec!["global['!']=".into()],
                strip_lines: vec![],            }]
        );
    }

    #[test]
    fn gitignore_injection_becomes_remove_line() {
        let plan = plan_remediation(
            &[finding(FindingKind::GitignoreInjection, Some(".gitignore"), "gitignore:config.bat")],
            &[polinrider_pack()],
        );
        assert_eq!(
            plan.actions,
            vec![RemediationAction::RemoveGitignoreLine {
                file: PathBuf::from(".gitignore"),
                line: "config.bat".into(),
            }]
        );
    }

    #[test]
    fn npm_and_deep_and_no_strategy_are_manual() {
        let mut npm = finding(FindingKind::NpmPackage, Some("package.json"), "npm:x");
        npm.remediable = false;
        let mut deep = finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary");
        deep.git_ref = Some("evil".into());
        let mut no_strategy = finding(FindingKind::ContentSignature, Some("f.js"), "x");
        no_strategy.campaign = "shai-hulud".into();
        let plan = plan_remediation(&[npm, deep, no_strategy], &[polinrider_pack()]);
        assert!(plan.actions.is_empty());
        assert_eq!(plan.manual.len(), 3);
    }

    #[test]
    fn duplicate_findings_on_one_file_dedupe() {
        let plan = plan_remediation(
            &[
                finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), "primary"),
                finding(FindingKind::ContentSignature, Some("postcss.config.mjs"), "xor-key-primary"),
            ],
            &[polinrider_pack()],
        );
        assert_eq!(plan.actions.len(), 1);
    }

    #[test]
    fn strip_removes_payload_keeps_prefix() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        fs::write(repo.join("postcss.config.mjs"), "export default {};\nglobal['!']='8';var x='rmcej%otb%';").unwrap();
        let a = RemediationAction::StripPayload {
            file: PathBuf::from("postcss.config.mjs"),
            markers: vec!["global['!']=".into()],
            strip_lines: vec![],        };
        let r = apply(repo, &[a], false);
        assert_eq!(r.applied.len(), 1);
        assert_eq!(fs::read_to_string(repo.join("postcss.config.mjs")).unwrap(), "export default {};\n");
    }

    #[test]
    fn strip_removes_payload_and_injected_shim() {
        // Multi-point injection: the createRequire ESM shim at the top AND the appended payload
        // at the bottom. strip_after_marker only cuts the bottom; strip_lines must also excise
        // the injected shim, leaving the legit config pristine.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        let padding = " ".repeat(240);
        let content = format!(
            "import path from 'path';\n\
             import {{ createRequire }} from 'module';\n\
             const require = createRequire(import.meta.url);\n\
             const nextConfig = {{ output: 'standalone' }};\n\
             export default nextConfig;{padding}global.i='5-3-168';var _$_46e0=[];global[_$_46e0[0]]=require;"
        );
        fs::write(repo.join("next.config.mjs"), &content).unwrap();
        let a = RemediationAction::StripPayload {
            file: PathBuf::from("next.config.mjs"),
            markers: vec![r"re:\x20{200,}".into(), "global['!']=".into()],
            strip_lines: vec![
                "import { createRequire } from 'module'".into(),
                "createRequire(import.meta.url)".into(),
            ],
        };
        let r = apply(repo, &[a], false);
        assert_eq!(r.applied.len(), 1);
        let cleaned = fs::read_to_string(repo.join("next.config.mjs")).unwrap();
        // Payload cut:
        assert!(!cleaned.contains("_$_46e0"), "payload must be gone:\n{cleaned}");
        assert!(!cleaned.contains("global.i="), "version marker must be gone:\n{cleaned}");
        // Injected shim removed:
        assert!(!cleaned.contains("createRequire"), "injected shim must be gone:\n{cleaned}");
        // Legit config preserved:
        assert!(cleaned.contains("import path from 'path';"));
        assert!(cleaned.contains("const nextConfig = { output: 'standalone' };"));
        assert!(cleaned.contains("export default nextConfig;"));
    }

    #[test]
    fn strip_without_marker_is_skipped_and_file_unchanged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        fs::write(repo.join("f.mjs"), "var q='rmcej%otb%';").unwrap();
        let a = RemediationAction::StripPayload {
            file: PathBuf::from("f.mjs"),
            markers: vec!["global['!']=".into()],
            strip_lines: vec![],        };
        let r = apply(repo, &[a], false);
        assert_eq!(r.skipped.len(), 1);
        assert_eq!(fs::read_to_string(repo.join("f.mjs")).unwrap(), "var q='rmcej%otb%';");
    }

    #[test]
    fn delete_removes_file_and_backs_it_up() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();
        let a = RemediationAction::DeleteFile { file: PathBuf::from("temp_auto_push.bat") };
        let r = apply(repo, &[a], true);
        assert!(!repo.join("temp_auto_push.bat").exists());
        let bd = r.backup_dir.unwrap();
        assert!(bd.join("temp_auto_push.bat").is_file());
    }

    #[test]
    fn remove_gitignore_line_drops_only_that_line() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        fs::write(repo.join(".gitignore"), "node_modules\nconfig.bat\ndist\n").unwrap();
        let a = RemediationAction::RemoveGitignoreLine {
            file: PathBuf::from(".gitignore"),
            line: "config.bat".into(),
        };
        apply(repo, &[a], false);
        let out = fs::read_to_string(repo.join(".gitignore")).unwrap();
        assert!(!out.contains("config.bat"));
        assert!(out.contains("node_modules") && out.contains("dist"));
    }

    #[test]
    fn restore_reverts_delete_and_modify() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();
        fs::write(repo.join("postcss.config.mjs"), "export default {};\nglobal['!']='8';payload").unwrap();
        let actions = vec![
            RemediationAction::DeleteFile { file: PathBuf::from("temp_auto_push.bat") },
            RemediationAction::StripPayload {
                file: PathBuf::from("postcss.config.mjs"),
                markers: vec!["global['!']=".into()],
                strip_lines: vec![],            },
        ];
        apply(repo, &actions, true);
        assert!(!repo.join("temp_auto_push.bat").exists());

        let r = restore(repo);
        assert_eq!(r.restored.len(), 2);
        assert_eq!(fs::read_to_string(repo.join("temp_auto_push.bat")).unwrap(), "@echo off");
        assert!(fs::read_to_string(repo.join("postcss.config.mjs")).unwrap().contains("payload"));
    }
}
