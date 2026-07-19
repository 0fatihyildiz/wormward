use std::path::PathBuf;

use serde::Serialize;
use wormward_core::{
    apply, discover_repos, plan_remediation, restore as core_restore, scan as core_scan, scan_deep,
    scan_repo, Finding, RemediationAction, ScanReport,
};
use wormward_osm::{enrich, OsmClient};
use wormward_packs::builtin_packs;

fn to_paths(dirs: Vec<String>) -> Vec<PathBuf> {
    dirs.into_iter().map(PathBuf::from).collect()
}

fn describe(a: &RemediationAction) -> String {
    match a {
        RemediationAction::StripPayload { file, .. } => {
            format!("strip payload from {}", file.display())
        }
        RemediationAction::DeleteFile { file } => format!("delete {}", file.display()),
        RemediationAction::RemoveGitignoreLine { file, line } => {
            format!("remove '{line}' from {}", file.display())
        }
    }
}

#[derive(Serialize)]
pub struct PackInfo {
    id: String,
    name: String,
    description: String,
}

#[derive(Serialize)]
pub struct RepoPlan {
    repo: String,
    actions: Vec<RemediationAction>,
    manual: Vec<Finding>,
}

#[derive(Serialize)]
pub struct SkippedAction {
    action: String,
    reason: String,
}

#[derive(Serialize)]
pub struct CleanSummary {
    repos: usize,
    applied: usize,
    skipped: Vec<SkippedAction>,
    backups: Vec<String>,
}

#[derive(Serialize)]
pub struct RestoreSummary {
    repos: usize,
    restored: usize,
}

#[tauri::command]
fn scan(
    dirs: Vec<String>,
    deep: bool,
    online: bool,
    token: Option<String>,
) -> Result<ScanReport, String> {
    let paths = to_paths(dirs);
    let packs = builtin_packs();
    let mut report = if deep {
        scan_deep(&paths, &packs)
    } else {
        core_scan(&paths, &packs)
    };
    if online {
        let token = token
            .filter(|t| !t.is_empty())
            .or_else(|| std::env::var("OSM_API_KEY").ok())
            .filter(|t| !t.is_empty());
        if let Some(token) = token {
            let base = std::env::var("OSM_BASE_URL")
                .unwrap_or_else(|_| "https://api.opensourcemalware.com/functions/v1".to_string());
            let client = OsmClient::new(base, token);
            let _ = enrich(&mut report.findings, &client);
        }
    }
    Ok(report)
}

#[tauri::command]
fn list_packs() -> Vec<PackInfo> {
    builtin_packs()
        .into_iter()
        .map(|p| PackInfo {
            id: p.manifest.id,
            name: p.manifest.name,
            description: p.manifest.description,
        })
        .collect()
}

#[tauri::command]
fn clean_preview(dirs: Vec<String>) -> Result<Vec<RepoPlan>, String> {
    let packs = builtin_packs();
    let mut out = Vec::new();
    for dir in to_paths(dirs) {
        for repo in discover_repos(&dir) {
            let findings = scan_repo(&repo, &packs);
            let plan = plan_remediation(&findings, &packs);
            if plan.actions.is_empty() && plan.manual.is_empty() {
                continue;
            }
            out.push(RepoPlan {
                repo: repo.display().to_string(),
                actions: plan.actions,
                manual: plan.manual,
            });
        }
    }
    Ok(out)
}

#[tauri::command]
fn clean_apply(dirs: Vec<String>) -> Result<CleanSummary, String> {
    let packs = builtin_packs();
    let mut summary = CleanSummary {
        repos: 0,
        applied: 0,
        skipped: Vec::new(),
        backups: Vec::new(),
    };
    for dir in to_paths(dirs) {
        for repo in discover_repos(&dir) {
            let findings = scan_repo(&repo, &packs);
            let plan = plan_remediation(&findings, &packs);
            if plan.actions.is_empty() {
                continue;
            }
            let res = apply(&repo, &plan.actions, true);
            summary.repos += 1;
            summary.applied += res.applied.len();
            for (a, e) in res.skipped {
                summary.skipped.push(SkippedAction {
                    action: describe(&a),
                    reason: e,
                });
            }
            if let Some(bd) = res.backup_dir {
                summary.backups.push(bd.display().to_string());
            }
        }
    }
    Ok(summary)
}

#[tauri::command]
fn restore(dirs: Vec<String>) -> Result<RestoreSummary, String> {
    let mut summary = RestoreSummary { repos: 0, restored: 0 };
    for dir in to_paths(dirs) {
        for repo in discover_repos(&dir) {
            let r = core_restore(&repo);
            if r.backup_dir.is_some() {
                summary.repos += 1;
                summary.restored += r.restored.len();
            }
        }
    }
    Ok(summary)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            scan,
            list_packs,
            clean_preview,
            clean_apply,
            restore
        ])
        .run(tauri::generate_context!())
        .expect("error while running Wormward desktop");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn list_packs_returns_bundled() {
        let packs = list_packs();
        assert!(packs.iter().any(|p| p.id == "polinrider"));
        assert!(packs.iter().any(|p| p.id == "shai-hulud"));
    }

    #[test]
    fn clean_preview_lists_actions_for_infected_repo() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();
        let plans = clean_preview(vec![tmp.path().display().to_string()]).unwrap();
        assert_eq!(plans.len(), 1);
        assert!(!plans[0].actions.is_empty());
    }
}
