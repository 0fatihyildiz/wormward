//! `wormward doctor` — machine-level PolinRider check (macOS-first).
//!
//! Complements the repo/git scanner by looking at the *machine*: running loader processes,
//! tainted toolchain caches, and the editor/npm trigger paths that let the worm re-run. Every
//! detector reuses [`polinrider_fingerprint`], so a machine hit is confirmed by the exact same
//! obfuscation fingerprint as an on-disk finding.

use std::path::{Path, PathBuf};

use wormward_packs::polinrider_fingerprint;

/// Payloads are small; skip huge cache blobs and cap how many files we walk.
const MAX_CACHE_FILES: usize = 20_000;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// A running process whose command line matches the loader fingerprint.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct ProcHit {
    pub pid: u32,
    pub reason: String,
    pub snippet: String,
}

/// Aggregated machine-check results. Grows as `doctor` capabilities are added.
#[derive(Debug, serde::Serialize)]
pub struct DoctorReport {
    pub processes: Vec<ProcHit>,
    pub caches: Vec<CacheHit>,
    pub triggers: Vec<TriggerCheck>,
}

impl DoctorReport {
    /// True if an ACTIVE infection was found (running loader or tainted cache) — drives the exit
    /// code. Trigger exposures are advisory risk, not an infection, so they don't fail the run.
    pub fn has_findings(&self) -> bool {
        !self.processes.is_empty() || !self.caches.is_empty()
    }
}

/// Run the machine check once (single point-in-time snapshot).
pub fn check() -> DoctorReport {
    DoctorReport {
        processes: scan_process_lines(&list_processes()),
        caches: scan_caches(),
        triggers: audit_triggers(),
    }
}

/// Render the report as a sectioned text summary.
pub fn render_text(r: &DoctorReport) -> String {
    let mut out = String::from("wormward doctor — machine check\n\n");

    out.push_str("Running loader processes\n");
    if r.processes.is_empty() {
        out.push_str(
            "  ✓ none right now — a point-in-time check is not proof; re-run with\n\
             \x20   --watch <secs> while opening your editor/projects to catch respawns\n",
        );
    } else {
        for h in &r.processes {
            out.push_str(&format!("  ✗ pid {} — {}\n      {}\n", h.pid, h.reason, h.snippet));
        }
    }

    out.push_str("\nToolchain caches\n");
    if r.caches.is_empty() {
        out.push_str("  ✓ no tainted files in the npx / TypeScript caches\n");
    } else {
        for h in &r.caches {
            out.push_str(&format!("  ✗ {} — {}\n", h.path.display(), h.reason));
        }
        out.push_str("    → re-run with --fix to clear the affected cache dirs (they regenerate)\n");
    }

    out.push_str("\nTrigger paths (how the worm re-runs)\n");
    if r.triggers.is_empty() {
        out.push_str("  · no trigger checks available on this platform\n");
    } else {
        for t in &r.triggers {
            let mark = if t.exposed { "⚠" } else { "✓" };
            out.push_str(&format!("  {mark} {}: {}\n", t.name, t.detail));
        }
        if r.triggers.iter().any(|t| t.exposed) {
            out.push_str("    → --fix sets npm/pnpm ignore-scripts=true; ATA/MCP are advised above\n");
        }
    }
    out
}

/// Render the report as JSON (for the desktop / scripting).
pub fn render_json(r: &DoctorReport) -> String {
    serde_json::to_string_pretty(r).unwrap_or_else(|_| "{}".to_string())
}

/// Scan `(pid, command-line)` pairs for the loader fingerprint. Pure — the caller supplies the
/// process list — so it is testable without spawning `ps`. Naive markers like a bare `node -e`
/// are deliberately NOT flagged; only the full obfuscation fingerprint (marker + decoder) is.
pub fn scan_process_lines(procs: &[(u32, String)]) -> Vec<ProcHit> {
    procs
        .iter()
        .filter_map(|(pid, cmd)| {
            polinrider_fingerprint(cmd).map(|reason| ProcHit {
                pid: *pid,
                reason,
                snippet: snippet(cmd),
            })
        })
        .collect()
}

/// A short, single-line, char-safe excerpt of a process command for display.
fn snippet(cmd: &str) -> String {
    let one_line = cmd.split_whitespace().collect::<Vec<_>>().join(" ");
    let short: String = one_line.chars().take(120).collect();
    if short.chars().count() < one_line.chars().count() {
        format!("{short}…")
    } else {
        short
    }
}

/// Enumerate running processes as `(pid, full command line)` via `ps`. Returns empty on a
/// platform without `ps` (e.g. Windows) or on error, so the caller degrades gracefully.
pub fn list_processes() -> Vec<(u32, String)> {
    let out = match std::process::Command::new("ps").args(["-Awwo", "pid=,command="]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|line| {
            let (pid, cmd) = line.trim_start().split_once(' ')?;
            Some((pid.trim().parse().ok()?, cmd.trim().to_string()))
        })
        .collect()
}

/// A cached file whose content matches the loader fingerprint.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct CacheHit {
    pub path: PathBuf,
    pub reason: String,
}

/// Pure: fingerprint `(path, content)` pairs. Testable without a filesystem.
pub fn scan_contents(files: &[(PathBuf, String)]) -> Vec<CacheHit> {
    files
        .iter()
        .filter_map(|(p, c)| {
            polinrider_fingerprint(c).map(|reason| CacheHit { path: p.clone(), reason })
        })
        .collect()
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default()
}

/// Toolchain cache dirs (present ones only) that may hold worm-executed artifacts — machine-level
/// state the repo scan does not cover.
pub fn cache_targets() -> Vec<PathBuf> {
    let home = home_dir();
    [home.join(".npm/_npx"), home.join("Library/Caches/typescript")]
        .into_iter()
        .filter(|p| p.is_dir())
        .collect()
}

/// Recursively collect regular files under `dir` (bounded; symlinks not followed).
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if out.len() >= MAX_CACHE_FILES {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        match entry.file_type() {
            Ok(t) if t.is_dir() => collect_files(&entry.path(), out),
            Ok(t) if t.is_file() => out.push(entry.path()),
            _ => {}
        }
        if out.len() >= MAX_CACHE_FILES {
            return;
        }
    }
}

/// Scan one cache directory: fingerprint each small text file.
pub fn scan_cache_dir(dir: &Path) -> Vec<CacheHit> {
    let mut files = Vec::new();
    collect_files(dir, &mut files);
    let contents: Vec<(PathBuf, String)> = files
        .into_iter()
        .filter(|p| std::fs::metadata(p).map(|m| m.len() <= MAX_FILE_BYTES).unwrap_or(false))
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|c| (p, c)))
        .collect();
    scan_contents(&contents)
}

/// Scan every present toolchain cache dir.
pub fn scan_caches() -> Vec<CacheHit> {
    cache_targets().iter().flat_map(|d| scan_cache_dir(d)).collect()
}

/// The distinct cache dirs that hold at least one tainted file — the `--fix` deletes these
/// whole (they regenerate cleanly), mirroring the guide's `rm -rf ~/.npm/_npx`.
pub fn affected_cache_dirs(report: &DoctorReport) -> Vec<PathBuf> {
    cache_targets()
        .into_iter()
        .filter(|t| report.caches.iter().any(|h| h.path.starts_with(t)))
        .collect()
}

// ---- trigger paths (how the worm re-runs) ----

/// An editor/toolchain setting that can auto-run installs and re-trigger the loader.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct TriggerCheck {
    pub name: String,
    /// True when the setting leaves the machine open to auto-run triggers.
    pub exposed: bool,
    pub detail: String,
}

/// True if `npm/pnpm config get ignore-scripts` reports scripts are blocked.
fn ignore_scripts_on(config_output: &str) -> bool {
    config_output.trim() == "true"
}

/// True if the editor settings disable TypeScript Automatic Type Acquisition. Tolerant of JSONC
/// (comments / trailing commas) — a targeted key/value check, not a full parse.
fn ata_disabled(settings: &str) -> bool {
    settings
        .split("\"typescript.disableAutomaticTypeAcquisition\"")
        .nth(1)
        .and_then(|rest| rest.split(':').nth(1))
        .map(|v| v.trim_start().starts_with("true"))
        .unwrap_or(false)
}

/// Number of MCP servers configured in an editor's MCP JSON (each can `npm exec` on startup).
fn count_mcp_servers(json: &str) -> usize {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v.get("mcpServers").and_then(|m| m.as_object()).map(|o| o.len()))
        .unwrap_or(0)
}

fn command_exists(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ignore_scripts_check(tool: &str) -> TriggerCheck {
    let value = std::process::Command::new(tool)
        .args(["config", "get", "ignore-scripts"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let on = ignore_scripts_on(&value);
    TriggerCheck {
        name: format!("{tool} ignore-scripts"),
        exposed: !on,
        detail: if on {
            "install lifecycle scripts blocked".into()
        } else {
            format!("lifecycle scripts run on install — `{tool} config set ignore-scripts true`")
        },
    }
}

fn editor_settings_paths() -> Vec<(&'static str, PathBuf)> {
    let base = home_dir().join("Library/Application Support");
    vec![
        ("VS Code", base.join("Code/User/settings.json")),
        ("Cursor", base.join("Cursor/User/settings.json")),
    ]
}

fn mcp_config_paths() -> Vec<PathBuf> {
    let home = home_dir();
    vec![
        home.join(".cursor/mcp.json"),
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        home.join(".codeium/windsurf/mcp_config.json"),
    ]
}

/// Audit the editor/npm trigger paths that let the worm re-run after a config is cleaned.
pub fn audit_triggers() -> Vec<TriggerCheck> {
    let mut checks = vec![ignore_scripts_check("npm")];
    if command_exists("pnpm") {
        checks.push(ignore_scripts_check("pnpm"));
    }
    for (label, path) in editor_settings_paths() {
        if let Ok(s) = std::fs::read_to_string(&path) {
            let disabled = ata_disabled(&s);
            checks.push(TriggerCheck {
                name: format!("{label} TypeScript ATA"),
                exposed: !disabled,
                detail: if disabled {
                    "automatic type acquisition disabled".into()
                } else {
                    format!(
                        "ATA can auto-run npm install — add \"typescript.disableAutomaticTypeAcquisition\": true to {}",
                        path.display()
                    )
                },
            });
        }
    }
    let mcp_total: usize = mcp_config_paths()
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| count_mcp_servers(&s))
        .sum();
    if mcp_total > 0 {
        checks.push(TriggerCheck {
            name: "MCP servers".into(),
            exposed: true,
            detail: format!(
                "{mcp_total} configured — any can npm-exec a package on startup; audit and disable ones you don't trust"
            ),
        });
    }
    checks
}

/// Apply the safe trigger fixes: set `ignore-scripts=true` for npm (and pnpm if present). ATA and
/// MCP are left as printed guidance (editing JSONC settings / picking MCP servers isn't safe to
/// automate). Returns a line per applied fix.
pub fn fix_triggers() -> Vec<String> {
    let mut done = Vec::new();
    for tool in ["npm", "pnpm"] {
        if tool == "pnpm" && !command_exists("pnpm") {
            continue;
        }
        let ok = std::process::Command::new(tool)
            .args(["config", "set", "ignore-scripts", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            done.push(format!("set {tool} ignore-scripts=true"));
        }
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_loader_process_not_benign_node_e() {
        // Real benign `node -e` invocations seen on the machine must NOT be flagged; only a
        // command line carrying the full obfuscation fingerprint is a hit.
        let procs = vec![
            // Benign: LM Studio's worker bootstrap.
            (
                10011,
                "node -e function connectPort(port){return{postMessage:d=>process.send({port,data:d})}}"
                    .to_string(),
            ),
            // Benign: a fly.io DB query the developer ran.
            (
                65454,
                "node -e import('/app/.output/server/chunks/nitro/nitro.mjs').then(async n=>{})"
                    .to_string(),
            ),
            // The loader: injection marker + string-shuffle decoder inline.
            (
                40404,
                "node -e global['!']='10';var _$_1e42=(function(r,i){return r})('x',7);global[_$_1e42[0]]=require"
                    .to_string(),
            ),
        ];
        let hits = scan_process_lines(&procs);
        assert_eq!(hits.len(), 1, "only the loader process should match, got {hits:?}");
        assert_eq!(hits[0].pid, 40404);
    }

    #[test]
    fn no_hits_on_clean_process_list() {
        let procs = vec![
            (1, "/sbin/launchd".to_string()),
            (200, "node /Users/me/app/server.js".to_string()),
            (201, "npm exec tsc --noEmit".to_string()),
        ];
        assert!(scan_process_lines(&procs).is_empty());
    }

    #[test]
    fn cache_scan_flags_tainted_file_only() {
        let files = vec![
            // A legit cached type stub / package file.
            (PathBuf::from("_npx/abc/index.js"), "module.exports = { hello: 1 };".to_string()),
            (PathBuf::from("typescript/node_modules/@types/node/index.d.ts"), "export {};".to_string()),
            // A tainted cached artifact carrying the loader.
            (
                PathBuf::from("_npx/evil/postinstall.js"),
                "global.i='5-3-168';var _$_8e2c=(function(r,i){return r})('x',7);".to_string(),
            ),
        ];
        let hits = scan_contents(&files);
        assert_eq!(hits.len(), 1, "only the tainted cache file should match, got {hits:?}");
        assert_eq!(hits[0].path, PathBuf::from("_npx/evil/postinstall.js"));
    }

    #[test]
    fn ignore_scripts_parsing() {
        assert!(ignore_scripts_on("true\n"));
        assert!(ignore_scripts_on("  true  "));
        assert!(!ignore_scripts_on("false"));
        assert!(!ignore_scripts_on("undefined"));
        assert!(!ignore_scripts_on(""));
    }

    #[test]
    fn ata_disabled_detection_tolerates_jsonc() {
        assert!(ata_disabled(
            "{\n  // editor config\n  \"typescript.disableAutomaticTypeAcquisition\": true,\n}"
        ));
        assert!(!ata_disabled("{ \"typescript.disableAutomaticTypeAcquisition\": false }"));
        assert!(!ata_disabled("{ \"editor.fontSize\": 13 }"));
    }

    #[test]
    fn mcp_server_count() {
        assert_eq!(
            count_mcp_servers(r#"{"mcpServers":{"a":{"command":"npx"},"b":{"command":"node"}}}"#),
            2
        );
        assert_eq!(count_mcp_servers(r#"{"mcpServers":{}}"#), 0);
        assert_eq!(count_mcp_servers("{}"), 0);
        assert_eq!(count_mcp_servers("not json"), 0);
    }
}
