//! `wormward doctor` — machine-level PolinRider check (macOS-first).
//!
//! Complements the repo/git scanner by looking at the *machine*: running loader processes,
//! tainted toolchain caches, and the editor/npm trigger paths that let the worm re-run. Every
//! detector reuses [`polinrider_fingerprint`], so a machine hit is confirmed by the exact same
//! obfuscation fingerprint as an on-disk finding.

use wormward_packs::polinrider_fingerprint;

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
}

impl DoctorReport {
    /// True if anything actionable was found — drives the process exit code.
    pub fn has_findings(&self) -> bool {
        !self.processes.is_empty()
    }
}

/// Run the machine check once (single point-in-time snapshot).
pub fn check() -> DoctorReport {
    DoctorReport { processes: scan_process_lines(&list_processes()) }
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
}
