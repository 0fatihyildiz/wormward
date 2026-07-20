//! CLI text/JSON rendering over the shared machine-check engine (`wormward-doctor`).

pub use wormward_doctor::*;

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

/// Render the report as JSON (for scripting).
pub fn render_json(r: &DoctorReport) -> String {
    serde_json::to_string_pretty(r).unwrap_or_else(|_| "{}".to_string())
}
