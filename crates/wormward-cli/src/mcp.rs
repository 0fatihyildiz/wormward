//! MCP (Model Context Protocol) stdio server — lets MCP clients (Claude Code, Cursor, Codex, …)
//! drive wormward as a set of tools. Hand-rolled newline-delimited JSON-RPC 2.0 over stdin/stdout
//! (the MCP stdio transport), so it ships inside the one binary with no async runtime or SDK dep.
//!
//! Every tool reuses the exact same core calls the CLI uses, so behaviour never drifts. Mutating
//! tools (`clean`, `harden`) default to DRY-RUN — a connected assistant must pass `apply: true`
//! explicitly, and `clean` always backs up first.

use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use wormward_core::RepoFiles;
use wormward_packs::builtin_packs;

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run the server against stdin/stdout until EOF.
pub fn run() -> std::process::ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(stdin.lock(), stdout.lock());
    std::process::ExitCode::SUCCESS
}

/// The JSON-RPC loop. Generic over reader/writer so it can be driven from a test with byte buffers.
fn serve<R: BufRead, W: Write>(mut reader: R, mut writer: W) {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break, // EOF or read error
            _ => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<Value>(trimmed) else {
            continue; // ignore malformed lines
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let result = dispatch(method, req.get("params"));
        // Only requests (which carry an `id`) get a response; notifications do not.
        if let Some(id) = id {
            let msg = match result {
                Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
                Err((code, message)) => {
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
                }
            };
            let _ = writeln!(writer, "{msg}");
            let _ = writer.flush();
        }
    }
}

fn dispatch(method: &str, params: Option<&Value>) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "wormward", "version": env!("CARGO_PKG_VERSION") }
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => {
            let p = params.cloned().unwrap_or_else(|| json!({}));
            let name = p.get("name").and_then(Value::as_str).unwrap_or("");
            let args = p.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let (text, is_error) = match call_tool(name, &args) {
                Ok(t) => (t, false),
                Err(e) => (e, true),
            };
            Ok(json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }))
        }
        // Notifications (e.g. notifications/initialized) reach here with no id and are ignored.
        _ if method.starts_with("notifications/") => Ok(Value::Null),
        _ => Err((-32601, format!("method not found: {method}"))),
    }
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({ "name": "scan", "description":
            "Scan a path for supply-chain worm infections (read-only, never executes scanned code). Returns findings as JSON.",
            "inputSchema": obj(json!({
                "path": { "type": "string", "description": "File-system path to scan (a repo or a directory of repos)." },
                "deep": { "type": "boolean", "description": "Also scan every branch tip (default false)." },
                "include_community": { "type": "boolean", "description": "Include lower-confidence community leads (default false)." }
            }), &["path"]) }),
        json!({ "name": "check_package", "description":
            "PRE-INSTALL check of an npm package: fetch its metadata + entry from the registry (no install, no execution) and flag dropper behaviour.",
            "inputSchema": obj(json!({ "name": { "type": "string", "description": "npm package, optionally name@version." } }), &["name"]) }),
        json!({ "name": "doctor", "description":
            "Read-only machine check: running loader processes, tainted caches, persistence, C2 connections, keychain-theft activity.",
            "inputSchema": obj(json!({}), &[]) }),
        json!({ "name": "export_iocs", "description":
            "Export takedown-ready IOCs from the tracked campaigns.",
            "inputSchema": obj(json!({ "format": { "type": "string", "enum": ["list", "npm-report", "stix"], "description": "Output format (default list)." } }), &[]) }),
        json!({ "name": "hunt", "description":
            "Mine NEW threat intelligence (decoder names, version-tag families, typosquat packages not yet in the baseline) from a directory of payloads.",
            "inputSchema": obj(json!({ "path": { "type": "string", "description": "Directory to mine." } }), &["path"]) }),
        json!({ "name": "list_packs", "description": "List the campaign detection packs compiled into this build.",
            "inputSchema": obj(json!({}), &[]) }),
        json!({ "name": "clean", "description":
            "Remediate a single repo: strip payloads / delete artifacts / fix .gitignore. DRY-RUN unless apply=true; always backs up first.",
            "inputSchema": obj(json!({
                "path": { "type": "string", "description": "Repo path to clean." },
                "apply": { "type": "boolean", "description": "Actually apply changes (default false = preview)." }
            }), &["path"]) }),
        json!({ "name": "harden", "description":
            "Prevent: set npm/pnpm ignore-scripts and install a global pre-commit guard. DRY-RUN unless apply=true. System steps are printed, never run.",
            "inputSchema": obj(json!({ "apply": { "type": "boolean", "description": "Apply the safe local changes (default false = preview)." } }), &[]) }),
    ]
}

fn call_tool(name: &str, args: &Value) -> Result<String, String> {
    match name {
        "scan" => tool_scan(args),
        "check_package" => tool_check_package(args),
        "doctor" => Ok(tool_doctor()),
        "export_iocs" => Ok(tool_export_iocs(args)),
        "hunt" => tool_hunt(args),
        "list_packs" => Ok(tool_list_packs()),
        "clean" => tool_clean(args),
        "harden" => Ok(tool_harden(args)),
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key).and_then(Value::as_str).ok_or_else(|| format!("missing required argument '{key}'"))
}
fn arg_bool(args: &Value, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn tool_scan(args: &Value) -> Result<String, String> {
    let path = arg_str(args, "path")?;
    let roots = vec![PathBuf::from(path)];
    let packs = builtin_packs();
    let mut report = if arg_bool(args, "deep") {
        wormward_core::scan_deep(&roots, &packs)
    } else {
        wormward_core::scan(&roots, &packs)
    };
    if !arg_bool(args, "include_community") {
        report.findings.retain(|f| !f.signature_id.starts_with("pkg-community:"));
    }
    Ok(serde_json::to_string_pretty(&json!({
        "repos_scanned": report.repos_scanned,
        "findings_count": report.findings.len(),
        "findings": report.findings,
    }))
    .unwrap_or_default())
}

fn tool_check_package(args: &Value) -> Result<String, String> {
    let name = arg_str(args, "name")?;
    let c = wormward_osm::check_npm_package(name).map_err(|e| e.to_string())?;
    Ok(serde_json::to_string_pretty(&c).unwrap_or_default())
}

fn tool_doctor() -> String {
    let hits = wormward_doctor::scan_machine();
    serde_json::to_string_pretty(&json!({ "machine_hits": hits.len(), "hits": hits }))
        .unwrap_or_default()
}

fn tool_export_iocs(args: &Value) -> String {
    let packs = builtin_packs();
    match args.get("format").and_then(Value::as_str).unwrap_or("list") {
        "npm-report" => wormward_core::to_npm_report(&packs),
        "stix" => wormward_core::to_stix(&packs),
        _ => wormward_core::to_ioc_list(&packs),
    }
}

fn tool_hunt(args: &Value) -> Result<String, String> {
    let path = arg_str(args, "path")?;
    let files = wormward_core::WorkingTree::new(Path::new(path));
    let (kd, kf) = wormward_core::baseline();
    let (mut dec, mut fam, mut pkg) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for rel in files.paths() {
        if let Some(c) = files.read(rel) {
            let n = wormward_core::extract_new_iocs(&c, &kd, &kf);
            dec.extend(n.decoders);
            fam.extend(n.version_families);
            pkg.extend(n.packages);
        }
    }
    Ok(serde_json::to_string_pretty(&json!({
        "new_decoders": dec, "new_version_families": fam, "new_typosquat_packages": pkg,
    }))
    .unwrap_or_default())
}

fn tool_list_packs() -> String {
    let packs = builtin_packs();
    let list: Vec<Value> = packs
        .iter()
        .map(|p| json!({ "id": p.manifest.id, "name": p.manifest.name, "description": p.manifest.description }))
        .collect();
    serde_json::to_string_pretty(&json!({ "packs": list })).unwrap_or_default()
}

fn tool_clean(args: &Value) -> Result<String, String> {
    let path = arg_str(args, "path")?;
    let repo = PathBuf::from(path);
    let packs = builtin_packs();
    let findings = wormward_core::scan_repo(&repo, &packs);
    let plan = wormward_core::plan_remediation(&findings, &packs);
    let targets: Vec<String> =
        plan.actions.iter().map(|a| a.target().to_string_lossy().to_string()).collect();
    if !arg_bool(args, "apply") {
        return Ok(serde_json::to_string_pretty(&json!({
            "mode": "dry-run",
            "would_remediate": targets,
            "manual_only": plan.manual.len(),
            "hint": "re-call with apply=true to strip payloads (a backup is written first)"
        }))
        .unwrap_or_default());
    }
    let result = wormward_core::apply(&repo, &plan.actions, true);
    Ok(serde_json::to_string_pretty(&json!({
        "mode": "apply",
        "applied": result.applied.len(),
        "skipped": result.skipped.len(),
        "backup_dir": result.backup_dir.map(|p| p.to_string_lossy().to_string()),
    }))
    .unwrap_or_default())
}

fn tool_harden(args: &Value) -> String {
    if !arg_bool(args, "apply") {
        return json!({
            "mode": "dry-run",
            "would": [
                "npm config set ignore-scripts true (+ pnpm if present)",
                "install ~/.git-hooks/pre-commit guard (opt-in to enable)"
            ],
            "manual": "a /etc/hosts C2 sinkhole is printed for you to apply with sudo (never run automatically)",
            "hint": "re-call with apply=true to make the safe local changes"
        })
        .to_string();
    }
    let applied = wormward_doctor::fix_triggers();
    let hook = match wormward_doctor::install_pre_commit_hook() {
        Ok(p) => format!("installed pre-commit hook at {}", p.display()),
        Err(e) => format!("pre-commit hook not installed: {e}"),
    };
    serde_json::to_string_pretty(&json!({ "mode": "apply", "applied": applied, "hook": hook }))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn drive(input: &str) -> Vec<Value> {
        let mut out = Vec::new();
        serve(Cursor::new(input.as_bytes()), &mut out);
        String::from_utf8(out)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn initialize_then_tools_list() {
        let msgs = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n\
             {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
             {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        );
        // The notification produced NO response, so only two messages come back.
        assert_eq!(msgs.len(), 2, "notification must not get a response: {msgs:?}");
        assert_eq!(msgs[0]["result"]["serverInfo"]["name"], "wormward");
        assert_eq!(msgs[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
        let tools = msgs[1]["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for expected in ["scan", "check_package", "doctor", "export_iocs", "hunt", "clean", "harden"] {
            assert!(names.contains(&expected), "tool {expected} must be listed");
        }
    }

    #[test]
    fn tools_call_export_iocs_returns_content() {
        let msgs = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"export_iocs\",\"arguments\":{\"format\":\"npm-report\"}}}\n",
        );
        assert_eq!(msgs.len(), 1);
        let text = msgs[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("npmjs.com/package"), "npm-report content expected: {text}");
        assert_eq!(msgs[0]["result"]["isError"], false);
    }

    #[test]
    fn unknown_method_is_json_rpc_error() {
        let msgs = drive("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"bogus\"}\n");
        assert_eq!(msgs[0]["error"]["code"], -32601);
    }

    #[test]
    fn unknown_tool_is_tool_error_not_protocol_error() {
        let msgs = drive(
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"nope\",\"arguments\":{}}}\n",
        );
        // A bad tool name is a tool-level error (isError:true), not a JSON-RPC error.
        assert!(msgs[0].get("error").is_none());
        assert_eq!(msgs[0]["result"]["isError"], true);
    }
}
