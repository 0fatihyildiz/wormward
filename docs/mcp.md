# wormward as an MCP server

`wormward mcp` runs wormward as a [Model Context Protocol](https://modelcontextprotocol.io) stdio
server, so MCP clients — **Claude Code, Cursor, Codex**, and any other — can drive its tools. It
speaks newline-delimited JSON-RPC 2.0 on stdin/stdout and ships inside the one binary (no runtime,
no SDK, no extra process).

## Tools

| Tool | What it does | Mutating? |
|---|---|---|
| `scan` | Scan a path for supply-chain worm infections (read-only, never executes scanned code) | no |
| `check_package` | Pre-install check of an npm package (fetch metadata + entry, no install/exec) | no |
| `doctor` | Read-only machine check (loader processes, tainted caches, persistence, C2, keychain) | no |
| `export_iocs` | Export takedown-ready IOCs (`list` / `npm-report` / `stix`) | no |
| `hunt` | Mine new decoder/version-family/typosquat intel from a directory of payloads | no |
| `list_packs` | List the campaign detection packs in this build | no |
| `clean` | Strip payloads / delete artifacts in a repo — **dry-run unless `apply: true`; backs up first** | yes |
| `harden` | Set npm/pnpm ignore-scripts + install a pre-commit guard — **dry-run unless `apply: true`** | yes |

The two mutating tools default to a **preview** — a connected assistant must pass `apply: true`
explicitly, and `clean` always writes a backup first. System-level steps (a `/etc/hosts` C2 sinkhole)
are only ever printed, never run.

## Prerequisite — `wormward` must be runnable

MCP clients spawn the command you configure, so `wormward` has to be on your `PATH` (or you point
the config at an absolute path). Install it once:

```bash
cargo install --path crates/wormward-cli    # → ~/.cargo/bin/wormward (usually on PATH)
```

Not installing? Use the absolute path to the built binary instead — e.g. the `command` becomes
`/path/to/wormward/target/release/wormward` (build it first with
`cargo build --release -p wormward-cli`). A client error like `Executable not found in $PATH:
"wormward"` means this step was skipped.

## Connect a client

**Claude Code**
```bash
claude mcp add wormward -- wormward mcp
```
or, project-scoped, in `.mcp.json`:
```json
{ "mcpServers": { "wormward": { "command": "wormward", "args": ["mcp"] } } }
```

**Cursor** — `.cursor/mcp.json`:
```json
{ "mcpServers": { "wormward": { "command": "wormward", "args": ["mcp"] } } }
```

**Codex** — `~/.codex/config.toml`:
```toml
[mcp_servers.wormward]
command = "wormward"
args = ["mcp"]
```

**Any MCP client** — command `wormward`, args `["mcp"]`, transport `stdio`.

## Sanity check by hand

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | wormward mcp
```
