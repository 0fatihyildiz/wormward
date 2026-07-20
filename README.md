# Wormward

Detect, remove, and prevent self-propagating supply-chain malware ("worms") across your local
repositories, your GitHub org, and your dev machine. Each campaign (PolinRider, Shai-Hulud,
Glassworm, Axios/BlueNoroff, …) ships as a modular signature pack, so one tool covers the whole
family — with a behavioral capability engine that catches variants no literal signature knows yet.

**Read-only by default.** `scan`, `doctor`, `github` (without `--fix`), and the CI Action never
execute scanned code and never write to your repos. Cleaning, pushing, and machine hardening are
always explicit, backed up, and dry-run first.

Precision is a first-class goal: every signature is designed not to false-positive on legitimate
code (lockfiles, WASM/Emscripten glue, minified bundles, popular dependencies). See
[docs/superpowers/specs/2026-07-20-wormward-fp-hardening.md](docs/superpowers/specs/2026-07-20-wormward-fp-hardening.md).

## Install

**CLI from source:**
```bash
cargo install --path crates/wormward-cli
# or: cargo build --release -p wormward-cli   →   target/release/wormward
```

**Prebuilt binaries & desktop app:** the [Releases](https://github.com/0fatihyildiz/wormward/releases)
page — CLI binaries (macOS / Linux / Windows) and desktop bundles (`.dmg` / `.msi` / `.AppImage`).

**Desktop app (Tauri + Svelte) from source:**
```bash
cd apps/desktop && pnpm install && pnpm tauri build   # or: pnpm tauri dev
```

## Scan

```bash
wormward scan ~                     # scan every git repo under your home dir (read-only)
wormward scan .                     # scan the current project
wormward scan . --format json       # machine-readable output for CI
wormward scan . --format sarif      # SARIF 2.1.0 for the GitHub Security tab
wormward scan ~ --deep              # also scan every branch tip (worms hide on non-default branches)
wormward scan ~ --history           # also pickaxe full git history for scrubbed-but-reachable payloads
wormward scan . --osv               # also gate lockfiles via `osv-scanner` (if installed)
wormward scan . --include-community # include lower-confidence community IOC leads (off by default)
```

Exit codes: `0` clean, `1` infections found, `2` error. A single scan covers:

- **content signatures** (literal / regex / sha256) on target config/entry files,
- a **capability engine** — value-independent behavioral detectors (obfuscation, credential access,
  network egress, process spawn, on-chain C2 resolution, self-propagation, download-and-exec,
  invisible-Unicode / Trojan-Source stego, fake-asset magic-byte mismatch, …) with a surface-aware
  gate, so **new variants** are caught without a literal signature,
- a campaign **analyzer** for high-confidence, variant-agnostic confirmation,
- **lockfiles** (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `composer.lock`, `go.sum`,
  Pipfile.lock, requirements.txt) matched **version-aware** against known-malicious packages,
- **`node_modules`** dependency entrypoints (the malware ships inside installed deps),
- dropped artifacts (`temp_auto_push.bat`), `.gitignore` tampering, and — with `--history` — git
  **author/committer date-skew** (anti-dated / clock-rewound commits).

`--deep` is diff-based: each branch tip is scanned only for what it changes vs HEAD (content shared
with HEAD is covered by the working-tree pass), so it stays fast and low-heat even on many-branch repos.

## Clean

```bash
wormward clean .                              # preview removals (dry-run)
wormward clean . --apply                      # strip payloads, delete artifacts, fix .gitignore (backup on)
wormward clean . --apply --all-branches --yes # also clean infected tips of other branches (via worktrees)
wormward clean . --apply --push --yes         # + commit and push the cleaned state
wormward clean . --apply --push --rewrite --yes        # + amend HEAD and force-with-lease (DANGEROUS)
wormward clean . --rewrite-history --yes      # rewrite ALL git history (git-filter-repo) to redact
                                              #   injection markers — for a committed-then-force-pushed
                                              #   payload. Dry-run unless --yes; tags a backup ref.
wormward restore .                            # revert the last clean from backup
```

Remediation is surgical (strip the appended payload, keep the legit config), always backed up to
`.wormward-backup/`, and verified after stripping (a residual re-flags rather than silently passing).

## Scan GitHub (org / account)

```bash
wormward github                        # scan every repo you own or belong to (clone-free, via the API)
wormward github --org my-org           # restrict to an org
wormward github --audit                # + read-only account-persistence audit (token scopes, SSH/GPG
                                       #   keys, app installs, per-repo webhooks/deploy-keys/runners)
wormward github --fix --push --yes     # remediate infected default branches (backs up, verifies, pushes)
```

Scans every branch tip clone-free through the GitHub API; a truncated (very large) tree falls back to
a local clone. Own git operations are hardened (hooks disabled, `--no-verify`, `GIT_CONFIG_NOSYSTEM`)
so a malicious scanned repo can't execute a hook during remediation. A push is gated behind the
account audit (fail-closed until you `--i-rotated`).

## Machine check (`doctor`)

Complements the repo scan by looking at the *machine* — read-only, macOS-first:

```bash
wormward doctor                 # running loader processes, tainted toolchain caches, trigger paths,
                                #   persistence (launchd/cron), live C2 connections, shell-rc injection,
                                #   globally-installed malicious packages, keychain-theft activity
wormward doctor --watch 180     # poll for 3 min to catch a loader that only respawns on a trigger
wormward doctor --fix           # clear tainted caches + set npm/pnpm ignore-scripts=true
wormward doctor --osv           # also gate discovered lockfiles against OSV
```

`doctor` fails closed: if a scan root exists but can't be read (macOS Full Disk Access / TCC), it
reports an **unscanned** blind spot rather than certifying "clean."

## Prevent (`harden`)

```bash
wormward harden                 # dry-run: show what would be hardened
wormward harden --apply         # install a global pre-commit guard + set npm/pnpm ignore-scripts
```

`harden` makes only safe, user-local changes automatically; system/global steps (a `/etc/hosts` C2
sinkhole, enabling the global hooks path) are **printed for you to run**, never executed silently.

## Export detection rules

Consume wormward's IOC catalog in your own pipeline instead of running the binary:

```bash
wormward export-rules --format yara      > wormward.yar
wormward export-rules --format sigma     > wormward.sigma.yml
wormward export-rules --format suricata  > wormward.rules
```

## CI integration

Ship the read-only scan as a GitHub Action that fails the build on findings and uploads SARIF. It is
safe on untrusted pull requests (never executes scanned code; the scanner comes from a pinned trusted
ref, not the PR). See [docs/ci-integration.md](docs/ci-integration.md).

## Online verification (opt-in)

Cross-check findings against the live OpenSourceMalware database (needs a free `OSM_API_KEY`):

```bash
export OSM_API_KEY=osm_...
wormward scan ~ --online                            # enrich npm/domain findings with live OSM data
wormward check --type package --ecosystem npm left-pad
```

Opt-in only: without `--online` nothing leaves your machine, and even then only the npm-package names
and domains your local packs already flagged are sent — nothing else.

## Campaigns covered

`wormward list-packs`

- **PolinRider** — DPRK / Contagious-Interview supply-chain worm: obfuscated JS appended to config
  files, blockchain dead-drop C2 (TRON/Aptos/BSC), `temp_auto_push.bat` history-rewriting
  propagation, cross-ecosystem malicious packages.
- **Shai-Hulud** — npm self-propagating worm (dropper + lifecycle scripts, CI exfil).
- **Glassworm** — invisible-Unicode / Trojan-Source stego with Solana-Memo C2 (kept structurally
  separate from PolinRider; the stego is caught by the capability engine).
- **Axios / BlueNoroff** — specific compromised `axios` versions delivering a Linux RAT (flagged
  strictly by version, never by name).

## Contributing a campaign pack

Most worms need only a data file: add `crates/wormward-packs/src/<id>/pack.yaml` and register it in
`builtin_packs()`. See `polinrider/pack.yaml` for the full schema (target files, content signatures,
version-aware `bad_packages`, artifacts, IOC domains, remediation). Before adding a signature, run
the FP checklist in the hardening spec — a signature that fires on a clean install of a popular
dependency is a bug, and every pack change ships with a clean-corpus regression test.

## License

MIT
