# Campaign-Agnostic Capability Engine — Design (v2)

- **Date:** 2026-07-19
- **Branch:** `variant-generalization`
- **Status:** Approved design (brainstorming) — validated against 8 real detectors + malware sources
  (3 Shai-Hulud, 5 PolinRider). All value-independent invariant gaps folded in; nothing deferred.

## 1. Context & Problem

Wormward detects supply-chain campaigns (PolinRider, Shai-Hulud) with **IOC-shaped signals**:
literal strings, regexes, sha256 hashes, C2 domains, bad npm package names
(`crates/wormward-core/src/matchers.rs`, `crates/wormward-core/src/scanner.rs`). Every one of
these is a **value the attacker chooses** (IP, wallet, decoder name, domain, literal). Values
rotate freely — a blocklist that loses the arms race.

**Generative reframe:** stop describing what the malware *is*; describe what it *must do* — its
**invariants**. An invariant is something the attacker cannot change without breaking the attack.
IOCs are infinite; invariants are finite and enumerable.

This engine is a static, lexical, campaign-agnostic core that (1) enumerates the finite **auto-run
surface** of a repo and (2) scores value-independent **capabilities** on it, firing on a
conservative surface-aware gate. IOCs remain in packs as complementary enrichment/attribution.

## 2. Decisions (locked)

1. **Approach A — capability scoring** (static, lexical, no AST). B (taint dataflow) and C
   (detonation sandbox) are separate future engines, not part of this build.
2. **Core engine, additive.** Lives in `wormward-core`, runs alongside packs on every scan. Packs
   keep their IOC layer.
3. **Conservative / near-zero FP.** A surface gate plus a capability gate is the FP spine. For
   behavioral surfaces (lifecycle/workflow/propagation/derived), the *behavior itself* is the
   near-zero-FP signal, so obfuscation is **not** required there.
4. **One-hop reachability accepted.** The strict "surface files only" rule is narrowly relaxed:
   a file invoked as `node ./X.js` from an auto-run surface is promoted to a scored **DerivedScript**.
   FP-safe (only auto-run-reachable files are scored).
5. **No deferred signals.** Every value-independent invariant found across the 8 detectors is
   included, including the two data-shape/payload behaviors (exfil-staging blob, destructive wiper).

### Cross-campaign validation (why v2 differs from v1)

Analysis of 8 real tools converged on one verdict: the invariant **axes** are correct, but v1's
**reach** missed both campaigns for structural reasons:

- **Payload in clean text** — Shai-Hulud's `"preinstall":"node setup_bun.js"` launcher and
  PolinRider's force-push `.bat` are not obfuscated, so a mandatory-obfuscation gate never fires.
- **Payload off-surface** — Shai-Hulud's harvester lives in an attacker-named dropped file
  (`setup_bun.js`); PolinRider injects into entry files (`index.js`/`App.js`/`truffle.js`) and
  drops `.bat` scripts — none on v1's surface map.
- **Biggest auto-run surface omitted** — `.github/workflows/*.yml` runs on push with no user intent.
- **TasksJson gate wrong shape** — the real TasksJacker tell is `folderOpen + remote-fetch/exec`
  (`curl|wget|bash|certutil|powershell -enc`), not the binary-asset exec v1 specified.

## 3. Architecture

New pack-independent `wormward-core` modules + a scanner integration point + one analyzer change.

- **`surface.rs`** — pure classification. Maps a repo-relative `Path` (and, for reachability, a set
  of already-known auto-run command strings) to a `Surface` or `None`. No I/O.

  ```
  enum Surface {
      ConfigFile, LifecycleScript, WorkflowFile, TasksJson,
      GitHook, PropagationScript, DerivedScript, BinaryAsset,
  }
  fn classify(path: &Path) -> Option<Surface>
  ```

- **`capability.rs`** — pure lexical/regex scoring; reuses `shannon_entropy`. No AST.

  ```
  struct CapabilityScore {
      obfuscation, credential_access, network_egress, process_spawn,
      magic_mismatch, download_exec, propagation, on_chain_resolve,
      trailing_code, destructive_wipe, exfil_staging: bool,
      evidence: Vec<String>,   // matched tokens, for explainability
  }
  fn score(content: &str, surface: Surface) -> CapabilityScore
  fn gate(surface: Surface, s: &CapabilityScore) -> bool
  ```

- **`reachability.rs`** (or a fn in `surface.rs`) — extracts `node|bun|ts-node|tsx ./X.{js,cjs,mjs}`
  targets from LifecycleScript / WorkflowFile-run / TasksJson command strings, resolves them
  against `files.paths()`, and yields DerivedScript paths. Depth 1 only.

- **Integration** — `scanner.rs` gains `scan_capabilities(repo, &files) -> Vec<Finding>`, called
  next to `scan_files` in **both** `scan_repo` and the per-tree loop of `deep_scan_repo` (working
  tree + every branch tip). Same `RepoFiles` abstraction.

- **Analyzer** — `crates/wormward-packs/src/polinrider/analyzer.rs`: broaden `marker_re` so the
  ESM re-entry shim confirms (see §10).

### Data flow

```
files.paths() ─┬─► surface::classify(path) ─► Some(surface) ─► read ─► content
               │                                                          │
               └─► scan auto-run command strings (lifecycle/workflow/tasks)
                        └─► reachability: node ./X.js ─► promote X ─► DerivedScript
                                                                          │
                                             capability::score(content, surface)
                                                                          │
                                             capability::gate(surface, &score) ─true─► Finding
```

## 4. Auto-run surfaces

Finite, curated. Only places that run **without user intent** (plus off-surface files reachable
one hop from them, and two data-shape checks).

| Surface | Members | Notes |
|---------|---------|-------|
| **ConfigFile** | toolchain configs (`postcss/vite/next/tailwind/eslint/svelte/nuxt/webpack/rollup/babel/astro/vitest/jest/remix/gatsby-config/gatsby-node .config.{js,mjs,cjs,ts}`, `.eslintrc.{js,cjs}`, `vue.config.*`, `gridsome.config.*`) **plus app entry files** (`index.js`, `src/index.js`, `App.js`/`app.js`, `truffle.js`) | Entry files are gated by the obfuscation/trailing-code prior → FP-safe. Closes the "generic engine narrower than the pack" gap. |
| **LifecycleScript** | `package.json` `scripts`: `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`, `prepack`, `postpack` | Scored content = the script string. Behavioral gate (no obfuscation required). Source of reachability hops. |
| **WorkflowFile** | `.github/workflows/*.{yml,yaml}`, `.gitlab-ci.yml` | Auto-runs on `push`/`pull_request`/`discussion`. Run-step bodies scored lexically (no YAML AST). Source of reachability hops. |
| **TasksJson** | `.vscode/tasks.json` tasks with `runOn:folderOpen` (a.k.a. `allowAutomaticTasks`) | Fires on remote-fetch/exec token (primary) or binary-asset exec. Source of reachability hops. |
| **GitHook** | `.git/hooks/*` (non-`*.sample`) + `.husky/*` | `.git/` is pruned by `walk_repo_files`; a dedicated pass lists `.git/hooks/*` for the working tree only. |
| **PropagationScript** | `*.bat`, `*.cmd`, `*.sh`, `*.ps1` anywhere in the repo | The worm's dropped auto-push/dropper scripts. Fires only on the git-falsification conjunction or download-exec — plain text, no obfuscation. (Binary droppers like `.pyz` are non-UTF-8 → `read()` returns `None` → stay IOC artifacts in the pack.) |
| **DerivedScript** | any local `*.{js,cjs,mjs}` reached one hop via `node ./X` from Lifecycle/Workflow/TasksJson | Where Shai-Hulud's `setup_bun.js` payload actually lives. Scored like a ConfigFile+behavioral. |
| **BinaryAsset** | font/image ext (`.woff`,`.woff2`,`.ttf`,`.otf`,`.eot`,`.png`,`.jpg`,`.jpeg`,`.gif`,`.ico`); `.svg` excluded | Fake-font vector. Fires on MagicMismatch. |

Two **repo-level data-shape checks** (not auto-run surfaces, run once per tree):

- **ExfilStaging** — any committed `*.json` at repo root (esp. `data.json`) whose first non-ws
  bytes are `eyJ` (base64 of `{"`) and which contains `==` → base64-encoded stolen-credential
  staging blob. Value-independent data shape.
- (Reflog/amend git corroboration already exists in `scan_repo`.)

## 5. Capability signals (lexical)

Each returns a bool and pushes matched tokens into `evidence`. Patterns are the starting set;
exact regexes are calibrated during implementation.

- **Obfuscation** — entropy tail over threshold (reuse `shannon_entropy`); dynamic
  `global/globalThis/process[...]` or `global.<x>` access/assign; long `fromCharCode`/`\xNN`/`\uNNNN`
  runs; single line >~500 chars (not `data:`/URL); `eval(`/`new Function(`/`atob(`; fragment-built
  `require`/`createRequire`; `_$_`-style decoder. **+ ESM re-entry shim**: `global['r']=require`,
  `global['m']=module`, `createRequire(import.meta.url)` (osm-source: strongest marker-independent tell).
- **CredentialAccess** — `.aws/credentials`, `.ssh/`, `.npmrc`, `.git-credentials`, bulk
  `process.env` (`Object.keys(process.env)`, serializing env), keychain
  (`security find-generic-password`), Windows Credential Manager, browser `Login Data`/`logins.json`,
  secret env names (`NPM_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_SECRET`, `AWS_ACCESS_KEY`).
  **+ GitHub Actions secret context** `${{ secrets.* }}` (WorkflowFile surface).
- **NetworkEgress** — `require('http'|'https'|'net'|'dgram'|'tls')` / matching `import`, `fetch(`,
  `axios`, `XMLHttpRequest`, `WebSocket`, or an outbound URL literal in a ConfigFile.
- **ProcessSpawn** — `child_process`, `spawn(`, `exec(`, `execSync(`, `Bun.spawn(Sync)`.
- **DownloadExec** — a fetch token (`curl`, `wget`, `fetch(`, `Invoke-WebRequest`, `iwr`,
  `certutil -urlcache`, `powershell -enc`) **AND** an exec sink (`| sh`, `| bash`, `node -e`,
  `node -`, `chmod +x`, `bun run`, `sh -c`, `eval`). Generalizes `trufflehog`/fake-Bun bootstrap.
- **Propagation** — **primary (near-zero-FP conjunction):** `--amend` **AND** `push` with
  `--force`/`-f`/`--force-with-lease`/`-uf` **AND** `--no-verify` (optionally + committer-date/clock
  manipulation). **Secondary (context-gated):** `npm publish`, `gh api …/repos`, `gh repo create`,
  `gh workflow`, registry publish — counts as propagation **only** on an auto-run surface
  (Lifecycle/Workflow/Derived/Hook) or co-occurring with CredentialAccess (never bare on a
  standalone PropagationScript).
- **OnChainResolve** — RPC-shaped fetch (URL/path/body containing `eth_call`,
  `eth_getTransactionByHash`, `/v1/accounts/`, `trongrid`, `aptoslabs`, `bsc-dataseed`, or
  `"method":"eth_`) **AND** a XOR-decode loop shape (`^` over `charCodeAt`/`fromCharCode`) feeding
  `eval`/`new Function`. Takedown-resistant blockchain dead-drop; only the shape is invariant.
- **TrailingCode** — non-comment, non-whitespace executable code following the **last**
  `export default …` / `module.exports = …` in a ConfigFile/DerivedScript. Closes the entropy/padding
  proxy's blind spot (low-entropy readable appended stage). Acts as a structural prior alongside
  Obfuscation.
- **MagicMismatch** — BinaryAsset ext **and** readable as UTF-8 **and** contains JS tokens
  (`require`/`eval`/`global`/`fromCharCode`/`function`). `RepoFiles::read` returns `Some` only for
  valid UTF-8, so a real binary asset yields `None` and is never scored.
- **DestructiveWipe** — `rm -rf` targeting `$HOME`/`~`/`/`, `shred -[nuvz]`, `cipher /W:`,
  `del /F /Q` via `Bun.spawnSync`, or a token-revocation-conditioned `rm` (dead-man's-switch).
- **ExfilStaging** — the `eyJ…==` double-base64 blob shape (see §4), scored on root `*.json`.

## 6. Reachability (one-hop)

For each LifecycleScript value, WorkflowFile `run:` step, and TasksJson command:

1. Tokenize and match `\b(node|bun|ts-node|tsx)\s+(?:--?\S+\s+)*(['"]?)((?:\.?/)?[\w.@-][\w./@-]*\.(?:c|m)?js)\2`
   — the path may be bare (`setup_bun.js`), `./`-relative, or nested (`dist/x.mjs`); optional
   flags before it are skipped. (Matching the bare form is required: the canonical Shai-Hulud
   example is `"preinstall":"node setup_bun.js"` with no `./` prefix.)
2. Resolve the captured path relative to the repo root (and to the surface file's dir for
   `./`-relative).
3. If the resolved path ∈ `files.paths()`, classify it as **DerivedScript** and score it.

Depth 1 only (a DerivedScript does not spawn further hops). Only files reachable from an auto-run
surface are promoted — a random repo `.js` is never scored. This is the entire relaxation of the
"surface files only" rule.

## 7. Scoring & gate (surface-aware)

Conservative, silence-first. Severity `Critical`. Evidence = capability breakdown + matched tokens.

| Surface | Fires when |
|---------|-----------|
| **ConfigFile** | (`obfuscation` **OR** `trailing_code`) **AND** ≥1 of {`credential_access`,`network_egress`,`process_spawn`,`on_chain_resolve`,`download_exec`} |
| **DerivedScript** | same as ConfigFile, **OR** `download_exec`, **OR** `propagation`, **OR** `destructive_wipe` |
| **LifecycleScript** | `download_exec` **OR** `propagation` **OR** `on_chain_resolve` **OR** `obfuscation` **OR** (`credential_access` **AND** `network_egress`) **OR** `destructive_wipe` |
| **WorkflowFile** | (`credential_access`/secrets **AND** `network_egress`) **OR** `propagation` **OR** `download_exec` **OR** (attacker `github.event.*.body` interpolated into `run:` on a `self-hosted` runner) |
| **TasksJson** | `runOn:folderOpen` **AND** (`download_exec` **OR** remote-fetch token **OR** binary-asset exec **OR** `propagation`) |
| **GitHook** | `download_exec` **OR** `propagation` **OR** (`credential_access` **AND** `network_egress`) **OR** `obfuscation` |
| **PropagationScript** | `propagation` (git-falsification conjunction) **OR** `download_exec` **OR** `destructive_wipe` |
| **BinaryAsset** | `magic_mismatch` |

**ExfilStaging** is not a `Surface` variant — it is a standalone repo-level check run once per tree
by `scan_capabilities`: scan root `*.json` (esp. `data.json`) and fire when `exfil_staging` is true.

Generic `process_spawn` alone never fires on a hook/lifecycle/workflow surface (legitimate build
steps spawn processes); it only contributes via a conjunction or the obfuscation-AND ConfigFile path.

## 8. False-positive strategy

- **Primary gate = the surface** (a random blob is never scored) + `walk_repo_files` prune
  (`.git`, `node_modules`, `.wormward-backup`).
- **Extra exclusions** for the capability pass: `dist/`, `build/`, `.next/`, `out/`, `coverage/`,
  `vendor/`, `*.min.*`.
- **Behavioral surfaces stay conservative** because the behaviors themselves (git-falsification
  conjunction, download-exec, npm-publish-in-install, secrets→egress) have no legitimate use there.
- **Calibration corpus / success criterion:** run against real clean repos (SweatCheck, Khorus,
  wormward itself) → **zero findings**. A regression test.

## 9. Finding model & integration

- Add `FindingKind::Capability` to `finding.rs` (serializes `"capability"`).
- Finding fields: `campaign = "generic"`, `signature_id = "capability:<surface>:<top-signal>"`,
  `kind = Capability`, `remediable = false` (v1), `severity = Critical`.
- **No pack dedup:** if a pack and the engine both fire on a file, both findings remain (different
  `kind`, corroborating). Report layer may group by file.
- The reflog heuristic in `scan_repo` keys off `findings[0].campaign`; `"generic"` keeps it working.

## 10. Analyzer change (PolinRider ESM shim)

Broaden `marker_re` in `polinrider/analyzer.rs` so the ESM re-entry shim is a first-class confirming
marker (osm-source: present in both variants, survives fingerprint rotation):

```
global(\.\w+|\['[^']+'\])\s*=\s*(require\b|module\b|'[\w-]+')
```

and treat `createRequire(import.meta.url)` as an additional confirming token — the shim confirms
structurally even without a `_$_` decoder. Decoder/seed logic unchanged.

## 11. Testing & success criteria

- **`surface.rs`**: classification unit tests for every surface incl. entry files, workflow paths,
  propagation scripts, binary assets, `.svg` → `None`; lifecycle-key extraction from package.json.
- **`reachability.rs`**: `"preinstall":"node setup_bun.js"` promotes `setup_bun.js`; non-existent
  target ignored; non-node command ignored; depth-1 only.
- **`capability.rs`**: each of the 11 detectors positive + negative; gate truth table per surface,
  incl. the conservatism checks (obfuscation-only ConfigFile with no behavior → no fire; clean
  `node build.js` lifecycle → no fire; plain force-push `.bat` → fire via propagation conjunction).
- **Key integration tests (campaign-agnostic, no pack loaded):**
  - PolinRider dot+bracket obfuscated `postcss.config.mjs` → fire.
  - Shai-Hulud `"preinstall":"node setup_bun.js"` + obfuscated `setup_bun.js` → fire via
    reachability (proves the dropped-file catch).
  - `.github/workflows/x.yml` with `${{ secrets.NPM_TOKEN }}` piped to `curl` → fire.
  - `.vscode/tasks.json` folderOpen running `curl … | bash` → fire.
  - fake `.woff2` containing JS → MagicMismatch fire.
  - `temp_auto_push.bat` with amend+force+no-verify → propagation fire.
  - root `data.json` starting `eyJ…==` → exfil-staging fire.
  - blockchain RPC fetch + XOR loop + eval → on-chain fire.
- **Regression:** clean-corpus zero-findings test.

## 12. Implementation phasing (guidance for the plan)

1. **Framework** — `Surface` enum + `surface::classify` + `CapabilityScore` struct + `gate` +
   `FindingKind::Capability` + `scan_capabilities` wired into `scan_repo`/`deep_scan_repo`. Land
   Obfuscation/Credential/Network/Spawn/MagicMismatch + ConfigFile/GitHook/BinaryAsset gates first
   (this reproduces v1 behavior under the new model). TDD each.
2. **Reachability** — the one-hop resolver + DerivedScript surface + LifecycleScript surface.
3. **New capabilities** — DownloadExec, Propagation, OnChainResolve, TrailingCode, DestructiveWipe,
   ExfilStaging + PropagationScript/WorkflowFile/TasksJson surfaces and gates; TasksJson gate fix.
4. **Analyzer** — ESM-shim broadening.
5. **Calibration** — run against the clean corpus, tune thresholds to zero findings, then run
   against known-infected fixtures to confirm every integration test above.

## 13. Beyond this engine (separate future tracks, not this build)

These are **different engines**, not deferred signals of this one — noted as roadmap so scope is
explicit: Approach B (AST taint dataflow), Approach C (detonation sandbox), install-time egress
allowlist, provenance/registry-tarball diff, and the host/endpoint + GitHub-account-audit +
network-containment IR layers. Nothing in the *capability-detection* paradigm is deferred.
