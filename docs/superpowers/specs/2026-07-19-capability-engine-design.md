# Campaign-Agnostic Capability Engine — Design

- **Date:** 2026-07-19
- **Branch:** `variant-generalization`
- **Status:** Approved (brainstorming) — pending spec review before implementation planning

## 1. Context & Problem

Wormward today detects supply-chain campaigns (PolinRider, Shai-Hulud) with **IOC-shaped
signals**: literal strings, regexes, sha256 hashes, C2 domains, bad npm package names
(`crates/wormward-core/src/matchers.rs`, `crates/wormward-core/src/scanner.rs`). The most
generalized piece — `PolinriderAnalyzer`
(`crates/wormward-packs/src/polinrider/analyzer.rs`) — confirms an obfuscation fingerprint
regardless of dot/bracket notation, but it still *describes PolinRider*.

Every one of these is a **value the attacker chooses** (IP, wallet, decoder name, domain,
literal). Values rotate freely — that is a blocklist, and blocklists lose the arms race.

**Generative reframe:** stop describing what the malware *is*; describe what it *must do* —
its **invariants**. An invariant is something the attacker cannot change without breaking the
attack. IOCs are infinite; invariants are finite and enumerable.

Invariants of this attack class (npm/git supply-chain worm, obfuscated JS, on-chain C2,
credential exfil, force-push propagation):

| # | Requirement | Invariant signal (value-independent) |
|---|-------------|--------------------------------------|
| 1 | Must auto-execute | The auto-run surface is *finite*: lifecycle scripts, toolchain configs, `.vscode/tasks.json` `runOn:folderOpen`, git hooks. |
| 2 | Must obfuscate to hide | Obfuscation *itself* is the signal (entropy + opaque-construct density), not its specific content. |
| 3 | Must access secrets | The *read* side is fixed: `~/.aws`, `~/.ssh`, `.npmrc`, `.git-credentials`, `process.env`, keychain. |
| 4 | Must reach C2 / propagate | The address rotates; the *capability* (socket / `child_process` / `git` from a build context) does not. |
| 5 | Must self-replicate | Git invariants: force-push, `--no-verify`, `--amend`, timezone/author anomaly. |

None of these name a campaign, IP, wallet, or literal. All five cover PolinRider,
Shai-Hulud, TasksJacker, **and the next campaign**.

## 2. Decisions (locked during brainstorming)

1. **Approach A — capability scoring** (static, cheap, lexical; no AST). Chosen over B (taint
   dataflow) and C (detonation sandbox), which are deferred.
2. **Core engine, additive.** Lives in `wormward-core`, runs alongside existing packs on
   every scan. Packs are **not** demoted yet; the reframe ("pack = optional enrichment") is
   directionally endorsed but not executed in v1.
3. **Conservative / near-zero FP posture.** Precision over recall. A surface gate plus a
   multi-capability gate is what makes the heuristic safe. A tool that cries wolf gets ignored.

## 3. Architecture

Two new pack-independent `wormward-core` modules plus one scanner integration point.

- **`surface.rs`** — pure classification. Maps a repo-relative `Path` to a `Surface` variant
  or `None`. No I/O.

  ```
  enum Surface { ConfigFile, LifecycleScript, TasksJson, GitHook, BinaryAsset }
  fn classify(path: &Path) -> Option<Surface>
  ```

- **`capability.rs`** — pure lexical/regex scoring. Reuses `shannon_entropy` from
  `matchers.rs`. **No AST parser** (that is Approach B, out of scope).

  ```
  struct CapabilityScore {
      obfuscation: bool,
      credential_access: bool,
      network_egress: bool,
      process_spawn: bool,
      magic_mismatch: bool,
      evidence: Vec<String>,   // matched tokens, for explainability
  }
  fn score(content: &str, surface: Surface) -> CapabilityScore
  fn gate(surface: Surface, s: &CapabilityScore) -> bool  // conservative fire decision
  ```

- **Integration** — `scanner.rs` gains `scan_capabilities(repo, &files, exclusions) -> Vec<Finding>`,
  called next to `scan_files` in **both** `scan_repo` (working tree) and the per-tree loop in
  `deep_scan_repo`. Because it uses the same `RepoFiles` abstraction, it runs on the working
  tree **and every branch tip** — payloads on non-checked-out branches are covered for free.

### Data flow

```
files.paths()  ──►  surface::classify(path)  ──► Some(surface)?
                                                     │
                              read(path) ──► content │
                                                     ▼
                                   capability::score(content, surface)
                                                     │
                                   capability::gate(surface, &score)  ── true ──►  Finding
```

## 4. Auto-run surface (v1)

Finite, curated list. Only places that run **without user intent**.

- **ConfigFile** — toolchain configs `require()`d during build/dev. Specific basenames, **not**
  a broad `*.config.js` wildcard (stay conservative): `postcss`, `vite`, `next`, `tailwind`,
  `eslint`, `svelte`, `nuxt`, `webpack`, `rollup`, `babel`, `astro`, `vitest`, `jest`,
  `remix`, `gatsby-config`, `gatsby-node` `.config.{js,mjs,cjs,ts}`, plus `.eslintrc.js`,
  `.eslintrc.cjs`. (PolinRider's vector: `postcss.config.mjs`.)
- **LifecycleScript** — from `package.json` `scripts`, **only** the auto-run lifecycle keys:
  `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`,
  `prepack`, `postpack`. The scored `content` is the script string value (not the whole file).
- **TasksJson** — `.vscode/tasks.json`; only tasks with a `runOn: "folderOpen"` trigger
  (the TasksJacker vector). The tell is a folderOpen task whose command **executes a
  binary-asset-extension path** (e.g. `node ./assets/x.woff2`) — no legitimate task runs a
  font/image as a script. Detected lexically on the task's command string; no cross-file
  resolution.
- **GitHook** — files under `.git/hooks/` excluding `*.sample`, plus `.husky/*`. Note:
  `.git/` is pruned by `walk_repo_files`, so working-tree hook scanning requires an explicit
  opt-in read of `.git/hooks` (see §6). `.husky/*` is a normal tracked path and needs no
  special handling.
- **BinaryAsset** — font/image extensions only, for the fake-font check: `.woff`, `.woff2`,
  `.ttf`, `.otf`, `.eot`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.ico`. **`.svg` excluded** (it is
  legitimately text).

## 5. Capability signals (lexical)

Each returns a bool and pushes matched tokens into `evidence`. Patterns below are the starting
set; exact regexes are refined and calibrated during implementation.

- **Obfuscation** (the strong prior) — any of:
  - entropy tail over threshold (reuse `shannon_entropy`, tuned during calibration);
  - dynamic global access/assign: `global[...]`, `globalThis[...]`, `process[...]` with a
    string/computed key, or dot form `global.<x>=` matching the PolinRider marker shape;
  - long `String.fromCharCode(` argument lists, or long runs of `\xNN` / `\uNNNN`;
  - a single line longer than ~500 chars that is not a `data:` URI or plain URL;
  - `eval(`, `new Function(`, `atob(`, or a `require(`/`createRequire` built from concatenated
    string fragments;
  - `_$_`-style decoder identifiers.
- **CredentialAccess** — references to credential sources: `.aws/credentials`, `.ssh/`,
  `.npmrc`, `.git-credentials`, bulk `process.env` access (e.g. `Object.keys(process.env)`,
  serializing `process.env`), keychain (`security find-generic-password`), and secret env
  names (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET`, `AWS_ACCESS_KEY`).
- **NetworkEgress** — `require('http'|'https'|'net'|'dgram'|'tls')` / matching `import`,
  `fetch(`, `axios`, `XMLHttpRequest`, `WebSocket`, or an outbound URL literal in a
  ConfigFile.
- **ProcessSpawn** — `child_process`, `spawn(`, `exec(`, `execSync(`, or git command strings:
  `git commit`, `git push`, `--no-verify`, `--force`, `commit --amend`.
- **MagicMismatch** — BinaryAsset extension **and** the file was readable as UTF-8 **and** it
  contains JS tokens (`require`/`eval`/`global`/`fromCharCode`/`function`). Because
  `RepoFiles::read` returns `Some` only for valid UTF-8, a real binary font/image yields `None`
  and is never scored; a JS-in-`.woff2` payload is valid UTF-8 and trips this. No raw-byte API
  needed.

## 6. Scoring & gate (surface-aware)

Conservative, silence-first. The fire decision depends on the surface class:

| Surface | Fires when |
|---------|-----------|
| ConfigFile / LifecycleScript / GitHook | `obfuscation` **AND** at least one of {`credential_access`, `network_egress`, `process_spawn`} |
| TasksJson | task has `runOn:folderOpen` **AND** its command executes a binary-asset-extension path (e.g. `node …/x.woff2`) |
| BinaryAsset | `magic_mismatch` (sufficient alone — already pathological) |

- **Severity:** `Critical` (an obfuscated config that exfiltrates is unambiguous).
- **Evidence:** capability breakdown + matched tokens, e.g. `"obfuscation + network egress +
  credential access: require('https'), process.env"`. Explainable, not magic.

`.git/hooks` read: `walk_repo_files` prunes `.git`, so hooks are invisible to the normal file
list. v1 adds a small dedicated pass in `scan_capabilities` that lists `.git/hooks/*` (non-
`.sample`) directly for the working tree only (GitTree has no `.git/hooks`).

## 7. False-positive strategy

- **Primary gate = the surface.** A random obfuscated bundle is not in the surface at all, so
  it is never scored. This plus the existing `walk_repo_files` prune (`.git`, `node_modules`,
  `.wormward-backup`) is the first line of defense.
- **Extra exclusions** for the capability pass: skip paths under `dist/`, `build/`, `.next/`,
  `out/`, `coverage/`, and `*.min.*`. (Belt-and-suspenders; the specific-basename surface
  already avoids most build output.)
- **Calibration corpus / success criterion:** run against real clean repos (SweatCheck,
  Khorus, wormward itself) and require **zero findings**. This becomes a regression guard.

## 8. Finding model & integration

- Add `FindingKind::Capability` to `finding.rs` (serializes `snake_case` → `"capability"`).
- Finding fields: `campaign = "generic"`, `signature_id = "capability:<surface>"`,
  `kind = Capability`, `remediable = false` (v1; remediation is separate work), `severity =
  Critical`.
- **No dedup with packs in v1.** If a pack signature and the capability engine both fire on the
  same file, both findings remain (different `kind`, mutually corroborating). The report layer
  may group by file later.
- The existing reflog heuristic in `scan_repo` keys off `findings[0].campaign`; capability
  findings use `campaign = "generic"`, so this continues to work (a capability finding can also
  trigger the reflog corroboration).

## 9. Testing & success criteria

- **`surface.rs`** unit tests: `postcss.config.mjs` → `ConfigFile`; `README.md` → `None`;
  `.vscode/tasks.json` with `runOn:folderOpen`; `package.json` lifecycle-key extraction;
  `.woff2` → `BinaryAsset`; `.svg` → `None`.
- **`capability.rs`** unit tests: each detector positive + negative; gate truth table —
  obfuscation-only → **no fire** (proves conservatism), obfuscation+network → **fire**, clean
  config → **no fire**.
- **Key integration test:** a real PolinRider sample (both dot and bracket variants) fires via
  the generic engine with **no pack loaded** — proving campaign-agnostic detection. A fake-font
  asset trips `MagicMismatch`.
- **Regression:** clean-corpus test asserting zero findings on legitimate config fixtures.

## 10. Out of scope (YAGNI, v1)

`.npmrc` scanning; taint dataflow (Approach B); detonation sandbox (Approach C); egress
allowlist; provenance/registry-tarball diff; automated remediation of capability findings;
pack demotion / full reframe. The engine lays groundwork for these but none ship in v1.
