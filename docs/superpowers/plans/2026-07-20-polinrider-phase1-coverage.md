# PolinRider Eradication — Phase 1: Close the Coverage Holes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the P0 coverage holes (G1–G4 in the spec) so no real PolinRider infection passes and `doctor` never falsely certifies "clean": refresh/expand the IOC catalog, add version-aware lockfile + cross-ecosystem package detection, add opt-in git-history pickaxe scanning, and make `doctor` fail-closed on unreadable roots with broader cache coverage.

**Architecture:** All work extends existing wormward-core / wormward-packs / wormward-doctor / wormward-cli crates. Detection stays FP-safe: every new literal/regex IOC ships with a clean-corpus regression, every new package entry is version-aware where a version is known, and new heuristics require structural confirmation before firing. No new runtime dependencies except an *optional* `osv-scanner` shell-out (feature-gated behind a flag; absent → skipped).

**Tech Stack:** Rust (workspace), `serde`/`serde_yaml`/`serde_json`, `git` CLI shell-outs, existing `SignatureEngine`, `globset`, `rayon`.

## Global Constraints

- **FP-safety is non-negotiable.** Every new IOC/heuristic must pass the clean-corpus regression in `crates/wormward-core/tests/capability_integration.rs` (and pack round-trip tests). The campaign's own tooling false-flagged `stamparm/maltrail` and self-flagged — that is the baseline to beat.
- **No `Co-Authored-By: Claude` trailer** in any commit message (user standing instruction).
- **Confidence tiering:** community-sourced IOCs (`[C]`) must NOT cause a hard "infected" verdict by default; they are opt-in via `--include-community`.
- **Backward-compatible serialization:** existing `Finding` JSON consumers (desktop app) must keep working — additive `FindingKind` variants only; do not rename existing ones.
- **Structural confirmation over literal breadth:** prefer the existing analyzer/engine confirmation to a raw literal wherever a variant may rotate the string.
- **Branch:** all work on `polinrider-eradication`. Run `cargo test -p <crate>` after each GREEN step; the workspace must stay green.

---

## File Structure

- `crates/wormward-packs/src/polinrider/pack.yaml` — IOC catalog (Tasks 1, 2, 3, 4). Add signatures, artifacts, domains, sha256 hashes, `confidence` tags, and the `bad_packages` block.
- `crates/wormward-core/src/pack.rs` — manifest schema (Tasks 3, 4). Add `confidence` to `ContentSignature`-adjacent lists and a `BadPackage`/`bad_packages` model.
- `crates/wormward-core/src/matchers.rs` — `ContentSignature` gains an optional `confidence` field (Task 3).
- `crates/wormward-core/src/finding.rs` — add `FindingKind::HistoryHit` (Task 7).
- `crates/wormward-core/src/scanner.rs` — lockfile parsing + node_modules entrypoint scan (Tasks 5, 6); history pickaxe (Task 7); community-IOC gating (Task 3).
- `crates/wormward-core/src/lockfile.rs` — **new** module: parse npm/pnpm/yarn/pypi/composer/go lockfiles → `(ecosystem, name, version)` list (Task 5).
- `crates/wormward-doctor/src/lib.rs` — anti-false-clean `Unscanned` state (Task 8); expanded `cache_targets` (Task 9); optional osv bridge (Task 10).
- `crates/wormward-cli/src/main.rs` — `scan --history`, `scan --include-community`, `doctor --osv` flags (Tasks 3, 7, 10).
- `crates/wormward-core/tests/` — integration coverage for lockfiles + history + clean-corpus regression.

---

## Task 1: IOC catalog refresh (schema-compatible additions) — G3

Add every missing IOC that fits the *current* schema (no code change): new literal/regex `content_signatures`, `artifacts`, `gitignore_injections`, `ioc_domains`, and the missing npm package. Vendor-confirmed `[V]`/cross-confirmed `[X]` only; community `[C]` items wait for Task 3's tiering.

**Files:**
- Modify: `crates/wormward-packs/src/polinrider/pack.yaml`
- Test: `crates/wormward-core/tests/capability_integration.rs` (clean-corpus regression) + a new fixture-based unit test in the packs crate.

**Interfaces:**
- Consumes: existing `PackManifest` fields (`content_signatures`, `artifacts`, `gitignore_injections`, `ioc_domains`, `bad_npm_packages`).
- Produces: no new symbols; larger IOC set consumed by `SignatureEngine` and `scan_files_inner`.

- [ ] **Step 1: Write the failing test** — assert the new IOCs are present and that a clean fixture stays clean.

```rust
// crates/wormward-packs/tests/ioc_catalog.rs  (new file)
use wormward_packs::load_packs; // existing loader that returns Vec<Pack>

fn polinrider_yaml() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/polinrider/pack.yaml"
    )).unwrap()
}

#[test]
fn catalog_has_refreshed_iocs() {
    let y = polinrider_yaml();
    // Exfil servers (rr-research / OSM IR) — vendor-confirmed.
    assert!(y.contains("136.0.9.8"), "missing primary exfil IP");
    assert!(y.contains("166.88.54.158"), "missing secondary exfil IP");
    // TRON wallets #3/#4.
    assert!(y.contains("TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v"));
    assert!(y.contains("TLmj13VL4p6NQ7jpxz8d9uYY6FUKCYatSe"));
    // Solana C2 (richkazz).
    assert!(y.contains("api.mainnet-beta.solana.com"));
    // New Vercel C2 domains.
    assert!(y.contains("auth-con-firm.vercel.app"));
    assert!(y.contains("auth-rho-dun.vercel.app"));
    // New artifacts + gitignore injections.
    assert!(y.contains("temp_interactive_push.bat"));
    assert!(y.contains("branch_structure.json"));
    // 8th npm typosquat.
    assert!(y.contains("tailwind-stylecss"));
    // Named seeds (v1 L2, v2 L1/L2).
    assert!(y.contains("2667686") && y.contains("1111436") && y.contains("3896884"));
}
```

- [ ] **Step 2: Run test to verify it fails** — `cargo test -p wormward-packs --test ioc_catalog` → FAIL (strings absent).

- [ ] **Step 3: Edit `pack.yaml`.** Under `content_signatures` add:

```yaml
  # --- Phase 1 IOC refresh (vendor-confirmed unless tagged) ---
  - id: seed-v1-l2
    kind: literal
    value: "2667686"
  - id: seed-v2-l1
    kind: literal
    value: "1111436"
  - id: seed-v2-l2
    kind: literal
    value: "3896884"
  - id: c2-tron-tertiary
    kind: literal
    value: "TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v"
  - id: c2-tron-quaternary
    kind: literal
    value: "TLmj13VL4p6NQ7jpxz8d9uYY6FUKCYatSe"
  - id: c2-exfil-ip-primary
    kind: literal
    value: "136.0.9.8"
  - id: c2-exfil-ip-secondary
    kind: literal
    value: "166.88.54.158"
  - id: c2-solana-rpc
    kind: literal
    value: "api.mainnet-beta.solana.com"
  # Vercel C2 URL shape (settings bootstrap). Anchored on the /settings/<os>?flag= path so a bare
  # vercel.app reference in legit code does not match.
  - id: c2-vercel-settings-url
    kind: regex
    value: 'vercel\.app/settings/(mac|linux|win)\?flag='
```

Under `artifacts` add:

```yaml
  - path: "temp_interactive_push.bat"
    label: "Interactive propagation script"
  - path: "branch_structure.json"
    label: "Propagation branch map"
```

Under `gitignore_injections` add:

```yaml
  - "temp_auto_push.bat"
  - "temp_interactive_push.bat"
  - "branch_structure.json"
```

Under `ioc_domains` add:

```yaml
  - auth-con-firm.vercel.app
  - auth-rho-dun.vercel.app
  - coingecko-liard.vercel.app
  - chalk-logger.vercel.app
  - cloudflare-protection.vercel.app
  - locate-my-ip.vercel.app
  - bsc-rpc.publicnode.com
  - bsc-dataseed1.bnbchain.org
```

Under `bad_npm_packages` add:

```yaml
  - tailwind-stylecss
```

- [ ] **Step 4: Run tests** — `cargo test -p wormward-packs && cargo test -p wormward-core --test capability_integration` → PASS (new IOCs present; clean corpus unaffected because every addition is a specific literal/anchored regex).

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-packs/src/polinrider/pack.yaml crates/wormward-packs/tests/ioc_catalog.rs
git commit -m "feat(packs): refresh PolinRider IOC catalog (exfil IPs, Solana, new C2 domains, artifacts, seeds)"
```

---

## Task 2: SHA256 payload-hash signatures — G3

The engine already supports `kind: sha256` (`matchers.rs:9`, `engine.rs`), but the pack defines none. Add the 8 vendor-confirmed stage hashes from rr-research so a byte-identical known payload is caught even under a full string rotation.

**Files:**
- Modify: `crates/wormward-packs/src/polinrider/pack.yaml`
- Test: `crates/wormward-packs/tests/ioc_catalog.rs` (extend) + reuse the engine's sha256 path (already tested in `engine.rs`).

**Interfaces:**
- Consumes: `SignatureKind::Sha256` + `sha256_hex` (already wired in `engine.rs`).
- Produces: no new symbols.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn catalog_has_stage_hashes() {
    let y = polinrider_yaml();
    for h in [
        "7488bc6b91a32c02fcfa17c80c9fd297d638e6d548a0fc0d8ea43d08da0bacb1", // Stage 1
        "11e87f7f27b3cf1a51e0b4b3903decd8945b5959eedf3cbc6be1920dab3c8823", // Stage 3
        "d4e269df0f50998c7ebf2bf56945d3d615fd6516702b1da8ac030ffcba735263", // Stage 4 BeaverTail
    ] {
        assert!(y.contains(h), "missing stage hash {h}");
    }
}
```

- [ ] **Step 2: Run test** → FAIL.

- [ ] **Step 3: Edit `pack.yaml`** — append under `content_signatures`:

```yaml
  # Known payload SHA256s (rr-research, byte-exact). Whole-file hash match; survives string rotation.
  - id: hash-stage1-loader
    kind: sha256
    value: "7488bc6b91a32c02fcfa17c80c9fd297d638e6d548a0fc0d8ea43d08da0bacb1"
  - id: hash-stage1-ref
    kind: sha256
    value: "904afe0337fbbd79def403b3204f75b4c5fbe4e2271252d22c0307f9cbd14646"
  - id: hash-stage3-recursive
    kind: sha256
    value: "11e87f7f27b3cf1a51e0b4b3903decd8945b5959eedf3cbc6be1920dab3c8823"
  - id: hash-stage3-eval
    kind: sha256
    value: "f9bb6118d7e9d2024dcb6a453f27c4ee33d12dbf7c659748bb6d9f816514a904"
  - id: hash-stage4-beavertail
    kind: sha256
    value: "d4e269df0f50998c7ebf2bf56945d3d615fd6516702b1da8ac030ffcba735263"
  - id: hash-stage3-var-a
    kind: sha256
    value: "32af4c538e484bb0c3d2a7e8967728ab3f73e7e605c00281561ecc24d99ef11c"
  - id: hash-stage3-var-b
    kind: sha256
    value: "6ab500ef10c246f595e3ff48a54df276b884ce11088e0a50ac1385ccf8225e1a"
  - id: hash-stage3-var-c
    kind: sha256
    value: "9ce4e50f0cb2b400153a4b32af4a6a8357bd0160fada71dd5f115b66303f220d"
```

- [ ] **Step 4: Run tests** — `cargo test -p wormward-packs && cargo test -p wormward-core` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-packs/src/polinrider/pack.yaml crates/wormward-packs/tests/ioc_catalog.rs
git commit -m "feat(packs): add known PolinRider stage payload SHA256 signatures"
```

---

## Task 3: Confidence tiering + `--include-community` — G3

Add an optional `confidence: vendor | community` to content signatures and IOC domains. Community IOCs are loaded but **suppressed by default** at scan time unless `--include-community` is passed; this lets us carry the 20-IP gist list and speculative package names without eroding precision (they become opt-in leads, never a default hard verdict).

**Files:**
- Modify: `crates/wormward-core/src/matchers.rs` (add field), `crates/wormward-core/src/pack.rs` (domain tiering model), `crates/wormward-core/src/scanner.rs` (filter), `crates/wormward-core/src/engine.rs` (thread the filter), `crates/wormward-cli/src/main.rs` (flag).
- Test: `crates/wormward-core/src/matchers.rs` unit test + a scanner test.

**Interfaces:**
- Consumes: `ContentSignature`.
- Produces: `pub enum Confidence { Vendor, Community }` (default `Vendor`); `ContentSignature.confidence: Confidence`; `scan_files`/`scan`/`scan_deep` gain an `include_community: bool` parameter (thread through; default callers pass `false`, except when the CLI flag is set).

- [ ] **Step 1: Write the failing test** (matchers)

```rust
// in matchers.rs #[cfg(test)]
#[test]
fn confidence_defaults_to_vendor_and_parses_community() {
    let vendor: ContentSignature =
        serde_yaml::from_str("id: a\nkind: literal\nvalue: x\n").unwrap();
    assert_eq!(vendor.confidence, Confidence::Vendor);
    let community: ContentSignature =
        serde_yaml::from_str("id: b\nkind: literal\nvalue: y\nconfidence: community\n").unwrap();
    assert_eq!(community.confidence, Confidence::Community);
}
```

- [ ] **Step 2: Run test** — `cargo test -p wormward-core matchers::` → FAIL (`Confidence` undefined).

- [ ] **Step 3: Implement** — in `matchers.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Vendor,
    Community,
}
impl Default for Confidence {
    fn default() -> Self { Confidence::Vendor }
}
```

and add to `ContentSignature`:

```rust
    #[serde(default)]
    pub confidence: Confidence,
```

Thread an `include_community: bool` into `SignatureEngine::build` (skip any signature whose `confidence == Community` when `!include_community`) and into the `ioc_domains` loop in `scanner.rs` (Task 1's domains are all vendor; a later community domain list would be tagged and filtered here). Add `include_community` to the public `scan_files`/`scan`/`scan_deep`/`scan_repo` signatures — existing internal callers pass `false`; only the CLI sets it.

- [ ] **Step 4: Run tests** — `cargo test -p wormward-core` → PASS.

- [ ] **Step 5: Wire the CLI flag** — in `main.rs` add `#[arg(long)] include_community: bool` to the `Scan` subcommand and pass it into `scan`/`scan_deep`. Add a smoke assertion test if the CLI has one, else manual: `cargo run -p wormward-cli -- scan --help | grep include-community`.

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-core/src/matchers.rs crates/wormward-core/src/pack.rs crates/wormward-core/src/engine.rs crates/wormward-core/src/scanner.rs crates/wormward-cli/src/main.rs
git commit -m "feat(core): confidence-tier IOC signatures; --include-community gates community leads"
```

---

## Task 4: Cross-ecosystem `bad_packages` schema — G3 / G2 foundation

Generalize `bad_npm_packages` (name-only) into an ecosystem-keyed, version-aware `bad_packages` block, keeping `bad_npm_packages` working for back-compat. This is the data model Task 5 (lockfiles) consumes.

**Files:**
- Modify: `crates/wormward-core/src/pack.rs` (schema), `crates/wormward-packs/src/polinrider/pack.yaml` (populate).
- Test: `crates/wormward-core/src/pack.rs` unit test.

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Deserialize)]
  pub struct BadPackage {
      pub name: String,
      #[serde(default)]
      pub versions: Vec<String>, // empty = any version
      #[serde(default)]
      pub confidence: crate::matchers::Confidence,
  }
  ```
  and `PackManifest.bad_packages: std::collections::BTreeMap<String, Vec<BadPackage>>` (key = ecosystem: `npm`|`pypi`|`composer`|`go`). A helper `PackManifest::npm_package_names()` returns `bad_npm_packages` ∪ `bad_packages["npm"]` names so Task 1's existing `check_npm` path keeps matching.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parses_cross_ecosystem_bad_packages() {
    let m = PackManifest::from_yaml("id: x\nname: X\nseverity: high\n\
bad_packages:\n  npm:\n    - {name: \"@common-stack/generate-plugin\", versions: [\"9.0.2-alpha.21\"]}\n  pypi:\n    - {name: graphalgo}\n").unwrap();
    assert_eq!(m.bad_packages["npm"][0].name, "@common-stack/generate-plugin");
    assert_eq!(m.bad_packages["npm"][0].versions, vec!["9.0.2-alpha.21".to_string()]);
    assert!(m.bad_packages["pypi"][0].versions.is_empty()); // any version
}
```

- [ ] **Step 2: Run test** → FAIL.

- [ ] **Step 3: Implement** — add `BadPackage` + `bad_packages` field (`#[serde(default)]`) to `pack.rs`, and the `npm_package_names()` helper. In `pack.yaml` add:

```yaml
bad_packages:
  npm:
    - {name: "@common-stack/generate-plugin", versions: ["9.0.2-alpha.21", "9.0.2-alpha.22"]}
    - {name: "tailwindcss-style-animate", versions: ["1.1.6"]}
    - {name: "tailwind-mainanimation", versions: ["2.3.3"]}
    - {name: "tailwind-autoanimation", versions: ["2.3.6"]}
    - {name: "tailwindcss-typography-style", versions: ["0.8.2"]}
    - {name: "tailwindcss-style-modify", versions: ["0.8.3"]}
    - {name: "tailwindcss-animate-style", versions: ["1.2.5"]}
    - {name: "plain-crypto-js", versions: ["4.2.1"], confidence: community}
  pypi:
    - {name: graphalgo, confidence: community}
    - {name: bignum, confidence: community}
  composer:
    - {name: "thiio/kubernetes-php-sdk"}
    - {name: "sevenspan/laravel-whatsapp"}
    - {name: "sevenspan/code-generator"}
    - {name: "sevenspan/laravel-chat"}
    - {name: "roberts/leads"}
    - {name: "lambda-platform/moqup"}
    - {name: "adxio/twig-hmvc"}
    - {name: "olc/olc-php"}
    - {name: "arsl/optima-class"}
    - {name: "plusinfolab/logstation"}
```

- [ ] **Step 4: Run tests** — `cargo test -p wormward-core pack:: && cargo test -p wormward-packs` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/pack.rs crates/wormward-packs/src/polinrider/pack.yaml
git commit -m "feat(core): ecosystem-keyed, version-aware bad_packages schema"
```

---

## Task 5: Lockfile parsing + version-aware matching — G2

Parse `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (and `composer.lock`, `poetry.lock`/`Pipfile.lock`, `go.sum`) into `(ecosystem, name, version)` triples and match against `bad_packages` with version awareness — so a payload shipped *inside a dependency* is caught even when `package.json` looks clean.

**Files:**
- Create: `crates/wormward-core/src/lockfile.rs`
- Modify: `crates/wormward-core/src/scanner.rs` (call it in `scan_files_inner`), `crates/wormward-core/src/lib.rs` (`mod lockfile;`).
- Test: `crates/wormward-core/src/lockfile.rs` unit tests + a scanner integration test.

**Interfaces:**
- Consumes: `RepoFiles` (already the file-source abstraction), `PackManifest.bad_packages`.
- Produces:
  ```rust
  pub struct LockEntry { pub ecosystem: String, pub name: String, pub version: Option<String> }
  pub fn parse_lockfiles(files: &dyn RepoFiles) -> Vec<LockEntry>;
  ```
  and a scanner helper `check_lockfiles(repo, files, pack) -> Vec<Finding>` emitting `FindingKind::NpmPackage` with `signature_id = format!("pkg:{ecosystem}:{name}@{ver}")`, `remediable: false`.

- [ ] **Step 1: Write the failing test** (parser)

```rust
// lockfile.rs #[cfg(test)]
#[test]
fn parses_pnpm_and_npm_lock_entries() {
    // npm v3 lockfile shape
    let npm = r#"{"packages":{"node_modules/@common-stack/generate-plugin":{"version":"9.0.2-alpha.21"}}}"#;
    let e = parse_npm_lock(npm);
    assert!(e.iter().any(|x| x.name == "@common-stack/generate-plugin"
        && x.version.as_deref() == Some("9.0.2-alpha.21")));
    // pnpm lockfile shape: keys like "/tailwindcss-style-animate@1.1.6"
    let pnpm = "packages:\n  /tailwindcss-style-animate@1.1.6:\n    resolution: {integrity: sha512-x}\n";
    let e = parse_pnpm_lock(pnpm);
    assert!(e.iter().any(|x| x.name == "tailwindcss-style-animate"
        && x.version.as_deref() == Some("1.1.6")));
}

#[test]
fn matches_bad_package_by_version() {
    let entry = LockEntry { ecosystem: "npm".into(), name: "x".into(), version: Some("1.1.6".into()) };
    // any-version rule matches
    assert!(version_matches(&entry, &[]));
    // exact match
    assert!(version_matches(&entry, &["1.1.6".to_string()]));
    // non-match
    assert!(!version_matches(&entry, &["9.9.9".to_string()]));
}
```

- [ ] **Step 2: Run test** — `cargo test -p wormward-core lockfile::` → FAIL (module absent).

- [ ] **Step 3: Implement `lockfile.rs`** — `parse_npm_lock` (serde_json over `packages`/`dependencies`, strip the `node_modules/` path prefix to get the bare name), `parse_pnpm_lock` (regex over `packages:` keys `^/(.+)@([^:]+):` and the newer `'<name>@<ver>':` form), `parse_yarn_lock` (blocks `"<name>@range:"` + `version "<v>"`), `parse_composer_lock`/`parse_poetry_lock` (json/toml `name`+`version`), `parse_go_sum` (`<module> <version>/go.mod`). `parse_lockfiles` reads whichever files exist via `RepoFiles::read` and concatenates. `version_matches(entry, versions)` = `versions.is_empty() || entry.version.as_deref().map_or(false, |v| versions.iter().any(|w| w == v))`.

- [ ] **Step 4: Run parser tests** → PASS.

- [ ] **Step 5: Wire into scanner** — add `check_lockfiles` in `scanner.rs`, call it in the `for pack in packs` block of `scan_files_inner` (alongside `check_npm`). Respect `include_community` (skip community entries). Write a scanner integration test: a temp repo whose `pnpm-lock.yaml` pins `tailwindcss-style-animate@1.1.6` yields one `NpmPackage` finding; a clean lockfile yields none.

- [ ] **Step 6: Run tests** — `cargo test -p wormward-core` → PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/wormward-core/src/lockfile.rs crates/wormward-core/src/scanner.rs crates/wormward-core/src/lib.rs
git commit -m "feat(core): version-aware lockfile parsing (npm/pnpm/yarn/composer/pypi/go) for bad_packages"
```

---

## Task 6: `node_modules` dependency-payload scan — G2

The campaign ships the payload inside an installed dependency's entrypoint. Scan `node_modules/<pkg>/package.json` (against `bad_packages`) and each package's `main`/`src/index.js` entrypoint with the existing analyzer — while keeping `node_modules` pruned from the *general* file walk (perf).

**Files:**
- Modify: `crates/wormward-core/src/scanner.rs` (new `scan_node_modules` helper + call site), reuse `crate::walk` discovery which already descends `node_modules/<pkg>/.git`.
- Test: scanner integration test.

**Interfaces:**
- Consumes: `RepoFiles`, the pack analyzer, `bad_packages`.
- Produces: `fn scan_node_modules(repo, files, packs) -> Vec<Finding>` (bounded: cap package count; `log`/evidence note if truncated — no silent cap).

- [ ] **Step 1: Write the failing test** — a temp repo with `node_modules/evil/package.json` (name in `bad_packages`) and `node_modules/evil/index.js` carrying the v1 payload yields a `NpmPackage` finding **and** an `Analyzer` finding; a clean `node_modules/lodash/...` yields none.

- [ ] **Step 2: Run test** → FAIL.

- [ ] **Step 3: Implement** — enumerate top-level (and one scoped level `@scope/pkg`) dirs under `node_modules`, read each `package.json` `name`+`version` (match `bad_packages`), and run the analyzer on the resolved entrypoint. Bound at e.g. 5,000 packages; if exceeded, push an informational finding noting the cap.

- [ ] **Step 4: Run tests** → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-core/src/scanner.rs
git commit -m "feat(core): scan node_modules dependency entrypoints for injected payloads"
```

---

## Task 7: Git-history pickaxe (`--history`) — G1

Add opt-in per-commit history scanning: `git log --all -S <marker>` for each pack marker, surfacing a distinct `HistoryHit` finding (past infection, reachable via checkout) — never conflated with a live working-tree finding. Compound-confirm each candidate commit by reading the blob and running the analyzer.

**Files:**
- Modify: `crates/wormward-core/src/finding.rs` (add `HistoryHit`), `crates/wormward-core/src/scanner.rs` (pickaxe fn + call under `--history`), `crates/wormward-cli/src/main.rs` (`--history` flag).
- Test: `finding.rs` serialization test + a scanner integration test using a temp git repo.

**Interfaces:**
- Consumes: pack markers (derive from `content_signatures` literals + the pack `remediation` markers), the persistent `git cat-file --batch` reader in `repo_files.rs`.
- Produces: `FindingKind::HistoryHit` (serialized `history_hit`); `fn scan_history(repo, packs) -> Vec<Finding>` returning Medium, `remediable:false`, `git_ref = Some("<short-sha>")`, evidence `"marker '<m>' present in history commit <sha> (<date>, <author>) — reachable via checkout"`.

- [ ] **Step 1: Write the failing serialization test**

```rust
// finding.rs #[cfg(test)]
#[test]
fn history_hit_kind_serializes() {
    assert_eq!(serde_json::to_string(&FindingKind::HistoryHit).unwrap(), "\"history_hit\"");
}
```

- [ ] **Step 2: Run test** → FAIL.

- [ ] **Step 3: Add the variant** to `FindingKind` (after `GitReflog`): `HistoryHit,`.

- [ ] **Step 4: Run test** → PASS.

- [ ] **Step 5: Write the scanner integration test** — build a temp repo, commit a file containing `("rmcej%otb%",2857687)`, then commit its removal (clean tip). `scan_repo` finds nothing at the tip; `scan_history(repo, &packs)` returns exactly one `HistoryHit` for the marker, with a non-empty `git_ref`. Run: expect FAIL (`scan_history` undefined).

- [ ] **Step 6: Implement `scan_history`** — collect distinct literal markers (`primary`, `secondary`, `variant-april`, `decoder-v1`) from each pack, run `git -C <repo> log --all -S <marker> --format=%h|%aI|%an|%ae|%s` (bounded: cap commits scanned per marker, dedup by sha), and for each hit read the blob at that commit for the changed path via the existing `cat-file --batch` reader and confirm with the analyzer before emitting (compound confirmation → FP-safe). Push a `HistoryHit`. Emit a truncation note if the cap is hit.

- [ ] **Step 7: Wire the CLI flag** — add `#[arg(long)] history: bool` to `Scan`; when set, extend results with `scan_history` per repo (and in `wormward-github`, a later `--deep-history` — out of scope for Phase 1). Render `HistoryHit` in its own "Past infections (in history)" section.

- [ ] **Step 8: Run tests** — `cargo test -p wormward-core` → PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/wormward-core/src/finding.rs crates/wormward-core/src/scanner.rs crates/wormward-cli/src/main.rs
git commit -m "feat(core): opt-in git-history pickaxe (--history) with compound confirmation → HistoryHit"
```

---

## Task 8: `doctor` anti-false-clean (fail on unreadable roots) — G4

`doctor` must never print "clean" when it could not read what it was asked to check. Add an `Unscanned` state; an unreadable scan root makes `has_findings()` true (non-zero exit) and is surfaced distinctly.

**Files:**
- Modify: `crates/wormward-doctor/src/lib.rs` (add `Unscanned`, populate in `check`, extend `has_findings`), `crates/wormward-cli/src/main.rs` (render), any GUI-facing serialization (additive).
- Test: `lib.rs` unit test.

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, PartialEq, serde::Serialize)]
  pub struct Unscanned { pub path: PathBuf, pub reason: String }
  ```
  `DoctorReport.unscanned: Vec<Unscanned>`; `has_findings()` returns true if any of processes/caches/**unscanned** are non-empty.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn unreadable_root_is_unscanned_not_clean() {
    // A path that exists but cannot be enumerated is recorded as Unscanned.
    let u = probe_root(Path::new("/definitely/not/a/dir/here"));
    assert!(u.is_some(), "missing/unreadable root must yield an Unscanned entry");
    let report = DoctorReport { processes: vec![], caches: vec![], triggers: vec![],
        cache_dirs: vec![], unscanned: vec![u.unwrap()] };
    assert!(report.has_findings(), "an unscanned root must not certify clean");
}
```

- [ ] **Step 2: Run test** → FAIL (`Unscanned`/`probe_root`/field undefined).

- [ ] **Step 3: Implement** — add the struct + field; `fn probe_root(p: &Path) -> Option<Unscanned>` returns `Some` when the path is configured for scanning but `read_dir` errors (permission/TCC) — the `ls` vs `ls -d` distinction: `p.exists()` (stat OK) but `std::fs::read_dir(p).is_err()` (enumerate blocked). Populate `unscanned` in `check()` for each intended scan root (the cache targets' parents and any configured roots). Extend `has_findings()`.

- [ ] **Step 4: Run test** — `cargo test -p wormward-doctor` → PASS.

- [ ] **Step 5: Render** — in `main.rs` doctor output, print an `UNSCANNED: <path> — <reason>` block and ensure exit code is non-zero. GUI: add to the serialized report (additive field).

- [ ] **Step 6: Commit**

```bash
git add crates/wormward-doctor/src/lib.rs crates/wormward-cli/src/main.rs
git commit -m "feat(doctor): fail-closed on unreadable scan roots (anti-false-clean)"
```

---

## Task 9: `doctor` cache coverage expansion — G4

The dropper lives in more than `_npx` + the TS cache. Expand `cache_targets` to the pnpm store, yarn cache, general `~/.npm`, node-gyp, and the global `node_modules` root.

**Files:**
- Modify: `crates/wormward-doctor/src/lib.rs` (`cache_targets`).
- Test: `lib.rs` unit test (pure — assert the target list composition given a fake `$HOME`).

**Interfaces:**
- Consumes: `home_dir()`, env (`PNPM_HOME`).
- Produces: expanded `cache_targets()` (still filtered to present dirs).

- [ ] **Step 1: Write the failing test** — refactor `cache_targets` to a pure `candidate_cache_dirs(home: &Path, pnpm_home: Option<&Path>) -> Vec<PathBuf>` and assert it contains the pnpm store, yarn cache, `~/.npm`, node-gyp, and a global-node-modules path in addition to the existing two.

```rust
#[test]
fn cache_candidates_cover_pnpm_yarn_global() {
    let home = PathBuf::from("/home/u");
    let c = candidate_cache_dirs(&home, None);
    assert!(c.contains(&home.join(".npm/_npx")));
    assert!(c.contains(&home.join("Library/Caches/typescript")));
    assert!(c.contains(&home.join("Library/pnpm")) || c.contains(&home.join(".local/share/pnpm")));
    assert!(c.iter().any(|p| p.ends_with("Caches/Yarn") || p.ends_with(".cache/yarn")));
    assert!(c.contains(&home.join(".npm")));
    assert!(c.contains(&home.join(".node-gyp")));
}
```

- [ ] **Step 2: Run test** → FAIL.

- [ ] **Step 3: Implement** — introduce `candidate_cache_dirs`; `cache_targets()` = `candidate_cache_dirs(&home_dir(), env PNPM_HOME).into_iter().filter(is_dir)`. Keep the `MAX_CACHE_FILES` bound (global `node_modules` can be huge — the bound already protects the walk).

- [ ] **Step 4: Run test** — `cargo test -p wormward-doctor` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-doctor/src/lib.rs
git commit -m "feat(doctor): expand cache coverage (pnpm store, yarn, ~/.npm, node-gyp, global node_modules)"
```

---

## Task 10: Optional `osv-scanner` lockfile bridge — G2 (opt-in)

If `osv-scanner` is on PATH, `doctor --osv` (and `scan --osv`) gate discovered lockfiles against Google OSV `MAL-*` advisories — a live malicious-package signal beyond our static list. Absent binary → skipped with a note (never a hard failure).

**Files:**
- Modify: `crates/wormward-doctor/src/lib.rs` (new `osv_scan(lockfile: &Path) -> Vec<OsvHit>`), `crates/wormward-cli/src/main.rs` (`--osv` flag).
- Test: `lib.rs` unit test over a captured `osv-scanner --format json` fixture (pure parse; no network).

**Interfaces:**
- Produces: `pub struct OsvHit { pub package: String, pub advisory: String }`; `fn parse_osv_json(json: &str) -> Vec<OsvHit>` filtering advisories whose id starts with `MAL-`.

- [ ] **Step 1: Write the failing test** — feed a small `osv-scanner` JSON fixture with one `MAL-2026-xxxx` advisory; assert `parse_osv_json` returns exactly that hit and ignores non-`MAL-` advisories.

- [ ] **Step 2: Run test** → FAIL.

- [ ] **Step 3: Implement** — `parse_osv_json` (serde over `results[].packages[].vulnerabilities[].id`); `osv_scan` shells `osv-scanner --format json --lockfile <path>` only if `command_exists("osv-scanner")`, else returns empty + a note. Wire `--osv`.

- [ ] **Step 4: Run test** — `cargo test -p wormward-doctor` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/wormward-doctor/src/lib.rs crates/wormward-cli/src/main.rs
git commit -m "feat(doctor): optional osv-scanner MAL-* lockfile bridge (--osv)"
```

---

## Phase 1 exit criteria

- `cargo test` green across the workspace; `cargo clippy` clean.
- Clean-corpus regression (`capability_integration.rs`) still passes — zero new false positives.
- `wormward scan --history` surfaces a payload that exists only in git history; `wormward scan` on a repo whose lockfile pins a bad package version flags it; `wormward doctor` exits non-zero (never "clean") when a scan root is unreadable and covers the expanded cache set.
- Manual dogfood: run `wormward scan --deep --history ~/Desktop` and `wormward doctor --osv` on this machine; confirm no false positives on the known-clean corpus.

## Self-review notes (author)

- **Spec coverage:** G1 → Task 7; G2 → Tasks 4,5,6,10; G3 → Tasks 1,2,3,4; G4 → Tasks 8,9. All Phase 1 gaps mapped.
- **Type consistency:** `Confidence` (matchers.rs) is reused by `BadPackage` (Task 4) and the scanner filter (Task 3); `BadPackage`/`bad_packages` (Task 4) is consumed by `check_lockfiles`/`scan_node_modules` (Tasks 5,6); `FindingKind::HistoryHit` (Task 7) is additive. `Unscanned` + `DoctorReport.unscanned` (Task 8) and `candidate_cache_dirs` (Task 9) are consistent.
- **No placeholders:** every step has concrete code or an exact edit list.
- **Out of Phase 1 (later plans):** Unicode/Glassworm (G5), git date-skew (G6), deeper doctor hygiene — launchd/network/keychain/global-npm/shell-rc (G7), tasks.json/.env remediation (G8), prevention (G9), Action/SARIF/rules (G10/G11), PR-mode/history-rewrite (G12), magic-byte (G13), own-git hardening (G14), sibling packs (G15).
