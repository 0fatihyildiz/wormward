# wormward False-Positive Hardening

**Date:** 2026-07-20
**Status:** Implemented (regression-tested)
**Scope:** The PolinRider analyzer + capability engine + scan surface, hardened against three
false-positive classes discovered by dogfooding on real projects.

---

## Why this matters

A supply-chain scanner that cries wolf is worse than no scanner: one `Critical / confirmed` false
positive on a popular dependency teaches the user to ignore the tool, and the next alert — the real
one — gets dismissed too. Precision is not a nicety here; it **is** the product. Every signature and
heuristic in wormward must answer: *can this fire on legitimate content?* — and if the answer is
"on any project using library X," it is a bug, not a detection.

This document consolidates three FP classes we hit, their root cause, the defense applied, and the
regression test that locks each one shut. All three shared one anti-pattern: **matching a short
literal (or a bare number) against raw file content, with no structural context.**

---

## FP class 1 — Lockfile / package-manager CAS metadata

### Symptom
`obfuscation: decoder + shuffle seed` (Critical, "confirmed") on files that structurally **cannot**
contain executable JS.

### Real-world evidence
- `.../better-opn/yarn.lock` — a standard `# yarn lockfile v1`: 865 package entries, 865 `resolved`
  URLs, 865 `integrity` hashes. **Zero** executable-JS tokens.
- pnpm content-addressed store blobs and `<hash>-index.json` metadata under
  `~/Library/pnpm/store/**`.

### Root cause
- The `MDy` decoder sentinel matched by bare substring — and `MDy` occurs by chance inside `integrity`
  **base64** hashes (`MDy` is three base64-alphabet chars).
- 6–7 digit runs inside tarball **SHA** hashes were read as "shuffle seeds".
- Neither is code. Worse, the CAS blob store is content-addressed and pruned, so reported paths go
  **stale** (they no longer exist at verification time) — pure noise.

### Defense applied
1. **Hard veto** (see class 3): no decoder/seed finding without a JS-code token. Lockfile metadata
   has none, so it can never confirm regardless of incidental substrings/numbers.
2. **Surface exclusions** — these paths are never content-scanned
   (`crates/wormward-core/src/surface.rs` `is_excluded_path`):
   - lockfiles: `yarn.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `*.lock`
   - CAS stores: `**/.pnpm/**`, `**/pnpm/store/**`, `Library/pnpm/store/**`, `**/.npm/_cacache/**`
   - Lockfiles are still **parsed by name** for malicious package versions in `check_lockfiles` —
     that path is unaffected; only *content-scanning them for obfuscation* is suppressed.
3. **`doctor` cache targets drop the CAS blob stores** (`crates/wormward-doctor/src/lib.rs`
   `candidate_cache_dirs`): only exec/install trees are scanned (npx exec cache, node-gyp, TS ATA
   cache, global `node_modules`) — not the pnpm/yarn tarball caches. Plus an `is_metadata_file`
   filter skips lockfiles / `*-index.json` inside any kept dir.

### Regression tests
- `analyzer.rs::no_finding_on_yarn_lock_metadata`
- `analyzer.rs::no_finding_on_pnpm_index_json_metadata`
- `surface.rs::lockfiles_and_stores_excluded_from_content_scan`
- `doctor/lib.rs::cache_candidates_are_exec_and_install_trees_not_cas_stores`
- `doctor/lib.rs::metadata_files_are_not_content_scanned`

---

## FP class 2 — Base64 / WASM-glue short-literal collision

### Symptom
`obfuscation: decoder + shuffle seed` (Critical, "confirmed") on legitimate, real JS that happens to
embed a base64 blob.

### Real-world evidence
- `node_modules/@rive-app/canvas-advanced-single@2.31.6/canvas_advanced_single.mjs` — 2 MB of
  **Emscripten/WASM glue** for the popular Rive animation library (standard `var Rive=(()=>{…
  moduleArg … m.ready=new Promise …})(); export default Rive;`, with `WebAssembly`/`HEAPU8`/
  `wasmBinary`/`emscripten`). Every real worm signature = **0**. The only trigger: `MDy` appears
  **once**, inside a base64-encoded WASM blob: `...oCkAOtAq4CVwCxAiQ...ApMDyAL...`. No `function`,
  no `fromCharCode`, no shuffle IIFE, no seed. It is encoded data, not a decoder.
- The two `@rive-app/canvas-advanced-single` and `… 2` entries were both symlinks to the **same**
  pnpm package — one dependency, not two infections.

### Root cause
`content.contains("MDy")` — a bare substring of **three base64-alphabet characters**. It appears by
chance in any large base64/minified content, so it flagged **Critical/confirmed on every project
using Rive** (and any other WASM/Emscripten dependency). The `decoder + shuffle seed` wording was
itself false: there was no seed (0) and no decoder structure — `confirm()` fired on `MDy` + an
unrelated `("name",<digits>)` call elsewhere in the 2 MB file.

### Defense applied
The decoder is now matched only as a **defined JS identifier**, never as raw text
(`crates/wormward-packs/src/polinrider/analyzer.rs` `decoder_re`):

```
\b_\$_[0-9a-f]{4,}\b            # base64-SAFE family name (base64 has no `$`), word-bounded
| \bfunction\s+MDy\s*\(          # MDy as a function DEFINITION
| \b(?:var|let|const)\s+MDy\s*=  # MDy as a var/const/let DEFINITION
```

The bare `content.contains("MDy")` is removed. `MDy` inside encoded data can never satisfy this;
real v2 (which defines `function MDy(f){…}` or `const MDy=(function(a,y){…})(…)`) still does.

### Regression tests
- `analyzer.rs::no_finding_on_wasm_glue_with_incidental_mdy_in_base64` (the Rive class)
- `analyzer.rs::true_positive_v2_mdy_function_definition_preserved`
- `analyzer.rs::true_positive_v2_mdy_var_definition_preserved`
- End-to-end: the real `~/Desktop/Projects/Other/Mirage` repo scans to **0 findings** (was flagging
  the Rive glue Critical/confirmed).

### The general principle (base64/entropy blobs)
Embedded base64 blobs (Emscripten WASM, `data:` URIs, integrity hashes) are high-entropy and contain
*every* short substring by chance. **Any detector that matches a short literal against raw content
will false-positive on them.** The rule: a signature short enough to occur in base64 (≲ ~6 chars of
`[A-Za-z0-9+/]`) must require **identifier + word-boundary + assignment/definition context**, or must
contain a non-base64 character (`$`, `%`, `(`, `.`, `-`, `;`, `<`, `[`) that makes accidental
collision impossible. Audit finding: `MDy` was the only pure-base64-alphabet short literal in the
pack; every other literal (`Cot%3t=shtP` has `%`, `_$_1e42` has `$`, the XOR keys have `[<;`) is
base64-safe by construction.

---

## FP class 3 — Bare literal / bare number (no structure)

### Symptom
The umbrella cause behind classes 1 and 2: treating a decoder-like substring, or a bare 6–7 digit
number, as sufficient evidence.

### Root cause
- "shuffle seed" was `\b\d{6,7}\b` — any 6–7 digit run, so it matched digits inside SHA/integrity
  hashes and unrelated numeric constants.
- "decoder" was matched by entropy/substring with no requirement that the file even contain the
  executable JS a shuffle-decoder *requires*.

### Defense applied — the "confirmed" contract
`confirm()` (`analyzer.rs`) now requires the full structure. It emits a finding only when **all** of:

1. **A JS-code token is present** (`has_js_code_token`) — the HARD VETO. The list is deliberately
   comprehensive (all realistic exec sinks: `eval(`, `atob(`, `Function(`, `setTimeout(`, `import(`,
   `require(`, `constructor(`; all realistic string ops: `function(`, `String.fromCharCode`,
   `fromCodePoint`, `charCodeAt`, `charAt`, `.split(`, `.join(`, `.slice(`, `.substr`, `.replace(`,
   `.reverse(`, `.map(`, `.at(`, `unescape(`, `decodeURIComponent(`, arrow-with-body `=> {`), so an
   attacker cannot dodge it by swapping `eval(`→`Function(` or `charAt`→`.slice(`: a decoder that
   uses **none** of these cannot decode or execute anything. Inert metadata has none.
2. **A real decoder as a defined identifier** (`decoder_re`, class 2) — never a bare substring.
3. **AND one of:**
   - an **injection marker** (`marker_re`: `global[...] = require|module|'<tag>'`), or
   - a **seed bound to its IIFE structure** (`seed_arg_re`: `['"][^'"]*['"]\s*,\s*\d{6,7}\s*\)` —
     e.g. `("rmcej%otb%",2857687)`), never a bare 6–7 digit number.

So `confirmed` means: *a defined decoder + (an injection marker OR a seed passed as a shuffle-IIFE
argument) + executable JS.* Two of three is not "confirmed."

### Regression tests
- `analyzer.rs::veto_resists_evasion_via_uncommon_tokens` (a decoder using `.slice`/`.reverse`/
  `Function(` — the uncommon tokens — is still caught; the veto is not dodgeable)
- `analyzer.rs::true_positive_shuffle_iife_with_code_token_preserved`
- `analyzer.rs::true_positive_dot_marker_with_fromcharcode_or_eval_preserved`
- `analyzer.rs::confirms_*` variant tests (bracket / dot / double-quote / ESM-shim / fromCharCode)
- `analyzer.rs::does_not_confirm_legit_esm_createrequire_bundle` (createRequire alone ≠ infection)

---

## Adjacent hardening (same philosophy)

- **Community-tier confidence** (`crates/wormward-core/src/matchers.rs` `Confidence`): single-source
  IOC leads are tagged `pkg-community:` and downgraded to `Low` severity, suppressed unless
  `--include-community`. A lead never produces a hard `Critical`/"infected" verdict on its own.
- **Version-pinned packages**: hugely-popular names (e.g. `axios`) are flagged only at the exact
  malicious versions (`bad_packages` with `versions`), never by name — a clean install never trips.
- **Binary magic-byte validation** (`crates/wormward-core/src/capability.rs` `magic_mismatch`): a
  real font/image (valid `wOF2`/`OTTO`/PNG/JPEG magic) with an incidental code token is spared;
  only a payload-carrying fake asset (no magic + code) fires.
- **Invisible-Unicode detector** (`capability.rs` `invisible_unicode`): fires on a run of ≥4
  consecutive invisible chars or a bidi override — legit emoji ZWJ sequences and RTL i18n text never
  form a 4-long run, so they are spared.

---

## Checklist for adding a new signature (avoid re-introducing FPs)

Before adding any literal/regex IOC, confirm:

1. **Base64 safety** — could this string occur in base64 / minified / WASM-glue content? If it is
   ≲ 6 chars of `[A-Za-z0-9+/]`, it will. Require identifier + word-boundary + assignment context, or
   ensure it contains a non-base64 character.
2. **Structure, not substring** — is a lone match meaningful, or does it need context (a marker, an
   IIFE arg, a definition)? Bare numbers are never seeds; bare names are never decoders.
3. **Surface** — does this file type contain executable code at all? Lockfiles, CAS blobs, and
   integrity metadata do not — exclude them from content scanning.
4. **Popular-dependency test** — would this fire on a clean install of a top-100 npm package? If
   yes, it is a bug. Add a clean-corpus regression fixture proving it does not.
5. **Confidence tier** — single-source lead? Tag it community/Low, not vendor/Critical.
6. **Verify on a real file** — dogfood against an actual project before shipping. Every FP in this
   document was found that way, not in review.
