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
   - CAS stores: `**/.pnpm/**`, `**/pnpm/store/**`, `**/.npm/_cacache/**`, `**/.bun/install/cache/**`,
     `**/.yarn/cache/**`, `**/.yarn/unplugged/**` (every package-manager blob cache)
   - Lockfiles are still **parsed by name** for malicious package versions in `check_lockfiles` —
     that path is unaffected; only *content-scanning them for obfuscation* is suppressed.

   Real case: legit `@babel/parser` and `node-fetch` bundles under `.bun/install/cache/` tripped the
   **capability engine** (`network-egress` / `.exec(` matching a regex `.exec()` read as
   `process-spawn` / `trailing-code` on the bundle's `exports.x = y` tail). Both scan passes honor
   `is_excluded_path` (`scanner.rs`), so excluding the cache dir suppresses it in both — the CAS
   store is not an install tree, so a library bundle there is never a meaningful detection.
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

## The mirror image — version-independent detection (false-NEGATIVE hardening)

The same principle that kills false positives — *match structure, not per-instance constants* —
also kills false **negatives**. A campaign that rotates its own constants each wave (the version
tag `5-3-235` → `5-3-168` → `5-3-999`, the decoder `_$_8e2c` → `_$_3317`, the seed `3899501` →
`3657078`) turns any constant-keyed signature into a next-wave miss. Detection must key on what the
family *cannot* change without abandoning its technique.

Three structural, version-independent detectors are the primary catch (per-version literals are kept
only as **attribution**, to label *which* wave — never as the sole detection):

1. **Padding-injection** (`capability.rs` `padding_injection`, a self-evident worm tell in `gate`):
   a physical line with `\S … [ \t]{200,} … \S` — real content, a ≥200 space/tab run, then more
   content. This is the injection's shape (`<legit code><~2000 spaces><obfuscated blob>` on the
   file's last line) and no constant rotation removes it. It fires **even when the payload's
   behavior is concealed** inside its obfuscated blob (so no plaintext network/spawn capability is
   visible) — which was exactly the wave-3 gate miss. FP-safe *by construction*: minifiers strip
   whitespace (no runs), lockfiles are short lines, and a base64/WASM blob is one contiguous token
   with no interior run-then-code. Shared with the analyzer's confirm path, one predicate.
2. **Generic version-tag / decoder / shim** (`analyzer.rs`, `capability.rs`): `global.<k>='5-3-*'`
   (any suffix), the `_$_[0-9a-f]{4,}` decoder as a defined identifier, and the
   `global[…]=require|module` ESM re-entry shim — all matched by shape, not by the specific string.
3. **Structure over enumeration at the FILE layer too.** The wave-3 repos were reported clean
   because the newly-targeted files (`metro.config.js`, `app.config.ts`, `seed.ts`, `migrate.ts`)
   were in *neither* the pack's `target_files` allowlist *nor* `classify()`'s config-stem allowlist —
   two enumerations that both failed on the same expansion. Fixed by generalizing both: **any**
   `*.config.{js,cjs,mjs,ts}` is a `ConfigFile` surface (`classify`) and a pack target (`*.config.*`
   globs), plus the known `seed`/`migrate` script names. A clean config of any name still never
   fires — the gate requires a concealment prior or a worm tell.

4. **Repo-wide structural catch-all** (`scanner.rs` `scan_injection_structure`). The surface/target
   passes only read recognized configs and entry files, but the family appends its payload to the
   last line of ARBITRARY executable source — `server.js`, `routes/*.js`, `Gruntfile.js`,
   `.prettierrc.mjs`, controllers, entry points. This pass reads every non-excluded, non-binary code
   file and fires on `capability::injected_payload` (a padding-run line or a `_$_hex` decoder
   identifier), both FP-safe by construction. Attributed to `polinrider` and remediable via the same
   structural strip; deduped against surface findings so a flagged config is not double-reported.

Remediation is structural to match: cut the payload at the ≥200-space padding run (or the generic
marker/decoder), and remove the injected `createRequire` shim **only if no genuine `require(`
remains** — so a config that legitimately uses `createRequire` for CJS interop is not broken.

### Corpus evidence (GitHub, 2026-07-21)

An IOC-seeded GitHub code-search sweep (wallets / C2 domains / dropper filenames / decoder /
malicious packages, rate-limit-paced, clone-free scan) surfaced **762 confirmed-infected repos**.
Two findings drove the hardening above:

- **Version tags rotate constantly.** The originally-tracked `5-3-*` family is a *minority*; the
  corpus is dominated by `8-*`, `9-*`, and `10-*` tags (8-270, 9-4365, 9-0674, 9-5607, 10-590, …
  dozens of distinct prefixes). A signature keyed on `5-3-*` would false-negative on the majority;
  the `_$_[0-9a-f]{4,}` decoder (2,768 files) and the padding structure catch them all.
- **~14% of infections lived only in non-config source.** Before the repo-wide pass, wormward
  detected 573/762 repos; the structural catch-all took that to 643/762 (the rest are dropper-only
  repos, caught by the `temp_auto_push.bat` artifact). The sole residual source-code miss is one
  payload inside a `vendor/` dir — deliberately excluded as third-party code (accepted trade-off).

### Delivery-vector detection — dependency-name typosquats (`typosquat.rs`, `scan_dependency_typosquats`)

To catch the *delivery* packages (`tailwindcss-style-animate`, `chalk-logger`, …) beyond the static
`bad_packages` list, a dependency whose NAME resembles a popular package is flagged — but only when
FP-safe. The design decision that makes it FP-safe: **the name is a weak signal; behaviour is the
discriminator.**

- **A one-edit misspelling** of a popular name (`expres`, `lodahs`) is a strong-enough name signal to
  surface as a suppressed community lead (`pkg-community:` id, off unless `--include-community`).
- **A decoration** (`<popular>-<word>`) NEVER produces a name-only finding — it fires only when the
  installed package also shows dropper behaviour, at which point it is a visible **Medium**.
- **Dropper behaviour** = the injected-payload structure (`_$_hex` decoder / padding run) or a
  malicious install script — both mathematically absent from legitimate code.
- Names a pack already tracks are skipped (the version-aware lockfile/node_modules checks own them),
  so the pass is purely additive and never overrides a version pin.

The FP-safety was proven by **auditing the matcher against 3,366 real npm package names** pulled from
the live registry across the exact worst-case ecosystems (`react`, `tailwind`, `chalk`, `eslint`,
`vue`, …). This caught a real FP class — `react`/`next`/`vite`/`eslint` have huge legit `<root>-<word>`
plugin ecosystems (`react-icons`, `lucide-react`, …) — which was fixed by removing those roots as
decoration bases. Even so, ~300 legit packages (`chalk-cli`, `prettier-plugin-tailwindcss`, hundreds
of `tailwindcss-*` plugins) still match the deliberately-broad decoration rule; the regression test
`real_legit_lookalikes_installed_clean_produce_no_findings` installs a representative sample **clean**
and asserts **zero** findings, so the behaviour gate — not the name — is what ever fires.

**Acceptance** (`wormward-packs` + `capability_integration`): a `5-3-168`/`_$_3317` payload (in no
signature list) and a hypothetical `5-3-999-zz` payload are both DETECTED and CLEANED across the
expanded file set and on non-default branch tips (`--deep`); minified bundles, `yarn.lock`,
`public/assets/` bundled copies, and `@rive-app` WASM `.mjs` (base64 containing `MDy`) are NOT.

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
