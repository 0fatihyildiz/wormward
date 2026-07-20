# GUI: bring `doctor` into the desktop app + professionalize the UI

Date: 2026-07-20

Two goals: (1) surface the Rust-side machine check (`wormward doctor`) in the Tauri GUI, and
(2) raise the whole desktop app to a polished, trustworthy commercial-security-tool bar, driven
by a parallel per-screen professionalism audit (66 findings: 10 P0, 29 P1, 27 P2; 9 themes).

## Part 1 — `doctor` in the GUI

**Constraint:** the doctor engine lives in `wormward-cli/src/doctor.rs`; the Tauri crate does not
depend on `wormward-cli`.

**Fix:** extract a new crate `wormward-doctor` (depends on `wormward-packs` for
`polinrider_fingerprint`). Both `wormward-cli` and the Tauri app depend on it — one engine, DRY.
The crate exposes the report types (`DoctorReport`, `ProcHit`, `CacheHit`, `TriggerCheck`, all
serde), `check()`, the scan/audit functions, `affected_cache_dirs`, and `fix_triggers`. The CLI
keeps its `render_text`/`--fix` orchestration.

**Tauri commands:** `doctor() -> DoctorReport` (async + `spawn_blocking`; it shells out to
`ps`/`npm`), `doctor_clear_cache(dir)`, `doctor_harden_triggers() -> Vec<String>`.

**Doctor screen** (design-system-native): runs `doctor()` on visit / via a Run-check button;
three sections — Processes / Caches / Triggers — each with ✓/⚠/✗ status; fix actions (Clear cache
per affected dir with confirm; Harden button for ignore-scripts; ATA/MCP advisory text); a Watch
toggle that re-polls `doctor()` every 5s for respawn detection. New tab + `types.ts` + `api.ts`.

## Part 2 — professionalization (audit-driven)

### Cross-cutting themes (fix once, benefits many screens)
1. **Notifications**: replace the single auto-dismissing 7s `app.error` string with a persistent,
   stackable, severity-aware toast system; map known backend/GitHub failures to plain language.
2. **Honest states**: never assert a clean/complete result that wasn't computed — gate every
   "none found"/"all-clear" on an explicit scanned/loaded flag; reflect cancelled/partial runs.
3. **Credentials**: labeled + hardened + verifiable token fields; honest storage disclosure
   (OS keychain via Tauri preferred; at minimum truthful copy).
4. **Explicit target**: no silent `["."]` — require/resolve a real folder and show it on Scan+Clean.
5. **Accessibility**: role=status/progressbar, text labels for state (not color-only), real
   `<label>`s, semantic lists, named nav + skip link, correct focus-visible.
6. **Loading**: standard button-spinner ("Applying…/Pushing…/Restoring…") + disable-on-click for
   every async mutation.
7. **Empty/success states**: reuse the `.state` glyph component; make empty states actionable (CTA).
8. **Microcopy**: plain, sentence-case product copy; real pluralization; drop CLI/git jargon.
9. **Risk signaling**: sort findings worst-first; critical ≠ high; drive counts/status from
   semantic `--ok/--warn/--danger`.

### P0 (trust/safety — do first)
- Errors can silently vanish/clobber in the 7s toast (shell).
- Scan runs against an unpredictable CWD via `["."]` (scan/clean).
- Aborted scan renders a green "No infections found" (results) — read `report.cancelled`.
- Restore re-writes malware on one unguarded click (clean) — confirm modal + backup-exists gate.
- Manual (non-auto-fixable) findings least visible on the clean screen (clean).
- Branch section asserts "clean" before any branch scan (clean) — add `branchesScanned` flag.
- Force-push stays armed against just-fixed repos (github) — reconcile after fix.
- Every fixable repo pre-checked, arming account-wide force-push by default (github).
- Packs card stuck on "Loading packs…" forever on empty/error (settings).
- Copy oversells plaintext localStorage token storage as safe (settings).

(Full 29 P1 + 27 P2 items: see the audit output — themes above capture the bulk.)

## Phased execution
- **Phase 0** — `doctor` in the GUI (new crate + commands + screen). ← explicit ask.
- **Phase 1** — foundation + all P0: token/`--border`/focus fixes, notification system, honest
  states, restore/force-push safety, manual-findings elevation, explicit target.
- **Phase 2** — P1 themes: risk signaling, loading states, empty states + CTAs, microcopy, a11y,
  credential fields.
- **Phase 3** — P2 nice-to-haves (optional).

Each phase committed incrementally; check in between phases.
