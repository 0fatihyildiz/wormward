# Wormward Antivirus-UX Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reshape the Wormward Tauri desktop GUI into a calm, minimalist consumer-antivirus experience — one protection status, one "Full Scan", a guided results→clean flow — with every power feature behind progressive disclosure. Frontend-only; reuses every existing Tauri command.

**Architecture:** Replace the 4-tab shell with a Svelte 5 view-state router (`home | flow | machine | repos | advanced | settings`). A single Full Scan runs the machine check (`doctor()`) and the repo scan (`scan()`) together in one guided flow (scanning → results → cleaning → clean). Pure logic (protection level, locations persistence, error humanizing) is extracted into vitest-tested modules; Svelte components/routes are verified via `svelte-check` + `build` + a manual smoke step. Each phase ends shippable with nothing unreachable.

**Tech Stack:** Tauri v2, Svelte 5 (runes), TypeScript (strict + verbatimModuleSyntax), Vite 6, pnpm, and vitest + jsdom (added in Phase 1, for the pure-logic modules only).

## Global Constraints & Shared Contract

Every task's requirements implicitly include this section. Names, signatures, and rules here are authoritative.

SHARED CONTRACT (every task in every phase MUST use these exact names, signatures, rules, and ordering).

REPO FACTS:
- Tauri v2 desktop app. Frontend: apps/desktop/, Svelte 5 (runes), TypeScript strict + verbatimModuleSyntax, Vite 6, pnpm. apps/desktop is self-contained (own pnpm-lock.yaml, no root JS workspace).
- Svelte 5 ONLY: use $state/$derived/$derived.by/$effect/$props runes and event attributes (onclick,oninput,onchange) NOT on:click. Components use <script lang="ts">. Type-only imports MUST use "import type" (verbatimModuleSyntax). Never redeclare a $derived/$state/const that already exists in the same module.
- COMMAND CWD: every pnpm AND git command runs from apps/desktop/ unless a step explicitly says "from repo root". Therefore git add paths are RELATIVE to apps/desktop (e.g. "git add src/lib/x.ts", "git add package.json vitest.config.ts") — NEVER "git add apps/desktop/...".
- NO frontend test runner exists today (only svelte-check via "pnpm check"). Rust has cargo tests (out of scope).
- Backend calls already exist in apps/desktop/src/lib/api.ts and are reused UNCHANGED: scan(dirs,deep,online,token), cancelScan(), cleanPreview(dirs), cleanApply(repos), restore(dirs), cleanBranchesPreview(dirs), cleanBranchesApply(selected,push), githubOrgs(token), githubScan(token,includeForks,orgs), githubFix(selected), cancelGithubScan(), doctor(), doctorClearCache(dir), doctorHardenTriggers(), listPacks(), pickDirs(). NO Rust/Tauri changes.
- Tauri events already emitted: "local-scan-progress" and "github-scan-progress" carrying ScanProgress { phase, done, total, repo, findings }.
- Types in apps/desktop/src/lib/types.ts (Finding, ScanReport, DoctorReport, RepoPlan, GithubRepoView, etc.) reused unchanged.
- Design system apps/desktop/src/app.css is ADDITIVE only: reuse tokens/classes (.card, .btn, .btn.primary, .btn.ghost, .btn.danger, .switch, .modal-backdrop, .modal, .state, .glyph, .progress, .spinner, .pill, .chip, semantic --ok/--warn/--danger surfaces + tints). Do NOT rewrite tokens. New CSS may be added (hero/shield scale, --gap-hero) but keep dark-only, borderless, single-accent, reduced-motion.
- Commits MUST NOT include a Co-Authored-By: Claude trailer. Conventional-commit style.

GLOBAL COPY + A11Y RULE (critical — prevents rework): write the FINAL user-facing plain-English copy AND the FINAL accessibility attributes in the component/route WHERE IT IS FIRST CREATED (Phases 2-5). Do NOT defer copy or a11y to a later phase. Phase 6 only VERIFIES and cleans up — it introduces NO new copy tables and rewrites NO markup. For pluralization keep a LOCAL "const plural = (n, one, many) => (n === 1 ? one : many);" inside each file that needs it (matching the existing Workspace.svelte pattern) — do NOT create a shared plural/count module and do NOT import plural across files (avoids duplicate-identifier errors).

HONEST STATES: never assert protected/clean/all-good before a real scan ran; reflect cancelled/partial runs. Preserve a11y everywhere: skip link, role=status/progressbar, role=alert on error/incomplete banners, real <label>s, focus-visible, prefers-reduced-motion, aria-label on bare count badges, and state conveyed by TEXT+color (never color alone).

NEW FILE: apps/desktop/src/lib/errors.ts (pure, vitest-tested). EXTRACT the existing humanizeError from state.svelte.ts verbatim into here and re-export; state.svelte.ts then imports it. Signature: export function humanizeError(e: unknown): string  (same 401/403/network/osm-token/default-passthrough branches as today).

NEW FILE: apps/desktop/src/lib/locations.ts (pure, vitest-tested). Persists protected locations in localStorage key "protected_locations".
  export function loadLocations(): string[]   // JSON.parse localStorage["protected_locations"]; return [] on missing/invalid-JSON/non-array
  export function saveLocations(dirs: string[]): void   // localStorage["protected_locations"] = JSON.stringify(dirs)
  export function hasLocations(): boolean   // loadLocations().length > 0

NEW FILE: apps/desktop/src/lib/protection.ts (pure, vitest-tested). Import types via "import type { DoctorReport, ScanReport } from ./types".
  export type ProtectionLevel = "protected" | "attention" | "threat" | "unknown";
  export interface SurfaceStatus { level: ProtectionLevel; label: string; }
  export function levelRank(l: ProtectionLevel): number   // threat=3, attention=2, protected=1, unknown=0
  export function machineStatus(report: DoctorReport | null): SurfaceStatus
  export function reposStatus(report: ScanReport | null): SurfaceStatus
  export function overallLevel(machine: SurfaceStatus, repos: SurfaceStatus): ProtectionLevel
  DERIVATION RULES (encode EXACTLY; honest-state precedence = real findings beat "incomplete"):
  machineStatus: null => {"unknown","Not checked"}; processes.length>0 => {"threat","Active threat running"}; caches.length>0 OR some trigger.exposed => {"attention","Needs attention"}; else {"protected","No active threats"}.
  reposStatus: null => {"unknown","Not scanned"}; findings has any severity==="critical" => {"threat","Critical threat found"}; else findings.length>0 => {"attention","Threats found"}; else report.cancelled => {"unknown","Scan incomplete"}; else {"protected","No threats"}.
  overallLevel (HONEST — you are "protected" ONLY when BOTH surfaces are protected; any unknown/cancelled keeps overall at "unknown", never "protected"): if machine.level==="threat" || repos.level==="threat" => "threat"; else if machine.level==="attention" || repos.level==="attention" => "attention"; else if machine.level==="unknown" || repos.level==="unknown" => "unknown"; else "protected".

STATE MODEL: extend apps/desktop/src/lib/state.svelte.ts. Keep Toast, notify(), fail(), dismiss(), clearErrors(). humanizeError MOVES to lib/errors.ts and is imported. New app shape:
  export type View = "home" | "flow" | "machine" | "repos" | "advanced" | "settings";
  export type FlowStep = "scanning" | "results" | "cleaning" | "clean";
  export const app = $state({ view: "home" as View, flow: null as FlowStep | null, dirs: [] as string[], report: null as ScanReport | null, machineReport: null as DoctorReport | null, lastScanAt: null as number | null, scanning: false, toasts: [] as Toast[] });
  export function go(view: View) { app.view = view; }
  On module init: app.dirs = loadLocations(); (import from ./locations). "dirs" ARE the protected locations (name kept for api.scan compatibility). When the user edits locations, call saveLocations(app.dirs).

COMPONENTS (new, apps/desktop/src/lib/components/, Svelte 5 $props, FINAL a11y from creation):
  ShieldStatus.svelte  props { level: ProtectionLevel; heading: string; sub?: string }. Big round shield badge (.shield) with an aria-hidden glyph/SVG keyed to level color (--ok protected / --warn attention / --danger threat / neutral unknown), a SIBLING <h1 class="shield-heading">{heading}</h1>, an .sr span "Status: <level word>", and optional .shield-sub {sub}. Heading text is ALWAYS rendered (never color-only). Keep a stable class structure so app.css hero styles apply.
  HealthChip.svelte    props { label: string; status: SurfaceStatus; onclick: () => void }. A <button class="health-chip"> with label text, an aria-hidden mark (checkmark/exclamation/x) colored by status.level, and status.label rendered as visible text. Fully self-styled with a <style> block including per-level mark colors.
  GuidedProgress.svelte props { label: string; done?: number; total?: number; indeterminate?: boolean }. Wraps .progress; a role=status live label element; role=progressbar with aria-valuemin/max/now when determinate, .indet when indeterminate.
  FindingCard.svelte   props { finding: Finding }. Plain human title; a native <details> "Details" disclosure exposing raw evidence, repo + file path, campaign, git_ref (branch) if present, and the online verdict if present. Plain labels: finding.remediable => "Removable automatically", else "Needs your attention".

APP SHELL (App.svelte) — SINGLE canonical form used by ALL phases (this matches the codebase pattern that already uses Record<string, Component> + {@const}):
  Keep skip link, the !isTauri env-banner, the global toast stack, and the window error/rejection handler. REMOVE the tab bar, the sliding .indicator pill, and the per-tab keep-mounted "visited" logic.
  Router: const views: Record<View, Component> = { home: Home, flow: <FlowComp>, machine: <MachineComp>, repos: <ReposComp>, advanced: <AdvancedComp>, settings: SettingsComp };
  Render: bind a mainEl and render <main id="main" tabindex="-1" bind:this={mainEl}> {#key app.view} {@const Current = views[app.view]} <Current /> {/key} </main>.
  FOCUS MANAGEMENT (add WHEN THE ROUTER IS FIRST CREATED in Phase 2, NOT deferred): a $effect that references app.view and, skipping the very first run, calls queueMicrotask(() => mainEl?.focus()) so keyboard/SR focus lands on the new view instead of document.body.
  A small gear (⚙) control opens a menu of PLAIN BUTTONS (Advanced, Settings) in a labelled container — do NOT use role=menu/role=menuitem (that advertises keyboard semantics we do not implement); Escape and outside-click close it. Home has no back control; machine/repos/advanced/settings/flow render their own back-to-Home control.
  Each phase only CHANGES specific entries of the views map (swapping a temporary component for the real one). Never re-typedef the map or convert it to an {#if} chain.

ROUTES (apps/desktop/src/routes/):
  Home.svelte (new, Phase 2): reads app + protection. Resting view: ShieldStatus(level=overall, heading/sub honest) + ONE primary "Full Scan" button (class "btn primary cta") + two HealthChips (This Mac -> go("machine"); "Repositories" -> go("repos")). Full Scan handler is named fullScan() and sets app.view="flow" (see shell). FIRST-RUN variant when !hasLocations(): short intro + "Choose your code folder" (pickDirs -> app.dirs + saveLocations) + secondary "Use my home folder". HONEST: when app.lastScanAt===null show a neutral "Not scanned yet" heading/level, NOT "protected".
  ScanFlow.svelte (new, Phase 3): the unified full scan. On scanning: run doctor() AND scan(app.dirs, false, !!osmToken, osmToken) together (osmToken = localStorage.getItem("osm_token") || undefined; online cross-check is enabled ONLY when a token exists). Combined progress via the "local-scan-progress" listener + GuidedProgress "Checking your Mac and your code…"; hidden-by-default <details> "Show details" reveals the existing per-repo terminal log; a quiet "Stop" -> cancelScan(). Store app.machineReport, app.report, app.lastScanAt = Date.now(). Then flow="results": human summary "N threats found. X can be removed safely and automatically; Y need your review." + worst-first FindingCard list (reuse the grouping/severity logic from Workspace.svelte; group-count badges MUST carry aria-label) + primary "Remove threats safely" (cleanPreview then cleanApply(fixableRepos)) -> flow="cleaning" ("Removing threats safely…") -> flow="clean" reassuring end + return Home. Cancelled/partial: an honest banner with role="alert" (write it NOW in Phase 3, not later). NO force-push / branch / remote actions here. Keep a LOCAL const plural.
  MachineDetail.svelte (new, Phase 5, replaces Doctor.svelte content): plain-language machine check. Does NOT auto-run on mount. If app.machineReport is null, resting idle state "This Mac hasn’t been checked yet" + a "Run a check" button; while a manual check runs show "Checking this Mac…"; when present, three worst-first sections: "Is a threat running right now?" (processes), "Infected app caches" (caches -> "Clean up" per dir via doctorClearCache, confirm), "Risky settings that let malware come back" (triggers -> "Turn on protection" via doctorHardenTriggers). A "Live monitoring" toggle with HONEST sublabel "re-checks every few seconds" re-polls doctor() every 5s. Writes app.machineReport. Keep a LOCAL const plural.
  RepositoriesDetail.svelte (new, Phase 5): per-repo findings from app.report, grouped worst-first (reuse Workspace grouping; count badges carry aria-label), plain labels, honest empty/cancelled states, and a quiet link to Advanced for other-branch cleaning and restore. Keep a LOCAL const plural.
  Advanced.svelte (new, Phase 4): hosts (a) GitHub account scan + Fix&force-push — PORT the whole current routes/GitHub.svelte behavior + EVERY safety (unselected-by-default, disarm-after-fix, confirm modal, github-scan-progress listener), (b) other-branch deep cleaning + optional push (from Workspace Advanced block: cleanBranchesPreview/Apply), (c) Restore last backup (guarded: restore(app.dirs) behind a confirm modal). All clearly labeled destructive/advanced. Keep LOCAL const plural.
  Settings.svelte (modified, Phase 4): ADD a "Protected locations" editor at top (list app.dirs, add via pickDirs, remove, persist via saveLocations). Keep the existing OSM + GitHub token cards and packs list. Add a minimal "Appearance" note (dark only for now).

PHASING — each phase ends SHIPPABLE with NOTHING unreachable. Full Scan always sets app.view="flow"; the flow map entry is a temporary component until Phase 3.
  Phase 1: lib/errors.ts (extract+TDD) + lib/locations.ts (TDD) + lib/protection.ts (TDD, covering EVERY derivation branch incl. overallLevel both-protected/any-unknown/any-attention/any-threat) + extend lib/state.svelte.ts (View/FlowStep, new app fields, go(), import humanizeError from ./errors, hydrate dirs). App.svelte UNCHANGED this phase (old tab UI still works). Shippable.
  Phase 2: components/ShieldStatus + components/HealthChip + routes/Home (resting + first-run, honest pre-scan) + swap App.svelte to the canonical views-map router WITH focus management + plain-button ⚙ menu + additive app.css hero/shield styles. TEMPORARY map so nothing is lost: { home: Home, flow: Workspace, machine: Doctor, repos: Workspace, advanced: GitHub, settings: Settings }. Full Scan sets view="flow" (temporarily shows old Workspace). Shippable.
  Phase 3: components/GuidedProgress + components/FindingCard + routes/ScanFlow; change ONLY the flow map entry to ScanFlow; Home Full Scan now runs the real guided scan. Shippable.
  Phase 4: routes/Advanced (GitHub + other-branches + restore, all safeties) + Settings protected-locations editor + Appearance; change map advanced->Advanced (retire temp GitHub). machine/repos still temp -> Doctor/Workspace (both still reachable, nothing lost). Shippable. (Advanced MUST exist before Phase 5 unroutes Workspace, so branch-clean + restore always have a home.)
  Phase 5: routes/MachineDetail + routes/RepositoriesDetail; change map machine->MachineDetail, repos->RepositoriesDetail (retire temp Doctor/Workspace). RepositoriesDetail links to Advanced (exists). Shippable.
  Phase 6: VERIFY + CLEANUP ONLY (NO new copy, NO markup rewrites): (6.1) a11y verification sweep — a checklist over Home/ScanFlow/MachineDetail/RepositoriesDetail/Advanced/Settings/ShieldStatus/HealthChip/GuidedProgress confirming reduced-motion, role=status/progressbar/alert, aria-labels, focus-on-view-change, text-not-color-only; fix any gap with a MINIMAL additive edit quoting the exact current markup. (6.2) empty/partial/cancelled-state audit referencing EXACT existing strings/markup (verify, do not duplicate branches). (6.3) delete now-dead files (routes/Doctor.svelte, routes/GitHub.svelte, and orphaned Workspace.svelte) and prove no import breaks via pnpm check + pnpm build. Shippable.

---

## Verification corrections (adversarial review) — apply within the named task

This plan was drafted by parallel agents and hardened by a six-lens adversarial review.
The two blocker anchors (App.svelte map/import edits in Tasks 4.4 & 5.3), the stale-report
refresh (Task 3.4 `removeThreats`), the honest-state precedence tests (Task 1.4) and their
counts (Tasks 1.4/1.5), the GuidedProgress determinate name (Task 3.1), and the scanning/
cleaning headings (Task 3.3) are **already applied inline above**. The following smaller
corrections must be applied *inside the named task* when you reach it — they are net-new
accessibility/spec items, not rewrites:

- **[C1 · Task 2.3 — Home, last-scan time]** Spec Screen 2 requires the post-scan status to
  show the last-scan time. In `Home.svelte`, when `app.lastScanAt !== null`, format it and
  include it in the `sub` passed to `<ShieldStatus>` (e.g. `const lastScan = $derived(app.lastScanAt ? new Date(app.lastScanAt).toLocaleString() : null);` and append `· Last scan: {lastScan}` to the scanned `sub`). Keep it OUT of the pre-scan "Not scanned yet" branch.
- **[C2 · Task 5.1 — MachineDetail, assertive threat]** The "Is a threat running right now?"
  section must interrupt, not defer, when a loader is found: when `procHits > 0`, give the
  threat block `role="alert"` (or `aria-live="assertive"`); keep `aria-live="polite"` only on
  the benign/clean sections.
- **[C3 · Tasks 4.1, 4.2, 5.1 — confirm modals, accessible name]** Every new
  `<div class="modal" role="dialog" aria-modal="true" tabindex="-1">` (GitHub Fix&push,
  branch-clean, restore, cache-clear) must name itself: give its heading a unique `id` and add
  `aria-labelledby="<that-id>"` to the dialog element.
- **[C4 · Task 2.4 — gear menu focus]** Capture the gear button (`bind:this={gearEl}`); on close
  via Escape or outside-click call `gearEl?.focus()` so focus returns to the trigger instead of
  `document.body`. Bind `aria-controls="app-menu"` only while the menu is open.
- **[C5 · Tasks 3.3/3.4 — flow sub-step focus]** The guided flow advances by mutating `app.flow`
  (not `app.view`), so the Phase-2 router focus effect never fires on scanning→results→cleaning→
  clean. In `ScanFlow.svelte`, give each step's heading `tabindex="-1"`, `bind:this` the active
  one, and in a `$effect` keyed on `app.flow` call `queueMicrotask(() => stepHeadingEl?.focus())`
  so completion is announced and focus moves. (The cleaning step already has `role="status"` via
  GuidedProgress.)
- **[C6 · Task 6.3 — remove the transitional `screen` field]** After the legacy routes are
  deleted, remove the transitional `screen` field and its type from the `app` `$state` in
  `lib/state.svelte.ts`. Verify `grep -rn '\.screen' src` returns empty first, then delete the
  `screen: "scan" as …` line and its comment; re-run `pnpm check` (0 errors) + `pnpm test`
  (36 passed) before committing.

---

## Phase 1: Test infra + pure logic modules + state backbone

### Task 1.1: Vitest + jsdom test runner with a sanity test

**Files:**
- Create: `apps/desktop/vitest.config.ts`
- Create: `apps/desktop/src/lib/sanity.test.ts`
- Modify: `apps/desktop/package.json:6-11` (scripts), `package.json:16-23` (devDependencies — written by pnpm)

**Interfaces:**
- Produces: a working `pnpm test` (= `vitest run`) with `environment: "jsdom"`, consumed by every later pure-logic task in this phase.

- [ ] **Step 1: Install the runner dev deps.** From `apps/desktop`, run:
  ```
  pnpm add -D vitest jsdom
  ```
  Expected: pnpm prints `+ vitest` and `+ jsdom` under "devDependencies", updates `package.json` and `pnpm-lock.yaml`, exits 0.

- [ ] **Step 2: Add the `test` script.** Edit `apps/desktop/package.json`. Replace this exact block:
  ```json
    "scripts": {
      "dev": "vite",
      "build": "vite build",
      "check": "svelte-check --tsconfig ./tsconfig.json",
      "tauri": "tauri"
    },
  ```
  with:
  ```json
    "scripts": {
      "dev": "vite",
      "build": "vite build",
      "check": "svelte-check --tsconfig ./tsconfig.json",
      "test": "vitest run",
      "tauri": "tauri"
    },
  ```

- [ ] **Step 3: Create `apps/desktop/vitest.config.ts`.** A standalone vitest config (used instead of `vite.config.ts`, so the Svelte plugin never runs for these pure-TS tests):
  ```ts
  import { defineConfig } from "vitest/config";

  export default defineConfig({
    test: {
      environment: "jsdom",
      include: ["src/**/*.test.ts"],
    },
  });
  ```

- [ ] **Step 4: Create `apps/desktop/src/lib/sanity.test.ts`.** One trivial passing test that proves the runner and jsdom load:
  ```ts
  import { describe, it, expect } from "vitest";

  describe("vitest runner", () => {
    it("runs and asserts", () => {
      expect(1 + 1).toBe(2);
    });

    it("has a jsdom localStorage", () => {
      expect(typeof localStorage).toBe("object");
    });
  });
  ```

- [ ] **Step 5: Run the suite.** From `apps/desktop`, run:
  ```
  pnpm test
  ```
  Expected: `Test Files  1 passed (1)` and `Tests  2 passed (2)`, exit 0.

- [ ] **Step 6: Confirm the typechecker still passes.** From `apps/desktop`, run:
  ```
  pnpm check
  ```
  Expected: `svelte-check` finishes with `0 errors` (the `.test.ts` file typechecks because it imports from `vitest` and `localStorage` comes from the default DOM lib).

- [ ] **Step 7: Commit.** From `apps/desktop`:
  ```
  git add package.json pnpm-lock.yaml vitest.config.ts src/lib/sanity.test.ts
  git commit -m "test(desktop): add vitest + jsdom runner with sanity test"
  ```
  No `Co-Authored-By: Claude` trailer.

---

### Task 1.2: Extract `humanizeError` into `lib/errors.ts` (TDD)

**Files:**
- Test: `apps/desktop/src/lib/errors.test.ts` (create)
- Create: `apps/desktop/src/lib/errors.ts`
- Modify: `apps/desktop/src/lib/state.svelte.ts:1` (import), `state.svelte.ts:20-33` (remove local fn)

**Interfaces:**
- Produces: `export function humanizeError(e: unknown): string` in `lib/errors.ts` — same 401/403/network/osm-token/default-passthrough branches as today. Consumed by `state.svelte.ts` (`fail()`) and re-exported for existing importers.

- [ ] **Step 1: Write the failing tests.** Create `apps/desktop/src/lib/errors.test.ts` — one `it()` per branch (9 total):
  ```ts
  import { describe, it, expect } from "vitest";
  import { humanizeError } from "./errors";

  describe("humanizeError", () => {
    it("maps 401 to an auth failure", () => {
      expect(humanizeError("Error: 401 Client Error")).toBe(
        "Authentication failed — check your token in Settings.",
      );
    });

    it("maps 'unauthorized' to an auth failure", () => {
      expect(humanizeError("request was unauthorized")).toBe(
        "Authentication failed — check your token in Settings.",
      );
    });

    it("maps 'bad credentials' to an auth failure", () => {
      expect(humanizeError("Bad credentials")).toBe(
        "Authentication failed — check your token in Settings.",
      );
    });

    it("maps 403 to a refused request", () => {
      expect(humanizeError("Error: 403")).toBe(
        "GitHub refused the request — token permissions or rate limit. Check the token's scope, or wait and retry.",
      );
    });

    it("maps 'forbidden' to a refused request", () => {
      expect(humanizeError("Forbidden")).toBe(
        "GitHub refused the request — token permissions or rate limit. Check the token's scope, or wait and retry.",
      );
    });

    it("maps 'rate limit' to a refused request", () => {
      expect(humanizeError("API rate limit exceeded")).toBe(
        "GitHub refused the request — token permissions or rate limit. Check the token's scope, or wait and retry.",
      );
    });

    it("maps network failures", () => {
      expect(humanizeError("failed to connect: connection timed out")).toBe(
        "Network error — couldn't reach the server. Check your connection and retry.",
      );
    });

    it("maps the OSM token requirement", () => {
      expect(humanizeError("online scan requires a token")).toBe(
        "Online cross-check needs an OpenSourceMalware token — add one in Settings.",
      );
    });

    it("passes unknown errors through, stripping the 'error:' prefix", () => {
      expect(humanizeError("Error: something odd happened")).toBe(
        "something odd happened",
      );
    });
  });
  ```

- [ ] **Step 2: Run the tests — expect failure.** From `apps/desktop`:
  ```
  pnpm exec vitest run src/lib/errors.test.ts
  ```
  Expected: the suite fails to load with `Failed to resolve import "./errors"` (the module does not exist yet).

- [ ] **Step 3: Create `apps/desktop/src/lib/errors.ts`** with the function moved verbatim from `state.svelte.ts`:
  ```ts
  /** Map raw backend / GitHub errors to plain language; pass anything else through. */
  export function humanizeError(e: unknown): string {
    const s = String(e);
    if (/\b401\b|unauthorized|bad credentials/i.test(s))
      return "Authentication failed — check your token in Settings.";
    if (/\b403\b|forbidden|rate limit/i.test(s))
      return "GitHub refused the request — token permissions or rate limit. Check the token's scope, or wait and retry.";
    if (/network|timed? ?out|connection|dns|failed to (fetch|connect|resolve)/i.test(s))
      return "Network error — couldn't reach the server. Check your connection and retry.";
    if (/requires an? (osm|opensourcemalware) token|online scan requires/i.test(s))
      return "Online cross-check needs an OpenSourceMalware token — add one in Settings.";
    return s.replace(/^error:\s*/i, "");
  }
  ```

- [ ] **Step 4: Run the tests — expect pass.** From `apps/desktop`:
  ```
  pnpm exec vitest run src/lib/errors.test.ts
  ```
  Expected: `Tests  9 passed (9)`, exit 0.

- [ ] **Step 5: Point `state.svelte.ts` at the new module.** Edit `apps/desktop/src/lib/state.svelte.ts`. Replace the import line (line 1):
  ```ts
  import type { ScanReport } from "./types";
  ```
  with:
  ```ts
  import type { ScanReport } from "./types";
  import { humanizeError } from "./errors";

  // Re-exported so existing importers keep working; impl now lives in ./errors.
  export { humanizeError };
  ```
  Then delete the now-duplicated local definition — remove this exact block (the blank line 20 through line 33):
  ```ts

  /** Map raw backend / GitHub errors to plain language; pass anything else through. */
  export function humanizeError(e: unknown): string {
    const s = String(e);
    if (/\b401\b|unauthorized|bad credentials/i.test(s))
      return "Authentication failed — check your token in Settings.";
    if (/\b403\b|forbidden|rate limit/i.test(s))
      return "GitHub refused the request — token permissions or rate limit. Check the token's scope, or wait and retry.";
    if (/network|timed? ?out|connection|dns|failed to (fetch|connect|resolve)/i.test(s))
      return "Network error — couldn't reach the server. Check your connection and retry.";
    if (/requires an? (osm|opensourcemalware) token|online scan requires/i.test(s))
      return "Online cross-check needs an OpenSourceMalware token — add one in Settings.";
    return s.replace(/^error:\s*/i, "");
  }
  ```
  Replace it with a single blank line. (The remaining `fail()` at what was line 45 still calls `humanizeError` — now the imported one.)

- [ ] **Step 6: Typecheck.** From `apps/desktop`:
  ```
  pnpm check
  ```
  Expected: `0 errors`. (`humanizeError` resolves via the new import; `App.svelte`, `Workspace.svelte`, `Doctor.svelte`, `GitHub.svelte`, `Settings.svelte` are untouched and still compile against the unchanged `app.screen`/`app.dirs` shape.)

- [ ] **Step 7: Commit.** From `apps/desktop`:
  ```
  git add src/lib/errors.ts src/lib/errors.test.ts src/lib/state.svelte.ts
  git commit -m "refactor(desktop): extract humanizeError into lib/errors.ts"
  ```
  No `Co-Authored-By: Claude` trailer.

---

### Task 1.3: `lib/locations.ts` — protected-locations persistence (TDD)

**Files:**
- Test: `apps/desktop/src/lib/locations.test.ts` (create)
- Create: `apps/desktop/src/lib/locations.ts`

**Interfaces:**
- Produces: `export function loadLocations(): string[]`, `export function saveLocations(dirs: string[]): void`, `export function hasLocations(): boolean` (localStorage key `"protected_locations"`). Consumed by `state.svelte.ts` (Task 1.5) and later routes.

- [ ] **Step 1: Write the failing tests.** Create `apps/desktop/src/lib/locations.test.ts` (7 `it()` blocks; jsdom supplies `localStorage`):
  ```ts
  import { describe, it, expect, beforeEach } from "vitest";
  import { loadLocations, saveLocations, hasLocations } from "./locations";

  const KEY = "protected_locations";

  describe("locations", () => {
    beforeEach(() => {
      localStorage.clear();
    });

    it("loadLocations returns [] when the key is missing", () => {
      expect(loadLocations()).toEqual([]);
    });

    it("loadLocations returns [] on invalid JSON", () => {
      localStorage.setItem(KEY, "{not json");
      expect(loadLocations()).toEqual([]);
    });

    it("loadLocations returns [] when the stored value is not an array", () => {
      localStorage.setItem(KEY, JSON.stringify({ a: 1 }));
      expect(loadLocations()).toEqual([]);
    });

    it("loadLocations returns the stored array when valid", () => {
      localStorage.setItem(KEY, JSON.stringify(["/a", "/b"]));
      expect(loadLocations()).toEqual(["/a", "/b"]);
    });

    it("saveLocations persists and round-trips through loadLocations", () => {
      saveLocations(["/x", "/y"]);
      expect(localStorage.getItem(KEY)).toBe(JSON.stringify(["/x", "/y"]));
      expect(loadLocations()).toEqual(["/x", "/y"]);
    });

    it("hasLocations is false when there are none", () => {
      expect(hasLocations()).toBe(false);
    });

    it("hasLocations is true when at least one is stored", () => {
      saveLocations(["/only"]);
      expect(hasLocations()).toBe(true);
    });
  });
  ```

- [ ] **Step 2: Run — expect failure.** From `apps/desktop`:
  ```
  pnpm exec vitest run src/lib/locations.test.ts
  ```
  Expected: fails to load with `Failed to resolve import "./locations"`.

- [ ] **Step 3: Create `apps/desktop/src/lib/locations.ts`:**
  ```ts
  const KEY = "protected_locations";

  /** JSON.parse localStorage["protected_locations"]; [] on missing/invalid-JSON/non-array. */
  export function loadLocations(): string[] {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw === null) return [];
      const parsed: unknown = JSON.parse(raw);
      return Array.isArray(parsed) ? (parsed as string[]) : [];
    } catch {
      return [];
    }
  }

  export function saveLocations(dirs: string[]): void {
    localStorage.setItem(KEY, JSON.stringify(dirs));
  }

  export function hasLocations(): boolean {
    return loadLocations().length > 0;
  }
  ```

- [ ] **Step 4: Run — expect pass.** From `apps/desktop`:
  ```
  pnpm exec vitest run src/lib/locations.test.ts
  ```
  Expected: `Tests  7 passed (7)`, exit 0.

- [ ] **Step 5: Typecheck.** From `apps/desktop`:
  ```
  pnpm check
  ```
  Expected: `0 errors`.

- [ ] **Step 6: Commit.** From `apps/desktop`:
  ```
  git add src/lib/locations.ts src/lib/locations.test.ts
  git commit -m "feat(desktop): add lib/locations.ts protected-location persistence"
  ```
  No `Co-Authored-By: Claude` trailer.

---

### Task 1.4: `lib/protection.ts` — status derivation (TDD, every branch)

**Files:**
- Test: `apps/desktop/src/lib/protection.test.ts` (create)
- Create: `apps/desktop/src/lib/protection.ts`

**Interfaces:**
- Consumes types: `import type { DoctorReport, ScanReport } from "./types"` (`ProcHit`, `CacheHit`, `TriggerCheck`, `Finding` shapes reused unchanged).
- Produces: `export type ProtectionLevel`, `export interface SurfaceStatus`, `export function levelRank(l: ProtectionLevel): number`, `export function machineStatus(report: DoctorReport | null): SurfaceStatus`, `export function reposStatus(report: ScanReport | null): SurfaceStatus`, `export function overallLevel(machine: SurfaceStatus, repos: SurfaceStatus): ProtectionLevel`. Consumed by Home/ShieldStatus/HealthChip in later phases.

- [ ] **Step 1: Write the failing tests.** Create `apps/desktop/src/lib/protection.test.ts` (18 `it()` blocks — every branch of every function, plus two honest-state precedence guards):
  ```ts
  import { describe, it, expect } from "vitest";
  import type { DoctorReport, ScanReport, Finding } from "./types";
  import {
    levelRank,
    machineStatus,
    reposStatus,
    overallLevel,
    type SurfaceStatus,
  } from "./protection";

  function doctor(p: Partial<DoctorReport> = {}): DoctorReport {
    return { processes: [], caches: [], triggers: [], cache_dirs: [], ...p };
  }
  function report(p: Partial<ScanReport> = {}): ScanReport {
    return { findings: [], repos_scanned: 1, ...p };
  }
  function finding(severity: Finding["severity"]): Finding {
    return {
      campaign: "c",
      severity,
      repo: "r",
      signature_id: "s",
      kind: "k",
      evidence: "e",
      remediable: true,
    };
  }
  const surf = (level: SurfaceStatus["level"]): SurfaceStatus => ({ level, label: "x" });

  describe("levelRank", () => {
    it("ranks threat > attention > protected > unknown", () => {
      expect(levelRank("threat")).toBe(3);
      expect(levelRank("attention")).toBe(2);
      expect(levelRank("protected")).toBe(1);
      expect(levelRank("unknown")).toBe(0);
    });
  });

  describe("machineStatus", () => {
    it("null => unknown / Not checked", () => {
      expect(machineStatus(null)).toEqual({ level: "unknown", label: "Not checked" });
    });
    it("a running process => threat", () => {
      expect(machineStatus(doctor({ processes: [{ pid: 1, reason: "r", snippet: "s" }] }))).toEqual(
        { level: "threat", label: "Active threat running" },
      );
    });
    it("tainted caches => attention", () => {
      expect(machineStatus(doctor({ caches: [{ path: "p", reason: "r" }] }))).toEqual(
        { level: "attention", label: "Needs attention" },
      );
    });
    it("an exposed trigger => attention", () => {
      expect(
        machineStatus(doctor({ triggers: [{ name: "n", exposed: true, detail: "d" }] })),
      ).toEqual({ level: "attention", label: "Needs attention" });
    });
    it("nothing wrong => protected", () => {
      expect(
        machineStatus(doctor({ triggers: [{ name: "n", exposed: false, detail: "d" }] })),
      ).toEqual({ level: "protected", label: "No active threats" });
    });
    it("a running process beats tainted caches => threat (precedence)", () => {
      expect(
        machineStatus(
          doctor({ processes: [{ pid: 1, reason: "r", snippet: "s" }], caches: [{ path: "p", reason: "r" }] }),
        ),
      ).toEqual({ level: "threat", label: "Active threat running" });
    });
  });

  describe("reposStatus", () => {
    it("null => unknown / Not scanned", () => {
      expect(reposStatus(null)).toEqual({ level: "unknown", label: "Not scanned" });
    });
    it("a critical finding => threat", () => {
      expect(reposStatus(report({ findings: [finding("critical")] }))).toEqual({
        level: "threat",
        label: "Critical threat found",
      });
    });
    it("non-critical findings => attention", () => {
      expect(reposStatus(report({ findings: [finding("high")] }))).toEqual({
        level: "attention",
        label: "Threats found",
      });
    });
    it("cancelled with no findings => unknown / Scan incomplete", () => {
      expect(reposStatus(report({ findings: [], cancelled: true }))).toEqual({
        level: "unknown",
        label: "Scan incomplete",
      });
    });
    it("clean completed scan => protected", () => {
      expect(reposStatus(report({ findings: [], cancelled: false }))).toEqual({
        level: "protected",
        label: "No threats",
      });
    });
    it("cancelled but with a critical finding => threat (findings beat incomplete)", () => {
      expect(reposStatus(report({ findings: [finding("critical")], cancelled: true }))).toEqual({
        level: "threat",
        label: "Critical threat found",
      });
    });
  });

  describe("overallLevel", () => {
    it("both protected => protected", () => {
      expect(overallLevel(surf("protected"), surf("protected"))).toBe("protected");
    });
    it("one unknown => unknown", () => {
      expect(overallLevel(surf("protected"), surf("unknown"))).toBe("unknown");
    });
    it("one attention => attention", () => {
      expect(overallLevel(surf("attention"), surf("protected"))).toBe("attention");
    });
    it("any threat => threat", () => {
      expect(overallLevel(surf("protected"), surf("threat"))).toBe("threat");
    });
    it("threat beats attention", () => {
      expect(overallLevel(surf("threat"), surf("attention"))).toBe("threat");
    });
  });
  ```

- [ ] **Step 2: Run — expect failure.** From `apps/desktop`:
  ```
  pnpm exec vitest run src/lib/protection.test.ts
  ```
  Expected: fails to load with `Failed to resolve import "./protection"`.

- [ ] **Step 3: Create `apps/desktop/src/lib/protection.ts`** (encode the derivation rules exactly; honest-state precedence = real findings beat "incomplete"):
  ```ts
  import type { DoctorReport, ScanReport } from "./types";

  export type ProtectionLevel = "protected" | "attention" | "threat" | "unknown";

  export interface SurfaceStatus {
    level: ProtectionLevel;
    label: string;
  }

  export function levelRank(l: ProtectionLevel): number {
    switch (l) {
      case "threat":
        return 3;
      case "attention":
        return 2;
      case "protected":
        return 1;
      default:
        return 0;
    }
  }

  export function machineStatus(report: DoctorReport | null): SurfaceStatus {
    if (report === null) return { level: "unknown", label: "Not checked" };
    if (report.processes.length > 0)
      return { level: "threat", label: "Active threat running" };
    if (report.caches.length > 0 || report.triggers.some((t) => t.exposed))
      return { level: "attention", label: "Needs attention" };
    return { level: "protected", label: "No active threats" };
  }

  export function reposStatus(report: ScanReport | null): SurfaceStatus {
    if (report === null) return { level: "unknown", label: "Not scanned" };
    if (report.findings.some((f) => f.severity === "critical"))
      return { level: "threat", label: "Critical threat found" };
    if (report.findings.length > 0)
      return { level: "attention", label: "Threats found" };
    if (report.cancelled) return { level: "unknown", label: "Scan incomplete" };
    return { level: "protected", label: "No threats" };
  }

  export function overallLevel(
    machine: SurfaceStatus,
    repos: SurfaceStatus,
  ): ProtectionLevel {
    if (machine.level === "threat" || repos.level === "threat") return "threat";
    if (machine.level === "attention" || repos.level === "attention")
      return "attention";
    if (machine.level === "unknown" || repos.level === "unknown") return "unknown";
    return "protected";
  }
  ```

- [ ] **Step 4: Run — expect pass.** From `apps/desktop`:
  ```
  pnpm exec vitest run src/lib/protection.test.ts
  ```
  Expected: `Tests  18 passed (18)`, exit 0.

- [ ] **Step 5: Typecheck.** From `apps/desktop`:
  ```
  pnpm check
  ```
  Expected: `0 errors`.

- [ ] **Step 6: Commit.** From `apps/desktop`:
  ```
  git add src/lib/protection.ts src/lib/protection.test.ts
  git commit -m "feat(desktop): add lib/protection.ts status derivation"
  ```
  No `Co-Authored-By: Claude` trailer.

---

### Task 1.5: Extend `lib/state.svelte.ts` — View/FlowStep, new fields, `go()`, hydrated dirs

**Files:**
- Modify: `apps/desktop/src/lib/state.svelte.ts:1` (imports), `state.svelte.ts:13-19` (app `$state` block + `go()` + hydrate)

**Interfaces:**
- Consumes: `humanizeError` from `./errors` (Task 1.2), `loadLocations` from `./locations` (Task 1.3), `type { ScanReport, DoctorReport } from "./types"`.
- Produces: `export type View`, `export type FlowStep`, the extended `export const app` (`view`, `flow`, `dirs`, `report`, `machineReport`, `lastScanAt`, `scanning`, `toasts` — plus transitional `screen`), and `export function go(view: View): void`. Consumed by App.svelte + all routes in Phases 2-5.

- [ ] **Step 1: Add the `DoctorReport` type and the `loadLocations` import.** Edit `apps/desktop/src/lib/state.svelte.ts`. The top of the file currently reads (after Task 1.2):
  ```ts
  import type { ScanReport } from "./types";
  import { humanizeError } from "./errors";

  // Re-exported so existing importers keep working; impl now lives in ./errors.
  export { humanizeError };
  ```
  Replace it with:
  ```ts
  import type { ScanReport, DoctorReport } from "./types";
  import { humanizeError } from "./errors";
  import { loadLocations } from "./locations";

  // Re-exported so existing importers keep working; impl now lives in ./errors.
  export { humanizeError };
  ```

- [ ] **Step 2: Extend the app state, add `View`/`FlowStep`, `go()`, and hydrate dirs.** Replace this exact block:
  ```ts
  export const app = $state({
    screen: "scan" as "scan" | "github" | "doctor" | "settings",
    dirs: [] as string[],
    report: null as ScanReport | null,
    scanning: false,
    toasts: [] as Toast[],
  });
  ```
  with:
  ```ts
  export type View = "home" | "flow" | "machine" | "repos" | "advanced" | "settings";
  export type FlowStep = "scanning" | "results" | "cleaning" | "clean";

  export const app = $state({
    view: "home" as View,
    flow: null as FlowStep | null,
    // TRANSITIONAL: drives the legacy tab UI; App.svelte drops this in Phase 2.
    screen: "scan" as "scan" | "github" | "doctor" | "settings",
    dirs: [] as string[],
    report: null as ScanReport | null,
    machineReport: null as DoctorReport | null,
    lastScanAt: null as number | null,
    scanning: false,
    toasts: [] as Toast[],
  });

  // "dirs" ARE the protected locations (name kept for api.scan compatibility).
  app.dirs = loadLocations();

  export function go(view: View) {
    app.view = view;
  }
  ```
  (`screen` is kept only so the untouched `App.svelte`/routes still compile this phase; Phase 2 removes it when App.svelte becomes the router. No identifier is declared twice.)

- [ ] **Step 3: Typecheck.** From `apps/desktop`:
  ```
  pnpm check
  ```
  Expected: `0 errors`. The legacy `App.svelte` (`app.screen`), `Workspace.svelte` (`app.dirs`, `app.report`, `app.scanning`), `Doctor.svelte`, `GitHub.svelte`, and `Settings.svelte` all still resolve against the extended shape.

- [ ] **Step 4: Build.** From `apps/desktop`:
  ```
  pnpm build
  ```
  Expected: `vite build` completes with `✓ built in …` and writes `dist/`, exit 0.

- [ ] **Step 5: Confirm the full test suite still passes.** From `apps/desktop`:
  ```
  pnpm test
  ```
  Expected: `Test Files  4 passed (4)` and `Tests  36 passed (36)` (sanity 2 + errors 9 + locations 7 + protection 18 — the extended `state.svelte.ts` has no unit test, per the Svelte/runes rule).

- [ ] **Step 6: Manual smoke — legacy UI still works.** From `apps/desktop`, run `pnpm tauri dev`. When the window opens, click through the existing top tabs (Scan / GitHub / Doctor / Settings) and confirm each pane still renders and the tab indicator moves — i.e. the old tab UI is untouched and shippable. Close the window.

- [ ] **Step 7: Commit.** From `apps/desktop`:
  ```
  git add src/lib/state.svelte.ts
  git commit -m "feat(desktop): extend app state with view/flow/machine backbone"
  ```
  No `Co-Authored-By: Claude` trailer.

---

## Phase 2: Home + status components + shell swap

### Task 2.1: `components/ShieldStatus.svelte` (status hero, full a11y)

**Files:**
- Create: `apps/desktop/src/lib/components/ShieldStatus.svelte`

**Interfaces:**
- Consumes: `type ProtectionLevel` from `apps/desktop/src/lib/protection.ts` (Phase 1): `"protected" | "attention" | "threat" | "unknown"`.
- Produces: default component `ShieldStatus` with props `{ level: ProtectionLevel; heading: string; sub?: string }`. Renders a `.shield {level}` badge (aria-hidden glyph), a `.sr` "Status: <word>" span, a sibling `<h1 class="shield-heading">`, and an optional `.shield-sub`. Relies on the global hero/shield styles added in Task 2.4 — do NOT add a `<style>` block here.

- [ ] **Step 1: Create the component with final copy + a11y.** Write `apps/desktop/src/lib/components/ShieldStatus.svelte`:

```svelte
<script lang="ts">
  import type { ProtectionLevel } from "../protection";

  let { level, heading, sub }: { level: ProtectionLevel; heading: string; sub?: string } = $props();

  // aria-hidden glyph — the status is ALSO conveyed by the .sr word and the visible heading,
  // so color+glyph are never the only signal.
  const glyph = $derived(
    level === "protected" ? "✓" : level === "attention" ? "!" : level === "threat" ? "✕" : "?",
  );
  const word = $derived(
    level === "protected"
      ? "Protected"
      : level === "attention"
        ? "Needs attention"
        : level === "threat"
          ? "Threat"
          : "Unknown",
  );
</script>

<div class="shield {level}">
  <span class="shield-glyph" aria-hidden="true">{glyph}</span>
</div>
<span class="sr">Status: {word}</span>
<h1 class="shield-heading">{heading}</h1>
{#if sub}<p class="shield-sub">{sub}</p>{/if}
```

- [ ] **Step 2: Typecheck.** From `apps/desktop`, run `pnpm check`. Expected: `svelte-check` completes with **0 errors** (ShieldStatus compiles standalone; the `.shield`/`.sr` classes are supplied by global `app.css` and are not validated by svelte-check).

- [ ] **Step 3: Commit.** From `apps/desktop`:
```
git add src/lib/components/ShieldStatus.svelte
git commit -m "feat(desktop): add ShieldStatus status-hero component"
```
Expected: one new file committed, no Co-Authored-By trailer.

---

### Task 2.2: `components/HealthChip.svelte` (surface-status button, self-styled)

**Files:**
- Create: `apps/desktop/src/lib/components/HealthChip.svelte`

**Interfaces:**
- Consumes: `type SurfaceStatus` from `apps/desktop/src/lib/protection.ts` (Phase 1): `{ level: ProtectionLevel; label: string }`.
- Produces: default component `HealthChip` with props `{ label: string; status: SurfaceStatus; onclick: () => void }`. Renders a `<button class="health-chip">` with the visible `label`, an aria-hidden `.hc-mark` colored by `status.level`, and the visible `status.label`. Fully self-styled (own `<style>` with per-level mark colors).

- [ ] **Step 1: Create the component.** Write `apps/desktop/src/lib/components/HealthChip.svelte` (level classes use `class:` directives so Svelte does not prune them as unused CSS):

```svelte
<script lang="ts">
  import type { SurfaceStatus } from "../protection";

  let { label, status, onclick }: { label: string; status: SurfaceStatus; onclick: () => void } =
    $props();

  // aria-hidden mark; status.label carries the same meaning as visible text.
  const mark = $derived(
    status.level === "protected"
      ? "✓"
      : status.level === "attention"
        ? "!"
        : status.level === "threat"
          ? "✕"
          : "?",
  );
</script>

<button class="health-chip" {onclick}>
  <span class="hc-label">{label}</span>
  <span class="hc-status">
    <span
      class="hc-mark"
      class:protected={status.level === "protected"}
      class:attention={status.level === "attention"}
      class:threat={status.level === "threat"}
      class:unknown={status.level === "unknown"}
      aria-hidden="true">{mark}</span
    >
    <span class="hc-word">{status.label}</span>
  </span>
</button>

<style>
  .health-chip {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 5px;
    background: var(--surface);
    border-radius: var(--radius);
    padding: 13px 18px;
    min-width: 148px;
    text-align: left;
  }
  .health-chip:hover {
    background: var(--surface-2);
  }
  .hc-label {
    font-size: 12px;
    color: var(--muted);
    font-weight: 500;
  }
  .hc-status {
    display: inline-flex;
    align-items: center;
    gap: 7px;
  }
  .hc-mark {
    font-weight: 700;
    font-size: 13px;
  }
  .hc-mark.protected {
    color: var(--ok);
  }
  .hc-mark.attention {
    color: var(--warn);
  }
  .hc-mark.threat {
    color: var(--danger);
  }
  .hc-mark.unknown {
    color: var(--faint);
  }
  .hc-word {
    font-size: 13px;
    color: var(--fg);
    font-weight: 600;
  }
</style>
```

- [ ] **Step 2: Typecheck.** From `apps/desktop`, run `pnpm check`. Expected: **0 errors**.

- [ ] **Step 3: Commit.** From `apps/desktop`:
```
git add src/lib/components/HealthChip.svelte
git commit -m "feat(desktop): add HealthChip surface-status button"
```
Expected: one new file committed, no Co-Authored-By trailer.

---

### Task 2.3: `routes/Home.svelte` (resting status + first-run, honest pre-scan)

**Files:**
- Create: `apps/desktop/src/routes/Home.svelte`

**Interfaces:**
- Consumes: `app`, `go`, `fail` from `../lib/state.svelte` (Phase 1); `machineStatus`, `reposStatus`, `overallLevel` from `../lib/protection` (Phase 1); `saveLocations` from `../lib/locations` (Phase 1); `pickDirs` from `../lib/api`; `homeDir` from `@tauri-apps/api/path` (already provided by the `@tauri-apps/api` dependency); components `ShieldStatus`, `HealthChip` from Tasks 2.1/2.2.
- Produces: default component `Home`. Reads `app.dirs` reactively to select the first-run variant (mirrors `hasLocations()` after Phase 1 hydrates `app.dirs = loadLocations()`). Defines `fullScan()` which sets `app.view = "flow"`.

- [ ] **Step 1: Create the route with final copy + honest states.** Write `apps/desktop/src/routes/Home.svelte`:

```svelte
<script lang="ts">
  import { app, go, fail } from "../lib/state.svelte";
  import { machineStatus, reposStatus, overallLevel } from "../lib/protection";
  import { saveLocations } from "../lib/locations";
  import { pickDirs } from "../lib/api";
  import { homeDir } from "@tauri-apps/api/path";
  import ShieldStatus from "../lib/components/ShieldStatus.svelte";
  import HealthChip from "../lib/components/HealthChip.svelte";

  // app.dirs ARE the protected locations; on init Phase 1 hydrates it from loadLocations(),
  // so an empty list is the honest "no locations saved yet" first-run signal (reactively).
  const firstRun = $derived(app.dirs.length === 0);

  const machine = $derived(machineStatus(app.machineReport));
  const repos = $derived(reposStatus(app.report));
  const overall = $derived(overallLevel(machine, repos));

  // HONEST: never claim "protected" before a real scan. Before any scan (lastScanAt === null)
  // the shield stays neutral/unknown with "Not scanned yet".
  const scanned = $derived(app.lastScanAt !== null);
  const heading = $derived.by(() => {
    if (!scanned) return "Not scanned yet";
    switch (overall) {
      case "protected":
        return "You're protected";
      case "attention":
        return "Needs your attention";
      case "threat":
        return "Threat found";
      default:
        return "Not scanned yet";
    }
  });
  const sub = $derived.by(() => {
    if (!scanned) return "Run a Full Scan to check this Mac and your code.";
    switch (overall) {
      case "protected":
        return "No threats on this Mac or in your code.";
      case "attention":
        return "Some things need a look. Open the details below to see what.";
      case "threat":
        return "A threat was found. Review it and remove it safely.";
      default:
        return "The last scan didn't finish. Run a Full Scan for a complete picture.";
    }
  });

  let picking = $state(false);

  async function chooseFolder() {
    picking = true;
    try {
      const picked = await pickDirs();
      if (picked.length) {
        app.dirs = picked;
        saveLocations(app.dirs);
      }
    } catch (e) {
      fail(e);
    } finally {
      picking = false;
    }
  }

  async function useHomeFolder() {
    picking = true;
    try {
      const home = await homeDir();
      app.dirs = [home];
      saveLocations(app.dirs);
    } catch (e) {
      fail(e);
    } finally {
      picking = false;
    }
  }

  // The single primary action. The router (App.svelte) renders the flow view.
  function fullScan() {
    app.view = "flow";
  }
</script>

{#if firstRun}
  <section class="hero">
    <h1 class="shield-heading">Protect your code from supply-chain worms</h1>
    <p class="shield-sub">
      Wormward checks this Mac and the folders where you keep your projects for malware that
      spreads through package updates. Choose your code folder to get started.
    </p>
    <div class="hero-actions">
      <button class="btn primary cta" onclick={chooseFolder} disabled={picking}>
        {#if picking}<span class="spinner"></span>Choosing…{:else}Choose your code folder{/if}
      </button>
      <button class="btn ghost" onclick={useHomeFolder} disabled={picking}>Use my home folder</button>
    </div>
  </section>
{:else}
  <section class="hero">
    <ShieldStatus level={overall} {heading} {sub} />
    <button class="btn primary cta" onclick={fullScan}>Full Scan</button>
    <div class="chips-row">
      <HealthChip label="This Mac" status={machine} onclick={() => go("machine")} />
      <HealthChip label="Repositories" status={repos} onclick={() => go("repos")} />
    </div>
  </section>
{/if}

<style>
  .hero-actions {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
  }
  .chips-row {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    justify-content: center;
  }
</style>
```

- [ ] **Step 2: Typecheck.** From `apps/desktop`, run `pnpm check`. Expected: **0 errors** (Home is created but not yet routed; App.svelte is swapped in Task 2.4). The `.hero`/`.shield*`/`.cta`/`.sr` classes come from `app.css` (added in Task 2.4) and are not validated by svelte-check.

- [ ] **Step 3: Commit.** From `apps/desktop`:
```
git add src/routes/Home.svelte
git commit -m "feat(desktop): add Home route (resting status + first-run)"
```
Expected: one new file committed, no Co-Authored-By trailer.

---

### Task 2.4: Swap `App.svelte` to the canonical views-map router + additive `app.css` hero styles

**Files:**
- Modify (replace entire file): `apps/desktop/src/App.svelte`
- Modify (additive): `apps/desktop/src/app.css` (insert before the `/* ---------- reduced motion ---------- */` block)

**Interfaces:**
- Consumes: `app`, `dismiss`, `notify`, `go`, `type View` from `./lib/state.svelte` (Phase 1); `isTauri` from `./lib/env`; `Home` (Task 2.3); existing routes `Workspace`, `GitHub`, `Doctor`, `Settings`; `type Component` from `svelte`.
- Produces: the shell — `const views: Record<View, Component>` map, `{#key app.view}{@const Current = views[app.view]}<Current />{/key}` render, a bound `mainEl` with focus-on-view-change, and a plain-button ⚙ menu (Advanced/Settings). TEMP map so nothing is unreachable: `{ home: Home, flow: Workspace, machine: Doctor, repos: Workspace, advanced: GitHub, settings: Settings }`. Later phases swap individual entries only.

- [ ] **Step 1: Replace the entire contents of `apps/desktop/src/App.svelte` with the router shell.** (This removes the tab bar, the sliding `.indicator` pill, and the `visited` keep-mounted logic; it keeps the skip link, `!isTauri` env-banner, toast stack, and global error/rejection handler.)

```svelte
<script lang="ts">
  import { app, dismiss, notify, go } from "./lib/state.svelte";
  import type { View } from "./lib/state.svelte";
  import Home from "./routes/Home.svelte";
  import Workspace from "./routes/Workspace.svelte";
  import GitHub from "./routes/GitHub.svelte";
  import Doctor from "./routes/Doctor.svelte";
  import Settings from "./routes/Settings.svelte";
  import { fly } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import logo from "./assets/logo.png";
  import { isTauri } from "./lib/env";
  import type { Component } from "svelte";

  // Canonical view router. Later phases swap INDIVIDUAL entries for the real component
  // (flow→ScanFlow, machine→MachineDetail, repos→RepositoriesDetail, advanced→Advanced);
  // never re-typedef this map or convert it to an {#if} chain. The temporary entries keep
  // every current capability reachable so nothing is lost this phase.
  const views: Record<View, Component> = {
    home: Home,
    flow: Workspace,
    machine: Doctor,
    repos: Workspace,
    advanced: GitHub,
    settings: Settings,
  };

  // Respect the user's motion preference for the JS-driven toast transitions (CSS media
  // queries can't reach Svelte transitions). Reactive, so toggling the OS setting mid-session
  // applies immediately and stays in sync with the CSS @media block.
  let reduce = $state(
    typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
  $effect(() => {
    if (typeof matchMedia === "undefined") return;
    const mq = matchMedia("(prefers-reduced-motion: reduce)");
    const on = () => (reduce = mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  });

  // Move keyboard/screen-reader focus to the freshly-rendered view on every view change so
  // focus lands on the new content instead of document.body. Skip the very first run — on
  // initial load focus belongs to the page as delivered.
  let mainEl = $state<HTMLElement | undefined>();
  let firstView = true;
  $effect(() => {
    app.view;
    if (firstView) {
      firstView = false;
      return;
    }
    queueMicrotask(() => mainEl?.focus());
  });

  // ⚙ menu: PLAIN buttons in a labelled container. We deliberately do NOT use
  // role=menu/menuitem (that advertises arrow-key semantics we don't implement). Escape and
  // any outside click close it.
  let menuOpen = $state(false);
  let menuWrap = $state<HTMLElement | undefined>();
  $effect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (menuWrap && !menuWrap.contains(e.target as Node)) menuOpen = false;
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") menuOpen = false;
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  });
  function pick(view: View) {
    menuOpen = false;
    go(view);
  }

  // Surface any uncaught JS error / rejection instead of failing silently. De-duped and
  // guarded to script errors so a repeated error can't spin up a toast loop.
  $effect(() => {
    const seen = new Set<string>();
    const report = (msg: string) => {
      if (seen.has(msg)) return;
      seen.add(msg);
      notify("error", msg);
    };
    const onErr = (e: ErrorEvent) => {
      if (e.error) report(`Unexpected error: ${e.message}`);
    };
    const onRej = (e: PromiseRejectionEvent) => report(`Unexpected error: ${String(e.reason)}`);
    window.addEventListener("error", onErr);
    window.addEventListener("unhandledrejection", onRej);
    return () => {
      window.removeEventListener("error", onErr);
      window.removeEventListener("unhandledrejection", onRej);
    };
  });
</script>

<a class="skip" href="#main">Skip to content</a>

<header class="topbar">
  <div class="brand">
    <img class="logo" src={logo} alt="Wormward" width="46" height="46" />
  </div>
  <div class="spacer"></div>
  <div class="menu-wrap" bind:this={menuWrap}>
    <button
      class="gear"
      aria-label="More options"
      aria-expanded={menuOpen}
      aria-controls="app-menu"
      onclick={() => (menuOpen = !menuOpen)}>⚙</button
    >
    {#if menuOpen}
      <div id="app-menu" class="menu" role="group" aria-label="More options">
        <button onclick={() => pick("advanced")}>Advanced</button>
        <button onclick={() => pick("settings")}>Settings</button>
      </div>
    {/if}
  </div>
</header>

{#if !isTauri}
  <div class="env-banner" role="status">
    <strong>Browser preview</strong> — scanning, cleaning, and GitHub actions run in the Wormward
    desktop app. Open it on your desktop to use them.
  </div>
{/if}

{#if app.toasts.length}
  <div class="toast-wrap">
    {#each app.toasts as t (t.id)}
      <div
        class="toast {t.kind}"
        role={t.kind === "error" ? "alert" : "status"}
        in:fly={{ y: -8, duration: reduce ? 0 : 150, easing: cubicOut }}
        out:fly={{ y: -10, duration: reduce ? 0 : 150, easing: cubicOut }}
      >
        <span class="dot"></span>
        <div class="body">
          <span class="msg">{t.message}</span>
          {#if t.detail}<span class="detail">{t.detail}</span>{/if}
        </div>
        <button class="x" aria-label="Dismiss" onclick={() => dismiss(t.id)}>×</button>
      </div>
    {/each}
  </div>
{/if}

<main id="main" tabindex="-1" bind:this={mainEl}>
  {#key app.view}
    {@const Current = views[app.view]}
    <Current />
  {/key}
</main>

<style>
  .topbar {
    position: sticky;
    top: 0;
    z-index: 20;
    height: var(--topbar-h);
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 0 24px;
    background: rgba(10, 10, 12, 0.7);
    backdrop-filter: blur(12px);
  }
  .brand { display: flex; align-items: center; }
  .logo { width: 46px; height: 46px; border-radius: 10px; display: block; }
  .skip {
    position: absolute;
    left: 12px;
    top: -48px;
    z-index: 100;
    background: var(--accent);
    color: #0a0a12;
    padding: 8px 14px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 600;
    transition: top var(--fast) var(--ease);
  }
  .skip:focus { top: 10px; }
  main:focus { outline: none; }
  main { min-height: calc(100vh - var(--topbar-h)); }

  .menu-wrap { position: relative; }
  .gear {
    background: transparent;
    color: var(--muted);
    font-size: 18px;
    line-height: 1;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
  }
  .gear:hover { color: var(--fg); background: var(--surface-2); }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 30;
    min-width: 168px;
    background: var(--surface-2);
    border-radius: var(--radius-sm);
    padding: 5px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .menu button {
    background: transparent;
    color: var(--fg);
    justify-content: flex-start;
    width: 100%;
    padding: 8px 12px;
    font-weight: 500;
  }
  .menu button:hover { background: var(--surface-3); }

  .env-banner {
    padding: 9px 24px;
    background: var(--surface-warn);
    color: var(--warn);
    font-size: 12.5px;
    line-height: 1.5;
  }
</style>
```

- [ ] **Step 2: Add the additive hero/shield styles to `app.css`.** In `apps/desktop/src/app.css`, insert the new block immediately BEFORE the reduced-motion block so the existing universal `prefers-reduced-motion` override still wins for the new transitions. Replace this exact existing line:

```css
/* ---------- reduced motion ---------- */
```

with:

```css
/* ---------- hero / shield (Home status) ---------- */
:root { --gap-hero: 24px; }
.sr {
  position: absolute; width: 1px; height: 1px;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap;
}
.hero {
  max-width: var(--content);
  margin: 0 auto;
  padding: 52px 24px 44px;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: var(--gap-hero);
}
.shield {
  width: 128px; height: 128px; border-radius: 50%;
  display: grid; place-items: center;
  background: var(--surface-2); color: var(--muted);
  transition: background var(--med) var(--ease), color var(--med) var(--ease);
}
.shield-glyph { font-size: 54px; line-height: 1; font-weight: 700; }
.shield.protected { background: var(--ok-tint); color: var(--ok); }
.shield.attention { background: var(--warn-tint); color: var(--warn); }
.shield.threat { background: var(--danger-tint); color: var(--danger); }
.shield.unknown { background: var(--surface-2); color: var(--muted); }
.shield-heading { font-size: 25px; letter-spacing: -0.03em; font-weight: 600; }
.shield-sub { color: var(--muted); font-size: 13.5px; line-height: 1.6; max-width: 44ch; }
.btn.cta, button.cta { font-size: 14.5px; padding: 13px 32px; border-radius: var(--radius); }

/* ---------- reduced motion ---------- */
```

- [ ] **Step 3: Typecheck.** From `apps/desktop`, run `pnpm check`. Expected: **0 errors**. (App.svelte now references `app.view` / `type View` / `go` from the Phase-1 state; the tab-era `app.screen`, `screens`, `visited`, `navEl`, and `ind` references are gone.)

- [ ] **Step 4: Build.** From `apps/desktop`, run `pnpm build`. Expected: Vite reports `✓ built in …` with no errors and emits `dist/`.

- [ ] **Step 5: Manual smoke.** From `apps/desktop`, run `pnpm tauri dev`. Observe:
  1. With no saved protected locations, Home shows the first-run variant: heading "Protect your code from supply-chain worms", a primary "Choose your code folder" button, and a secondary "Use my home folder" button. Click "Use my home folder" (or "Choose your code folder" and pick a directory) — the view flips to the resting hero.
  2. Resting hero shows a neutral shield with heading "Not scanned yet", the sub "Run a Full Scan to check this Mac and your code.", a primary "Full Scan" button, and two chips "This Mac" / "Repositories" each reading "Not checked" / "Not scanned".
  3. Click the ⚙ button: a menu with plain "Advanced" and "Settings" buttons appears. Press Escape → it closes; open again and click outside → it closes; click "Settings" → the old Settings screen renders (temp map).
  4. Click "Full Scan" → the old Workspace renders (temp `flow` entry). Click a chip on Home → the corresponding temp detail (Doctor / Workspace) renders.
  5. Tab into the page after switching views and confirm keyboard focus lands inside the newly rendered `<main>` (focus-on-view-change), not at the top of `document.body`.

- [ ] **Step 6: Commit.** From `apps/desktop`:
```
git add src/App.svelte src/app.css
git commit -m "feat(desktop): swap App shell to views-map router with gear menu"
```
Expected: two files changed, no Co-Authored-By trailer. Phase 2 is shippable — Home is the hub, every prior capability stays reachable through the temporary map, and Full Scan routes to `flow`.

---

## Phase 3: Guided scan flow

### Task 3.1: `GuidedProgress.svelte` — status label + progressbar

**Files:**
- Create: `apps/desktop/src/lib/components/GuidedProgress.svelte`

**Interfaces:**
- Produces (per CONTRACT): `GuidedProgress` with props `{ label: string; done?: number; total?: number; indeterminate?: boolean }`. Consumed by `ScanFlow.svelte` (Tasks 3.3, 3.4).
- Reuses global `.progress` / `.progress.indet` from `app.css` (no new tokens).

- [ ] **Step 1: Write the component.** Create `apps/desktop/src/lib/components/GuidedProgress.svelte` with exactly:

```svelte
<script lang="ts">
  let {
    label,
    done = 0,
    total = 0,
    indeterminate = false,
  }: { label: string; done?: number; total?: number; indeterminate?: boolean } = $props();

  const pct = $derived(total ? Math.min(100, (done / total) * 100) : 0);
</script>

<div class="guided">
  <p class="guided-label" role="status" aria-live="polite">{label}</p>
  {#if indeterminate}
    <div class="progress indet" role="progressbar" aria-label={label}>
      <span></span>
    </div>
  {:else}
    <div class="progress" role="progressbar" aria-label={label} aria-valuemin="0" aria-valuemax={total} aria-valuenow={done}>
      <span style="width: {pct}%"></span>
    </div>
  {/if}
</div>

<style>
  .guided { display: flex; flex-direction: column; gap: 12px; }
  .guided-label { font-size: 14px; color: var(--fg); text-align: center; }
  .guided .progress { height: 6px; }
</style>
```

- [ ] **Step 2: Typecheck.** Run (from `apps/desktop`):
```
pnpm check
```
Expected: `svelte-check` finishes with `0 errors` (no new warnings).

- [ ] **Step 3: Commit.** Run (from `apps/desktop`):
```
git add src/lib/components/GuidedProgress.svelte
git commit -m "feat(desktop): GuidedProgress status label + progressbar component"
```
Expected: one commit created, no `Co-Authored-By` trailer.

---

### Task 3.2: `FindingCard.svelte` — plain title + native Details disclosure

**Files:**
- Create: `apps/desktop/src/lib/components/FindingCard.svelte`

**Interfaces:**
- Consumes: `Finding` type from `src/lib/types.ts` (`import type`).
- Produces (per CONTRACT): `FindingCard` with props `{ finding: Finding }`. Consumed by `ScanFlow.svelte` results step (Task 3.4).
- Plain labels (per CONTRACT): `finding.remediable => "Removable automatically"`, else `"Needs your attention"`.

- [ ] **Step 1: Write the component.** Create `apps/desktop/src/lib/components/FindingCard.svelte` with exactly:

```svelte
<script lang="ts">
  import type { Finding } from "../types";

  let { finding }: { finding: Finding } = $props();

  const SEV_WORD: Record<string, string> = {
    critical: "Critical threat",
    high: "Serious threat",
    medium: "Threat",
    low: "Minor issue",
    info: "Note",
  };
  const title = $derived(SEV_WORD[finding.severity] ?? "Threat");
  const where = $derived(finding.file ?? finding.repo);
  const label = $derived(finding.remediable ? "Removable automatically" : "Needs your attention");
</script>

<div class="finding-card">
  <div class="fc-top">
    <span class="fc-title sev-{finding.severity}">{title}</span>
    <span class="fc-where mono">{where}</span>
    <span class="fc-label {finding.remediable ? 'ok' : 'warn'}">{label}</span>
  </div>
  <details class="fc-details">
    <summary>Details</summary>
    <dl class="fc-dl">
      <dt>What we found</dt>
      <dd class="mono">{finding.evidence}</dd>
      <dt>Repository</dt>
      <dd class="mono">{finding.repo}</dd>
      {#if finding.file}
        <dt>File</dt>
        <dd class="mono">{finding.file}</dd>
      {/if}
      <dt>Campaign</dt>
      <dd>{finding.campaign}</dd>
      {#if finding.git_ref}
        <dt>Branch</dt>
        <dd class="mono">{finding.git_ref}</dd>
      {/if}
      {#if finding.online}
        <dt>Online check</dt>
        <dd class={finding.online.malicious ? "crit" : "muted"}>
          OpenSourceMalware: {finding.online.malicious ? "flagged as malicious" : "not flagged"}{#if finding.online.message} — {finding.online.message}{/if}{#if finding.online.osm_url} · <a href={finding.online.osm_url} target="_blank" rel="noreferrer noopener">View advisory ↗</a>{/if}
        </dd>
      {/if}
    </dl>
  </details>
</div>

<style>
  .finding-card { background: var(--surface-2); border-radius: var(--radius-sm); padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; }
  .fc-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .fc-title { font-size: 13px; font-weight: 600; color: var(--fg); }
  .fc-title.sev-critical, .fc-title.sev-high { color: var(--danger); }
  .fc-title.sev-medium { color: var(--warn); }
  .fc-where { font-size: 12px; color: var(--muted); overflow-wrap: anywhere; min-width: 0; }
  .fc-label { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px; margin-left: auto; white-space: nowrap; }
  .fc-label.ok { background: var(--ok-tint); color: var(--ok); }
  .fc-label.warn { background: var(--warn-tint); color: var(--warn); }
  .fc-details > summary { cursor: pointer; color: var(--muted); font-size: 12px; width: fit-content; }
  .fc-details > summary:hover { color: var(--fg); }
  .fc-dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; margin: 10px 0 0; }
  .fc-dl dt { color: var(--faint); font-size: 11px; }
  .fc-dl dd { margin: 0; color: var(--fg); font-size: 12px; overflow-wrap: anywhere; min-width: 0; }
  .fc-dl dd.mono { font-family: var(--mono); font-size: 11.5px; color: var(--faint); }
  .fc-dl dd.crit { color: var(--danger); }
  .fc-dl dd.muted { color: var(--muted); }
</style>
```

- [ ] **Step 2: Typecheck.** Run (from `apps/desktop`):
```
pnpm check
```
Expected: `svelte-check` finishes with `0 errors`.

- [ ] **Step 3: Commit.** Run (from `apps/desktop`):
```
git add src/lib/components/FindingCard.svelte
git commit -m "feat(desktop): FindingCard with plain title and native Details disclosure"
```
Expected: one commit created, no `Co-Authored-By` trailer.

---

### Task 3.3: `ScanFlow.svelte` — scanning step (combined doctor + scan)

**Files:**
- Create: `apps/desktop/src/routes/ScanFlow.svelte`

**Interfaces:**
- Consumes: `app`, `fail`, `clearErrors`, `go` from `../lib/state.svelte` (Phase 1); `scan`, `doctor`, `cancelScan`, `cleanPreview` from `../lib/api`; `listen` from `@tauri-apps/api/event`; `GuidedProgress` (Task 3.1); types `ScanProgress`, `RepoPlan`.
- Runtime contract: `doctor()` AND `scan(app.dirs, false, !!osmToken, osmToken)` run together; combined progress via `"local-scan-progress"`; stores `app.machineReport`, `app.report`, `app.lastScanAt = Date.now()`.
- Produces: script surface (`runScan`, `stop`, `backHome`, `plans`, `removedSummary`, `report`/`findings`/`total`/`cancelled`/`removable`/`manual`) that Task 3.4 extends. LOCAL `const plural`.

- [ ] **Step 1: Create the file with full script + scanning/cleaning/clean steps and an interim results step.** Create `apps/desktop/src/routes/ScanFlow.svelte` with exactly:

```svelte
<script lang="ts">
  import { onMount } from "svelte";
  import { app, fail, clearErrors, go } from "../lib/state.svelte";
  import { scan, doctor, cancelScan, cleanPreview } from "../lib/api";
  import { listen } from "@tauri-apps/api/event";
  import GuidedProgress from "../lib/components/GuidedProgress.svelte";
  import type { ScanProgress, RepoPlan } from "../lib/types";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  // --- scanning ---
  let stopping = $state(false);
  let repoLog = $state<ScanProgress[]>([]);
  let progress = $state<ScanProgress | null>(null);
  let logEl = $state<HTMLDivElement | null>(null);

  // --- results / clean ---
  let plans = $state<RepoPlan[]>([]);
  let removedSummary = $state("");

  const report = $derived(app.report);
  const findings = $derived(report?.findings ?? []);
  const total = $derived(findings.length);
  const cancelled = $derived(report?.cancelled ?? false);
  const removable = $derived(findings.filter((f) => f.remediable).length);
  const manual = $derived(total - removable);

  async function runScan() {
    clearErrors();
    app.flow = "scanning";
    app.scanning = true;
    stopping = false;
    repoLog = [];
    progress = null;
    plans = [];
    removedSummary = "";
    const unlisten = await listen<ScanProgress>("local-scan-progress", (e) => {
      const p = e.payload;
      if (!progress || p.done > progress.done) progress = p;
      const idx = repoLog.findIndex((r) => r.repo === p.repo);
      if (idx >= 0) repoLog[idx] = p;
      else repoLog = [...repoLog, p];
    });
    try {
      const osmToken = localStorage.getItem("osm_token") || undefined;
      const [machine, repos] = await Promise.all([
        doctor(),
        scan(app.dirs, false, !!osmToken, osmToken),
      ]);
      app.machineReport = machine;
      app.report = repos;
      app.lastScanAt = Date.now();
      plans = await cleanPreview(app.dirs);
      app.flow = "results";
    } catch (e) {
      fail(e);
      if (app.report) app.flow = "results";
      else backHome();
    } finally {
      unlisten();
      app.scanning = false;
      stopping = false;
      progress = null;
    }
  }

  async function stop() {
    stopping = true;
    try {
      await cancelScan();
    } catch (e) {
      fail(e);
    }
  }

  function backHome() {
    app.flow = null;
    go("home");
  }

  onMount(runScan);

  // Keep the live log pinned to its latest line.
  $effect(() => {
    void progress;
    void repoLog.length;
    if (logEl) logEl.scrollTop = logEl.scrollHeight;
  });
</script>

<div class="flow">
  {#if app.flow === "scanning" || app.flow === null}
    <section class="flow-step">
      <h1 class="flow-title">Scanning…</h1>
      <GuidedProgress
        label="Checking your Mac and your code…"
        done={progress?.done ?? 0}
        total={progress?.total ?? 0}
        indeterminate={!progress}
      />
      <div class="flow-actions">
        <button class="btn ghost" onclick={stop} disabled={stopping}>{stopping ? "Stopping…" : "Stop"}</button>
      </div>
      <details class="log-details">
        <summary>Show details</summary>
        <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
        <div class="term-body" bind:this={logEl} tabindex="0" role="log" aria-label="Scan progress log">
          {#each repoLog as r (r.repo)}
            {#if r.phase === "scanning"}
              <div class="line scanning"><span class="spinner"></span><span class="tag">scanning</span><span class="repo" title={r.repo}>{r.repo}</span></div>
            {:else}
              <div class="line" class:hit={r.findings}>
                <span class="mark {r.findings ? 'hit' : 'ok'}" aria-hidden="true">{r.findings ? "✗" : "✓"}</span>
                <span class="sr">{r.findings ? "threats found:" : "clean:"}</span>
                <span class="repo" title={r.repo}>{r.repo}</span>
                {#if r.findings}<span class="crit">{r.findings} {plural(r.findings, "finding", "findings")}</span>{/if}
              </div>
            {/if}
          {/each}
          {#if !repoLog.length}<div class="line dim"><span class="tag">discovering repositories…</span></div>{/if}
        </div>
      </details>
    </section>
  {/if}

  {#if app.flow === "results"}
    <section class="flow-step">
      <h1 class="flow-title">Scan complete</h1>
      {#if total === 0}
        <p class="flow-summary">{cancelled ? "Scan stopped early — nothing checked was infected, but the check is incomplete." : "No threats found."}</p>
      {:else}
        <p class="flow-summary">{total} {plural(total, "threat", "threats")} found. {removable} can be removed safely and automatically; {manual} need your review.</p>
      {/if}
      <div class="flow-actions">
        <button class="btn ghost" onclick={backHome}>Back to Home</button>
      </div>
    </section>
  {/if}

  {#if app.flow === "cleaning"}
    <section class="flow-step">
      <h1 class="flow-title">Removing threats…</h1>
      <GuidedProgress label="Removing threats safely…" indeterminate={true} />
    </section>
  {/if}

  {#if app.flow === "clean"}
    <section class="flow-step">
      <div class="card ok">
        <div class="state ok">
          <div class="glyph" aria-hidden="true">✓</div>
          {#if manual > 0}
            <h2>Threats removed — a few need your review</h2>
            <p class="muted micro">{removedSummary} {manual} {plural(manual, "threat", "threats")} still {plural(manual, "needs", "need")} your attention.</p>
          {:else}
            <h2>Everything's clean — you're protected</h2>
            <p class="muted micro">{removedSummary}</p>
          {/if}
        </div>
      </div>
      <div class="flow-actions">
        {#if manual > 0}
          <button class="btn" onclick={() => { app.flow = null; go("repos"); }}>Review remaining</button>
        {/if}
        <button class="btn ghost" onclick={backHome}>Back to Home</button>
      </div>
    </section>
  {/if}
</div>

<style>
  .flow { max-width: var(--content); margin: 0 auto; padding: 40px 24px; display: flex; flex-direction: column; gap: var(--gap-page); }
  .flow-step { display: flex; flex-direction: column; gap: 16px; }
  .flow-title { font-size: 20px; letter-spacing: -0.025em; }
  .flow-summary { font-size: 14px; line-height: 1.6; color: var(--fg); }
  .flow-actions { display: flex; gap: 10px; flex-wrap: wrap; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }

  .log-details > summary { cursor: pointer; color: var(--muted); font-size: 12.5px; width: fit-content; }
  .log-details > summary:hover { color: var(--fg); }
  .log-details[open] > summary { margin-bottom: 10px; }
  .term-body { background: var(--inset); border-radius: var(--radius); padding: 12px 14px; max-height: 220px; overflow-y: auto; font-family: var(--mono); font-size: 12px; line-height: 1.6; color: var(--fg); }
  .line { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .line .spinner { width: 11px; height: 11px; flex: none; border-color: var(--ok-tint); border-top-color: var(--ok); }
  .tag { flex: none; color: var(--faint); }
  .repo { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--fg); }
  .scanning .repo { color: var(--muted); }
  .mark { flex: none; font-weight: 700; }
  .mark.ok { color: var(--ok); }
  .mark.hit { color: var(--danger); }
  .crit { flex: none; color: var(--danger); }
  .dim .tag { color: var(--faint); }
  .line.hit { background: var(--surface-danger); margin: 0 -6px; padding: 2px 6px; border-radius: 5px; }
</style>
```

- [ ] **Step 2: Typecheck.** Run (from `apps/desktop`):
```
pnpm check
```
Expected: `svelte-check` finishes with `0 errors`. (`ScanFlow` is not yet routed — App.svelte still maps `flow: Workspace` — so no runtime wiring is exercised yet; this task proves it compiles.)

- [ ] **Step 3: Build.** Run (from `apps/desktop`):
```
pnpm build
```
Expected: `vite build` completes with `✓ built in …`, exit code 0.

- [ ] **Step 4: Commit.** Run (from `apps/desktop`):
```
git add src/routes/ScanFlow.svelte
git commit -m "feat(desktop): ScanFlow scanning step — combined doctor+scan with live log"
```
Expected: one commit created, no `Co-Authored-By` trailer.

---

### Task 3.4: `ScanFlow.svelte` — results step (grouped findings + safe removal)

**Files:**
- Modify: `apps/desktop/src/routes/ScanFlow.svelte` (created in Task 3.3)

**Interfaces:**
- Consumes: `FindingCard` (Task 3.2); `cleanApply` from `../lib/api`; `Finding` type; existing `plans`/`removable`/`manual`/`cancelled`/`total`/`removedSummary` from Task 3.3.
- Produces: `grouped` (worst-first `[campaign, Finding[]][]`), `applicable`, `fixableRepos`, `removeThreats()`; the final results markup with role="alert" cancelled banner, human summary, grouped `FindingCard` list (count badges `aria-label`led), and the "Remove threats safely" → `cleaning` → `clean` transition.

- [ ] **Step 1: Add `cleanApply` to the api import.** Edit `apps/desktop/src/routes/ScanFlow.svelte`, replacing the exact line:
```
  import { scan, doctor, cancelScan, cleanPreview } from "../lib/api";
```
with:
```
  import { scan, doctor, cancelScan, cleanPreview, cleanApply } from "../lib/api";
```

- [ ] **Step 2: Add the `FindingCard` import.** Edit `apps/desktop/src/routes/ScanFlow.svelte`, replacing the exact line:
```
  import GuidedProgress from "../lib/components/GuidedProgress.svelte";
```
with:
```
  import GuidedProgress from "../lib/components/GuidedProgress.svelte";
  import FindingCard from "../lib/components/FindingCard.svelte";
```

- [ ] **Step 3: Add `Finding` to the type import.** Edit `apps/desktop/src/routes/ScanFlow.svelte`, replacing the exact line:
```
  import type { ScanProgress, RepoPlan } from "../lib/types";
```
with:
```
  import type { ScanProgress, Finding, RepoPlan } from "../lib/types";
```

- [ ] **Step 4: Add grouping + fixable derivations.** Edit `apps/desktop/src/routes/ScanFlow.svelte`, replacing the exact line:
```
  const manual = $derived(total - removable);
```
with:
```
  const manual = $derived(total - removable);

  const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const rank = (s: string) => SEV_RANK[s] ?? 0;
  const grouped = $derived.by(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      if (!map.has(f.campaign)) map.set(f.campaign, []);
      map.get(f.campaign)!.push(f);
    }
    for (const list of map.values()) list.sort((a, b) => rank(b.severity) - rank(a.severity));
    return [...map.entries()].sort(
      (a, b) => rank(b[1][0].severity) - rank(a[1][0].severity) || b[1].length - a[1].length,
    );
  });
  const applicable = $derived(plans.filter((p) => p.actions.length));
  const fixableRepos = $derived(applicable.map((p) => p.repo));
```

- [ ] **Step 5: Add `removeThreats()`.** Edit `apps/desktop/src/routes/ScanFlow.svelte`, replacing the exact block:
```
  function backHome() {
    app.flow = null;
    go("home");
  }
```
with:
```
  function backHome() {
    app.flow = null;
    go("home");
  }

  async function removeThreats() {
    app.flow = "cleaning";
    clearErrors();
    try {
      const s = await cleanApply(fixableRepos);
      // Re-scan so app.report reflects the cleaned tree — Home's shield and the
      // Repositories detail must NOT keep showing threats we just removed (honest state,
      // mirrors Workspace.apply()'s re-run). scan() is already imported (Task 3.3).
      const osmToken = localStorage.getItem("osm_token") || undefined;
      app.report = await scan(app.dirs, false, !!osmToken, osmToken);
      app.lastScanAt = Date.now();
      removedSummary =
        `Removed ${s.applied} ${plural(s.applied, "threat", "threats")} across ${s.repos} ${plural(s.repos, "place", "places")}.` +
        (s.backups.length ? " A backup was saved." : "");
      app.flow = "clean";
    } catch (e) {
      fail(e);
      app.flow = "results";
    }
  }
```

- [ ] **Step 6: Replace the interim results step with the final one.** Edit `apps/desktop/src/routes/ScanFlow.svelte`, replacing the exact block:
```
  {#if app.flow === "results"}
    <section class="flow-step">
      <h1 class="flow-title">Scan complete</h1>
      {#if total === 0}
        <p class="flow-summary">{cancelled ? "Scan stopped early — nothing checked was infected, but the check is incomplete." : "No threats found."}</p>
      {:else}
        <p class="flow-summary">{total} {plural(total, "threat", "threats")} found. {removable} can be removed safely and automatically; {manual} need your review.</p>
      {/if}
      <div class="flow-actions">
        <button class="btn ghost" onclick={backHome}>Back to Home</button>
      </div>
    </section>
  {/if}
```
with:
```
  {#if app.flow === "results"}
    <section class="flow-step">
      <h1 class="flow-title">Scan complete</h1>

      {#if cancelled}
        <div class="card danger" role="alert">
          <p class="danger-text"><strong>Scan stopped early — results are incomplete.</strong></p>
          <p class="muted small">Anything after the stop point wasn't checked. Run a Full Scan again for a complete picture.</p>
        </div>
      {/if}

      {#if total === 0}
        <div class="card {cancelled ? '' : 'ok'}">
          <div class="state {cancelled ? '' : 'ok'}">
            <div class="glyph" aria-hidden="true">{cancelled ? "◔" : "✓"}</div>
            <h2>{cancelled ? "Nothing infected so far" : "No threats found"}</h2>
            <p class="muted micro">{cancelled ? "The parts checked were clean, but the scan didn't finish." : `Checked ${report?.repos_scanned ?? 0} ${plural(report?.repos_scanned ?? 0, "place", "places")} — everything looks clean.`}</p>
          </div>
        </div>
      {:else}
        <p class="flow-summary"><strong>{total} {plural(total, "threat", "threats")} found.</strong> {removable} can be removed safely and automatically; {manual} need your review.</p>

        {#if applicable.length}
          <div class="flow-actions">
            <button class="btn primary" onclick={removeThreats}>Remove threats safely</button>
          </div>
        {/if}

        {#each grouped as [campaign, list] (campaign)}
          <div class="camp">
            <div class="camp-head">
              <h2>{campaign}</h2>
              <span class="count sev-{list[0].severity}" aria-label="{list.length} {plural(list.length, 'threat', 'threats')} in this group">{list.length}</span>
            </div>
            <ul class="finding-list">
              {#each list as f, i (f.repo + (f.file ?? "") + f.signature_id + i)}
                <li><FindingCard finding={f} /></li>
              {/each}
            </ul>
          </div>
        {/each}
      {/if}

      <div class="flow-actions">
        <button class="btn ghost" onclick={backHome}>Back to Home</button>
      </div>
    </section>
  {/if}
```

- [ ] **Step 7: Add styles for the grouped list + count badges.** Edit `apps/desktop/src/routes/ScanFlow.svelte`, replacing the exact block:
```
  .line.hit { background: var(--surface-danger); margin: 0 -6px; padding: 2px 6px; border-radius: 5px; }
</style>
```
with:
```
  .line.hit { background: var(--surface-danger); margin: 0 -6px; padding: 2px 6px; border-radius: 5px; }

  .camp { display: flex; flex-direction: column; gap: 8px; }
  .camp-head { display: flex; align-items: center; justify-content: space-between; }
  .camp-head h2 { font-size: 13.5px; }
  .finding-list { display: flex; flex-direction: column; gap: 8px; list-style: none; margin: 0; padding: 0; }
  .count.sev-critical { background: var(--danger); color: #150a0b; }
  .count.sev-high { background: var(--danger-tint); color: var(--danger); }
  .count.sev-medium { background: var(--warn-tint); color: var(--warn); }
</style>
```

- [ ] **Step 8: Typecheck.** Run (from `apps/desktop`):
```
pnpm check
```
Expected: `svelte-check` finishes with `0 errors` (no unused-import or unused-CSS warnings — `cleanApply`, `FindingCard`, `Finding`, `grouped`, `applicable`, `fixableRepos`, `removeThreats`, and the `.camp`/`.count.sev-*`/`.finding-list` selectors are all now referenced).

- [ ] **Step 9: Build.** Run (from `apps/desktop`):
```
pnpm build
```
Expected: `vite build` completes with `✓ built in …`, exit code 0.

- [ ] **Step 10: Commit.** Run (from `apps/desktop`):
```
git add src/routes/ScanFlow.svelte
git commit -m "feat(desktop): ScanFlow results + clean steps with grouped FindingCards"
```
Expected: one commit created, no `Co-Authored-By` trailer.

---

### Task 3.5: Route the flow to `ScanFlow` in `App.svelte`

**Files:**
- Modify: `apps/desktop/src/App.svelte` (canonical views-map router created in Phase 2)

**Interfaces:**
- Consumes: `ScanFlow` (Tasks 3.3–3.4).
- Changes ONLY the `flow` entry of the `views` map from the temporary `Workspace` to `ScanFlow`. `Home.svelte`'s `fullScan()` (sets `app.view = "flow"`) is left as-is. `Workspace` import stays (still the temp `repos` entry this phase).

- [ ] **Step 1: Import `ScanFlow`.** Edit `apps/desktop/src/App.svelte`, replacing the exact line (the Phase-2 Workspace import):
```
  import Workspace from "./routes/Workspace.svelte";
```
with:
```
  import Workspace from "./routes/Workspace.svelte";
  import ScanFlow from "./routes/ScanFlow.svelte";
```

- [ ] **Step 2: Swap the `flow` map entry.** Edit `apps/desktop/src/App.svelte`, replacing the exact line in the `views` map:
```
    flow: Workspace,
```
with:
```
    flow: ScanFlow,
```
(Leave every other map entry — `home: Home`, `machine: Doctor`, `repos: Workspace`, `advanced: GitHub`, `settings: Settings` — unchanged. Do NOT re-typedef the map.)

- [ ] **Step 3: Typecheck.** Run (from `apps/desktop`):
```
pnpm check
```
Expected: `svelte-check` finishes with `0 errors`.

- [ ] **Step 4: Build.** Run (from `apps/desktop`):
```
pnpm build
```
Expected: `vite build` completes with `✓ built in …`, exit code 0.

- [ ] **Step 5: Manual smoke — happy path.** Run (from `apps/desktop`):
```
pnpm tauri dev
```
Then, in the app window: on Home, ensure a protected folder is set, and click **Full Scan**. Observe:
  - the guided **scanning** step shows the `role=status` label "Checking your Mac and your code…" with a moving progressbar (indeterminate until the first repo event, then determinate);
  - **Show details** expands the per-repo terminal log; **Stop** flips to "Stopping…";
  - on completion the **results** step shows the human summary (`N threats found. X can be removed safely and automatically; Y need your review.`), worst-first campaign groups with a count badge per group, and each finding rendered as a `FindingCard` whose **Details** disclosure exposes evidence / repository / file / campaign / branch / online verdict;
  - clicking **Remove threats safely** shows the **cleaning** step ("Removing threats safely…"), then the **clean** step ("Everything's clean — you're protected" or the honest "N removed · M still need your attention"), and **Back to Home** returns to Home.

- [ ] **Step 6: Manual smoke — cancelled path.** Start another Full Scan and click **Stop** mid-scan. Observe the **results** step renders the red `role="alert"` banner "Scan stopped early — results are incomplete." above whatever partial findings were collected (no false "all clear"). Stop `pnpm tauri dev` with Ctrl-C.

- [ ] **Step 7: Commit.** Run (from `apps/desktop`):
```
git add src/App.svelte
git commit -m "feat(desktop): route the guided flow to ScanFlow"
```
Expected: one commit created, no `Co-Authored-By` trailer.

---

## Phase 4: Advanced area + settings (built BEFORE detail unrouting)

### Task 4.1: `routes/Advanced.svelte` — port the GitHub account scan + Fix & force-push

**Files:**
- Create: `apps/desktop/src/routes/Advanced.svelte`

**Interfaces:**
- Consumes from CONTRACT (Phase 1 state): `app` (with `app.dirs: string[]`, `app.view`), `fail(e: unknown): void`, `clearErrors(): void`, `go(view: View): void` from `../lib/state.svelte`.
- Consumes UNCHANGED backend from `../lib/api`: `githubScan(token, includeForks, orgs)`, `githubFix(selected)`, `githubOrgs(token)`, `cancelGithubScan()`.
- Consumes `dialog` from `../lib/modal`; `listen` from `@tauri-apps/api/event`; types `GithubRepoView`, `GithubFixView`, `ScanProgress`.
- Produces the route component `Advanced` (default export) that Task 4.4 routes as the `advanced` map entry. Produces a LOCAL `const plural` reused by Task 4.2.

- [ ] **Step 1: Create the file with the full GitHub account port, back-to-Home control, unselected-by-default, disarm-after-fix, confirm modal, and the `github-scan-progress` listener.** Copy is final plain-English; a11y is final (progressbar, role=status, aria-labels on count badges, real labels).

Write `apps/desktop/src/routes/Advanced.svelte`:

```svelte
<script lang="ts">
  import { app, fail, clearErrors, go } from "../lib/state.svelte";
  import { githubScan, githubFix, githubOrgs, cancelGithubScan } from "../lib/api";
  import { dialog } from "../lib/modal";
  import { listen } from "@tauri-apps/api/event";
  import type { GithubRepoView, GithubFixView, ScanProgress } from "../lib/types";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  // ---------------- GitHub account: scan + fix & force-push ----------------
  let token = $state(localStorage.getItem("github_token") ?? "");
  let includeForks = $state(false);
  let scanning = $state(false);
  let stopping = $state(false);
  let fixing = $state(false);
  let confirming = $state(false);
  let scanned = $state(false);
  let progress = $state<ScanProgress | null>(null);

  let repos = $state<GithubRepoView[]>([]);
  let sel = $state<Record<string, boolean>>({});
  let results = $state<GithubFixView[]>([]);

  // Orgs the token owner belongs to, loaded for the org picker. `orgsError` records a
  // discovery failure so the UI can note we're falling back to scanning every org.
  let orgs = $state<string[]>([]);
  let selectedOrgs = $state<Record<string, boolean>>({});
  let loadingOrgs = $state(false);
  let orgsError = $state(false);

  function saveToken() {
    if (token) localStorage.setItem("github_token", token);
    else localStorage.removeItem("github_token");
  }

  // Discover the orgs the token can see, defaulting every one to checked. On failure,
  // leave `orgs` empty and flag the error — scanning still proceeds (all orgs).
  async function loadOrgs() {
    loadingOrgs = true;
    orgsError = false;
    try {
      const found = await githubOrgs(token || undefined);
      orgs = found;
      const s: Record<string, boolean> = {};
      for (const o of found) s[o] = true;
      selectedOrgs = s;
    } catch {
      orgs = [];
      selectedOrgs = {};
      orgsError = true;
    } finally {
      loadingOrgs = false;
    }
  }

  const fixableRepos = $derived(repos.filter((r) => r.fixable));
  // Repos already cleaned this session — never re-arm the force-push against them.
  const fixedNames = $derived(new Set(results.filter((r) => r.fixed).map((r) => r.full_name)));
  const selectedNames = $derived(
    fixableRepos
      .filter((r) => sel[r.full_name] && !fixedNames.has(r.full_name))
      .map((r) => r.full_name),
  );
  const selectableCount = $derived(fixableRepos.filter((r) => !fixedNames.has(r.full_name)).length);

  function selectAll() {
    const s = { ...sel };
    for (const r of fixableRepos) if (!fixedNames.has(r.full_name)) s[r.full_name] = true;
    sel = s;
  }
  function clearAll() {
    sel = {};
  }

  function allOrgs() {
    const s: Record<string, boolean> = {};
    for (const o of orgs) s[o] = true;
    selectedOrgs = s;
  }
  function noOrgs() {
    selectedOrgs = {};
  }

  async function githubAccountScan() {
    scanning = true;
    clearErrors();
    results = [];
    progress = null;
    // Register BEFORE invoking so no early event is missed.
    const unlisten = await listen<ScanProgress>("github-scan-progress", (e) => {
      // Events arrive in completion order; never roll the counter backwards.
      if (!progress || e.payload.done > progress.done) progress = e.payload;
    });
    try {
      // If we discovered orgs, pass the checked subset; if discovery failed or found none,
      // pass [] so the backend scans every org. Your own repos are always scanned.
      const chosen = orgs.filter((o) => selectedOrgs[o]);
      repos = await githubScan(token || undefined, includeForks, chosen);
      // Default to UNSELECTED — a destructive multi-repo remote force-push must be a
      // deliberate, per-repo choice, never armed for the whole account by default.
      sel = {};
      results = [];
      scanned = true;
    } catch (e) {
      fail(e);
    } finally {
      unlisten();
      scanning = false;
      stopping = false;
      progress = null;
    }
  }

  async function stopScan() {
    stopping = true;
    try {
      await cancelGithubScan();
    } catch (e) {
      fail(e);
    }
  }

  async function fix() {
    confirming = false;
    fixing = true;
    clearErrors();
    try {
      results = await githubFix(selectedNames);
      // Disarm: clear the selection so the just-pushed repos aren't re-fixable in one click.
      sel = {};
    } catch (e) {
      fail(e);
    } finally {
      fixing = false;
    }
  }

  const pct = $derived(progress && progress.total ? (progress.done / progress.total) * 100 : 0);
</script>

<div class="page">
  <div class="page-head">
    <button class="btn ghost sm back" onclick={() => go("home")}>← Home</button>
    <h1>Advanced</h1>
    <p class="lede">
      Power-user tools that overwrite remote history or re-introduce removed files. Each action is
      clearly labeled and asks you to confirm — most people never need this screen.
    </p>
  </div>

  <!-- GitHub account -->
  <section class="card">
    <h2>GitHub account — scan &amp; force-push</h2>
    <p class="lede">
      Scan repos you own and repos in your organizations — read-only via the GitHub API, no clones.
      Fixing a repo <strong>force-pushes</strong> the cleaned history back to GitHub, overwriting
      remote history.
    </p>
    <div class="row">
      <input
        type="password"
        aria-label="GitHub token"
        placeholder="ghp_… (or leave blank to use your gh CLI login)"
        autocomplete="off"
        spellcheck="false"
        bind:value={token}
        oninput={saveToken}
        style="flex:1"
      />
      <button class="btn" onclick={loadOrgs} disabled={loadingOrgs || scanning || fixing}>
        {loadingOrgs ? "Loading orgs…" : "Load orgs"}
      </button>
    </div>
    <label class="switch">
      <input type="checkbox" bind:checked={includeForks} />
      <span class="track"></span>
      <span class="lbl">Include forks</span>
    </label>

    {#if orgs.length}
      <div class="stack">
        <div class="row between">
          <p class="muted small">
            Choose organizations to scan. <strong>Your own repos are always scanned.</strong>
          </p>
          <div class="row" style="gap: 6px">
            <button class="btn ghost sm" onclick={allOrgs}>All</button>
            <button class="btn ghost sm" onclick={noOrgs}>None</button>
          </div>
        </div>
        <div class="row" style="gap: 14px 18px">
          {#each orgs as o (o)}
            <label class="switch">
              <input type="checkbox" bind:checked={selectedOrgs[o]} />
              <span class="track"></span>
              <span class="lbl small">{o}</span>
            </label>
          {/each}
        </div>
      </div>
    {:else if orgsError}
      <p class="warn-note">Couldn't list your organizations, so all of them will be scanned.</p>
    {/if}

    <div class="row">
      {#if scanning}
        <button class="btn primary" disabled aria-busy="true">
          <span class="spinner"></span> Scanning account…
        </button>
        <button class="btn danger" onclick={stopScan} disabled={stopping}>
          {stopping ? "Stopping…" : "Cancel"}
        </button>
      {:else}
        <button class="btn primary" onclick={githubAccountScan} disabled={fixing}>Scan account</button>
        <button
          class="btn danger"
          onclick={() => (confirming = true)}
          disabled={fixing || selectedNames.length === 0}
        >
          {#if fixing}<span class="spinner"></span>Pushing…{:else}Fix &amp; push {selectedNames.length} selected…{/if}
        </button>
      {/if}
    </div>

    {#if scanning}
      <div class="stack" role="status" aria-live="polite">
        <div
          class="progress"
          class:indet={!progress}
          role="progressbar"
          aria-valuemin="0"
          aria-valuemax={progress?.total ?? 0}
          aria-valuenow={progress?.done ?? 0}
        >
          <span style="width: {progress ? pct : 35}%"></span>
        </div>
        <p class="muted small">
          {#if progress}
            <span class="mono">{progress.repo}</span> — {progress.done} of {progress.total}
          {:else}
            Scanning repositories via the GitHub API…
          {/if}
        </p>
      </div>
    {/if}
  </section>

  {#if !scanning && scanned && repos.length === 0}
    <div class="card ok">
      <div class="state ok">
        <div class="glyph">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M5 12.5 10 17.5 19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </div>
        <h2>No infected repositories</h2>
        <p class="muted small">Nothing to fix in this account.</p>
      </div>
    </div>
  {:else if repos.length}
    <section class="card">
      <div class="row between">
        <h2>Infected repositories</h2>
        {#if selectableCount}
          <div class="row" style="gap: 8px">
            <span class="muted micro">{selectedNames.length} of {selectableCount} selected</span>
            <button class="btn ghost sm" onclick={selectAll}>Select all</button>
            <button class="btn ghost sm" onclick={clearAll}>Clear</button>
          </div>
        {/if}
      </div>
      <ul class="repo-list">
        {#each repos as r, i (r.full_name)}
          {@const done = fixedNames.has(r.full_name)}
          <li class="reveal" style="animation-delay: {Math.min(i, 12) * 25}ms">
            <label class="switch item" class:done>
              <input type="checkbox" bind:checked={sel[r.full_name]} disabled={!r.fixable || done} />
              <span class="track"></span>
              <span class="lbl small repo-line">
                <strong class="mono">{r.full_name}</strong>
                <span class="count" aria-label="{r.findings} {plural(r.findings, 'finding', 'findings')}">{r.findings}</span>
                {#if r.campaigns.length}<span class="muted">{r.campaigns.join(", ")}</span>{/if}
                {#if done}<span class="chip ok-chip">Cleaned ✓</span>
                {:else if !r.fixable}<span class="chip">branch-only</span>{/if}
              </span>
            </label>
          </li>
        {/each}
      </ul>
      {#if repos.some((r) => !r.fixable)}
        <p class="muted micro">
          "branch-only" repositories have the infection on a non-default branch — clean those in the
          Other branches section below.
        </p>
      {/if}
    </section>
  {/if}

  {#if results.length}
    <section class="card" aria-live="polite">
      <div class="row between">
        <h2>Fix results</h2>
        <button class="btn sm" onclick={githubAccountScan} disabled={scanning || fixing}>Re-scan to confirm</button>
      </div>
      <div class="stack">
        {#each results as r, i (i)}
          <div class="res-line small {r.error || r.manual_review ? 'crit' : r.fixed ? 'ok-text' : 'muted'}">
            <span class="mono">{r.full_name}</span> —
            {#if r.error}
              couldn't fix: {r.error}
            {:else if r.manual_review}
              needs manual review — the malicious code couldn't be safely removed automatically
            {:else if r.fixed}
              cleaned and pushed{r.pushed.length ? ` to ${r.pushed.join(", ")}` : ""}
            {:else}
              already clean — no changes needed
            {/if}
          </div>
        {/each}
      </div>
    </section>
  {/if}
</div>

{#if confirming}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirming = false)}>
      <h3>Force-push cleaned history?</h3>
      <p class="crit small">
        <strong>This is destructive and remote.</strong> Wormward will remediate
        {selectedNames.length} selected repo(s) and <strong>force-push</strong> the cleaned default
        branch to their GitHub remotes, overwriting remote history. The pre-clean tip is backed up
        as a <code>wormward-backup/…</code> branch on each remote.
      </p>
      <div class="row">
        <button class="btn ghost" onclick={() => (confirming = false)}>Cancel</button>
        <button class="btn danger" onclick={fix}>Fix &amp; push</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .back { align-self: flex-start; margin-bottom: 6px; }
  .repo-list { list-style: none; display: flex; flex-direction: column; }
  .repo-line { flex: 1; min-width: 0; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .switch.item.done { opacity: 0.65; }
  .ok-chip { background: var(--ok-tint); color: var(--ok); }
  .warn-note {
    color: var(--warn);
    background: var(--surface-warn);
    padding: 8px 11px;
    border-radius: var(--radius-sm);
    font-size: 12px;
  }
  .res-line { word-break: break-all; }
</style>
```

- [ ] **Step 2: Type-check.** From `apps/desktop`, run:

```
pnpm check
```

Expect `svelte-check` to finish with `0 errors` (Advanced.svelte compiles even though it isn't routed until Task 4.4).

- [ ] **Step 3: Build.** From `apps/desktop`, run:

```
pnpm build
```

Expect a successful Vite build ("✓ built in …"), no TypeScript/Svelte errors.

- [ ] **Step 4: Commit.** From `apps/desktop`:

```
git add src/routes/Advanced.svelte
git commit -m "feat(desktop): add Advanced route with GitHub account scan + force-push"
```

(No `Co-Authored-By: Claude` trailer.) Interactive smoke of this route happens in Task 4.4 once it is routed.

---

### Task 4.2: Add other-branch deep cleaning + restore-last-backup to `Advanced.svelte`

**Files:**
- Modify: `apps/desktop/src/routes/Advanced.svelte`

**Interfaces:**
- Consumes UNCHANGED backend from `../lib/api`: `cleanBranchesPreview(dirs)`, `cleanBranchesApply(selected, push)`, `restore(dirs)`.
- Consumes `app.dirs`, `fail`, `clearErrors` (already imported in Task 4.1), the LOCAL `const plural` (already declared), `dialog` (already imported).
- Consumes types `BranchCleanPreview`, `BranchSelection`, `BranchCleanResult`.

- [ ] **Step 1: Extend the api import to add the branch + restore calls.** Edit — old string:

```
  import { githubScan, githubFix, githubOrgs, cancelGithubScan } from "../lib/api";
```

new string:

```
  import {
    githubScan,
    githubFix,
    githubOrgs,
    cancelGithubScan,
    cleanBranchesPreview,
    cleanBranchesApply,
    restore,
  } from "../lib/api";
```

- [ ] **Step 2: Extend the type import.** Edit — old string:

```
  import type { GithubRepoView, GithubFixView, ScanProgress } from "../lib/types";
```

new string:

```
  import type {
    GithubRepoView,
    GithubFixView,
    ScanProgress,
    BranchCleanPreview,
    BranchSelection,
    BranchCleanResult,
  } from "../lib/types";
```

- [ ] **Step 3: Add branch + restore state and handlers after the GitHub `pct` derived.** Edit — old string:

```
  const pct = $derived(progress && progress.total ? (progress.done / progress.total) * 100 : 0);
</script>
```

new string:

```
  const pct = $derived(progress && progress.total ? (progress.done / progress.total) * 100 : 0);

  // ---------------- Other branches: deep clean + optional force-push ----------------
  let busy = $state(false);
  let busyKind = $state<"branches" | "restore" | "">("");
  let branchPlans = $state<BranchCleanPreview[]>([]);
  let branchSel = $state<Record<string, boolean>>({});
  let pushBranches = $state(false);
  let branchLoading = $state(false);
  let confirmingBranches = $state(false);
  let branchResults = $state<BranchCleanResult[]>([]);
  let branchSummary = $state("");
  let branchesScanned = $state(false);
  const branchKey = (b: { repo: string; branch: string }) => `${b.repo}\n${b.branch}`;
  const selectedBranches = $derived<BranchSelection[]>(
    branchPlans.filter((b) => branchSel[branchKey(b)]).map((b) => ({ repo: b.repo, branch: b.branch })),
  );

  async function previewBranches() {
    branchLoading = true;
    clearErrors();
    try {
      branchPlans = await cleanBranchesPreview(app.dirs);
      const s: Record<string, boolean> = {};
      for (const b of branchPlans) s[branchKey(b)] = true;
      branchSel = s;
      branchesScanned = true;
    } catch (e) {
      fail(e);
    } finally {
      branchLoading = false;
    }
  }

  async function applyBranches() {
    confirmingBranches = false;
    busy = true;
    busyKind = "branches";
    branchSummary = "";
    clearErrors();
    try {
      const s = await cleanBranchesApply(selectedBranches, pushBranches);
      branchResults = s.results;
      branchSummary =
        `Cleaned ${s.cleaned} ${plural(s.cleaned, "branch", "branches")}` +
        (s.skipped ? `, ${s.skipped} skipped` : "") +
        (s.failed ? `, ${s.failed} failed` : "") +
        ".";
      await previewBranches();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
    }
  }

  // ---------------- Restore last backup ----------------
  let restoreConfirm = $state(false);
  let restoreResult = $state("");

  async function doRestore() {
    restoreConfirm = false;
    busy = true;
    busyKind = "restore";
    restoreResult = "";
    clearErrors();
    try {
      const s = await restore(app.dirs);
      restoreResult =
        s.restored > 0
          ? `Restored ${s.restored} ${plural(s.restored, "file", "files")} across ${s.repos} ${plural(s.repos, "repo", "repos")}.`
          : "No backup found to restore.";
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
    }
  }
</script>
```

- [ ] **Step 4: Add the Other-branches and Restore cards before the page's closing `</div>`.** Edit — old string:

```
</div>

{#if confirming}
```

new string:

```
  <!-- Other branches -->
  <section class="card">
    <h2>Other branches — deep clean &amp; optional push</h2>
    <p class="lede">
      Deep-scan every branch tip and rewrite infected tips on a fresh commit (the old tip is kept in
      a <code>refs/wormward-backup/…</code> ref). Turning on <strong>Push</strong> force-pushes the
      rewritten tips, overwriting remote history.
    </p>
    {#if !app.dirs.length}
      <p class="muted small">Add a protected location in Settings to scan branches.</p>
    {/if}
    <div class="row">
      <button class="btn sm" onclick={previewBranches} disabled={branchLoading || busy || !app.dirs.length}>
        {#if branchLoading}<span class="spinner"></span>Scanning branches…{:else}Scan other branches{/if}
      </button>
      <button class="btn primary sm" onclick={() => (confirmingBranches = true)} disabled={busy || selectedBranches.length === 0}>
        {#if busyKind === "branches"}<span class="spinner"></span>Cleaning…{:else}Clean {selectedBranches.length} {plural(selectedBranches.length, "branch", "branches")}{/if}
      </button>
      <label class="switch sm">
        <input type="checkbox" bind:checked={pushBranches} />
        <span class="track"></span>
        <span class="lbl small">Push <span class="muted">— force-push tips</span></span>
      </label>
    </div>
    {#if branchSummary}<p class="ok-text small" role="status">{branchSummary}</p>{/if}
    {#if branchPlans.length === 0}
      {#if branchesScanned}<p class="muted micro">No infected branch tips found.</p>{/if}
    {:else}
      <ul class="branch-list">
        {#each branchPlans as b (branchKey(b))}
          <li>
            <label class="switch item">
              <input type="checkbox" bind:checked={branchSel[branchKey(b)]} />
              <span class="track"></span>
              <span class="lbl small"><span class="mono">{b.repo}</span> <span class="chip">branch: {b.branch}</span> <span class="muted">— {b.action_count} {plural(b.action_count, "action", "actions")}</span></span>
            </label>
          </li>
        {/each}
      </ul>
    {/if}
    {#if branchResults.length}
      <div class="stack" style="margin-top: 4px" role="status">
        {#each branchResults as r, i (i)}
          <div class="branch-res {r.status}"><span class="dot"></span><span class="mono">{r.branch}</span> — {r.status}{r.pushed ? " (pushed)" : ""}{#if r.message} — {r.message}{/if}</div>
        {/each}
      </div>
    {/if}
  </section>

  <!-- Restore last backup -->
  <section class="card">
    <h2>Restore last backup</h2>
    <p class="lede">
      Undo a clean by restoring the last backup. <strong>This re-introduces the removed payloads</strong>
      over the current files — only do this if a clean went wrong. If no backup exists, nothing changes.
    </p>
    <div class="row between">
      {#if restoreResult}<p class="ok-text small" role="status">{restoreResult}</p>{:else}<span></span>{/if}
      <button class="btn danger sm" onclick={() => (restoreConfirm = true)} disabled={busy || !app.dirs.length}>
        {#if busyKind === "restore"}<span class="spinner"></span>Restoring…{:else}Restore last backup{/if}
      </button>
    </div>
  </section>
</div>

{#if confirming}
```

- [ ] **Step 5: Add the branch and restore confirm modals after the GitHub confirm modal.** Edit — old string:

```
{/if}

<style>
```

new string:

```
{/if}

{#if confirmingBranches}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirmingBranches = false)}>
      <h3>Rewrite branch tips?</h3>
      <p class="lede">Rewrites the tips of {selectedBranches.length} selected {plural(selectedBranches.length, "branch", "branches")} with a new clean commit. The old tip of each is kept in a <code>refs/wormward-backup/…</code> ref.</p>
      {#if pushBranches}
        <p class="crit small"><strong>Push is ON:</strong> cleaned tips will be <strong>force-pushed</strong>, overwriting remote history.</p>
      {:else}
        <p class="muted small">Push is OFF — local branches rewritten in place; remote-tracking branches are reported as skipped.</p>
      {/if}
      <div class="row">
        <button class="btn ghost" onclick={() => (confirmingBranches = false)}>Cancel</button>
        <button class="btn {pushBranches ? 'danger' : 'primary'}" onclick={applyBranches}>{pushBranches ? "Clean & force-push" : "Clean branches"}</button>
      </div>
    </div>
  </div>
{/if}

{#if restoreConfirm}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (restoreConfirm = false)}>
      <h3>Restore the last backup?</h3>
      <p class="crit small"><strong>This re-writes the backed-up originals over the current files</strong> — including the malware that was cleaned. Only do this if a clean went wrong.</p>
      <p class="muted small">If no backup exists, nothing changes.</p>
      <div class="row">
        <button class="btn ghost" onclick={() => (restoreConfirm = false)}>Cancel</button>
        <button class="btn danger" onclick={doRestore}>Restore &amp; re-introduce</button>
      </div>
    </div>
  </div>
{/if}

<style>
```

- [ ] **Step 6: Add the branch-list styles.** Edit — old string:

```
  .res-line { word-break: break-all; }
</style>
```

new string:

```
  .res-line { word-break: break-all; }
  .branch-list { list-style: none; display: flex; flex-direction: column; gap: 2px; }
  .branch-res { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
  .branch-res .dot { flex: none; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .branch-res.cleaned { color: var(--ok); }
  .branch-res.cleaned .dot { background: var(--ok); }
  .branch-res.skipped .dot { background: var(--warn); }
  .branch-res.failed { color: var(--danger); }
  .branch-res.failed .dot { background: var(--danger); }
  .branch-res.planned .dot { background: var(--accent); }
</style>
```

- [ ] **Step 7: Type-check.** From `apps/desktop`:

```
pnpm check
```

Expect `svelte-check` `0 errors` (all three new backend calls and the three new types resolve; `plural`, `app`, `fail`, `clearErrors`, `dialog` are already in scope — no redeclarations).

- [ ] **Step 8: Build.** From `apps/desktop`:

```
pnpm build
```

Expect a successful Vite build.

- [ ] **Step 9: Commit.** From `apps/desktop`:

```
git add src/routes/Advanced.svelte
git commit -m "feat(desktop): add other-branch cleaning + restore to Advanced"
```

---

### Task 4.3: `Settings.svelte` — protected-locations editor + Appearance note

**Files:**
- Modify: `apps/desktop/src/routes/Settings.svelte`

**Interfaces:**
- Consumes `app` (`app.dirs`), `fail` from `../lib/state.svelte`; `pickDirs` from `../lib/api`; `saveLocations(dirs: string[]): void` from `../lib/locations` (CONTRACT, Phase 1).
- Keeps the existing OSM + GitHub token cards and packs list unchanged.

- [ ] **Step 1: Add the new imports.** Edit — old string:

```
  import { onMount } from "svelte";
  import { listPacks, githubOrgs } from "../lib/api";
  import type { PackInfo } from "../lib/types";
```

new string:

```
  import { onMount } from "svelte";
  import { app, fail } from "../lib/state.svelte";
  import { listPacks, githubOrgs, pickDirs } from "../lib/api";
  import { saveLocations } from "../lib/locations";
  import type { PackInfo } from "../lib/types";
```

- [ ] **Step 2: Add the location editor handlers after the packs loader.** Edit — old string:

```
  onMount(loadPacks);
```

new string:

```
  onMount(loadPacks);

  // Protected locations are the folders a Full Scan targets. `app.dirs` is the live source
  // (hydrated from loadLocations() on state init); every edit persists via saveLocations.
  async function addLocations() {
    try {
      const picked = await pickDirs();
      if (!picked.length) return;
      const merged = [...app.dirs];
      for (const d of picked) if (!merged.includes(d)) merged.push(d);
      app.dirs = merged;
      saveLocations(app.dirs);
    } catch (e) {
      fail(e);
    }
  }
  function removeLocation(dir: string) {
    app.dirs = app.dirs.filter((d) => d !== dir);
    saveLocations(app.dirs);
  }
```

- [ ] **Step 3: Add the Protected-locations card at the top of the page.** Edit — old string:

```
  <section class="card">
    <h2>OpenSourceMalware token</h2>
```

new string:

```
  <section class="card">
    <h2>Protected locations</h2>
    <p class="lede">
      The folders a Full Scan checks. Add the folders where you keep your code — Wormward scans them
      and everything inside.
    </p>
    {#if app.dirs.length}
      <ul class="loc-list">
        {#each app.dirs as d (d)}
          <li class="loc">
            <span class="loc-path mono" title={d}>{d}</span>
            <button class="btn ghost sm" aria-label="Remove {d}" onclick={() => removeLocation(d)}>Remove</button>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="muted small">No locations yet — add the folder where you keep your code.</p>
    {/if}
    <div class="row" style="margin-top: 10px">
      <button class="btn sm" onclick={addLocations}>Add folder…</button>
    </div>
  </section>

  <section class="card">
    <h2>OpenSourceMalware token</h2>
```

- [ ] **Step 4: Add the Appearance card at the bottom of the page.** Edit — old string:

```
      </ul>
    {/if}
  </section>
</div>
```

new string:

```
      </ul>
    {/if}
  </section>

  <section class="card">
    <h2>Appearance</h2>
    <p class="lede">Wormward uses a dark theme for now. A light theme may come later.</p>
  </section>
</div>
```

- [ ] **Step 5: Add the location-list styles.** Edit — old string:

```
  .packs { display: flex; flex-direction: column; gap: 12px; list-style: none; }
  .pack { display: flex; flex-direction: column; gap: 3px; }
</style>
```

new string:

```
  .packs { display: flex; flex-direction: column; gap: 12px; list-style: none; }
  .pack { display: flex; flex-direction: column; gap: 3px; }
  .loc-list { display: flex; flex-direction: column; gap: 6px; list-style: none; }
  .loc { display: flex; align-items: center; gap: 8px; background: var(--inset); border-radius: var(--radius-sm); padding: 6px 6px 6px 12px; }
  .loc-path { flex: 1; min-width: 0; font-size: 12px; color: var(--fg); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
```

- [ ] **Step 6: Type-check.** From `apps/desktop`:

```
pnpm check
```

Expect `svelte-check` `0 errors` (`app`, `fail`, `pickDirs`, `saveLocations` all resolve; no identifier collisions).

- [ ] **Step 7: Build.** From `apps/desktop`:

```
pnpm build
```

Expect a successful Vite build.

- [ ] **Step 8: Manual smoke.** From `apps/desktop` run `pnpm tauri dev`; open ⚙ → Settings. Observe the new **Protected locations** card at the top listing `app.dirs`; click **Add folder…**, pick a folder, and confirm it appears in the list and survives an app relaunch (persisted under `localStorage["protected_locations"]`); click **Remove** on an entry and confirm it disappears and stays gone after relaunch. Scroll to the bottom and confirm the **Appearance** card reads "Wormward uses a dark theme for now." The OSM/GitHub token cards and Campaign packs list still work unchanged.

- [ ] **Step 9: Commit.** From `apps/desktop`:

```
git add src/routes/Settings.svelte
git commit -m "feat(desktop): add protected-locations editor + appearance note to Settings"
```

---

### Task 4.4: Route `advanced` → `Advanced`; retire temporary GitHub routing

**Files:**
- Modify: `apps/desktop/src/App.svelte`

**Interfaces:**
- Consumes the canonical `views: Record<View, Component>` router established in Phase 2 (with the `flow → ScanFlow` change from Phase 3). This task changes ONLY the `advanced` entry (`GitHub → Advanced`) and swaps the corresponding import. Does NOT re-typedef the map, touch `machine`/`repos` (still temporarily `Doctor`/`Workspace`), or alter the ⚙ menu, focus management, toast stack, skip link, or env-banner.

- [ ] **Step 1: Swap the temporary GitHub import for the Advanced import.** Edit — old string:

```
  import GitHub from "./routes/GitHub.svelte";
```

new string:

```
  import Advanced from "./routes/Advanced.svelte";
```

- [ ] **Step 2: Point the `advanced` map entry at the real route.** The `views` map is **multi-line** (created that way in Task 2.4; only its `flow:` line was changed in Task 3.5), so change ONLY the single entry line — old string:

```
    advanced: GitHub,
```

new string:

```
    advanced: Advanced,
```

- [ ] **Step 3: Type-check.** From `apps/desktop`:

```
pnpm check
```

Expect `svelte-check` `0 errors`. The `GitHub` import is gone with no remaining references (`GitHub.svelte` itself still exists on disk and is deleted in Phase 6); `Advanced` is now the `advanced` route.

- [ ] **Step 4: Build.** From `apps/desktop`:

```
pnpm build
```

Expect a successful Vite build.

- [ ] **Step 5: Manual smoke — full Advanced flow.** From `apps/desktop` run `pnpm tauri dev`:
  - From Home, open the ⚙ menu and click **Advanced**. Confirm the Advanced route renders with the **← Home** back control (keyboard focus lands on `<main>` after the view change), the intro lede, and three cards: **GitHub account — scan & force-push**, **Other branches — deep clean & optional push**, **Restore last backup**.
  - **GitHub:** paste/confirm a token, click **Load orgs** (org switches appear or the "all orgs" warn-note shows), click **Scan account** — the progressbar animates from `github-scan-progress` events; when done, the infected-repo list appears with **every checkbox unselected** (Fix button disabled). Select one repo, click **Fix & push …**, confirm the modal copy, cancel it; then confirm again and observe the fixed repo becomes "Cleaned ✓" and its checkbox disarms.
  - **Other branches:** click **Scan other branches** (requires a protected location; disabled with the Settings hint when `app.dirs` is empty), toggle a branch, click **Clean … branch(es)**, confirm the modal, and observe the results list. Toggle **Push** and confirm the modal switches to the red "Clean & force-push" copy.
  - **Restore:** click **Restore last backup**, confirm the red modal warns it re-introduces payloads, cancel, then confirm and observe the restore result line.
  - Click **← Home** and confirm return to Home. Re-open ⚙ → the GitHub tab is gone; only **Advanced** and **Settings** are offered.

- [ ] **Step 6: Commit.** From `apps/desktop`:

```
git add src/App.svelte
git commit -m "feat(desktop): route advanced to Advanced, retire temp GitHub routing"
```

---

## Phase 5: Machine + repositories detail

This phase replaces the two remaining temporary routes with their real, plain-language antivirus versions. `MachineDetail.svelte` becomes the plain-language "This Mac" view (no auto-run, honest idle/checking states, worst-first sections, live-monitoring toggle) writing `app.machineReport`. `RepositoriesDetail.svelte` renders per-repo findings from `app.report` with the shared worst-first grouping and honest empty/cancelled states, linking quietly to Advanced. Then the canonical `App.svelte` views map swaps `machine → MachineDetail` and `repos → RepositoriesDetail`, retiring the temporary `Doctor`/`Workspace` routing. Every route renders its own back-to-Home control and carries final copy + final a11y. Ships with nothing unreachable: Advanced (built in Phase 4) still hosts branch cleaning and restore, which `RepositoriesDetail` links to.

### Task 5.1: routes/MachineDetail.svelte — plain-language "This Mac"

**Files:**
- Create: `apps/desktop/src/routes/MachineDetail.svelte`

**Interfaces:**
- Consumes: `doctor()`, `doctorClearCache(dir: string)`, `doctorHardenTriggers()` from `../lib/api` (unchanged); `app` (with `app.machineReport: DoctorReport | null`), `fail(e: unknown)`, `go(view: View)` from `../lib/state.svelte`; `dialog` action from `../lib/modal`; `DoctorReport` type (via `app.machineReport`, no direct import needed).
- Produces: writes `app.machineReport` (a `DoctorReport`); no exports (route component).

- [ ] **Step 1: Create the component with the full script + honest markup + styles.** No auto-run on mount; idle "This Mac hasn't been checked yet" when `app.machineReport === null` and not running; "Checking this Mac…" (role=status) while a manual/live check runs with no report yet; three worst-first sections once a report exists; a "Live monitoring" 5s toggle with the honest sublabel; a confirm modal before each cache clean-up. Write the entire file:

```svelte
<script lang="ts">
  import { onDestroy } from "svelte";
  import { doctor, doctorClearCache, doctorHardenTriggers } from "../lib/api";
  import { app, fail, go } from "../lib/state.svelte";
  import { dialog } from "../lib/modal";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  let running = $state(false);
  let watching = $state(false);
  let hardening = $state(false);
  let clearing = $state<string | null>(null);
  let confirmDir = $state<string | null>(null);
  let timer: ReturnType<typeof setInterval> | null = null;

  // The machine report lives in shared state so Home / chips stay in sync.
  const report = $derived(app.machineReport);
  const procHits = $derived(report?.processes.length ?? 0);
  const cacheHits = $derived(report?.caches.length ?? 0);
  const exposed = $derived(report?.triggers.filter((t) => t.exposed).length ?? 0);
  const scriptsExposed = $derived(
    report?.triggers.some((t) => t.name.includes("ignore-scripts") && t.exposed) ?? false,
  );
  // Shorten $HOME to ~ for readable paths.
  const short = (p: string) => p.replace(/^\/Users\/[^/]+/, "~").replace(/^\/home\/[^/]+/, "~");

  async function runCheck() {
    if (running) return;
    running = true;
    try {
      app.machineReport = await doctor();
    } catch (e) {
      fail(e);
    } finally {
      running = false;
    }
  }

  function stopWatch() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    watching = false;
  }
  function toggleWatch() {
    if (watching) {
      stopWatch();
    } else {
      watching = true;
      runCheck();
      timer = setInterval(runCheck, 5000);
    }
  }
  onDestroy(stopWatch);

  async function harden() {
    hardening = true;
    try {
      await doctorHardenTriggers();
      await runCheck();
    } catch (e) {
      fail(e);
    } finally {
      hardening = false;
    }
  }

  async function clearCache(dir: string) {
    confirmDir = null;
    clearing = dir;
    try {
      await doctorClearCache(dir);
      await runCheck();
    } catch (e) {
      fail(e);
    } finally {
      clearing = null;
    }
  }
</script>

<div class="page" aria-busy={running}>
  <button class="back" onclick={() => go("home")}>← Home</button>
  <div class="page-head">
    <h1>This Mac</h1>
    <p class="lede">
      Check this computer for malware that's running right now, infected app caches, and settings
      that let malware come back.
    </p>
  </div>

  <div class="row">
    <button class="btn primary" onclick={runCheck} disabled={running}>
      {#if running}<span class="spinner"></span>Checking this Mac…{:else}{report ? "Check again" : "Run a check"}{/if}
    </button>
    <label class="switch">
      <input type="checkbox" checked={watching} onchange={toggleWatch} />
      <span class="track"></span>
      <span class="lbl">Live monitoring <span class="muted">— re-checks every few seconds</span></span>
    </label>
  </div>

  {#if !report && !running}
    <div class="state">
      <span class="glyph">◎</span>
      <h2>This Mac hasn't been checked yet</h2>
      <p class="muted micro">
        Run a check to look for malware running right now, infected app caches, and risky settings.
      </p>
    </div>
  {:else if !report && running}
    <div class="state" role="status">
      <span class="spinner"></span>
      <p>Checking this Mac…</p>
    </div>
  {:else if report}
    <!-- Worst-first: an active threat is the most urgent thing to surface. -->
    <section class="card" class:danger={procHits} aria-live="polite">
      <div class="row between">
        <h2>Is a threat running right now?</h2>
        <span class="count" class:hot={procHits} aria-label="{procHits} {plural(procHits, 'threat', 'threats')} running">{procHits}</span>
      </div>
      {#if procHits === 0}
        <div class="state ok">
          <span class="glyph">✓</span>
          <p>Nothing malicious is running right now.</p>
          <p class="lede">
            A one-time check isn't proof. Turn on Live monitoring, then open your editor and projects
            to catch malware that only starts on a trigger.
          </p>
        </div>
      {:else}
        {#each report.processes as p (p.pid)}
          <div class="hit">
            <div class="row between">
              <strong>Program {p.pid}</strong>
              <span class="pill critical">threat</span>
            </div>
            <p class="muted micro">{p.reason}</p>
            <code class="snippet mono">{p.snippet}</code>
          </div>
        {/each}
      {/if}
    </section>

    <section class="card" class:danger={cacheHits} aria-live="polite">
      <div class="row between">
        <h2>Infected app caches</h2>
        <span class="count" class:hot={cacheHits} aria-label="{cacheHits} infected {plural(cacheHits, 'cache', 'caches')}">{cacheHits}</span>
      </div>
      {#if cacheHits === 0}
        <div class="state ok">
          <span class="glyph">✓</span>
          <p>No infected files in your developer tool caches.</p>
        </div>
      {:else}
        {#each report.caches as c (c.path)}
          <div class="hit">
            <code class="snippet mono">{short(c.path)}</code>
            <p class="muted micro">{c.reason}</p>
          </div>
        {/each}
        <div class="row">
          {#each report.cache_dirs as dir (dir)}
            <button class="btn danger sm" onclick={() => (confirmDir = dir)} disabled={clearing !== null}>
              {#if clearing === dir}<span class="spinner"></span>Cleaning up…{:else}Clean up {short(dir)}{/if}
            </button>
          {/each}
        </div>
        <p class="lede">These caches rebuild cleanly the next time you use them.</p>
      {/if}
    </section>

    <section class="card" class:warn={exposed} aria-live="polite">
      <div class="row between">
        <h2>Risky settings that let malware come back</h2>
        <span class="count" class:warnc={exposed} aria-label="{exposed} risky {plural(exposed, 'setting', 'settings')}">{exposed}</span>
      </div>
      {#if report.triggers.length === 0}
        <p class="muted micro">No settings to check on this computer.</p>
      {:else}
        <ul class="triggers">
          {#each report.triggers as t (t.name)}
            <li class:exposed={t.exposed}>
              <span class="mark" aria-hidden="true">{t.exposed ? "⚠" : "✓"}</span>
              <div>
                <strong>{t.name}</strong>
                <span class="sr">{t.exposed ? "risky" : "protected"}</span>
                <p class="muted micro">{t.detail}</p>
              </div>
            </li>
          {/each}
        </ul>
        {#if scriptsExposed}
          <button class="btn primary sm" onclick={harden} disabled={hardening}>
            {#if hardening}<span class="spinner"></span>Turning on protection…{:else}Turn on protection{/if}
          </button>
        {/if}
      {/if}
    </section>
  {/if}
</div>

{#if confirmDir}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirmDir = null)}>
      <h3>Clean up this cache?</h3>
      <p class="lede">
        Deletes the infected files in <code>{short(confirmDir)}</code>. The cache rebuilds cleanly
        the next time you use those tools.
      </p>
      <div class="row">
        <button class="btn ghost" onclick={() => (confirmDir = null)}>Cancel</button>
        <button class="btn danger" onclick={() => clearCache(confirmDir!)}>Clean up</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .back {
    align-self: flex-start;
    background: none;
    color: var(--muted);
    font-size: 13px;
    padding: 4px 0;
  }
  .back:hover { color: var(--fg); background: none; }
  .hit {
    display: flex;
    flex-direction: column;
    gap: 5px;
    padding: 11px 13px;
    background: var(--inset);
    border-radius: var(--radius-sm);
  }
  .hit + .hit { margin-top: 8px; }
  .snippet {
    font-size: 11.5px;
    color: var(--fg);
    word-break: break-all;
    line-height: 1.5;
  }
  .count.hot { background: var(--danger-tint); color: var(--danger); }
  .count.warnc { background: var(--warn-tint); color: var(--warn); }
  .triggers {
    display: flex;
    flex-direction: column;
    gap: 9px;
    list-style: none;
  }
  .triggers li { display: flex; gap: 10px; align-items: flex-start; }
  .triggers .mark {
    flex: none;
    font-weight: 700;
    color: var(--ok);
    line-height: 1.4;
  }
  .triggers li.exposed .mark { color: var(--warn); }
  .triggers strong { font-size: 13px; }
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
</style>
```

- [ ] **Step 2: Typecheck.** Run from `apps/desktop`:
```
pnpm check
```
Expected: `svelte-check` completes with `0 errors` (warnings unrelated to this file are acceptable if pre-existing, but this file must contribute none). The file is not yet routed, so it is compiled but unreached.

- [ ] **Step 3: Build.** Run from `apps/desktop`:
```
pnpm build
```
Expected: `vite build` finishes with `✓ built in …` and no TypeScript/Svelte errors.

- [ ] **Step 4: Commit.** Run from `apps/desktop`:
```
git add src/routes/MachineDetail.svelte
git commit -m "feat(desktop): plain-language This Mac detail (no auto-run, honest states)"
```
Expected: one commit created; no `Co-Authored-By: Claude` trailer present (`git log -1 --format=%b` shows no such line).

### Task 5.2: routes/RepositoriesDetail.svelte — per-repo findings

**Files:**
- Create: `apps/desktop/src/routes/RepositoriesDetail.svelte`

**Interfaces:**
- Consumes: `app` (with `app.report: ScanReport | null`, `app.lastScanAt: number | null`), `go(view: View)` from `../lib/state.svelte`; `Finding` type from `../lib/types` (type-only import); `FindingCard` component from `../lib/components/FindingCard.svelte` (created in Phase 3, props `{ finding: Finding }`).
- Produces: no exports (route component). Reuses the exact campaign grouping + severity-rank logic from `Workspace.svelte`.

- [ ] **Step 1: Create the component.** Reuse the Workspace grouping (`SEV_RANK`, `rank`, `grouped`, `affected`) verbatim; render worst-first campaign groups with aria-labelled count badges; render each finding through `FindingCard` (which supplies the plain "Removable automatically" / "Needs your attention" labels + Details disclosure); honest empty/cancelled states keyed off `app.lastScanAt` and `report.cancelled`; a quiet link to Advanced. Write the entire file:

```svelte
<script lang="ts">
  import { app, go } from "../lib/state.svelte";
  import type { Finding } from "../lib/types";
  import FindingCard from "../lib/components/FindingCard.svelte";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  const report = $derived(app.report);
  const findings = $derived(report?.findings ?? []);
  const total = $derived(findings.length);
  const cancelled = $derived(report?.cancelled ?? false);
  // Honest: "scanned" means a Full Scan actually recorded a time, not just a stale report.
  const scanned = $derived(app.lastScanAt !== null);

  const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const rank = (s: string) => SEV_RANK[s] ?? 0;
  const grouped = $derived.by(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      if (!map.has(f.campaign)) map.set(f.campaign, []);
      map.get(f.campaign)!.push(f);
    }
    for (const list of map.values()) list.sort((a, b) => rank(b.severity) - rank(a.severity));
    return [...map.entries()].sort(
      (a, b) => rank(b[1][0].severity) - rank(a[1][0].severity) || b[1].length - a[1].length,
    );
  });
  const affected = $derived(new Set(findings.map((f) => f.repo)).size);
  const removable = $derived(findings.filter((f) => f.remediable).length);
  const manual = $derived(total - removable);
</script>

<div class="page">
  <button class="back" onclick={() => go("home")}>← Home</button>
  <div class="page-head">
    <h1>Repositories</h1>
    <p class="lede">Threats found in your code folders during the last scan.</p>
  </div>

  {#if !scanned}
    <div class="state">
      <span class="glyph">◎</span>
      <h2>Not scanned yet</h2>
      <p class="muted micro">Run a Full Scan from the home screen to check your repositories.</p>
    </div>
  {:else}
    {#if cancelled}
      <section class="card danger" role="alert">
        <h2 class="danger-text">Scan stopped early — results are incomplete</h2>
        <p class="muted small">Some repositories weren't scanned. Run a Full Scan again for a complete picture.</p>
      </section>
    {/if}

    {#if total === 0}
      <div class="card {cancelled ? '' : 'ok'}">
        <div class="state {cancelled ? '' : 'ok'}">
          <div class="glyph">{cancelled ? "◔" : "✓"}</div>
          <h2>{cancelled ? "No threats in what was scanned" : "No threats found"}</h2>
          <p class="muted micro">
            {cancelled
              ? "Nothing malicious in the repositories checked so far."
              : `Checked ${report?.repos_scanned ?? 0} ${plural(report?.repos_scanned ?? 0, "repository", "repositories")}.`}
          </p>
        </div>
      </div>
    {:else}
      <section class="card">
        <div class="stack" style="gap: 4px">
          <h2>
            {total} {plural(total, "threat", "threats")} in {affected} of
            {report?.repos_scanned ?? 0} {plural(report?.repos_scanned ?? 0, "repository", "repositories")}
          </h2>
          <p class="muted micro">
            {removable} can be removed automatically · {manual} {plural(manual, "needs", "need")} your attention
          </p>
        </div>

        {#each grouped as [campaign, list] (campaign)}
          <div class="camp">
            <div class="camp-head">
              <h3>{campaign}</h3>
              <span class="count sev-{list[0].severity}" aria-label="{list.length} {plural(list.length, 'threat', 'threats')}">{list.length}</span>
            </div>
            <ul class="findings">
              {#each list as f, i (f.repo + (f.file ?? "") + f.signature_id + i)}
                <li><FindingCard finding={f} /></li>
              {/each}
            </ul>
          </div>
        {/each}
      </section>
    {/if}

    <p class="adv-link">
      Need to clean other branches or restore a backup?
      <button class="linkish" onclick={() => go("advanced")}>Open Advanced</button>
    </p>
  {/if}
</div>

<style>
  .back {
    align-self: flex-start;
    background: none;
    color: var(--muted);
    font-size: 13px;
    padding: 4px 0;
  }
  .back:hover { color: var(--fg); background: none; }
  .danger-text { color: var(--danger); }
  .camp { padding-top: 11px; border-top: 1px solid var(--surface-3); }
  .camp:first-of-type { border-top: 0; padding-top: 2px; }
  .camp-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 7px;
  }
  .camp-head h3 { font-size: 13px; color: var(--fg); }
  .count.sev-critical { background: var(--danger); color: #150a0b; }
  .count.sev-high { background: var(--danger-tint); color: var(--danger); }
  .count.sev-medium { background: var(--warn-tint); color: var(--warn); }
  .findings { display: flex; flex-direction: column; gap: 8px; list-style: none; }
  .adv-link { font-size: 12.5px; color: var(--muted); }
  .linkish {
    background: none;
    color: var(--accent-hi);
    font-size: 12.5px;
    padding: 0;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .linkish:hover { background: none; color: var(--accent); }
</style>
```

- [ ] **Step 2: Typecheck.** Run from `apps/desktop`:
```
pnpm check
```
Expected: `0 errors`. Confirms `FindingCard`'s `{ finding: Finding }` prop matches and the type-only `Finding` import satisfies `verbatimModuleSyntax`.

- [ ] **Step 3: Build.** Run from `apps/desktop`:
```
pnpm build
```
Expected: `vite build` finishes with `✓ built in …` and no errors.

- [ ] **Step 4: Commit.** Run from `apps/desktop`:
```
git add src/routes/RepositoriesDetail.svelte
git commit -m "feat(desktop): repositories detail with worst-first findings + honest states"
```
Expected: one commit created; no `Co-Authored-By: Claude` trailer.

### Task 5.3: App.svelte — route machine → MachineDetail, repos → RepositoriesDetail

**Files:**
- Modify: `apps/desktop/src/App.svelte` (imports block + `views` map only)

**Interfaces:**
- Consumes: the canonical `views: Record<View, Component>` map and its component imports established in Phases 2–4.
- Produces: `machine: MachineDetail` and `repos: RepositoriesDetail` entries; removes the now-dead `Doctor`/`Workspace` imports. The map typedef, router `{#key}` block, focus `$effect`, ⚙ menu, toast stack, and skip link are untouched.

- [ ] **Step 1: Replace the two temporary imports (as TWO independent single-line edits).** Entering Phase 5, the component-import lines in `App.svelte` read in this accumulated order (Task 2.4 wrote Home/Workspace/GitHub/Doctor/Settings; Task 3.5 inserted ScanFlow after Workspace; Task 4.4 replaced GitHub with Advanced in place):
```
  import Home from "./routes/Home.svelte";
  import Workspace from "./routes/Workspace.svelte";
  import ScanFlow from "./routes/ScanFlow.svelte";
  import Advanced from "./routes/Advanced.svelte";
  import Doctor from "./routes/Doctor.svelte";
  import Settings from "./routes/Settings.svelte";
```
`Workspace` (2nd) and `Doctor` (5th) are **not adjacent**, so replace them as two separate single-line edits — do NOT quote them as one contiguous block. First change:
```
  import Workspace from "./routes/Workspace.svelte";
```
to:
```
  import RepositoriesDetail from "./routes/RepositoriesDetail.svelte";
```
Then change:
```
  import Doctor from "./routes/Doctor.svelte";
```
to:
```
  import MachineDetail from "./routes/MachineDetail.svelte";
```

- [ ] **Step 2: Confirm the current views map.** Entering Phase 5, the map reads exactly:
```
  const views: Record<View, Component> = {
    home: Home,
    flow: ScanFlow,
    machine: Doctor,
    repos: Workspace,
    advanced: Advanced,
    settings: Settings,
  };
```
Change only these two lines. Change:
```
    machine: Doctor,
    repos: Workspace,
```
to:
```
    machine: MachineDetail,
    repos: RepositoriesDetail,
```
Do NOT re-typedef the map, convert it to an `{#if}` chain, or touch any other entry (`home`, `flow`, `advanced`, `settings` stay). `Doctor.svelte` and `Workspace.svelte` are now unrouted but still on disk — their files are deleted in Phase 6, not here.

- [ ] **Step 3: Typecheck.** Run from `apps/desktop`:
```
pnpm check
```
Expected: `0 errors`. In particular, no "declared but never read" for a leftover `Doctor`/`Workspace` import (both import lines were replaced) and no missing-module error for `MachineDetail`/`RepositoriesDetail`.

- [ ] **Step 4: Build.** Run from `apps/desktop`:
```
pnpm build
```
Expected: `vite build` finishes with `✓ built in …` and no errors.

- [ ] **Step 5: Manual smoke.** Run from `apps/desktop`:
```
pnpm tauri dev
```
Then verify:
  - From Home, click the **This Mac** health chip → lands on `MachineDetail`. Observe the idle state "This Mac hasn't been checked yet" with a "Run a check" button and NO automatic scan (nothing spins on arrival) when `app.machineReport` is null. Click **Run a check** → button shows "Checking this Mac…"; on completion the three sections render worst-first (threat running → infected caches → risky settings). Toggle **Live monitoring** on → it re-checks roughly every 5s; toggle off → re-checks stop. If a cache is listed, click **Clean up …** → the confirm modal appears; confirm → the section refreshes.
  - Click **← Home**, then click the **Repositories** health chip → lands on `RepositoriesDetail`. Before any Full Scan this session it shows "Not scanned yet". Run a **Full Scan** from Home, then reopen Repositories → observe the "N threats in X of Y repositories" summary, worst-first campaign groups with count badges, per-finding **Details** disclosures, and the honest "No threats found" / cancelled-banner states when applicable. Click **Open Advanced** → navigates to the Advanced view.
  - Confirm the old tab bar is gone and both detail views are reachable only via the Home chips + ⚙, with each rendering its own **← Home** control.

- [ ] **Step 6: Commit.** Run from `apps/desktop`:
```
git add src/App.svelte
git commit -m "feat(desktop): route machine/repos to real detail views; retire temp routing"
```
Expected: one commit created; no `Co-Authored-By: Claude` trailer.

---

## Phase 6: A11y verification + state audit + dead-file cleanup

### Task 6.1: Accessibility verification sweep across every new screen and component

**Files:**
- Verify (read-only unless a gap is found): `apps/desktop/src/App.svelte`, `apps/desktop/src/routes/Home.svelte`, `apps/desktop/src/routes/ScanFlow.svelte`, `apps/desktop/src/routes/MachineDetail.svelte`, `apps/desktop/src/routes/RepositoriesDetail.svelte`, `apps/desktop/src/routes/Advanced.svelte`, `apps/desktop/src/routes/Settings.svelte`, `apps/desktop/src/lib/components/ShieldStatus.svelte`, `apps/desktop/src/lib/components/HealthChip.svelte`, `apps/desktop/src/lib/components/GuidedProgress.svelte`, `apps/desktop/src/lib/components/FindingCard.svelte`, `apps/desktop/src/app.css`
- Modify only if a step reports a GAP (additive edit, exact old→new quoted in that step).

**Interfaces:**
- Consumes (from Phases 2–5, already created): App.svelte focus `$effect` with `queueMicrotask(() => mainEl?.focus())`; `GuidedProgress` `role="status"` + `role="progressbar"`; ScanFlow cancelled banner `role="alert"`; ShieldStatus `<h1 class="shield-heading">` + `.sr` "Status: …"; HealthChip visible `status.label`; grouped `count` badges with `aria-label`; app.css global `@media (prefers-reduced-motion: reduce)` block (lines 355–366).
- Produces: nothing new; only confirmations, and minimal additive a11y fixes if a gap is real.

- [ ] **Step 1: Reduced-motion sweep (new hero/flow/shield animations).** The global block in `app.css` (`@media (prefers-reduced-motion: reduce) { *,*::before,*::after { animation-duration:0.001ms !important; … } }`, lines 355–366) already neutralizes every CSS keyframe animation, so any new `.shield` pulse / hero rise is covered by CSS alone. Only Svelte JS transitions (`in:`/`out:`/`transition:`) can escape that block, so confirm none exist un-gated. Run from `apps/desktop`:
  ```bash
  grep -rn "in:fly\|out:fly\|transition:fly\|in:fade\|out:fade\|in:slide\|transition:slide\|in:scale" src/App.svelte src/routes src/lib/components
  ```
  Expected output: ONLY the two toast lines in `src/App.svelte`, each already gated by the reactive `reduce` flag:
  ```
  src/App.svelte:125:        in:fly={{ y: -8, duration: reduce ? 0 : 150, easing: cubicOut }}
  src/App.svelte:126:        out:fly={{ y: -10, duration: reduce ? 0 : 150, easing: cubicOut }}
  ```
  PASS if the only matches are those two `reduce ?`-gated lines. GAP if any new route/component line appears WITHOUT `reduce ?` — for that file add, in its `<script lang="ts">`, the exact reactive flag used by App.svelte and gate the transition duration with `reduce ? 0 : <n>`:
  ```svelte
  let reduce = $state(
    typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
  $effect(() => {
    if (typeof matchMedia === "undefined") return;
    const mq = matchMedia("(prefers-reduced-motion: reduce)");
    const on = () => (reduce = mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  });
  ```

- [ ] **Step 2: `role="status"` + `role="progressbar"` on GuidedProgress.** Run from `apps/desktop`:
  ```bash
  grep -n 'role="status"\|role="progressbar"\|aria-valuemin\|aria-valuemax\|aria-valuenow\|class:indet\|class="progress' src/lib/components/GuidedProgress.svelte
  ```
  Expected: a `role="status"` live label element AND a `.progress` element with `role="progressbar"`, `aria-valuemin="0"`, `aria-valuemax={total}`, `aria-valuenow={done}` when determinate, plus `class:indet={indeterminate}`. PASS if all appear. GAP (determinate bar missing the value attrs) — additive fix, replacing the bare progress element's opening tag:
  ```svelte
  <!-- old -->
  <div class="progress" class:indet={indeterminate}>
  <!-- new -->
  <div
    class="progress"
    class:indet={indeterminate}
    role="progressbar"
    aria-valuemin="0"
    aria-valuemax={total ?? 0}
    aria-valuenow={done ?? 0}
  >
  ```

- [ ] **Step 3: `role="alert"` on error / incomplete banners.** Run from `apps/desktop`:
  ```bash
  grep -rn 'role="alert"\|role={t.kind' src/App.svelte src/routes/ScanFlow.svelte
  ```
  Expected: `src/App.svelte` toast wrapper `role={t.kind === "error" ? "alert" : "status"}` (line ~124) AND the ScanFlow cancelled/partial banner carrying `role="alert"`. PASS if both present. GAP (ScanFlow banner not an alert) — additive fix on that banner's `<section>` opening tag, mirroring Workspace's honest banner:
  ```svelte
  <!-- old -->
  <section class="card danger">
  <!-- new -->
  <section class="card danger" role="alert">
  ```

- [ ] **Step 4: `aria-label` on bare count badges.** Bare numeric badges (`.count`) must name what they count. Run from `apps/desktop`:
  ```bash
  grep -rn 'class="count' src/routes/ScanFlow.svelte src/routes/RepositoriesDetail.svelte src/lib/components
  ```
  Expected: every `.count` badge that renders only a number carries an `aria-label` (e.g. `aria-label="{list.length} findings"`, matching the Workspace pattern at Workspace.svelte:401). PASS if each match already includes `aria-label`. GAP for any bare badge — additive fix on that span:
  ```svelte
  <!-- old -->
  <span class="count sev-{list[0].severity}">{list.length}</span>
  <!-- new -->
  <span class="count sev-{list[0].severity}" aria-label="{list.length} findings">{list.length}</span>
  ```

- [ ] **Step 5: Focus lands on the new view after navigation.** Run from `apps/desktop`:
  ```bash
  grep -n "queueMicrotask\|mainEl\|app.view" src/App.svelte
  ```
  Expected: a `bind:this={mainEl}` on `<main id="main" tabindex="-1">` AND a `$effect` that references `app.view`, skips the first run, and calls `queueMicrotask(() => mainEl?.focus())`. PASS if that effect and binding exist. GAP (no focus effect) — additive fix, adding after the router markup in the `<script>`:
  ```svelte
  let mainEl = $state<HTMLElement | undefined>();
  let firstView = true;
  $effect(() => {
    app.view;
    if (firstView) {
      firstView = false;
      return;
    }
    queueMicrotask(() => mainEl?.focus());
  });
  ```

- [ ] **Step 6: State conveyed by text, never color alone.** Run from `apps/desktop`:
  ```bash
  grep -n 'shield-heading\|Status:\|class="sr"' src/lib/components/ShieldStatus.svelte
  grep -n 'status.label' src/lib/components/HealthChip.svelte
  grep -n 'Removable automatically\|Needs your attention' src/lib/components/FindingCard.svelte
  ```
  Expected: ShieldStatus renders `<h1 class="shield-heading">{heading}</h1>` plus an `.sr` span containing "Status: …"; HealthChip renders `{status.label}` as visible text alongside its aria-hidden mark; FindingCard renders the literal phrase "Removable automatically" or "Needs your attention". PASS if all three greps return matches. GAP in HealthChip (mark only, no text) — additive fix inside the `<button class="health-chip">`, after the mark:
  ```svelte
  <span class="status-label">{status.label}</span>
  ```
  GAP in ShieldStatus (no textual status word) — additive fix, adding a visually-hidden status word as a sibling of the heading:
  ```svelte
  <span class="sr">Status: {level === "protected" ? "protected" : level === "attention" ? "needs attention" : level === "threat" ? "active threat" : "not yet scanned"}</span>
  ```

- [ ] **Step 7: Skip link, real labels, gear menu semantics.** Run from `apps/desktop`:
  ```bash
  grep -n 'class="skip"\|href="#main"' src/App.svelte
  grep -rn 'role="menu"\|role="menuitem"' src/App.svelte
  grep -rn '<label' src/routes/Settings.svelte
  ```
  Expected: `src/App.svelte` keeps `<a class="skip" href="#main">Skip to content</a>`; the gear (⚙) menu grep for `role="menu"`/`role="menuitem"` returns NOTHING (plain buttons in a labelled container, per contract); Settings token/location fields use real `<label>`/`aria-label`. PASS if skip link present, menu-role grep empty, Settings labels present. GAP (a stray `role="menu"` was added) — additive fix: delete the `role="menu"`/`role="menuitem"` attributes from those elements (they advertise keyboard semantics not implemented). GAP (skip link removed) — re-add the exact line above as the first child of the shell markup.

- [ ] **Step 8: Typecheck and commit any a11y fixes.** From `apps/desktop`:
  ```bash
  pnpm check
  ```
  Expected: `svelte-check found 0 errors and 0 warnings`. If Steps 1–7 applied one or more additive fixes, stage exactly the files you edited and commit; if the sweep found zero gaps, nothing was edited — skip the commit and proceed to Task 6.2. Example (adjust the path list to the files actually edited):
  ```bash
  git add src/App.svelte src/lib/components/GuidedProgress.svelte
  git commit -m "fix(desktop): a11y sweep — restore role/aria/focus gaps on new screens"
  ```
  Expected: a commit is created (or "nothing to commit" if no gaps were found, in which case do not force an empty commit).

### Task 6.2: Empty / partial / cancelled-state audit (verify honest copy, do not duplicate branches)

**Files:**
- Verify (read-only unless a gap is found): `apps/desktop/src/routes/Home.svelte`, `apps/desktop/src/routes/ScanFlow.svelte`, `apps/desktop/src/routes/MachineDetail.svelte`, `apps/desktop/src/routes/RepositoriesDetail.svelte`, `apps/desktop/src/lib/protection.ts`
- Modify only if a step reports a real, missing branch (additive, exact old→new quoted).

**Interfaces:**
- Consumes: honest-state copy written in Phases 2–5; `protection.ts` derivation rules (`machineStatus` null → "Not checked", `reposStatus` null → "Not scanned", cancelled → "Scan incomplete", `overallLevel` never "protected" while any surface is "unknown").
- Produces: confirmation that each enumerated state is handled by an existing branch; no new copy tables.

- [ ] **Step 1: Pre-scan (Home, nothing scanned yet).** Honest requirement: when `app.lastScanAt === null` the hero shows a neutral "not scanned" heading/level, never "protected". Run from `apps/desktop`:
  ```bash
  grep -n 'lastScanAt\|Not scanned yet\|hasLocations' src/routes/Home.svelte
  ```
  Expected: a branch keyed on `app.lastScanAt === null` (and/or `!hasLocations()` for first-run) that passes a neutral heading such as "Not scanned yet" and a non-"protected" level into `ShieldStatus`. PASS if that branch exists. GAP (Home derives level from protection even before any scan) — additive fix on the level passed to the hero:
  ```svelte
  <!-- old -->
  <ShieldStatus level={overall} heading={heading} sub={sub} />
  <!-- new -->
  <ShieldStatus
    level={app.lastScanAt === null ? "unknown" : overall}
    heading={app.lastScanAt === null ? "Not scanned yet" : heading}
    sub={app.lastScanAt === null ? "Run a Full Scan to check." : sub}
  />
  ```

- [ ] **Step 2: Scanning (ScanFlow in progress).** Run from `apps/desktop`:
  ```bash
  grep -n 'Checking your Mac and your code\|GuidedProgress\|cancelScan\|Stop' src/routes/ScanFlow.svelte
  ```
  Expected: the `scanning` step renders `<GuidedProgress label="Checking your Mac and your code…" … />` with a quiet Stop button wired to `cancelScan()`. PASS if both present. GAP (Stop missing) — additive fix inside the scanning branch, mirroring Workspace's Stop:
  ```svelte
  <button class="btn ghost sm" onclick={stop} disabled={stopping}>{stopping ? "Stopping…" : "Stop"}</button>
  ```

- [ ] **Step 3: Cancelled / partial run (ScanFlow).** Honest requirement: a cancelled or partial scan must NOT show "all clear". Run from `apps/desktop`:
  ```bash
  grep -n 'cancelled\|incomplete\|role="alert"' src/routes/ScanFlow.svelte
  ```
  Expected: a `report?.cancelled`-guarded banner with `role="alert"` stating the run was stopped early and results are incomplete (parallel to Workspace.svelte:354–359 "Scan stopped early — results are incomplete"). PASS if that guarded alert exists. GAP (no cancelled branch) — additive fix, inserted at the top of the `results` step:
  ```svelte
  {#if report?.cancelled}
    <section class="card danger" role="alert">
      <h2 class="danger-text">Scan stopped early — results are incomplete</h2>
      <p class="muted small">Some of your Mac or code wasn't checked. Run a Full Scan again for a complete picture.</p>
    </section>
  {/if}
  ```

- [ ] **Step 4: No-threats (ScanFlow results + RepositoriesDetail).** Honest requirement: a clean/"protected" state only after a real, completed scan. Run from `apps/desktop`:
  ```bash
  grep -n 'No threats\|Everything.s clean\|you.re protected\|cancelled' src/routes/ScanFlow.svelte
  grep -n 'No threats\|hasn.t been scanned\|lastScanAt\|report ==' src/routes/RepositoriesDetail.svelte
  ```
  Expected: ScanFlow's `clean` step reads "Everything's clean — you're protected" ONLY when not cancelled and findings are zero; RepositoriesDetail distinguishes "not scanned yet" (`app.report === null`) from "no threats" (report present, zero findings) rather than asserting clean on a null report. PASS if both distinctions exist. GAP (RepositoriesDetail asserts clean on null report) — additive fix guarding the empty state:
  ```svelte
  <!-- old -->
  {#if findings.length === 0}
    <div class="state ok"><div class="glyph">✓</div><h2>No threats</h2></div>
  {/if}
  <!-- new -->
  {#if app.report === null}
    <div class="state"><div class="glyph">◎</div><h2>Not scanned yet</h2><p class="muted micro">Run a Full Scan from Home to check your repositories.</p></div>
  {:else if findings.length === 0}
    <div class="state {app.report.cancelled ? '' : 'ok'}"><div class="glyph">{app.report.cancelled ? "◔" : "✓"}</div><h2>{app.report.cancelled ? "Scan incomplete" : "No threats"}</h2></div>
  {/if}
  ```

- [ ] **Step 5: Threats found (ScanFlow results).** Run from `apps/desktop`:
  ```bash
  grep -n 'threats found\|can be removed safely\|need your review\|Remove threats safely' src/routes/ScanFlow.svelte
  ```
  Expected: the human summary line "N threats found. X can be removed safely and automatically; Y need your review." (built with the local `const plural`) plus the primary "Remove threats safely" button. PASS if both present. GAP (summary hard-codes singular/plural wrong) — verify a LOCAL `const plural = (n, one, many) => (n === 1 ? one : many);` exists in the file (`grep -n 'const plural' src/routes/ScanFlow.svelte`); if absent, add that exact line at the top of the `<script>` and use it in the summary — do NOT import a shared plural.

- [ ] **Step 6: Machine-not-checked (MachineDetail idle).** Honest requirement: no "all good" before a manual check; does not auto-run on mount. Run from `apps/desktop`:
  ```bash
  grep -n 'been checked yet\|Run a check\|Checking this Mac\|onMount' src/routes/MachineDetail.svelte
  ```
  Expected: when `app.machineReport === null` an idle state "This Mac hasn't been checked yet" + a "Run a check" button; while a manual check runs "Checking this Mac…"; and NO `onMount(runCheck)` (unlike the old Doctor.svelte:71–73). PASS if the idle branch exists and no `onMount` auto-run is present. GAP (auto-runs on mount) — additive fix: delete the `onMount(() => { runCheck(); });` block so the view rests idle until the user clicks "Run a check". GAP (no idle state) — additive fix guarding the report:
  ```svelte
  {#if app.machineReport === null && !running}
    <div class="state"><span class="glyph">◎</span><p>This Mac hasn't been checked yet.</p>
      <button class="btn primary" onclick={runCheck}>Run a check</button>
    </div>
  {/if}
  ```

- [ ] **Step 7: Confirm `overallLevel` cannot read "protected" while any surface is unknown.** Run from `apps/desktop`:
  ```bash
  pnpm exec vitest run src/lib/protection.test.ts
  ```
  Expected: the Phase-1 protection suite passes, including the case that `overallLevel({level:"protected"}, {level:"unknown"})` returns `"unknown"` (never "protected"). PASS if the suite is green. This is a read-only confirmation; if the test is missing this exact case the gap belongs to Phase 1 — record it, do not add copy here.

- [ ] **Step 8: Commit any honest-state fixes.** From `apps/desktop`:
  ```bash
  pnpm check
  ```
  Expected: `svelte-check found 0 errors and 0 warnings`. If Steps 1–6 applied any additive branch, stage the edited files and commit; otherwise skip. Example (adjust to files actually edited):
  ```bash
  git add src/routes/RepositoriesDetail.svelte src/routes/Home.svelte
  git commit -m "fix(desktop): honest empty/cancelled states on Home and Repositories"
  ```
  Expected: a commit is created, or "nothing to commit" if no gaps were found (do not force an empty commit).

### Task 6.3: Delete dead routes, prove no import breaks, commit

**Files:**
- Delete: `apps/desktop/src/routes/Doctor.svelte`, `apps/desktop/src/routes/GitHub.svelte`, `apps/desktop/src/routes/Workspace.svelte`
- Verify (read-only): `apps/desktop/src/App.svelte` (must already import `Home`, `ScanFlow`, `MachineDetail`, `RepositoriesDetail`, `Advanced`, `Settings` and none of the deleted three, per the Phase-5 views map).

**Interfaces:**
- Consumes: the Phase-5 canonical `views` map `{ home: Home, flow: ScanFlow, machine: MachineDetail, repos: RepositoriesDetail, advanced: Advanced, settings: Settings }` — the three deleted files are unrouted by now.
- Produces: a smaller tree; `pnpm check` (0 errors) and `pnpm build` (success) as proof nothing imported them.

- [ ] **Step 1: Prove nothing imports the three files before deleting.** Run from `apps/desktop`:
  ```bash
  grep -rn "routes/Doctor\|routes/GitHub\|routes/Workspace\|from \"./Doctor\|from \"./GitHub\|from \"./Workspace" src
  ```
  Expected: NO output (empty). If any line appears (e.g. a lingering `import Doctor from "./routes/Doctor.svelte"` in `src/App.svelte`), that import is a Phase-5 leftover — replace it with the correct real component from the views map before deleting, e.g.:
  ```svelte
  <!-- old -->
  import Doctor from "./routes/Doctor.svelte";
  <!-- new -->
  import MachineDetail from "./routes/MachineDetail.svelte";
  ```
  Re-run the grep until it returns empty.

- [ ] **Step 2: Delete the three dead route files.** Run from `apps/desktop`:
  ```bash
  git rm src/routes/Doctor.svelte src/routes/GitHub.svelte src/routes/Workspace.svelte
  ```
  Expected output: `rm 'src/routes/Doctor.svelte'`, `rm 'src/routes/GitHub.svelte'`, `rm 'src/routes/Workspace.svelte'` (three lines), and the files are staged for deletion.

- [ ] **Step 3: Confirm no dangling references remain after deletion.** Run from `apps/desktop`:
  ```bash
  grep -rn "Doctor\.svelte\|GitHub\.svelte\|Workspace\.svelte" src
  ```
  Expected: NO output. If anything appears, remove that reference (it is dead) before continuing.

- [ ] **Step 4: Typecheck.** Run from `apps/desktop`:
  ```bash
  pnpm check
  ```
  Expected: `svelte-check found 0 errors and 0 warnings` — proving nothing depended on the deleted files.

- [ ] **Step 5: Production build.** Run from `apps/desktop`:
  ```bash
  pnpm build
  ```
  Expected: Vite completes with `✓ built in …` and a non-error exit; no "Could not resolve" / "Rollup failed to resolve import" errors referencing the removed routes.

- [ ] **Step 6: Manual smoke.** Run from `apps/desktop`:
  ```bash
  pnpm tauri dev
  ```
  Then: on Home click "Full Scan" and watch the guided flow reach results; press the gear (⚙) → open Advanced and confirm GitHub account scan, other-branches, and Restore are reachable; click the "This Mac" and "Repositories" chips and confirm MachineDetail and RepositoriesDetail render. Observe: every view loads with no blank screen and no console error about a missing `Doctor`/`GitHub`/`Workspace` module — proving the deletions left nothing unreachable.

- [ ] **Step 7: Commit the cleanup.** From `apps/desktop`:
  ```bash
  git commit -m "refactor(desktop): remove dead Doctor/GitHub/Workspace routes after antivirus redesign"
  ```
  Expected: a commit recording three file deletions (`git show --stat HEAD` lists the three removed routes). No `Co-Authored-By: Claude` trailer.