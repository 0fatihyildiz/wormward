# GUI: reshape the desktop app into a consumer-antivirus experience

Date: 2026-07-20

Turn the current developer-oriented, tab-based Tauri UI into a calm, minimalist
**antivirus-style** app that a non-technical person can use comfortably — one big
protection status, one dominant "Full Scan" button, a guided results→clean flow, and
all technical power tucked behind progressive disclosure. The Rust detection/remediation
engine and Tauri commands stay as-is; this is an information-architecture, flow, and
language redesign in the Svelte frontend.

## Locked decisions (from brainstorming)
- **Structural model:** Home screen + guided flow. The tab bar is removed.
- **Scan model:** a single **Full Scan** runs both surfaces — this machine (`doctor()`)
  and the user's repos (`scan(dirs)`) — in one flow with one combined result.
- **Theme:** keep the existing refined **dark** design system; calm it (bigger hero, more
  whitespace, larger type, friendly shield). No light theme this round.
- **Language:** product copy stays **English**, but all jargon is rewritten in plain
  language. No i18n this round.
- **Scope:** plan the **whole** transformation as one cohesive spec + phased build.

## Goals
- A non-technical user can open the app, understand their status at a glance, run one
  scan, and remove threats without meeting a single git/CLI term.
- A power user still reaches every current capability (GitHub force-push, other-branch
  cleaning, restore, tokens, packs) — one quiet click away, never in the main path.
- No loss of the existing accessibility, honest-state, and notification wins.

## Non-goals / YAGNI
- No new detection or remediation engine; no new Rust crates required for the core flow.
- No light theme, no i18n, no real background daemon. "Live monitoring" remains the
  existing periodic `doctor()` re-check — labeled honestly, never oversold as always-on.
- No multi-step onboarding wizard — first-run is a single "choose your code folder" step.

## Principles
- **One status, one action.** The resting app answers "am I safe?" and offers "Full Scan".
- **Honest states.** Never assert "protected"/"clean" before a scan has actually run;
  reflect cancelled/partial runs. (Preserves the current `scanned`/`cancelled` discipline.)
- **Progressive disclosure.** Plain outcome first; raw evidence, paths, campaign IDs, and
  destructive git operations live behind "Details" / the Advanced area.
- **Calm over dense.** Fewer things per screen, larger targets, generous space.

## Target users
- **Primary:** a less-technical developer / small-team owner who wants reassurance and a
  guided cleanup, not a control panel.
- **Secondary (unchanged power):** an engineer who wants branch rewrites, remote
  force-push, and token control — served by the Advanced area.

---

## Information architecture

The `app.screen` 4-tab model is replaced by a small view state machine:

```
view:  home | flow | machine | repos | advanced | settings
flow (only when view === 'flow'):  scanning | results | cleaning | clean
```

- **Home** — default resting view. Protection status + Full Scan + two health chips + ⚙.
- **Flow** — full-screen guided scan takeover (not a tab). Owns scanning→results→
  cleaning→clean. Reuses today's Workspace scan/clean logic.
- **Machine** — "This Mac" detail (today's Doctor, in plain language).
- **Repos** — "Repositories" detail (per-repo findings from the last report).
- **Advanced** — GitHub account scan + force-push, other-branch cleaning, restore backup.
- **Settings** — protected locations (new), tokens, campaign packs, appearance.

Navigation: Home is the hub. The ⚙ button opens a small menu → Advanced / Settings.
Detail views and the flow have a back affordance to Home. No persistent tab bar.

---

## Screens

### 1. First-run (protected locations)
On launch with no saved locations, Home shows a "Get started" variant instead of a
status: one line explaining what Wormward protects, and one action —
**"Choose your code folder"** (multi-select `pickDirs()`), with a secondary
**"Use my home folder"** (defaults to `~`). The chosen set is persisted as
**protected locations** and becomes the default Full Scan target. Editable later in
Settings. No wizard, no second step.

### 2. Home (resting status)
```
┌────────────────────────────────────────┐
│  Wormward                          ⚙   │
│                                        │
│                 ◯  (large shield)      │
│                                        │
│            You're protected            │
│      Last scan: today 14:20 · clean    │
│                                        │
│          [     Full Scan     ]         │
│                                        │
│     This Mac  ✓         Repos  ✓        │
└────────────────────────────────────────┘
```
- **Shield color = overall protection level** (see logic below): green protected /
  amber needs-attention / red active-threat / neutral not-yet-scanned.
- **Status line** is honest: before any scan → "Not scanned yet — run a Full Scan to
  check." After → level-appropriate copy + last-scan time and one-line summary.
- **Full Scan** is the single primary button; starts the guided flow.
- **Health chips** ("This Mac", "Repos") summarize each surface with a ✓/⚠/✗ and open
  the corresponding detail view.

### 3. Guided Scan Flow (the single button → full screen)
One flow, both surfaces, one progress. Full Scan triggers `doctor()` and `scan(locations, deep, online, token)`
and presents a unified journey:

- **scanning** — calm progress: "Checking your Mac and your code…" with a combined
  counter fed by the existing `local-scan-progress` events and the doctor call. The raw
  per-repo log is hidden by default behind "Show details" (reuses today's terminal log).
  A quiet **Stop** maps to `cancelScan()`.
- **results** — human summary first:
  > **3 threats found.** 2 can be removed safely and automatically; 1 needs your review.
  >
  > [ Remove threats safely ]   [ Details ]

  Worst-first ordering preserved; critical ≠ high. Each item is a card with plain title +
  a per-item **Details** disclosure exposing raw evidence, file path, campaign, branch,
  and the online verdict. If the scan was cancelled/partial, say so (no false "all clear").
  Clean result → **cleaning** → then:
- **clean** — a reassuring end state: "Everything's clean — you're protected," with a
  return to Home. If manual-review items remain, the copy is honest ("2 removed · 1 still
  needs your attention") and links into the Repos detail.

Remediation maps to existing calls: `cleanPreview()` (auto-run to build the plan, as
today) → `cleanApply(fixableRepos)`. Destructive remote/branch operations never appear
here — they live in Advanced.

### 4. This Mac (Machine detail — today's Doctor, plain language)
Same three checks, rewritten and reordered worst-first:

| Current (technical) | Plain-language surface |
|---|---|
| Running loader (process) | "Is a threat running right now?" — ✓ none / ✗ found (with fix guidance) |
| Toolchain caches | "Infected app caches" → **[Clean up]** (per dir, with confirm) |
| Re-infection triggers | "Risky settings that let malware come back" → **[Fix]** (harden) |
| Watch (5s poll) | **"Live monitoring"** toggle — honest sublabel: "re-checks every few seconds" |
| Harden / block install scripts | **"Turn on protection"** |

Keeps `doctor()` / `doctorClearCache()` / `doctorHardenTriggers()` verbatim.

### 5. Repositories (Repos detail)
Per-repo findings from the last `ScanReport`, grouped and worst-first (reuses today's
grouping). Plain labels: "Removable automatically" / "Needs your attention". A quiet link
to Advanced for other-branch cleaning and restore.

### 6. Advanced (⚙ → Advanced)
Everything dangerous or power-only, clearly labeled and behind the existing confirm
modals:
- **GitHub account** — token, org picker, account scan, **Fix & force-push** (destructive,
  remote). Moves out of the main path; keeps all current safety (unselected-by-default,
  disarm-after-fix, confirm modal).
- **Other branches** — deep branch-tip cleaning + optional force-push (today's Advanced
  block in Workspace).
- **Restore last backup** — the guarded re-introduce-originals action.

### 7. Settings (⚙ → Settings)
- **Protected locations** (new) — view/add/remove the folders Full Scan targets.
- **Tokens** — OSM + GitHub (unchanged fields, honest local-storage disclosure).
- **Campaign packs** — unchanged read-only list.
- **Appearance** — minimal; dark only for now (placeholder for a future light theme).

---

## Protection-level logic (single source of truth)
A derived `protectionLevel` drives the shield, status line, and chips:

- **red (active threat):** any running-loader process, OR any `critical` finding.
- **amber (needs attention):** no red, but any finding remains, OR exposed re-infection
  triggers, OR infected caches, OR manual-review items after a clean.
- **green (protected):** a scan ran, nothing above is true.
- **neutral (unknown):** no scan has run yet this session, or last run was cancelled.

Machine chip derives from the `DoctorReport`; Repos chip from the `ScanReport`. Overall =
worst of the two. This logic lives in one module, not scattered across components.

---

## Frontend structure (design for isolation)

New/changed units, each with one clear job:

- `lib/state.svelte.ts` — extend: `view`, `flow`, `machineReport: DoctorReport | null`,
  `lastScanAt`, protected locations getters. Keep `report`, `toasts`, notify/fail.
- `lib/protection.svelte.ts` (new) — pure derivation of `protectionLevel` + per-surface
  status from `machineReport` + `report`. No UI.
- `lib/locations.ts` (new) — load/save protected locations (localStorage; a Tauri store
  is a later option). Small, testable.
- `App.svelte` — becomes a shell: view routing, global toasts, ⚙ menu. Tab bar + sliding
  pill removed.
- `routes/Home.svelte` (new) — status hero + Full Scan + chips + first-run variant.
- `routes/ScanFlow.svelte` (new) — orchestrates the unified scan + the 4 flow steps.
  Absorbs the scan/results/clean logic from today's `Workspace.svelte`.
- `routes/MachineDetail.svelte` (rename of `Doctor.svelte`) — plain-language machine view.
- `routes/RepositoriesDetail.svelte` (new) — per-repo findings detail.
- `routes/Advanced.svelte` (new) — GitHub (from `GitHub.svelte`) + branches + restore.
- `routes/Settings.svelte` — add protected locations + appearance.
- Shared components: `ShieldStatus.svelte`, `HealthChip.svelte`, `FindingCard.svelte`
  (with Details disclosure), `GuidedProgress.svelte`.

`Workspace.svelte` and `GitHub.svelte` are decomposed into the above; no logic is
discarded, only relocated and re-skinned.

## Design-system changes (`app.css`)
Additive, not a rewrite — the token system, semantic surfaces, buttons, switches, modals,
and motion all stay. Add: a large hero/shield scale, a bigger primary-CTA size, a
`--gap-hero` spacing step, and status-tinted shield styles keyed to `protectionLevel`.
Everything else (borderless elevation, single accent, reduced-motion, focus-visible)
is preserved.

## Backend / Tauri impact
Effectively none for the core flow. All of `scan`, `cancel_scan`, `clean_preview`,
`clean_apply`, `restore`, `clean_branches_*`, `github_*`, `doctor*`, `list_packs` are
reused as-is. `scan(dirs)` already walks recursively, so "protected locations" are just
the dirs we pass — no discovery command needed. Any Tauri work (e.g. keychain-backed
token storage) is out of scope here.

## Accessibility & motion (preserve)
Carry forward every current win: skip link, `role=status`/`progressbar`, text labels for
state (not color-only — the shield always pairs color with a word), real `<label>`s,
semantic lists, focus-visible, and full `prefers-reduced-motion` support for the new
hero/flow animations. The shield's status must be conveyed textually, never by color alone.

---

## Phased implementation
Each phase is committed on its own and checked in between. No phase leaves the app broken
or a feature unreachable.

- **Phase 1 — Shell & state.** New `view`/`flow` state machine, `protection.svelte.ts`,
  `locations.ts`; strip the tab bar; App becomes a shell with ⚙ menu. Old screens
  temporarily reachable via Advanced so nothing is lost.
- **Phase 2 — Home & first-run.** `ShieldStatus`, `HealthChip`, Home screen, protected-
  locations first-run + Settings editor.
- **Phase 3 — Guided Scan Flow.** `ScanFlow` with unified `doctor()`+`scan()` orchestration
  and the scanning→results→cleaning→clean steps; `FindingCard` with Details disclosure.
- **Phase 4 — Detail views.** `MachineDetail` (plain-language Doctor) + `RepositoriesDetail`.
- **Phase 5 — Advanced & Settings.** Relocate GitHub, other-branches, restore into
  Advanced; finish Settings (locations, appearance).
- **Phase 6 — Microcopy & polish.** Plain-language pass across every string, a11y sweep on
  new screens, motion/reduced-motion verification, empty/partial-state audit.

## Risks / open questions
- **"Full Scan" runtime** if protected locations include a huge tree — mitigate with the
  existing progress + Stop, and by defaulting the first-run pick to the user's code folder
  rather than all of `~` when they choose "Choose your code folder".
- **"Live monitoring" honesty** — must read as periodic re-check, not always-on protection.
- **GitHub discoverability** — a power user must still find account scanning; the ⚙ menu
  labels it clearly ("GitHub account — advanced").
