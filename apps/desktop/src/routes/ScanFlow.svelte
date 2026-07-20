<script lang="ts">
  import { onMount } from "svelte";
  import { app, fail, clearErrors, go, notify } from "../lib/state.svelte";
  import { scan, doctor, cancelScan, cleanPreview, cleanApply } from "../lib/api";
  import { listen } from "@tauri-apps/api/event";
  import GuidedProgress from "../lib/components/GuidedProgress.svelte";
  import FindingCard from "../lib/components/FindingCard.svelte";
  import type { ScanProgress, Finding, RepoPlan } from "../lib/types";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  // --- scanning ---
  let stopping = $state(false);
  let repoLog = $state<ScanProgress[]>([]);
  let progress = $state<ScanProgress | null>(null);
  let logEl = $state<HTMLDivElement | null>(null);

  // --- results / clean ---
  let plans = $state<RepoPlan[]>([]);
  let removedSummary = $state("");

  // C5: the guided flow advances by mutating app.flow (not app.view), so App.svelte's
  // view-level focus effect never fires on scanning→results→cleaning→clean. Only one flow
  // step renders at a time, so a single binding tracks whichever heading is on screen.
  let stepHeadingEl = $state<HTMLElement | undefined>();

  const report = $derived(app.report);
  const findings = $derived(report?.findings ?? []);
  const total = $derived(findings.length);
  const cancelled = $derived(report?.cancelled ?? false);
  // Branch-tip findings (git_ref set) have no working-tree clean action — cleanPreview
  // produces no plan for them, so the "Remove threats safely" button can't touch them.
  // They're only reachable via Advanced → branch cleaning, so they must count toward
  // "manual" (need your review), not "removable" — otherwise the summary promises an
  // automatic removal the UI has no button for.
  const removable = $derived(findings.filter((f) => f.remediable && !f.git_ref).length);
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
      // Online cross-check is opt-in (app.online) AND needs a token; without one, fall back to an
      // offline scan and tell the user rather than erroring or silently ignoring the choice.
      const online = app.online && !!osmToken;
      if (app.online && !osmToken) {
        notify("warn", "Scanned offline — add an OpenSourceMalware token in Settings to check packages online.");
      }
      // Full Scan covers the surfaces the user chose (both on by default). An excluded surface keeps
      // its previous result rather than being re-checked. Deep is always on: it also checks the
      // latest commit on every branch (worms hide on non-default branches); branch-tip findings
      // surface with git_ref set and are cleaned from Advanced, not the "Remove threats" button.
      const [machine, repos] = await Promise.all([
        app.scanMac ? doctor() : Promise.resolve(app.machineReport),
        app.scanRepos
          ? scan(app.dirs, true, online, osmToken, app.history, app.community, app.osv)
          : Promise.resolve(app.report),
      ]);
      app.machineReport = machine;
      app.report = repos;
      app.lastScanAt = Date.now();
      // cleanPreview re-scans every repo (uncancellable). Skip it when code wasn't scanned, or the
      // run was cancelled/partial — Stop/partial should land on results at once, and a one-click
      // clean shouldn't be offered on partial or stale data.
      plans = app.scanRepos && !repos?.cancelled ? await cleanPreview(app.dirs) : [];
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

  async function removeThreats() {
    app.flow = "cleaning";
    clearErrors();
    try {
      const s = await cleanApply(fixableRepos);
      // Re-scan so app.report reflects the cleaned tree — Home's shield and the
      // Repositories detail must NOT keep showing threats we just removed (honest state,
      // mirrors Workspace.apply()'s re-run). scan() is already imported (Task 3.3).
      const osmToken = localStorage.getItem("osm_token") || undefined;
      app.report = await scan(app.dirs, true, app.online && !!osmToken, osmToken, app.history, app.community, app.osv);
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

  onMount(runScan);

  // Keep the live log pinned to its latest line.
  $effect(() => {
    void progress;
    void repoLog.length;
    if (logEl) logEl.scrollTop = logEl.scrollHeight;
  });

  // C5: move keyboard/screen-reader focus to the freshly-rendered step heading on every
  // flow transition (scanning→results→cleaning→clean). App.svelte's focus effect is keyed
  // on app.view and never sees these app.flow sub-steps. queueMicrotask defers until the new
  // heading has mounted and rebound stepHeadingEl. Complements GuidedProgress's role="status".
  $effect(() => {
    void app.flow;
    queueMicrotask(() => stepHeadingEl?.focus());
  });
</script>

<div class="flow">
  {#if app.flow === "scanning" || app.flow === null}
    <section class="flow-step scanning-step">
      <h1 class="flow-title" tabindex="-1" bind:this={stepHeadingEl}>Scanning…</h1>
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
      <h1 class="flow-title" tabindex="-1" bind:this={stepHeadingEl}>Scan complete</h1>

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

  {#if app.flow === "cleaning"}
    <section class="flow-step">
      <h1 class="flow-title" tabindex="-1" bind:this={stepHeadingEl}>Removing threats…</h1>
      <GuidedProgress label="Removing threats safely…" indeterminate={true} />
    </section>
  {/if}

  {#if app.flow === "clean"}
    <section class="flow-step">
      <div class="card ok">
        <div class="state ok">
          <div class="glyph" aria-hidden="true">✓</div>
          {#if manual > 0}
            <h2 tabindex="-1" bind:this={stepHeadingEl}>Threats removed — a few need your review</h2>
            <p class="muted micro">{removedSummary} {manual} {plural(manual, "threat", "threats")} still {plural(manual, "needs", "need")} your attention.</p>
          {:else}
            <h2 tabindex="-1" bind:this={stepHeadingEl}>Everything's clean — you're protected</h2>
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
  /* Fill the view and center the step so a short/compact flow (and the capped log) doesn't
     leave a tall empty tail below it — `main` reserves min-height: 100vh - topbar, and a
     top-aligned .flow left that space blank (the "scroll gap" under Show details). `safe`
     centering falls back to top-aligned + page scroll when a step is taller than the viewport
     (e.g. a long results list), so nothing is ever clipped. */
  .flow { max-width: var(--content); margin: 0 auto; padding: 40px 24px; min-height: calc(100vh - var(--topbar-h)); display: flex; flex-direction: column; justify-content: safe center; gap: var(--gap-page); }
  .flow-step { display: flex; flex-direction: column; gap: 16px; }
  .flow-title { font-size: 20px; letter-spacing: -0.025em; }
  .flow-summary { font-size: 14px; line-height: 1.6; color: var(--fg); }
  .flow-actions { display: flex; gap: 10px; flex-wrap: wrap; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }

  .log-details > summary { cursor: pointer; color: var(--muted); font-size: 12.5px; width: fit-content; }
  .log-details > summary:hover { color: var(--fg); }
  .log-details[open] > summary { margin-bottom: 10px; }
  .term-body { background: var(--inset); border-radius: var(--radius); padding: 12px 14px; max-height: 220px; overflow-y: auto; font-family: var(--mono); font-size: 12px; line-height: 1.6; color: var(--fg); }

  /* Scanning step fills the view; its OPEN log takes the leftover height and scrolls INTERNALLY,
     so a streaming log never grows the page (no growing scroll), leaves no empty tail, and doesn't
     reflow as lines stream in. The status block above it keeps its natural height. */
  .scanning-step { flex: 1; min-height: 0; justify-content: safe center; }
  .scanning-step .log-details[open] { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  .scanning-step .log-details[open] > summary { flex: none; }
  .scanning-step .log-details[open] .term-body { flex: 1; min-height: 0; max-height: none; }
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

  .camp { display: flex; flex-direction: column; gap: 8px; }
  .camp-head { display: flex; align-items: center; justify-content: space-between; }
  .camp-head h2 { font-size: 13.5px; }
  .finding-list { display: flex; flex-direction: column; gap: 8px; list-style: none; margin: 0; padding: 0; }
  .count.sev-critical { background: var(--danger); color: #150a0b; }
  .count.sev-high { background: var(--danger-tint); color: var(--danger); }
  .count.sev-medium { background: var(--warn-tint); color: var(--warn); }
</style>
