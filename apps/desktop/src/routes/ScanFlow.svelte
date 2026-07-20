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

  // C5: the guided flow advances by mutating app.flow (not app.view), so App.svelte's
  // view-level focus effect never fires on scanning→results→cleaning→clean. Only one flow
  // step renders at a time, so a single binding tracks whichever heading is on screen.
  let stepHeadingEl = $state<HTMLElement | undefined>();

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
    <section class="flow-step">
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
