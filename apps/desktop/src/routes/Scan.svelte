<script lang="ts">
  import { app, fail, clearErrors } from "../lib/state.svelte";
  import { scan, pickDirs, cancelScan } from "../lib/api";
  import { listen } from "@tauri-apps/api/event";
  import type { ScanProgress } from "../lib/types";

  let deep = $state(false);
  let online = $state(false);
  let stopping = $state(false);
  // One entry per repo, upserted as it moves scanning → scanned (with its finding count).
  let repoLog = $state<ScanProgress[]>([]);
  let progress = $state<ScanProgress | null>(null);

  // Re-evaluated whenever `online` toggles (localStorage itself isn't reactive).
  const noOsmToken = $derived(online && !localStorage.getItem("osm_token"));

  async function choose() {
    try {
      const dirs = await pickDirs();
      if (dirs.length) app.dirs = dirs;
    } catch (e) {
      fail(e);
    }
  }

  async function run() {
    clearErrors();
    app.scanning = true;
    repoLog = [];
    progress = null;
    // Register BEFORE invoking so no early event is missed.
    const unlisten = await listen<ScanProgress>("local-scan-progress", (e) => {
      const p = e.payload;
      // `done` only advances on "scanned"; never roll the counter backwards.
      if (!progress || p.done > progress.done) progress = p;
      // Upsert by repo so each row transitions scanning → scanned in place.
      const idx = repoLog.findIndex((r) => r.repo === p.repo);
      if (idx >= 0) repoLog[idx] = p;
      else repoLog = [...repoLog, p];
    });
    try {
      const token = localStorage.getItem("osm_token") || undefined;
      app.report = await scan(app.dirs, deep, online, token);
      app.screen = "results";
    } catch (e) {
      fail(e);
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

  const pct = $derived(progress && progress.total ? (progress.done / progress.total) * 100 : 0);

  // Keep the log pinned to its latest line as repos start/finish.
  let bodyEl = $state<HTMLDivElement | null>(null);
  $effect(() => {
    void progress;
    void repoLog.length;
    if (bodyEl) bodyEl.scrollTop = bodyEl.scrollHeight;
  });
</script>

<div class="page">
  <div class="page-head">
    <h1>Scan</h1>
    <p class="lede">Detect supply-chain worms across your repositories — read-only.</p>
  </div>

  <section class="card">
    <div class="field">
      <div class="row between">
        <span class="field-label">Target folders</span>
        <button class="btn sm" onclick={choose} disabled={app.scanning}>Choose folders…</button>
      </div>
      <p class="path-preview mono" class:empty={!app.dirs.length}>
        {app.dirs.length ? app.dirs.join("  ·  ") : "No folder chosen — pick one to scan."}
      </p>
    </div>

    <div class="opts">
      <label class="switch">
        <input type="checkbox" bind:checked={deep} disabled={app.scanning} />
        <span class="track"></span>
        <span class="lbl">Deep scan <span class="muted">— inspect every branch tip</span></span>
      </label>
      <label class="switch">
        <input type="checkbox" bind:checked={online} disabled={app.scanning} />
        <span class="track"></span>
        <span class="lbl">Online cross-check <span class="muted">— check packages against OpenSourceMalware</span></span>
      </label>
      {#if online}
        <p class="opt-note">
          Sends the names of packages found in your scan to the external opensourcemalware.com
          service.{#if noOsmToken} Needs a token — add one in Settings.{/if}
        </p>
      {/if}
    </div>

    <div class="row">
      {#if app.scanning}
        <button class="btn primary" disabled aria-busy="true">
          <span class="spinner"></span>Scanning…
        </button>
        <button class="btn danger" onclick={stop} disabled={stopping}>
          {stopping ? "Stopping…" : "Stop"}
        </button>
      {:else}
        <button class="btn primary" onclick={run} disabled={!app.dirs.length}>Scan →</button>
        {#if !app.dirs.length}<span class="muted micro">Choose a folder to scan.</span>{/if}
      {/if}
    </div>

    {#if app.scanning}
      <div class="scan-status" role="status" aria-live="polite">
        {#if progress}
          <strong>{progress.done} of {progress.total}</strong> repositories scanned
        {:else}
          Discovering repositories…
        {/if}
      </div>
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
    {/if}
  </section>

  {#if app.scanning || repoLog.length}
    <section class="terminal">
      <div class="term-body" bind:this={bodyEl}>
        {#each repoLog as r (r.repo)}
          {#if r.phase === "scanning"}
            <div class="line scanning">
              <span class="spinner"></span>
              <span class="tag">scanning</span>
              <span class="repo" title={r.repo}>{r.repo}</span>
            </div>
          {:else}
            <div class="line" class:hit={r.findings}>
              <span class="mark {r.findings ? 'hit' : 'ok'}" aria-hidden="true">{r.findings ? "✗" : "✓"}</span>
              <span class="sr">{r.findings ? "threats found:" : "clean:"}</span>
              <span class="repo" title={r.repo}>{r.repo}</span>
              {#if r.findings}<span class="crit"
                  >{r.findings} finding{r.findings === 1 ? "" : "s"}</span
                >{/if}
            </div>
          {/if}
        {/each}
        {#if !repoLog.length}
          <div class="line dim"><span class="tag">discovering repositories…</span></div>
        {/if}
      </div>
    </section>
  {/if}
</div>

<style>
  .field { display: flex; flex-direction: column; gap: 8px; }
  .field-label { font-size: 12px; color: var(--muted); font-weight: 500; }
  .path-preview {
    font-size: 12px;
    color: var(--fg);
    background: var(--inset);
    border-radius: var(--radius-sm);
    padding: 9px 12px;
    word-break: break-all;
  }
  .path-preview.empty { color: var(--faint); }
  .opts { display: flex; flex-direction: column; gap: 4px; padding: 2px 0; }
  .opt-note {
    font-size: 11.5px;
    color: var(--muted);
    background: var(--inset);
    padding: 7px 11px;
    border-radius: var(--radius-sm);
    line-height: 1.5;
  }
  .scan-status { font-size: 12.5px; color: var(--fg); }
  .scan-status strong { font-variant-numeric: tabular-nums; }
  .sr {
    position: absolute;
    width: 1px; height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
  .line.hit {
    background: var(--surface-danger);
    margin: 0 -6px;
    padding: 2px 6px;
    border-radius: 5px;
  }

  /* ---- terminal-styled progress log ---- */
  .terminal {
    background: var(--inset);
    border-radius: var(--radius);
    overflow: hidden;
    font-family: var(--mono);
  }
  .term-body {
    padding: 14px;
    max-height: 320px;
    overflow-y: auto;
    font-size: 12px;
    line-height: 1.7;
    color: var(--fg);
    scroll-behavior: smooth;
  }
  .line { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .line .spinner {
    width: 11px; height: 11px; flex: none;
    border-color: var(--ok-tint); border-top-color: var(--ok);
  }
  .tag { flex: none; color: var(--faint); }
  .repo { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--fg); }
  .scanning .repo { color: var(--muted); }
  .mark { flex: none; font-weight: 700; }
  .mark.ok { color: var(--ok); }
  .mark.hit { color: var(--danger); }
  .crit { flex: none; color: var(--danger); }
  .dim .tag { color: var(--faint); }
</style>
