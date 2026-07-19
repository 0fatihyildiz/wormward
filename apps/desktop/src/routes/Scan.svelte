<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { scan, pickDirs, cancelScan } from "../lib/api";
  import { listen } from "@tauri-apps/api/event";
  import type { ScanProgress } from "../lib/types";

  let deep = $state(false);
  let online = $state(false);
  let log = $state<string[]>([]);
  let progress = $state<ScanProgress | null>(null);

  async function choose() {
    try {
      const dirs = await pickDirs();
      if (dirs.length) app.dirs = dirs;
    } catch (e) {
      app.error = String(e);
    }
  }

  async function run() {
    app.error = "";
    app.scanning = true;
    log = [];
    progress = null;
    // Register BEFORE invoking so no early event is missed.
    const unlisten = await listen<ScanProgress>("local-scan-progress", (e) => {
      const p = e.payload;
      // Events arrive in order; never roll the counter backwards.
      if (!progress || p.done > progress.done) progress = p;
      log = [...log, `✓ ${p.repo}`];
    });
    try {
      const token = localStorage.getItem("osm_token") || undefined;
      app.report = await scan(app.dirs.length ? app.dirs : ["."], deep, online, token);
      app.screen = "results";
    } catch (e) {
      app.error = String(e);
    } finally {
      unlisten();
      app.scanning = false;
      progress = null;
    }
  }

  async function stop() {
    try {
      await cancelScan();
    } catch (e) {
      app.error = String(e);
    }
  }

  const pct = $derived(progress && progress.total ? (progress.done / progress.total) * 100 : 0);
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
      <p class="path-preview mono">
        {app.dirs.length ? app.dirs.join("  ·  ") : "current folder (.)"}
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
        <span class="lbl">Online cross-check <span class="muted">— OpenSourceMalware</span></span>
      </label>
    </div>

    <div class="row">
      {#if app.scanning}
        <button class="btn primary" disabled>
          <span class="spinner"></span>
          {progress ? `Scanning… ${progress.done}/${progress.total}` : "Scanning…"}
        </button>
        <button class="btn danger" onclick={stop}>Stop</button>
      {:else}
        <button class="btn primary" onclick={run}>Scan →</button>
      {/if}
    </div>

    {#if app.scanning}
      <div class="progress" class:indet={!progress}>
        <span style="width: {progress ? pct : 35}%"></span>
      </div>
    {/if}
  </section>

  {#if app.scanning || log.length}
    <section class="card">
      <div class="row between">
        <h2>Progress</h2>
        {#if progress}<span class="count">{progress.done}/{progress.total}</span>{/if}
      </div>
      <div class="scanlog stack">
        {#each log as line}<div class="mono micro muted">{line}</div>{/each}
        {#if !log.length}<div class="muted small">Discovering repositories…</div>{/if}
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
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 9px 12px;
    word-break: break-all;
  }
  .opts { display: flex; flex-direction: column; gap: 4px; padding: 2px 0; }
</style>
