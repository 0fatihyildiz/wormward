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
</script>

<section class="card">
  <h2>Scan for supply-chain worms</h2>
  <div class="row">
    <button onclick={choose} disabled={app.scanning}>Choose folders…</button>
    <span class="muted">{app.dirs.length ? app.dirs.join(", ") : "current folder (.)"}</span>
  </div>
  <label><input type="checkbox" bind:checked={deep} disabled={app.scanning} /> Deep scan — inspect every branch tip</label>
  <label><input type="checkbox" bind:checked={online} disabled={app.scanning} /> Cross-check findings online (OpenSourceMalware)</label>
  <div class="row">
    {#if app.scanning}
      <button class="primary" disabled>
        {progress ? `Scanning… ${progress.done}/${progress.total}` : "Scanning…"}
      </button>
      <button onclick={stop}>Stop</button>
    {:else}
      <button class="primary" onclick={run}>Scan</button>
    {/if}
  </div>
</section>

{#if app.scanning || log.length}
  <section class="card">
    <h2>
      Progress
      {#if progress}<span class="count">{progress.done}/{progress.total}</span>{/if}
    </h2>
    <div class="scanlog">
      {#each log as line}
        <div class="muted small">{line}</div>
      {/each}
      {#if !log.length}<div class="muted small">Discovering repositories…</div>{/if}
    </div>
  </section>
{/if}
