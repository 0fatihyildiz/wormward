<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { scan, pickDirs } from "../lib/api";

  let deep = $state(false);
  let online = $state(false);

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
    try {
      const token = localStorage.getItem("osm_token") || undefined;
      app.report = await scan(app.dirs.length ? app.dirs : ["."], deep, online, token);
      app.screen = "results";
    } catch (e) {
      app.error = String(e);
    } finally {
      app.scanning = false;
    }
  }
</script>

<section class="card">
  <h2>Scan for supply-chain worms</h2>
  <div class="row">
    <button onclick={choose}>Choose folders…</button>
    <span class="muted">{app.dirs.length ? app.dirs.join(", ") : "current folder (.)"}</span>
  </div>
  <label><input type="checkbox" bind:checked={deep} /> Deep scan — inspect every branch tip</label>
  <label><input type="checkbox" bind:checked={online} /> Cross-check findings online (OpenSourceMalware)</label>
  <div class="row">
    <button class="primary" onclick={run} disabled={app.scanning}>
      {app.scanning ? "Scanning…" : "Scan"}
    </button>
  </div>
</section>
