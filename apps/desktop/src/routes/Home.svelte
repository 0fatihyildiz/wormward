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
        // Reached only when scanned=true (see !scanned guard above) — a scan ran but a
        // surface came back unknown (e.g. cancelled). Distinct from the true pre-scan text.
        return "Scan incomplete";
    }
  });
  // Spec Screen 2: once scanned, the sub line also carries the last-scan time.
  const lastScan = $derived(app.lastScanAt ? new Date(app.lastScanAt).toLocaleString() : null);
  const sub = $derived.by(() => {
    if (!scanned) return "Run a Full Scan to check this Mac and your code.";
    switch (overall) {
      case "protected":
        return `No threats on this Mac or in your code. · Last scan: ${lastScan}`;
      case "attention":
        return `Some things need a look. Open the details below to see what. · Last scan: ${lastScan}`;
      case "threat":
        return `A threat was found. Review it and remove it safely. · Last scan: ${lastScan}`;
      default:
        return `The last scan didn't finish. Run a Full Scan for a complete picture. · Last scan: ${lastScan}`;
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

  // Full Scan online cross-check (OpenSourceMalware) — opt-in, persisted. Re-reads the token when
  // toggled (and on each Home mount, since the router remounts views) so the hint stays honest.
  const osmToken = $derived.by(() => {
    void app.online;
    return localStorage.getItem("osm_token");
  });
  function persistOnline() {
    localStorage.setItem("online_scan", app.online ? "1" : "0");
  }
  // Persist the remaining scan options + surfaces (each mirrors a CLI flag or an old scan toggle).
  const persist = (key: string, on: boolean) => localStorage.setItem(key, on ? "1" : "0");
  // A Full Scan needs at least one surface selected.
  const noSurface = $derived(!app.scanMac && !app.scanRepos);
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
    <button class="btn primary cta" onclick={fullScan} disabled={noSurface}>Full Scan</button>
    {#if noSurface}<p class="scan-opt-hint">Pick at least one thing to scan below.</p>{/if}
    <div class="scan-opts">
      <span class="scan-opts-title">What to scan</span>
      <label class="switch">
        <input type="checkbox" bind:checked={app.scanMac} onchange={() => persist("scan_mac", app.scanMac)} />
        <span class="track"></span>
        <span class="lbl">This Mac <span class="muted">— running threats, infected caches, risky settings</span></span>
      </label>
      <label class="switch">
        <input type="checkbox" bind:checked={app.scanRepos} onchange={() => persist("scan_repos", app.scanRepos)} />
        <span class="track"></span>
        <span class="lbl">My code <span class="muted">— every git repo in your protected folders (all branches)</span></span>
      </label>

      <span class="scan-opts-title">Deeper checks</span>
      <label class="switch">
        <input type="checkbox" bind:checked={app.online} onchange={persistOnline} />
        <span class="track"></span>
        <span class="lbl">Check online <span class="muted">— cross-check packages against OpenSourceMalware</span></span>
      </label>
      {#if app.online && !osmToken}
        <p class="scan-opt-hint">
          Online checks need an OpenSourceMalware token.
          <button class="linklike" onclick={() => go("settings")}>Add one in Settings →</button>
        </p>
      {/if}
      <label class="switch">
        <input type="checkbox" bind:checked={app.history} onchange={() => persist("scan_history", app.history)} />
        <span class="track"></span>
        <span class="lbl">Search git history <span class="muted">— find payloads scrubbed from files but still reachable (slower)</span></span>
      </label>
      <label class="switch">
        <input type="checkbox" bind:checked={app.osv} onchange={() => persist("scan_osv", app.osv)} />
        <span class="track"></span>
        <span class="lbl">Check lockfiles (OSV) <span class="muted">— gate lockfiles via osv-scanner (must be installed)</span></span>
      </label>
      <label class="switch">
        <input type="checkbox" bind:checked={app.community} onchange={() => persist("scan_community", app.community)} />
        <span class="track"></span>
        <span class="lbl">Include community leads <span class="muted">— show lower-confidence, community-sourced flags</span></span>
      </label>

      <button class="linklike gh-link" onclick={() => go("advanced")}>Scan my GitHub account →</button>
    </div>
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
  .scan-opts {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
    text-align: left;
    padding: 14px 18px;
    background: var(--surface);
    border-radius: var(--radius);
  }
  .scan-opts-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--faint);
    margin-bottom: 2px;
  }
  .scan-opts-title:not(:first-child) { margin-top: 8px; }
  .scan-opt-hint { font-size: 12px; color: var(--warn); }
  .linklike { background: none; padding: 0; color: var(--accent); font: inherit; }
  .linklike:hover { background: none; color: var(--accent-hi); text-decoration: underline; }
  .gh-link { margin-top: 8px; }
</style>
