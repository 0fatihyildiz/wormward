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
