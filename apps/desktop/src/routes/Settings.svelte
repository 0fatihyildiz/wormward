<script lang="ts">
  import { onMount } from "svelte";
  import { listPacks, githubOrgs } from "../lib/api";
  import type { PackInfo } from "../lib/types";

  let packs = $state<PackInfo[]>([]);
  let packsLoading = $state(true);
  let packsError = $state<string | null>(null);

  let osm = $state(localStorage.getItem("osm_token") ?? "");
  let gh = $state(localStorage.getItem("github_token") ?? "");
  let showOsm = $state(false);
  let showGh = $state(false);
  let osmSaved = $state(false);
  let ghSaved = $state(false);
  let osmTimer: ReturnType<typeof setTimeout> | undefined;
  let ghTimer: ReturnType<typeof setTimeout> | undefined;

  function loadPacks() {
    packsLoading = true;
    packsError = null;
    listPacks()
      .then((p) => (packs = p))
      .catch((e) => (packsError = String(e)))
      .finally(() => (packsLoading = false));
  }
  onMount(loadPacks);

  function save(key: string, value: string) {
    const v = value.trim();
    if (v) localStorage.setItem(key, v);
    else localStorage.removeItem(key);
  }
  function saveOsm() {
    save("osm_token", osm);
    osmSaved = true;
    clearTimeout(osmTimer);
    osmTimer = setTimeout(() => (osmSaved = false), 1600);
  }
  function saveGh() {
    save("github_token", gh);
    ghTest = "idle";
    ghSaved = true;
    clearTimeout(ghTimer);
    ghTimer = setTimeout(() => (ghSaved = false), 1600);
  }

  // Loose prefix check so an obviously-wrong paste is caught before it fails elsewhere.
  const osmBad = $derived(osm.trim().length > 0 && !osm.trim().startsWith("osm_"));
  const ghBad = $derived(
    gh.trim().length > 0 && !/^(ghp_|github_pat_|gho_|ghs_)/.test(gh.trim()),
  );

  // Verify the GitHub token actually works by listing the orgs it can see.
  let ghTest = $state<"idle" | "testing" | "ok" | "fail">("idle");
  async function testGh() {
    ghTest = "testing";
    try {
      await githubOrgs(gh.trim() || undefined);
      ghTest = "ok";
    } catch {
      ghTest = "fail";
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <h1>Settings</h1>
    <p class="lede">
      Tokens are saved in this app's local storage on this device — not synced anywhere. Use a
      minimum-scope token.
    </p>
  </div>

  <section class="card">
    <h2>OpenSourceMalware token</h2>
    <p class="lede">
      Checks packages found in your scans against the opensourcemalware.com database. Optional —
      local scanning works without it. Get a free token from your opensourcemalware.com profile.
    </p>
    <label class="tk-label" for="osm-token">Token</label>
    <div class="tk-row">
      <input
        id="osm-token"
        type={showOsm ? "text" : "password"}
        placeholder="osm_…"
        autocomplete="off"
        spellcheck="false"
        autocapitalize="off"
        bind:value={osm}
        oninput={saveOsm}
      />
      <button class="btn ghost sm" type="button" onclick={() => (showOsm = !showOsm)}>
        {showOsm ? "Hide" : "Show"}
      </button>
    </div>
    <div class="tk-status">
      {#if osmBad}<span class="warn-txt">Doesn't look like an OSM token (expected osm_…).</span>
      {:else if osmSaved}<span class="ok-txt">Saved ✓</span>{/if}
    </div>
  </section>

  <section class="card">
    <h2>GitHub token</h2>
    <p class="lede">
      Lets Wormward list and fix repositories you can access — a token with <code>repo</code> scope
      is enough.
    </p>
    <label class="tk-label" for="gh-token">Token</label>
    <div class="tk-row">
      <input
        id="gh-token"
        type={showGh ? "text" : "password"}
        placeholder="ghp_…"
        autocomplete="off"
        spellcheck="false"
        autocapitalize="off"
        bind:value={gh}
        oninput={saveGh}
      />
      <button class="btn ghost sm" type="button" onclick={() => (showGh = !showGh)}>
        {showGh ? "Hide" : "Show"}
      </button>
      <button class="btn sm" type="button" onclick={testGh} disabled={ghTest === "testing"}>
        {ghTest === "testing" ? "Testing…" : "Test"}
      </button>
    </div>
    <div class="tk-status">
      {#if ghBad}<span class="warn-txt">Doesn't look like a GitHub token (expected ghp_… / github_pat_…).</span>
      {:else if ghTest === "ok"}<span class="ok-txt">Token works ✓</span>
      {:else if ghTest === "fail"}<span class="warn-txt">Token didn't work — check it's valid and has repo scope.</span>
      {:else if ghSaved}<span class="ok-txt">Saved ✓</span>{/if}
    </div>
    <p class="muted micro fallback">
      Leave blank to fall back to your <code>gh</code> CLI login (<code>gh auth token</code>) or the
      <code>GITHUB_TOKEN</code> / <code>GH_TOKEN</code> environment variables.
    </p>
  </section>

  <section class="card">
    <h2>Campaign packs</h2>
    <p class="lede">Detection rule sets bundled with the app. Read-only.</p>
    {#if packsLoading}
      <div class="state"><span class="spinner"></span><p class="muted micro">Loading packs…</p></div>
    {:else if packsError}
      <div class="state">
        <div class="glyph warn-glyph">!</div>
        <p>Couldn't load the packs.</p>
        <p class="muted micro">{packsError}</p>
        <button class="btn sm" onclick={loadPacks}>Retry</button>
      </div>
    {:else if packs.length === 0}
      <div class="state"><p class="muted micro">No campaign packs are bundled.</p></div>
    {:else}
      <ul class="packs">
        {#each packs as p, i (p.id)}
          <li class="pack reveal" style="animation-delay: {Math.min(i, 12) * 25}ms">
            <div class="row" style="gap: 8px">
              <strong>{p.name}</strong>
              <code>{p.id}</code>
            </div>
            <div class="muted micro">{p.description}</div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>

<style>
  .tk-label { font-size: 12px; color: var(--muted); font-weight: 500; display: block; margin-bottom: 5px; }
  .tk-row { display: flex; gap: 8px; align-items: stretch; }
  .tk-row input { flex: 1; }
  .tk-status { min-height: 16px; margin-top: 6px; font-size: 11.5px; }
  .ok-txt { color: var(--ok); }
  .warn-txt { color: var(--warn); }
  .fallback { margin-top: 10px; }
  .warn-glyph {
    color: var(--warn); background: var(--warn-tint);
    font-weight: 700;
  }
  .packs { display: flex; flex-direction: column; gap: 12px; list-style: none; }
  .pack { display: flex; flex-direction: column; gap: 3px; }
</style>
