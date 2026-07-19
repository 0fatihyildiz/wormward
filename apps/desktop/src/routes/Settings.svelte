<script lang="ts">
  import { listPacks } from "../lib/api";
  import type { PackInfo } from "../lib/types";
  import { app } from "../lib/state.svelte";

  let packs = $state<PackInfo[]>([]);
  let token = $state(localStorage.getItem("osm_token") ?? "");
  let githubToken = $state(localStorage.getItem("github_token") ?? "");

  $effect(() => {
    listPacks()
      .then((p) => (packs = p))
      .catch((e) => (app.error = String(e)));
  });

  function saveToken() {
    if (token) localStorage.setItem("osm_token", token);
    else localStorage.removeItem("osm_token");
  }

  function saveGithubToken() {
    if (githubToken) localStorage.setItem("github_token", githubToken);
    else localStorage.removeItem("github_token");
  }
</script>

<div class="page">
  <div class="page-head">
    <h1>Settings</h1>
    <p class="lede">Tokens are stored locally in this app only.</p>
  </div>

  <section class="card">
    <h2>OSM API token</h2>
    <p class="lede">
      Free token from your opensourcemalware.com profile — enables the online cross-check.
    </p>
    <input type="password" placeholder="osm_…" bind:value={token} oninput={saveToken} />
  </section>

  <section class="card">
    <h2>GitHub token</h2>
    <p class="lede">
      Used by the GitHub screen to enumerate and fix repositories you own or belong to via an
      organization. Leave blank to fall back to
      <code>gh auth token</code> / <code>GITHUB_TOKEN</code> / <code>GH_TOKEN</code>.
    </p>
    <input type="password" placeholder="ghp_…" bind:value={githubToken} oninput={saveGithubToken} />
  </section>

  <section class="card">
    <h2>Campaign packs</h2>
    {#if !packs.length}
      <p class="muted small">Loading packs…</p>
    {:else}
      {#each packs as p, i}
        <div class="pack reveal" style="animation-delay: {Math.min(i, 12) * 25}ms">
          <div class="row" style="gap:8px">
            <strong>{p.name}</strong>
            <code>{p.id}</code>
          </div>
          <div class="muted small">{p.description}</div>
        </div>
      {/each}
    {/if}
  </section>
</div>
