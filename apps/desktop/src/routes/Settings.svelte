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

<section class="card">
  <h2>OSM API token</h2>
  <p class="muted">
    Free token from your opensourcemalware.com profile — enables the online cross-check.
    Stored locally in this app only.
  </p>
  <div class="row">
    <input
      type="password"
      placeholder="osm_…"
      bind:value={token}
      oninput={saveToken}
      style="flex:1"
    />
  </div>
</section>

<section class="card">
  <h2>GitHub token</h2>
  <p class="muted">
    Used by the GitHub screen to enumerate and fix your repositories. Leave blank to fall back to
    <code>gh auth token</code> / <code>GITHUB_TOKEN</code> / <code>GH_TOKEN</code>. Stored locally
    in this app only.
  </p>
  <div class="row">
    <input
      type="password"
      placeholder="ghp_…"
      bind:value={githubToken}
      oninput={saveGithubToken}
      style="flex:1"
    />
  </div>
</section>

<section class="card">
  <h2>Campaign packs</h2>
  {#each packs as p}
    <div class="pack">
      <strong>{p.name}</strong> <code>{p.id}</code>
      <div class="muted small">{p.description}</div>
    </div>
  {/each}
</section>
