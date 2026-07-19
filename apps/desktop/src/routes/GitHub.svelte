<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { githubScan, githubFix } from "../lib/api";
  import type { GithubRepoView, GithubFixView } from "../lib/types";

  let token = $state(localStorage.getItem("github_token") ?? "");
  let includeForks = $state(false);
  let scanning = $state(false);
  let fixing = $state(false);
  let confirming = $state(false);
  let scanned = $state(false);

  let repos = $state<GithubRepoView[]>([]);
  let sel = $state<Record<string, boolean>>({});
  let results = $state<GithubFixView[]>([]);

  function saveToken() {
    if (token) localStorage.setItem("github_token", token);
    else localStorage.removeItem("github_token");
  }

  const selectedNames = $derived(
    repos.filter((r) => r.fixable && sel[r.full_name]).map((r) => r.full_name)
  );

  async function scan() {
    scanning = true;
    app.error = "";
    results = [];
    try {
      repos = await githubScan(token || undefined, includeForks);
      const s: Record<string, boolean> = {};
      for (const r of repos) if (r.fixable) s[r.full_name] = true;
      sel = s;
      scanned = true;
    } catch (e) {
      app.error = String(e);
    } finally {
      scanning = false;
    }
  }

  async function fix() {
    confirming = false;
    fixing = true;
    app.error = "";
    try {
      results = await githubFix(selectedNames);
    } catch (e) {
      app.error = String(e);
    } finally {
      fixing = false;
    }
  }
</script>

<section class="card">
  <h2>GitHub account</h2>
  <p class="muted">
    Scan the token owner's repositories: each is scanned read-only via the GitHub API, with
    no clones. Fixing a repo <strong>force-pushes</strong> the cleaned history back to GitHub.
  </p>
  <div class="row">
    <input
      type="password"
      placeholder="ghp_… (blank = gh auth token / GITHUB_TOKEN / GH_TOKEN)"
      bind:value={token}
      oninput={saveToken}
      style="flex:1"
    />
  </div>
  <label><input type="checkbox" bind:checked={includeForks} /> Include forks</label>
  <div class="row">
    <button class="primary" onclick={scan} disabled={scanning || fixing}>
      {scanning ? "Scanning account…" : "Scan account"}
    </button>
    <button
      class="primary"
      onclick={() => (confirming = true)}
      disabled={fixing || selectedNames.length === 0}
    >
      Fix &amp; push selected…
    </button>
  </div>
</section>

{#if scanning}
  <p class="muted">Scanning repositories via the GitHub API…</p>
{:else if scanned && repos.length === 0}
  <section class="card ok">
    <h2>No infected repositories</h2>
    <p class="muted">Nothing to fix in this account.</p>
  </section>
{:else if repos.length}
  <section class="card">
    <h3>Infected repositories</h3>
    {#each repos as r}
      <div class="action">
        <label>
          <input type="checkbox" bind:checked={sel[r.full_name]} disabled={!r.fixable} />
          <strong>{r.full_name}</strong>
          <span class="count">{r.findings}</span>
          {#if r.campaigns.length}<span class="muted small">{r.campaigns.join(", ")}</span>{/if}
          {#if !r.fixable}<span class="chip">branch-only — not auto-fixable</span>{/if}
        </label>
      </div>
    {/each}
  </section>
{/if}

{#if results.length}
  <section class="card">
    <h3>Fix results</h3>
    {#each results as r}
      <div class="small {r.error ? 'crit' : r.fixed ? 'ok-text' : 'muted'}">
        {r.full_name}:
        {#if r.error}
          error — {r.error}
        {:else if r.fixed}
          fixed{r.pushed.length ? ` — pushed ${r.pushed.join(", ")}` : ""}
        {:else}
          no changes
        {/if}
      </div>
    {/each}
  </section>
{/if}

{#if confirming}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1">
      <h3>Force-push cleaned history?</h3>
      <p class="crit">
        <strong>This is destructive and remote.</strong> Wormward will remediate
        {selectedNames.length} selected repo(s) and <strong>force-push</strong> the cleaned
        default branch to their GitHub remotes, overwriting remote history. The pre-clean tip is
        backed up as a <code>wormward-backup/…</code> branch on each remote.
      </p>
      <div class="row">
        <button onclick={() => (confirming = false)}>Cancel</button>
        <button class="primary" onclick={fix}>Fix &amp; push</button>
      </div>
    </div>
  </div>
{/if}
