<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { githubScan, githubFix, githubOrgs } from "../lib/api";
  import { dialog } from "../lib/modal";
  import { listen } from "@tauri-apps/api/event";
  import type { GithubRepoView, GithubFixView, ScanProgress } from "../lib/types";

  let token = $state(localStorage.getItem("github_token") ?? "");
  let includeForks = $state(false);
  let scanning = $state(false);
  let fixing = $state(false);
  let confirming = $state(false);
  let scanned = $state(false);
  let progress = $state<ScanProgress | null>(null);

  let repos = $state<GithubRepoView[]>([]);
  let sel = $state<Record<string, boolean>>({});
  let results = $state<GithubFixView[]>([]);

  // Orgs the token owner belongs to, loaded for the org picker. `orgsError` records a
  // discovery failure so the UI can note we're falling back to scanning every org.
  let orgs = $state<string[]>([]);
  let selectedOrgs = $state<Record<string, boolean>>({});
  let loadingOrgs = $state(false);
  let orgsError = $state(false);

  function saveToken() {
    if (token) localStorage.setItem("github_token", token);
    else localStorage.removeItem("github_token");
  }

  // Discover the orgs the token can see, defaulting every one to checked. On failure,
  // leave `orgs` empty and flag the error — scanning still proceeds (all orgs).
  async function loadOrgs() {
    loadingOrgs = true;
    orgsError = false;
    try {
      const found = await githubOrgs(token || undefined);
      orgs = found;
      const s: Record<string, boolean> = {};
      for (const o of found) s[o] = true;
      selectedOrgs = s;
    } catch {
      orgs = [];
      selectedOrgs = {};
      orgsError = true;
    } finally {
      loadingOrgs = false;
    }
  }

  const selectedNames = $derived(
    repos.filter((r) => r.fixable && sel[r.full_name]).map((r) => r.full_name)
  );

  async function scan() {
    scanning = true;
    app.error = "";
    results = [];
    progress = null;
    // Register BEFORE invoking so no early event is missed.
    const unlisten = await listen<ScanProgress>("github-scan-progress", (e) => {
      // Events arrive in completion order; never roll the counter backwards.
      if (!progress || e.payload.done > progress.done) progress = e.payload;
    });
    try {
      // If we discovered orgs, pass the checked subset; if discovery failed or found none,
      // pass [] so the backend scans every org (today's behavior). Your own repos are
      // always scanned regardless.
      const chosen = orgs.filter((o) => selectedOrgs[o]);
      repos = await githubScan(token || undefined, includeForks, chosen);
      const s: Record<string, boolean> = {};
      for (const r of repos) if (r.fixable) s[r.full_name] = true;
      sel = s;
      scanned = true;
    } catch (e) {
      app.error = String(e);
    } finally {
      unlisten();
      scanning = false;
      progress = null;
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

  const pct = $derived(progress && progress.total ? (progress.done / progress.total) * 100 : 0);
</script>

<div class="page">
  <div class="page-head">
    <h1>GitHub account</h1>
    <p class="lede">
      Scan repos you own and repos in your organizations — read-only via the GitHub API, no clones.
      Fixing a repo <strong>force-pushes</strong> the cleaned history back to GitHub.
    </p>
  </div>

  <section class="card">
    <div class="row">
      <input
        type="password"
        placeholder="ghp_… (blank = gh auth token / GITHUB_TOKEN / GH_TOKEN)"
        bind:value={token}
        oninput={saveToken}
        style="flex:1"
      />
      <button class="btn" onclick={loadOrgs} disabled={loadingOrgs || scanning || fixing}>
        {loadingOrgs ? "Loading orgs…" : "Load orgs"}
      </button>
    </div>
    <label class="switch">
      <input type="checkbox" bind:checked={includeForks} />
      <span class="track"></span>
      <span class="lbl">Include forks</span>
    </label>

    {#if orgs.length}
      <div class="stack">
        <p class="muted small">
          Choose which organizations to scan. <strong>Your own repos are always scanned.</strong>
        </p>
        <div class="row" style="gap:14px 18px">
          {#each orgs as o}
            <label class="switch">
              <input type="checkbox" bind:checked={selectedOrgs[o]} />
              <span class="track"></span>
              <span class="lbl small">{o}</span>
            </label>
          {/each}
        </div>
      </div>
    {:else if orgsError}
      <p class="muted small">Couldn't list orgs — scanning all.</p>
    {/if}

    <div class="row">
      <button class="btn primary" onclick={scan} disabled={scanning || fixing}>
        {#if scanning}<span class="spinner"></span> Scanning account…{:else}Scan account{/if}
      </button>
      <button
        class="btn danger"
        onclick={() => (confirming = true)}
        disabled={fixing || selectedNames.length === 0}
      >
        Fix &amp; push selected…
      </button>
    </div>

    {#if scanning}
      <div class="stack">
        <div class="progress" class:indet={!progress}><span style="width: {progress ? pct : 35}%"></span></div>
        <p class="muted small">
          {#if progress}
            <span class="mono">{progress.repo}</span> — {progress.done} of {progress.total}
          {:else}
            Scanning repositories via the GitHub API…
          {/if}
        </p>
      </div>
    {/if}
  </section>

  {#if !scanning && scanned && repos.length === 0}
    <div class="card ok">
      <div class="state ok">
        <div class="glyph">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M5 12.5 10 17.5 19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </div>
        <h2>No infected repositories</h2>
        <p class="muted small">Nothing to fix in this account.</p>
      </div>
    </div>
  {:else if repos.length}
    <section class="card">
      <h2>Infected repositories</h2>
      {#each repos as r, i}
        <label class="switch item reveal" style="animation-delay: {Math.min(i, 12) * 25}ms">
          <input type="checkbox" bind:checked={sel[r.full_name]} disabled={!r.fixable} />
          <span class="track"></span>
          <span class="lbl small" style="flex:1;min-width:0;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <strong class="mono">{r.full_name}</strong>
            <span class="count">{r.findings}</span>
            {#if r.campaigns.length}<span class="muted">{r.campaigns.join(", ")}</span>{/if}
            {#if !r.fixable}<span class="chip">branch-only</span>{/if}
          </span>
        </label>
      {/each}
    </section>
  {/if}

  {#if results.length}
    <section class="card">
      <h2>Fix results</h2>
      <div class="stack">
        {#each results as r}
          <div class="small {r.error || r.manual_review ? 'crit' : r.fixed ? 'ok-text' : 'muted'}">
            <span class="mono">{r.full_name}</span>:
            {#if r.error}
              error — {r.error}
            {:else if r.manual_review}
              detected — manual review needed (payload not auto-strippable)
            {:else if r.fixed}
              fixed{r.pushed.length ? ` — pushed ${r.pushed.join(", ")}` : ""}
            {:else}
              no changes
            {/if}
          </div>
        {/each}
      </div>
    </section>
  {/if}
</div>

{#if confirming}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirming = false)}>
      <h3>Force-push cleaned history?</h3>
      <p class="crit small">
        <strong>This is destructive and remote.</strong> Wormward will remediate
        {selectedNames.length} selected repo(s) and <strong>force-push</strong> the cleaned default
        branch to their GitHub remotes, overwriting remote history. The pre-clean tip is backed up
        as a <code>wormward-backup/…</code> branch on each remote.
      </p>
      <div class="row">
        <button class="btn ghost" onclick={() => (confirming = false)}>Cancel</button>
        <button class="btn danger" onclick={fix}>Fix &amp; push</button>
      </div>
    </div>
  </div>
{/if}
