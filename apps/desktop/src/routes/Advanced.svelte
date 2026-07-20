<script lang="ts">
  import { app, fail, clearErrors, go } from "../lib/state.svelte";
  import { githubScan, githubFix, githubOrgs, cancelGithubScan } from "../lib/api";
  import { dialog } from "../lib/modal";
  import { listen } from "@tauri-apps/api/event";
  import type { GithubRepoView, GithubFixView, ScanProgress } from "../lib/types";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  // ---------------- GitHub account: scan + fix & force-push ----------------
  let token = $state(localStorage.getItem("github_token") ?? "");
  let includeForks = $state(false);
  let scanning = $state(false);
  let stopping = $state(false);
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

  const fixableRepos = $derived(repos.filter((r) => r.fixable));
  // Repos already cleaned this session — never re-arm the force-push against them.
  const fixedNames = $derived(new Set(results.filter((r) => r.fixed).map((r) => r.full_name)));
  const selectedNames = $derived(
    fixableRepos
      .filter((r) => sel[r.full_name] && !fixedNames.has(r.full_name))
      .map((r) => r.full_name),
  );
  const selectableCount = $derived(fixableRepos.filter((r) => !fixedNames.has(r.full_name)).length);

  function selectAll() {
    const s = { ...sel };
    for (const r of fixableRepos) if (!fixedNames.has(r.full_name)) s[r.full_name] = true;
    sel = s;
  }
  function clearAll() {
    sel = {};
  }

  function allOrgs() {
    const s: Record<string, boolean> = {};
    for (const o of orgs) s[o] = true;
    selectedOrgs = s;
  }
  function noOrgs() {
    selectedOrgs = {};
  }

  async function githubAccountScan() {
    scanning = true;
    clearErrors();
    results = [];
    progress = null;
    // Register BEFORE invoking so no early event is missed.
    const unlisten = await listen<ScanProgress>("github-scan-progress", (e) => {
      // Events arrive in completion order; never roll the counter backwards.
      if (!progress || e.payload.done > progress.done) progress = e.payload;
    });
    try {
      // If we discovered orgs, pass the checked subset; if discovery failed or found none,
      // pass [] so the backend scans every org. Your own repos are always scanned.
      const chosen = orgs.filter((o) => selectedOrgs[o]);
      repos = await githubScan(token || undefined, includeForks, chosen);
      // Default to UNSELECTED — a destructive multi-repo remote force-push must be a
      // deliberate, per-repo choice, never armed for the whole account by default.
      sel = {};
      results = [];
      scanned = true;
    } catch (e) {
      fail(e);
    } finally {
      unlisten();
      scanning = false;
      stopping = false;
      progress = null;
    }
  }

  async function stopScan() {
    stopping = true;
    try {
      await cancelGithubScan();
    } catch (e) {
      fail(e);
    }
  }

  async function fix() {
    confirming = false;
    fixing = true;
    clearErrors();
    try {
      results = await githubFix(selectedNames);
      // Disarm: clear the selection so the just-pushed repos aren't re-fixable in one click.
      sel = {};
    } catch (e) {
      fail(e);
    } finally {
      fixing = false;
    }
  }

  const pct = $derived(progress && progress.total ? (progress.done / progress.total) * 100 : 0);
</script>

<div class="page">
  <div class="page-head">
    <button class="btn ghost sm back" onclick={() => go("home")}>← Home</button>
    <h1>Advanced</h1>
    <p class="lede">
      Power-user tools that overwrite remote history or re-introduce removed files. Each action is
      clearly labeled and asks you to confirm — most people never need this screen.
    </p>
  </div>

  <!-- GitHub account -->
  <section class="card">
    <h2>GitHub account — scan &amp; force-push</h2>
    <p class="lede">
      Scan repos you own and repos in your organizations — read-only via the GitHub API, no clones.
      Fixing a repo <strong>force-pushes</strong> the cleaned history back to GitHub, overwriting
      remote history.
    </p>
    <div class="row">
      <input
        type="password"
        aria-label="GitHub token"
        placeholder="ghp_… (or leave blank to use your gh CLI login)"
        autocomplete="off"
        spellcheck="false"
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
        <div class="row between">
          <p class="muted small">
            Choose organizations to scan. <strong>Your own repos are always scanned.</strong>
          </p>
          <div class="row" style="gap: 6px">
            <button class="btn ghost sm" onclick={allOrgs}>All</button>
            <button class="btn ghost sm" onclick={noOrgs}>None</button>
          </div>
        </div>
        <div class="row" style="gap: 14px 18px">
          {#each orgs as o (o)}
            <label class="switch">
              <input type="checkbox" bind:checked={selectedOrgs[o]} />
              <span class="track"></span>
              <span class="lbl small">{o}</span>
            </label>
          {/each}
        </div>
      </div>
    {:else if orgsError}
      <p class="warn-note">Couldn't list your organizations, so all of them will be scanned.</p>
    {/if}

    <div class="row">
      {#if scanning}
        <button class="btn primary" disabled aria-busy="true">
          <span class="spinner"></span> Scanning account…
        </button>
        <button class="btn danger" onclick={stopScan} disabled={stopping}>
          {stopping ? "Stopping…" : "Cancel"}
        </button>
      {:else}
        <button class="btn primary" onclick={githubAccountScan} disabled={fixing}>Scan account</button>
        <button
          class="btn danger"
          onclick={() => (confirming = true)}
          disabled={fixing || selectedNames.length === 0}
        >
          {#if fixing}<span class="spinner"></span>Pushing…{:else}Fix &amp; push {selectedNames.length} selected…{/if}
        </button>
      {/if}
    </div>

    {#if scanning}
      <div class="stack" role="status" aria-live="polite">
        <div
          class="progress"
          class:indet={!progress}
          role="progressbar"
          aria-valuemin="0"
          aria-valuemax={progress?.total ?? 0}
          aria-valuenow={progress?.done ?? 0}
        >
          <span style="width: {progress ? pct : 35}%"></span>
        </div>
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
      <div class="row between">
        <h2>Infected repositories</h2>
        {#if selectableCount}
          <div class="row" style="gap: 8px">
            <span class="muted micro">{selectedNames.length} of {selectableCount} selected</span>
            <button class="btn ghost sm" onclick={selectAll}>Select all</button>
            <button class="btn ghost sm" onclick={clearAll}>Clear</button>
          </div>
        {/if}
      </div>
      <ul class="repo-list">
        {#each repos as r, i (r.full_name)}
          {@const done = fixedNames.has(r.full_name)}
          <li class="reveal" style="animation-delay: {Math.min(i, 12) * 25}ms">
            <label class="switch item" class:done>
              <input type="checkbox" bind:checked={sel[r.full_name]} disabled={!r.fixable || done} />
              <span class="track"></span>
              <span class="lbl small repo-line">
                <strong class="mono">{r.full_name}</strong>
                <span class="count" aria-label="{r.findings} {plural(r.findings, 'finding', 'findings')}">{r.findings}</span>
                {#if r.campaigns.length}<span class="muted">{r.campaigns.join(", ")}</span>{/if}
                {#if done}<span class="chip ok-chip">Cleaned ✓</span>
                {:else if !r.fixable}<span class="chip">branch-only</span>{/if}
              </span>
            </label>
          </li>
        {/each}
      </ul>
      {#if repos.some((r) => !r.fixable)}
        <p class="muted micro">
          "branch-only" repositories have the infection on a non-default branch — clean those in the
          Other branches section below.
        </p>
      {/if}
    </section>
  {/if}

  {#if results.length}
    <section class="card" aria-live="polite">
      <div class="row between">
        <h2>Fix results</h2>
        <button class="btn sm" onclick={githubAccountScan} disabled={scanning || fixing}>Re-scan to confirm</button>
      </div>
      <div class="stack">
        {#each results as r, i (i)}
          <div class="res-line small {r.error || r.manual_review ? 'crit' : r.fixed ? 'ok-text' : 'muted'}">
            <span class="mono">{r.full_name}</span> —
            {#if r.error}
              couldn't fix: {r.error}
            {:else if r.manual_review}
              needs manual review — the malicious code couldn't be safely removed automatically
            {:else if r.fixed}
              cleaned and pushed{r.pushed.length ? ` to ${r.pushed.join(", ")}` : ""}
            {:else}
              already clean — no changes needed
            {/if}
          </div>
        {/each}
      </div>
    </section>
  {/if}
</div>

{#if confirming}
  <div class="modal-backdrop">
    <div
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="ghfix-title"
      tabindex="-1"
      use:dialog={() => (confirming = false)}
    >
      <h3 id="ghfix-title">Force-push cleaned history?</h3>
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

<style>
  .back { align-self: flex-start; margin-bottom: 6px; }
  .repo-list { list-style: none; display: flex; flex-direction: column; }
  .repo-line { flex: 1; min-width: 0; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .switch.item.done { opacity: 0.65; }
  .ok-chip { background: var(--ok-tint); color: var(--ok); }
  .warn-note {
    color: var(--warn);
    background: var(--surface-warn);
    padding: 8px 11px;
    border-radius: var(--radius-sm);
    font-size: 12px;
  }
  .res-line { word-break: break-all; }
</style>
