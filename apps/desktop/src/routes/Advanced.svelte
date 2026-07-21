<script lang="ts">
  import { app, fail, clearErrors, go } from "../lib/state.svelte";
  import {
    githubScan,
    githubFix,
    githubOrgs,
    cancelGithubScan,
    cleanBranchesPreview,
    cleanBranchesApply,
    restore,
    exportIocs,
    checkPackage,
  } from "../lib/api";
  import { dialog } from "../lib/modal";
  import { listen } from "@tauri-apps/api/event";
  import type {
    GithubRepoView,
    GithubFixView,
    ScanProgress,
    BranchCleanPreview,
    BranchSelection,
    BranchCleanResult,
    PackageCheck,
  } from "../lib/types";

  // ---------------- Threat-intel tools: pre-install package check + IOC export ----------------
  let pkgName = $state("");
  let pkgResult = $state<PackageCheck | null>(null);
  let pkgBusy = $state(false);
  let iocFormat = $state<"list" | "npm-report" | "stix">("npm-report");
  let iocOutput = $state("");
  let iocBusy = $state(false);

  async function runCheckPackage() {
    const name = pkgName.trim();
    if (!name) return;
    pkgBusy = true;
    pkgResult = null;
    clearErrors();
    try {
      pkgResult = await checkPackage(name);
    } catch (e) {
      fail(e);
    } finally {
      pkgBusy = false;
    }
  }

  async function runExportIocs() {
    iocBusy = true;
    clearErrors();
    try {
      iocOutput = await exportIocs(iocFormat);
    } catch (e) {
      fail(e);
    } finally {
      iocBusy = false;
    }
  }

  async function copyIocs() {
    if (iocOutput) await navigator.clipboard.writeText(iocOutput);
  }

  // ---------------- MCP: connect AI assistants (static setup info) ----------------
  async function copy(text: string) {
    await navigator.clipboard.writeText(text);
  }
  const mcpClaude = "claude mcp add wormward -- wormward mcp";
  const mcpJson = `{
  "mcpServers": {
    "wormward": { "command": "wormward", "args": ["mcp"] }
  }
}`;
  const mcpCodexToml = `[mcp_servers.wormward]
command = "wormward"
args = ["mcp"]`;

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

  // ---------------- Other branches: deep clean + optional force-push ----------------
  let busy = $state(false);
  let busyKind = $state<"branches" | "restore" | "">("");
  let branchPlans = $state<BranchCleanPreview[]>([]);
  let branchSel = $state<Record<string, boolean>>({});
  let pushBranches = $state(false);
  let branchLoading = $state(false);
  let confirmingBranches = $state(false);
  let branchResults = $state<BranchCleanResult[]>([]);
  let branchSummary = $state("");
  let branchesScanned = $state(false);
  const branchKey = (b: { repo: string; branch: string }) => `${b.repo}\n${b.branch}`;
  const selectedBranches = $derived<BranchSelection[]>(
    branchPlans.filter((b) => branchSel[branchKey(b)]).map((b) => ({ repo: b.repo, branch: b.branch })),
  );

  async function previewBranches() {
    branchLoading = true;
    clearErrors();
    try {
      branchPlans = await cleanBranchesPreview(app.dirs);
      const s: Record<string, boolean> = {};
      for (const b of branchPlans) s[branchKey(b)] = true;
      branchSel = s;
      branchesScanned = true;
    } catch (e) {
      fail(e);
    } finally {
      branchLoading = false;
    }
  }

  async function applyBranches() {
    confirmingBranches = false;
    busy = true;
    busyKind = "branches";
    branchSummary = "";
    clearErrors();
    try {
      const s = await cleanBranchesApply(selectedBranches, pushBranches);
      branchResults = s.results;
      branchSummary =
        `Cleaned ${s.cleaned} ${plural(s.cleaned, "branch", "branches")}` +
        (s.skipped ? `, ${s.skipped} skipped` : "") +
        (s.failed ? `, ${s.failed} failed` : "") +
        ".";
      await previewBranches();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
    }
  }

  // ---------------- Restore last backup ----------------
  let restoreConfirm = $state(false);
  let restoreResult = $state("");

  async function doRestore() {
    restoreConfirm = false;
    busy = true;
    busyKind = "restore";
    restoreResult = "";
    clearErrors();
    try {
      const s = await restore(app.dirs);
      restoreResult =
        s.restored > 0
          ? `Restored ${s.restored} ${plural(s.restored, "file", "files")} across ${s.repos} ${plural(s.repos, "repo", "repos")}.`
          : "No backup found to restore.";
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
    }
  }
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

  <!-- Pre-install package check -->
  <section class="card">
    <h2>Pre-install package check</h2>
    <p class="lede">
      Check an npm package <strong>before</strong> you install it — wormward fetches its metadata and
      entry file (no install, no code execution) and flags dropper behaviour.
    </p>
    <div class="row" style="gap: 8px; align-items: center">
      <input
        aria-label="npm package name"
        placeholder="package name — e.g. left-pad or name@1.2.3"
        spellcheck="false"
        autocomplete="off"
        bind:value={pkgName}
        onkeydown={(e) => e.key === "Enter" && runCheckPackage()}
        style="flex: 1"
      />
      <button class="btn primary" onclick={runCheckPackage} disabled={pkgBusy || !pkgName.trim()}>
        {pkgBusy ? "Checking…" : "Check"}
      </button>
    </div>
    {#if pkgResult}
      <p style="margin-top: 12px">
        {#if pkgResult.malicious}
          <strong class="warn-text">⚠ MALICIOUS</strong>
        {:else}
          <strong style="color: var(--ok)">✓ clean</strong>
        {/if}
        <span class="mono">{pkgResult.name}@{pkgResult.version}</span>
        <span class="muted">— {pkgResult.reason}</span>
      </p>
    {/if}
  </section>

  <!-- Export takedown IOCs -->
  <section class="card">
    <h2>Export takedown IOCs</h2>
    <p class="lede">
      Turn the tracked campaigns into disruption-ready artifacts. Reporting the malicious packages to
      npm cuts the delivery vector at the source; the STIX bundle is for sharing with the ecosystem.
    </p>
    <div class="row" style="gap: 8px; align-items: center">
      <select bind:value={iocFormat} aria-label="IOC export format" style="flex: 1">
        <option value="npm-report">npm abuse report</option>
        <option value="stix">STIX 2.1 bundle</option>
        <option value="list">IOC feed</option>
      </select>
      <button class="btn" onclick={runExportIocs} disabled={iocBusy}>
        {iocBusy ? "…" : "Generate"}
      </button>
      <button class="btn ghost" onclick={copyIocs} disabled={!iocOutput}>Copy</button>
    </div>
    {#if iocOutput}
      <textarea
        class="mono"
        readonly
        rows="10"
        style="margin-top: 12px; width: 100%; resize: vertical"
        >{iocOutput}</textarea
      >
    {/if}
  </section>

  <!-- MCP: connect AI assistants -->
  <section class="card">
    <h2>Connect AI assistants (MCP)</h2>
    <p class="lede">
      Run wormward as an MCP server so Claude Code, Cursor, or Codex can drive its tools — scan,
      check-package, doctor, export-iocs, hunt, list-packs (read-only), plus clean/harden (dry-run
      unless explicitly applied). The assistant spawns <span class="mono">wormward mcp</span> itself;
      nothing runs here.
    </p>

    <p class="muted small" style="margin-bottom: 4px">Claude Code</p>
    <div class="row" style="gap: 8px; align-items: flex-start">
      <pre
        class="mono"
        style="flex: 1; margin: 0; padding: 8px 10px; background: #101217; border-radius: 6px; overflow-x: auto">{mcpClaude}</pre>
      <button class="btn ghost sm" onclick={() => copy(mcpClaude)}>Copy</button>
    </div>

    <p class="muted small" style="margin: 12px 0 4px">Cursor — <span class="mono">.cursor/mcp.json</span></p>
    <div class="row" style="gap: 8px; align-items: flex-start">
      <pre
        class="mono"
        style="flex: 1; margin: 0; padding: 8px 10px; background: #101217; border-radius: 6px; overflow-x: auto">{mcpJson}</pre>
      <button class="btn ghost sm" onclick={() => copy(mcpJson)}>Copy</button>
    </div>

    <p class="muted small" style="margin: 12px 0 4px">Codex — <span class="mono">~/.codex/config.toml</span></p>
    <div class="row" style="gap: 8px; align-items: flex-start">
      <pre
        class="mono"
        style="flex: 1; margin: 0; padding: 8px 10px; background: #101217; border-radius: 6px; overflow-x: auto">{mcpCodexToml}</pre>
      <button class="btn ghost sm" onclick={() => copy(mcpCodexToml)}>Copy</button>
    </div>
  </section>

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

  <!-- Other branches -->
  <section class="card">
    <h2>Other branches — deep clean &amp; optional push</h2>
    <p class="lede">
      Deep-scan every branch tip and rewrite infected tips on a fresh commit (the old tip is kept in
      a <code>refs/wormward-backup/…</code> ref). Turning on <strong>Push</strong> force-pushes the
      rewritten tips, overwriting remote history.
    </p>
    {#if !app.dirs.length}
      <p class="muted small">Add a protected location in Settings to scan branches.</p>
    {/if}
    <div class="row">
      <button class="btn sm" onclick={previewBranches} disabled={branchLoading || busy || !app.dirs.length}>
        {#if branchLoading}<span class="spinner"></span>Scanning branches…{:else}Scan other branches{/if}
      </button>
      <button class="btn primary sm" onclick={() => (confirmingBranches = true)} disabled={busy || selectedBranches.length === 0}>
        {#if busyKind === "branches"}<span class="spinner"></span>Cleaning…{:else}Clean {selectedBranches.length} {plural(selectedBranches.length, "branch", "branches")}{/if}
      </button>
      <label class="switch sm">
        <input type="checkbox" bind:checked={pushBranches} />
        <span class="track"></span>
        <span class="lbl small">Push <span class="muted">— force-push tips</span></span>
      </label>
    </div>
    {#if branchSummary}<p class="ok-text small" role="status">{branchSummary}</p>{/if}
    {#if branchPlans.length === 0}
      {#if branchesScanned}<p class="muted micro">No infected branch tips found.</p>{/if}
    {:else}
      <ul class="branch-list">
        {#each branchPlans as b (branchKey(b))}
          <li>
            <label class="switch item">
              <input type="checkbox" bind:checked={branchSel[branchKey(b)]} />
              <span class="track"></span>
              <span class="lbl small"><span class="mono">{b.repo}</span> <span class="chip">branch: {b.branch}</span> <span class="muted">— {b.action_count} {plural(b.action_count, "action", "actions")}</span></span>
            </label>
          </li>
        {/each}
      </ul>
    {/if}
    {#if branchResults.length}
      <div class="stack" style="margin-top: 4px" role="status">
        {#each branchResults as r, i (i)}
          <div class="branch-res {r.status}"><span class="dot"></span><span class="mono">{r.branch}</span> — {r.status}{r.pushed ? " (pushed)" : ""}{#if r.message} — {r.message}{/if}</div>
        {/each}
      </div>
    {/if}
  </section>

  <!-- Restore last backup -->
  <section class="card">
    <h2>Restore last backup</h2>
    <p class="lede">
      Undo a clean by restoring the last backup. <strong>This re-introduces the removed payloads</strong>
      over the current files — only do this if a clean went wrong. If no backup exists, nothing changes.
    </p>
    <div class="row between">
      {#if restoreResult}<p class="ok-text small" role="status">{restoreResult}</p>{:else}<span></span>{/if}
      <button class="btn danger sm" onclick={() => (restoreConfirm = true)} disabled={busy || !app.dirs.length}>
        {#if busyKind === "restore"}<span class="spinner"></span>Restoring…{:else}Restore last backup{/if}
      </button>
    </div>
  </section>
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

{#if confirmingBranches}
  <div class="modal-backdrop">
    <div
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="branch-clean-title"
      tabindex="-1"
      use:dialog={() => (confirmingBranches = false)}
    >
      <h3 id="branch-clean-title">Rewrite branch tips?</h3>
      <p class="lede">Rewrites the tips of {selectedBranches.length} selected {plural(selectedBranches.length, "branch", "branches")} with a new clean commit. The old tip of each is kept in a <code>refs/wormward-backup/…</code> ref.</p>
      {#if pushBranches}
        <p class="crit small"><strong>Push is ON:</strong> cleaned tips will be <strong>force-pushed</strong>, overwriting remote history.</p>
      {:else}
        <p class="muted small">Push is OFF — local branches rewritten in place; remote-tracking branches are reported as skipped.</p>
      {/if}
      <div class="row">
        <button class="btn ghost" onclick={() => (confirmingBranches = false)}>Cancel</button>
        <button class="btn {pushBranches ? 'danger' : 'primary'}" onclick={applyBranches}>{pushBranches ? "Clean & force-push" : "Clean branches"}</button>
      </div>
    </div>
  </div>
{/if}

{#if restoreConfirm}
  <div class="modal-backdrop">
    <div
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="restore-title"
      tabindex="-1"
      use:dialog={() => (restoreConfirm = false)}
    >
      <h3 id="restore-title">Restore the last backup?</h3>
      <p class="crit small"><strong>This re-writes the backed-up originals over the current files</strong> — including the malware that was cleaned. Only do this if a clean went wrong.</p>
      <p class="muted small">If no backup exists, nothing changes.</p>
      <div class="row">
        <button class="btn ghost" onclick={() => (restoreConfirm = false)}>Cancel</button>
        <button class="btn danger" onclick={doRestore}>Restore &amp; re-introduce</button>
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
  .branch-list { list-style: none; display: flex; flex-direction: column; gap: 2px; }
  .branch-res { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
  .branch-res .dot { flex: none; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .branch-res.cleaned { color: var(--ok); }
  .branch-res.cleaned .dot { background: var(--ok); }
  .branch-res.skipped .dot { background: var(--warn); }
  .branch-res.failed { color: var(--danger); }
  .branch-res.failed .dot { background: var(--danger); }
  .branch-res.planned .dot { background: var(--accent); }
</style>
