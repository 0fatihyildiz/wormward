<script lang="ts">
  import { app, fail, clearErrors } from "../lib/state.svelte";
  import {
    cleanPreview,
    cleanApply,
    restore,
    cleanBranchesPreview,
    cleanBranchesApply,
  } from "../lib/api";
  import { dialog } from "../lib/modal";
  import type {
    RepoPlan,
    RemediationAction,
    BranchCleanPreview,
    BranchSelection,
    BranchCleanResult,
  } from "../lib/types";

  // Feature A: working-tree cleaning with per-repo selection.
  let plans = $state<RepoPlan[]>([]);
  let repoSel = $state<Record<string, boolean>>({});
  let loading = $state(false);
  let busy = $state(false);
  let confirming = $state(false);
  let result = $state("");

  // Feature B: cross-branch cleaning.
  let branchPlans = $state<BranchCleanPreview[]>([]);
  let branchSel = $state<Record<string, boolean>>({});
  let pushBranches = $state(false);
  let branchLoading = $state(false);
  let confirmingBranches = $state(false);
  let branchResults = $state<BranchCleanResult[]>([]);
  let branchSummary = $state("");

  const dirs = $derived(app.dirs.length ? app.dirs : ["."]);

  // "\n" separator: never appears in a filesystem path or a git branch name, so the
  // key is collision-free (a raw NUL byte here would corrupt the source file as binary).
  const branchKey = (b: { repo: string; branch: string }) => `${b.repo}\n${b.branch}`;

  function describe(a: RemediationAction): string {
    if ("StripPayload" in a) return `strip payload from ${a.StripPayload.file}`;
    if ("DeleteFile" in a) return `delete ${a.DeleteFile.file}`;
    return `remove '${a.RemoveGitignoreLine.line}' from ${a.RemoveGitignoreLine.file}`;
  }

  async function preview() {
    loading = true;
    clearErrors();
    try {
      plans = await cleanPreview(dirs);
      const sel: Record<string, boolean> = {};
      for (const p of plans) if (p.actions.length) sel[p.repo] = true;
      repoSel = sel;
    } catch (e) {
      fail(e);
    } finally {
      loading = false;
    }
  }

  const applicable = $derived(plans.filter((p) => p.actions.length));
  const selectedRepos = $derived(applicable.filter((p) => repoSel[p.repo]).map((p) => p.repo));
  const nothingToApply = $derived(selectedRepos.length === 0);

  async function apply() {
    confirming = false;
    busy = true;
    result = "";
    clearErrors();
    try {
      const s = await cleanApply(selectedRepos);
      result =
        `Cleaned ${s.repos} repo(s): ${s.applied} action(s) applied` +
        (s.skipped.length ? `, ${s.skipped.length} skipped` : "") +
        (s.backups.length ? `. Backup at ${s.backups[0]}` : "");
      await preview();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
    }
  }

  async function doRestore() {
    busy = true;
    result = "";
    clearErrors();
    try {
      const s = await restore(dirs);
      result = `Restored ${s.restored} file(s) across ${s.repos} repo(s).`;
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
    }
  }

  async function previewBranches() {
    branchLoading = true;
    clearErrors();
    try {
      branchPlans = await cleanBranchesPreview(dirs);
      const sel: Record<string, boolean> = {};
      for (const b of branchPlans) sel[branchKey(b)] = true;
      branchSel = sel;
    } catch (e) {
      fail(e);
    } finally {
      branchLoading = false;
    }
  }

  const selectedBranches = $derived<BranchSelection[]>(
    branchPlans
      .filter((b) => branchSel[branchKey(b)])
      .map((b) => ({ repo: b.repo, branch: b.branch }))
  );

  async function applyBranches() {
    confirmingBranches = false;
    busy = true;
    branchSummary = "";
    clearErrors();
    try {
      const s = await cleanBranchesApply(selectedBranches, pushBranches);
      branchResults = s.results;
      branchSummary =
        `Cleaned ${s.cleaned} branch(es)` +
        (s.skipped ? `, ${s.skipped} skipped` : "") +
        (s.failed ? `, ${s.failed} failed` : "") +
        ".";
      await previewBranches();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    preview();
  });
</script>

<div class="page">
  <div class="page-head">
    <h1>Clean</h1>
    <p class="lede">Remove detected infections. Originals are backed up before anything changes.</p>
  </div>

  <section class="card">
    <h2>Working tree</h2>
    <p class="lede">
      Payloads stripped, dropped artifacts deleted, <code>.gitignore</code> fixed — the current
      checkout only. Pick which repos to fix below.
    </p>
    <div class="row">
      <button class="btn" onclick={preview} disabled={loading || busy}>Refresh</button>
      <button class="btn primary" onclick={() => (confirming = true)} disabled={busy || nothingToApply}>
        Apply &amp; fix…
      </button>
      <button class="btn" onclick={doRestore} disabled={busy}>Restore last backup</button>
    </div>
    {#if result}<p class="ok-text small">{result}</p>{/if}
  </section>

  {#if loading}
    <div class="card"><div class="row"><span class="spinner"></span><span class="muted small">Scanning…</span></div></div>
  {:else if plans.length === 0}
    <div class="card"><p class="muted small">Nothing to clean.</p></div>
  {:else}
    {#each plans as p, i}
      <section class="card reveal" style="animation-delay: {Math.min(i, 12) * 25}ms">
        {#if p.actions.length}
          <label class="switch">
            <input type="checkbox" bind:checked={repoSel[p.repo]} />
            <span class="track"></span>
            <span class="lbl mono small">{p.repo}</span>
          </label>
        {:else}
          <h3 class="mono small">{p.repo}</h3>
        {/if}
        {#each p.actions as a}<div class="action"><span class="tick">✓</span> {describe(a)}</div>{/each}
        {#each p.manual as m}
          <div class="muted small">
            manual: {m.campaign} — {m.file ?? "-"}{m.git_ref ? ` (branch: ${m.git_ref})` : ""} — {m.evidence}
          </div>
        {/each}
      </section>
    {/each}
  {/if}

  <section class="card">
    <h2>Other branches</h2>
    <p class="lede">
      Deep-scan every branch tip and rewrite infected tips on a fresh commit (the old tip is
      preserved in a <code>refs/wormward-backup/…</code> ref). Remote-tracking branches can only be
      fixed with push enabled — otherwise they are reported as skipped.
    </p>
    <div class="row">
      <button class="btn" onclick={previewBranches} disabled={branchLoading || busy}>
        {branchLoading ? "Scanning branches…" : "Scan other branches"}
      </button>
      <button
        class="btn primary"
        onclick={() => (confirmingBranches = true)}
        disabled={busy || selectedBranches.length === 0}
      >
        Clean selected branches…
      </button>
    </div>
    <label class="switch">
      <input type="checkbox" bind:checked={pushBranches} />
      <span class="track"></span>
      <span class="lbl">Push cleaned branches <span class="muted">— force-push rewritten tips</span></span>
    </label>
    {#if branchSummary}<p class="ok-text small">{branchSummary}</p>{/if}

    {#if branchLoading}
      <div class="row"><span class="spinner"></span><span class="muted small">Scanning branch tips…</span></div>
    {:else if branchPlans.length === 0}
      <p class="muted small">No infected branch tips found (run a scan).</p>
    {:else}
      {#each branchPlans as b}
        <label class="switch item">
          <input type="checkbox" bind:checked={branchSel[branchKey(b)]} />
          <span class="track"></span>
          <span class="lbl small">
            <span class="mono">{b.repo}</span>
            <span class="chip">branch: {b.branch}</span>
            <span class="muted">— {b.action_count} action(s)</span>
          </span>
        </label>
      {/each}
    {/if}

    {#if branchResults.length}
      <div class="stack" style="margin-top:4px">
        {#each branchResults as r}
          <div class="small {r.status === 'failed' ? 'crit' : 'muted'}">
            {r.branch}: {r.status}{r.pushed ? " (pushed)" : ""}{r.message ? ` — ${r.message}` : ""}
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>

{#if confirming}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirming = false)}>
      <h3>Apply changes?</h3>
      <p class="lede">
        This modifies files in the working tree of {selectedRepos.length} selected repo(s)
        (originals are backed up under <code>.wormward-backup/</code>). It does not touch git
        history or push anything.
      </p>
      <div class="row">
        <button class="btn ghost" onclick={() => (confirming = false)}>Cancel</button>
        <button class="btn primary" onclick={apply}>Apply &amp; fix</button>
      </div>
    </div>
  </div>
{/if}

{#if confirmingBranches}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirmingBranches = false)}>
      <h3>Rewrite branch tips?</h3>
      <p class="lede">
        This rewrites the tips of {selectedBranches.length} selected branch(es) with a new clean
        commit. The old tip of each is preserved in a <code>refs/wormward-backup/…</code> ref for
        rollback.
      </p>
      {#if pushBranches}
        <p class="crit small">
          <strong>Push is ON:</strong> cleaned tips will be <strong>force-pushed</strong> to their
          remotes, overwriting remote history.
        </p>
      {:else}
        <p class="muted small">
          Push is OFF — local branches are rewritten in place; remote-tracking branches are
          reported as skipped.
        </p>
      {/if}
      <div class="row">
        <button class="btn ghost" onclick={() => (confirmingBranches = false)}>Cancel</button>
        <button class="btn {pushBranches ? 'danger' : 'primary'}" onclick={applyBranches}>
          {pushBranches ? "Clean & force-push" : "Clean branches"}
        </button>
      </div>
    </div>
  </div>
{/if}
