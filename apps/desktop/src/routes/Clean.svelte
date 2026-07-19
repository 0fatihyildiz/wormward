<script lang="ts">
  import { app } from "../lib/state.svelte";
  import {
    cleanPreview,
    cleanApply,
    restore,
    cleanBranchesPreview,
    cleanBranchesApply,
  } from "../lib/api";
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
    app.error = "";
    try {
      plans = await cleanPreview(dirs);
      const sel: Record<string, boolean> = {};
      for (const p of plans) if (p.actions.length) sel[p.repo] = true;
      repoSel = sel;
    } catch (e) {
      app.error = String(e);
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
    app.error = "";
    try {
      const s = await cleanApply(selectedRepos);
      result =
        `Cleaned ${s.repos} repo(s): ${s.applied} action(s) applied` +
        (s.skipped.length ? `, ${s.skipped.length} skipped` : "") +
        (s.backups.length ? `. Backup at ${s.backups[0]}` : "");
      await preview();
    } catch (e) {
      app.error = String(e);
    } finally {
      busy = false;
    }
  }

  async function doRestore() {
    busy = true;
    result = "";
    app.error = "";
    try {
      const s = await restore(dirs);
      result = `Restored ${s.restored} file(s) across ${s.repos} repo(s).`;
    } catch (e) {
      app.error = String(e);
    } finally {
      busy = false;
    }
  }

  async function previewBranches() {
    branchLoading = true;
    app.error = "";
    try {
      branchPlans = await cleanBranchesPreview(dirs);
      const sel: Record<string, boolean> = {};
      for (const b of branchPlans) sel[branchKey(b)] = true;
      branchSel = sel;
    } catch (e) {
      app.error = String(e);
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
    app.error = "";
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
      app.error = String(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    preview();
  });
</script>

<section class="card">
  <h2>Clean infections</h2>
  <p class="muted">
    Working tree only — payloads stripped, dropped artifacts deleted, <code>.gitignore</code> fixed.
    Originals are backed up. Pick which repos to fix below.
  </p>
  <div class="row">
    <button onclick={preview} disabled={loading || busy}>Refresh</button>
    <button class="primary" onclick={() => (confirming = true)} disabled={busy || nothingToApply}>
      Apply &amp; fix…
    </button>
    <button onclick={doRestore} disabled={busy}>Restore last backup</button>
  </div>
  {#if result}<p class="ok-text">{result}</p>{/if}
</section>

{#if loading}
  <p class="muted">Scanning…</p>
{:else if plans.length === 0}
  <p class="muted">Nothing to clean.</p>
{:else}
  {#each plans as p}
    <section class="card">
      <h3>
        {#if p.actions.length}
          <label>
            <input type="checkbox" bind:checked={repoSel[p.repo]} />
            {p.repo}
          </label>
        {:else}
          {p.repo}
        {/if}
      </h3>
      {#each p.actions as a}<div class="action">✓ {describe(a)}</div>{/each}
      {#each p.manual as m}
        <div class="muted small">
          manual: {m.campaign} — {m.file ?? "-"}{m.git_ref ? ` (branch: ${m.git_ref})` : ""} — {m.evidence}
        </div>
      {/each}
    </section>
  {/each}
{/if}

<section class="card">
  <h2>Also clean other branches</h2>
  <p class="muted">
    Deep-scan every branch tip and rewrite infected tips on a fresh commit (old tip is preserved
    in a <code>refs/wormward-backup/…</code> ref). Remote-tracking branches can only be fixed with
    push enabled — they are reported as skipped otherwise.
  </p>
  <div class="row">
    <button onclick={previewBranches} disabled={branchLoading || busy}>
      {branchLoading ? "Scanning branches…" : "Scan other branches"}
    </button>
    <button
      class="primary"
      onclick={() => (confirmingBranches = true)}
      disabled={busy || selectedBranches.length === 0}
    >
      Clean selected branches…
    </button>
  </div>
  <label>
    <input type="checkbox" bind:checked={pushBranches} />
    Push cleaned branches (force-push rewritten tips to their remotes)
  </label>
  {#if branchSummary}<p class="ok-text">{branchSummary}</p>{/if}

  {#if branchLoading}
    <p class="muted">Scanning branch tips…</p>
  {:else if branchPlans.length === 0}
    <p class="muted small">No infected branch tips found (run a scan).</p>
  {:else}
    {#each branchPlans as b}
      <div class="action">
        <label>
          <input type="checkbox" bind:checked={branchSel[branchKey(b)]} />
          {b.repo} <span class="chip">branch: {b.branch}</span> — {b.action_count} action(s)
        </label>
      </div>
    {/each}
  {/if}

  {#if branchResults.length}
    <div class="results">
      {#each branchResults as r}
        <div class="small {r.status === 'failed' ? 'crit' : 'muted'}">
          {r.branch}: {r.status}{r.pushed ? " (pushed)" : ""}{r.message ? ` — ${r.message}` : ""}
        </div>
      {/each}
    </div>
  {/if}
</section>

{#if confirming}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1">
      <h3>Apply changes?</h3>
      <p>
        This modifies files in the working tree of {selectedRepos.length} selected repo(s)
        (originals are backed up under <code>.wormward-backup/</code>). It does not touch git
        history or push anything.
      </p>
      <div class="row">
        <button onclick={() => (confirming = false)}>Cancel</button>
        <button class="primary" onclick={apply}>Apply &amp; fix</button>
      </div>
    </div>
  </div>
{/if}

{#if confirmingBranches}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1">
      <h3>Rewrite branch tips?</h3>
      <p>
        This rewrites the tips of {selectedBranches.length} selected branch(es) with a new clean
        commit. The old tip of each is preserved in a <code>refs/wormward-backup/…</code> ref for
        rollback.
      </p>
      {#if pushBranches}
        <p class="crit">
          <strong>Push is ON:</strong> cleaned tips will be <strong>force-pushed</strong> to their
          remotes, overwriting remote history.
        </p>
      {:else}
        <p class="muted">
          Push is OFF — local branches are rewritten in place; remote-tracking branches are
          reported as skipped.
        </p>
      {/if}
      <div class="row">
        <button onclick={() => (confirmingBranches = false)}>Cancel</button>
        <button class="primary" onclick={applyBranches}>
          {pushBranches ? "Clean & force-push" : "Clean branches"}
        </button>
      </div>
    </div>
  </div>
{/if}
