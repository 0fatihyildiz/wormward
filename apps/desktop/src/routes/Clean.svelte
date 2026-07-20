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
  let busyKind = $state<"apply" | "restore" | "branches" | "">("");
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
  let branchesScanned = $state(false);
  let restoreConfirm = $state(false);

  const dirs = $derived(app.dirs.length ? app.dirs : ["."]);
  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  // "\n" separator: never appears in a filesystem path or a git branch name, so the
  // key is collision-free (a raw NUL byte here would corrupt the source file as binary).
  const branchKey = (b: { repo: string; branch: string }) => `${b.repo}\n${b.branch}`;

  function describe(a: RemediationAction): string {
    if ("StripPayload" in a) return `Strip injected payload from ${a.StripPayload.file}`;
    if ("DeleteFile" in a) return `Delete dropped artifact ${a.DeleteFile.file}`;
    return `Remove '${a.RemoveGitignoreLine.line}' from ${a.RemoveGitignoreLine.file}`;
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
  const manualCount = $derived(plans.reduce((n, p) => n + p.manual.length, 0));

  async function apply() {
    confirming = false;
    busy = true;
    busyKind = "apply";
    result = "";
    clearErrors();
    try {
      const s = await cleanApply(selectedRepos);
      result =
        `Cleaned ${s.repos} ${plural(s.repos, "repo", "repos")}: ${s.applied} ${plural(s.applied, "action", "actions")} applied` +
        (s.skipped.length ? `, ${s.skipped.length} skipped` : "") +
        (manualCount ? `. ${manualCount} ${plural(manualCount, "item", "items")} still need manual review` : "") +
        (s.backups.length ? `. Backup at ${s.backups[0]}` : "");
      await preview();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
    }
  }

  async function doRestore() {
    restoreConfirm = false;
    busy = true;
    busyKind = "restore";
    result = "";
    clearErrors();
    try {
      const s = await restore(dirs);
      result =
        s.restored > 0
          ? `Restored ${s.restored} ${plural(s.restored, "file", "files")} across ${s.repos} ${plural(s.repos, "repo", "repos")}.`
          : "No backup found to restore.";
      // Reflect the re-introduced (or unchanged) tree in the plan list.
      await preview();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
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
      branchesScanned = true;
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
    busyKind = "branches";
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
      busyKind = "";
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
        {#if busyKind === "apply"}<span class="spinner"></span>Applying…{:else}Apply &amp; fix…{/if}
      </button>
      <button class="btn" onclick={() => (restoreConfirm = true)} disabled={busy}>
        {#if busyKind === "restore"}<span class="spinner"></span>Restoring…{:else}Restore last backup{/if}
      </button>
    </div>
    {#if result}<p class="ok-text small">{result}</p>{/if}
  </section>

  {#if loading}
    <div class="card"><div class="row"><span class="spinner"></span><span class="muted small">Scanning…</span></div></div>
  {:else if applicable.length === 0 && manualCount === 0}
    <div class="card ok">
      <div class="state ok">
        <div class="glyph">✓</div>
        <h2>Working tree is clean</h2>
        <p class="muted micro">
          No payloads, dropped artifacts, or injected <code>.gitignore</code> entries in the current
          checkout.
        </p>
      </div>
    </div>
  {:else}
    {#each plans.filter((p) => p.actions.length || p.manual.length) as p, i (p.repo)}
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
        {#each p.actions as a, ai (ai)}
          <div class="action"><span class="will" aria-hidden="true">→</span> {describe(a)}</div>
        {/each}
        {#if p.manual.length}
          <div class="manual-block">
            <div class="manual-head">
              Needs manual review
              <span class="count warnc">{p.manual.length}</span>
            </div>
            {#each p.manual as m, mi (mi)}
              <div class="manual-item">
                <span class="pill {m.severity}">{m.severity}</span>
                <div class="stack" style="min-width: 0; flex: 1">
                  <div class="path">
                    {#if m.file}{m.file}{:else}<span class="muted">repository-level</span>{/if}
                    {#if m.git_ref}<span class="chip">branch: {m.git_ref}</span>{/if}
                  </div>
                  <div class="muted micro">{m.campaign} — {m.evidence}</div>
                </div>
              </div>
            {/each}
          </div>
        {/if}
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
        {#if branchLoading}<span class="spinner"></span>Scanning branches…{:else}Scan other branches{/if}
      </button>
      <button
        class="btn primary"
        onclick={() => (confirmingBranches = true)}
        disabled={busy || selectedBranches.length === 0}
      >
        {#if busyKind === "branches"}<span class="spinner"></span>Cleaning branches…{:else}Clean selected branches…{/if}
      </button>
    </div>
    <label class="switch">
      <input type="checkbox" bind:checked={pushBranches} />
      <span class="track"></span>
      <span class="lbl">Push cleaned branches <span class="muted">— force-push rewritten tips</span></span>
    </label>
    {#if branchSummary}<p class="ok-text small">{branchSummary}</p>{/if}

    {#if branchPlans.length === 0}
      {#if branchesScanned}
        <div class="state ok"><div class="glyph">✓</div><p>No infected branch tips found.</p></div>
      {:else if !branchLoading}
        <p class="muted micro">Scan other branches to check every branch tip.</p>
      {/if}
    {:else}
      {#each branchPlans as b (branchKey(b))}
        <label class="switch item">
          <input type="checkbox" bind:checked={branchSel[branchKey(b)]} />
          <span class="track"></span>
          <span class="lbl small">
            <span class="mono">{b.repo}</span>
            <span class="chip">branch: {b.branch}</span>
            <span class="muted">— {b.action_count} {plural(b.action_count, "action", "actions")}</span>
          </span>
        </label>
      {/each}
    {/if}

    {#if branchResults.length}
      <div class="stack" style="margin-top: 4px">
        {#each branchResults as r, i (i)}
          <div class="branch-res {r.status}">
            <span class="dot" aria-hidden="true"></span>
            <span class="mono">{r.branch}</span> — {r.status}{r.pushed ? " (pushed)" : ""}{#if r.message} — {r.message}{/if}
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>

{#if restoreConfirm}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (restoreConfirm = false)}>
      <h3>Restore the last backup?</h3>
      <p class="crit small">
        <strong>This re-writes the backed-up originals over the current files</strong> — including
        the detected malware that was cleaned. Only do this if a clean went wrong.
      </p>
      <p class="muted small">If no backup exists, nothing is changed.</p>
      <div class="row">
        <button class="btn ghost" onclick={() => (restoreConfirm = false)}>Cancel</button>
        <button class="btn danger" onclick={doRestore}>Restore &amp; re-introduce</button>
      </div>
    </div>
  </div>
{/if}

{#if confirming}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirming = false)}>
      <h3>Apply changes?</h3>
      <p class="lede">
        This modifies files in the working tree of {selectedRepos.length} selected
        {plural(selectedRepos.length, "repository", "repositories")} (originals are backed up under
        <code>.wormward-backup/</code>). It does not touch git history or push anything.
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

<style>
  /* Pending actions read as "will do", not done (the global .action is green). */
  .action { color: var(--fg); }
  .will { flex: none; color: var(--accent); font-weight: 700; }

  .manual-block {
    margin-top: 10px;
    padding: 11px 13px;
    background: var(--surface-warn);
    border-radius: var(--radius-sm);
    display: flex;
    flex-direction: column;
    gap: 9px;
  }
  .manual-head {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--warn);
    font-weight: 600;
    font-size: 13px;
  }
  .manual-item { display: flex; gap: 10px; align-items: flex-start; }
  .count.warnc { background: var(--warn-tint); color: var(--warn); }
  .path {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-wrap: wrap;
    font-size: 12px;
    color: var(--fg);
    word-break: break-all;
  }

  .branch-res { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
  .branch-res .dot { flex: none; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .branch-res.cleaned { color: var(--ok); }
  .branch-res.cleaned .dot { background: var(--ok); }
  .branch-res.skipped .dot { background: var(--warn); }
  .branch-res.failed { color: var(--danger); }
  .branch-res.failed .dot { background: var(--danger); }
  .branch-res.planned .dot { background: var(--accent); }
</style>
