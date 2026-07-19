<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { cleanPreview, cleanApply, restore } from "../lib/api";
  import type { RepoPlan, RemediationAction } from "../lib/types";

  let plans = $state<RepoPlan[]>([]);
  let loading = $state(false);
  let busy = $state(false);
  let confirming = $state(false);
  let result = $state("");

  const dirs = $derived(app.dirs.length ? app.dirs : ["."]);

  function describe(a: RemediationAction): string {
    if ("StripPayload" in a) return `strip payload from ${a.StripPayload.file}`;
    if ("DeleteFile" in a) return `delete ${a.DeleteFile.file}`;
    return `remove '${a.RemoveGitignoreLine.line}' from ${a.RemoveGitignoreLine.file}`;
  }

  async function preview() {
    loading = true;
    result = "";
    app.error = "";
    try {
      plans = await cleanPreview(dirs);
    } catch (e) {
      app.error = String(e);
    } finally {
      loading = false;
    }
  }

  async function apply() {
    confirming = false;
    busy = true;
    result = "";
    app.error = "";
    try {
      const s = await cleanApply(dirs);
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

  const nothingToApply = $derived(plans.every((p) => p.actions.length === 0));

  $effect(() => {
    preview();
  });
</script>

<section class="card">
  <h2>Clean infections</h2>
  <p class="muted">
    Working tree only — payloads stripped, dropped artifacts deleted, <code>.gitignore</code> fixed.
    Originals are backed up. Git history / push are CLI-only.
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
      <h3>{p.repo}</h3>
      {#each p.actions as a}<div class="action">✓ {describe(a)}</div>{/each}
      {#each p.manual as m}
        <div class="muted small">
          manual: {m.campaign} — {m.file ?? "-"}{m.git_ref ? ` (branch: ${m.git_ref})` : ""} — {m.evidence}
        </div>
      {/each}
    </section>
  {/each}
{/if}

{#if confirming}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1">
      <h3>Apply changes?</h3>
      <p>
        This modifies files in the working tree (originals are backed up under
        <code>.wormward-backup/</code>). It does not touch git history or push anything.
      </p>
      <div class="row">
        <button onclick={() => (confirming = false)}>Cancel</button>
        <button class="primary" onclick={apply}>Apply &amp; fix</button>
      </div>
    </div>
  </div>
{/if}
