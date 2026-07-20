<script lang="ts">
  import { app, go } from "../lib/state.svelte";
  import type { Finding } from "../lib/types";
  import FindingCard from "../lib/components/FindingCard.svelte";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  const report = $derived(app.report);
  const findings = $derived(report?.findings ?? []);
  const total = $derived(findings.length);
  const cancelled = $derived(report?.cancelled ?? false);
  // Honest: "scanned" means a Full Scan actually recorded a time, not just a stale report.
  const scanned = $derived(app.lastScanAt !== null);

  const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const rank = (s: string) => SEV_RANK[s] ?? 0;
  const grouped = $derived.by(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      if (!map.has(f.campaign)) map.set(f.campaign, []);
      map.get(f.campaign)!.push(f);
    }
    for (const list of map.values()) list.sort((a, b) => rank(b.severity) - rank(a.severity));
    return [...map.entries()].sort(
      (a, b) => rank(b[1][0].severity) - rank(a[1][0].severity) || b[1].length - a[1].length,
    );
  });
  const affected = $derived(new Set(findings.map((f) => f.repo)).size);
  const removable = $derived(findings.filter((f) => f.remediable).length);
  const manual = $derived(total - removable);
</script>

<div class="page">
  <button class="back" onclick={() => go("home")}>← Home</button>
  <div class="page-head">
    <h1>Repositories</h1>
    <p class="lede">Threats found in your code folders during the last scan.</p>
  </div>

  {#if !scanned}
    <div class="state">
      <span class="glyph">◎</span>
      <h2>Not scanned yet</h2>
      <p class="muted micro">Run a Full Scan from the home screen to check your repositories.</p>
    </div>
  {:else}
    {#if cancelled}
      <section class="card danger" role="alert">
        <h2 class="danger-text">Scan stopped early — results are incomplete</h2>
        <p class="muted small">Some repositories weren't scanned. Run a Full Scan again for a complete picture.</p>
      </section>
    {/if}

    {#if total === 0}
      <div class="card {cancelled ? '' : 'ok'}">
        <div class="state {cancelled ? '' : 'ok'}">
          <div class="glyph">{cancelled ? "◔" : "✓"}</div>
          <h2>{cancelled ? "No threats in what was scanned" : "No threats found"}</h2>
          <p class="muted micro">
            {cancelled
              ? "Nothing malicious in the repositories checked so far."
              : `Checked ${report?.repos_scanned ?? 0} ${plural(report?.repos_scanned ?? 0, "repository", "repositories")}.`}
          </p>
        </div>
      </div>
    {:else}
      <section class="card">
        <div class="stack" style="gap: 4px">
          <h2>
            {total} {plural(total, "threat", "threats")} in {affected} of
            {report?.repos_scanned ?? 0} {plural(report?.repos_scanned ?? 0, "repository", "repositories")}
          </h2>
          <p class="muted micro">
            {removable} can be removed automatically · {manual} {plural(manual, "needs", "need")} your attention
          </p>
        </div>

        {#each grouped as [campaign, list] (campaign)}
          <div class="camp">
            <div class="camp-head">
              <h3>{campaign}</h3>
              <span class="count sev-{list[0].severity}" aria-label="{list.length} {plural(list.length, 'threat', 'threats')}">{list.length}</span>
            </div>
            <ul class="findings">
              {#each list as f, i (f.repo + (f.file ?? "") + f.signature_id + i)}
                <li><FindingCard finding={f} /></li>
              {/each}
            </ul>
          </div>
        {/each}
      </section>
    {/if}

    <p class="adv-link">
      Need to clean other branches or restore a backup?
      <button class="linkish" onclick={() => go("advanced")}>Open Advanced</button>
    </p>
  {/if}
</div>

<style>
  .back {
    align-self: flex-start;
    background: none;
    color: var(--muted);
    font-size: 13px;
    padding: 4px 0;
  }
  .back:hover { color: var(--fg); background: none; }
  .danger-text { color: var(--danger); }
  .camp { padding-top: 11px; border-top: 1px solid var(--surface-3); }
  .camp:first-of-type { border-top: 0; padding-top: 2px; }
  .camp-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 7px;
  }
  .camp-head h3 { font-size: 13px; color: var(--fg); }
  .count.sev-critical { background: var(--danger); color: #150a0b; }
  .count.sev-high { background: var(--danger-tint); color: var(--danger); }
  .count.sev-medium { background: var(--warn-tint); color: var(--warn); }
  .findings { display: flex; flex-direction: column; gap: 8px; list-style: none; }
  .adv-link { font-size: 12.5px; color: var(--muted); }
  .linkish {
    background: none;
    color: var(--accent-hi);
    font-size: 12.5px;
    padding: 0;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .linkish:hover { background: none; color: var(--accent); }
</style>
