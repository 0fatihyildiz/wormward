<script lang="ts">
  import { app } from "../lib/state.svelte";
  import type { Finding } from "../lib/types";

  const grouped = $derived.by(() => {
    const map = new Map<string, Finding[]>();
    for (const f of app.report?.findings ?? []) {
      if (!map.has(f.campaign)) map.set(f.campaign, []);
      map.get(f.campaign)!.push(f);
    }
    return [...map.entries()];
  });
</script>

{#if !app.report}
  <p class="muted">Run a scan first.</p>
{:else if app.report.findings.length === 0}
  <section class="card ok">
    <h2>No infections found</h2>
    <p class="muted">Scanned {app.report.repos_scanned} repositories.</p>
  </section>
{:else}
  <p class="muted">
    {app.report.findings.length} finding(s) across {app.report.repos_scanned} repositories.
  </p>
  {#each grouped as [campaign, findings]}
    <section class="card">
      <h2>{campaign} <span class="count">{findings.length}</span></h2>
      {#each findings as f}
        <div class="finding">
          <span class="badge {f.severity}">{f.severity}</span>
          <div>
            <div class="path">
              {f.file ?? "-"}
              {#if f.git_ref}<span class="chip">branch: {f.git_ref}</span>{/if}
            </div>
            <div class="muted small">{f.evidence}</div>
            {#if f.online}
              <div class="small {f.online.malicious ? 'crit' : 'muted'}">
                OSM: {f.online.malicious ? "MALICIOUS" : "not flagged"}
                {#if f.online.osm_url}
                  — <a href={f.online.osm_url} target="_blank" rel="noreferrer">{f.online.osm_url}</a>
                {/if}
              </div>
            {/if}
          </div>
        </div>
      {/each}
    </section>
  {/each}
{/if}
