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

  const total = $derived(app.report?.findings.length ?? 0);
</script>

<div class="page">
  <div class="page-head">
    <h1>Results</h1>
    {#if app.report && total > 0}
      <p class="lede">
        {total} finding{total === 1 ? "" : "s"} across {app.report.repos_scanned} repositories.
      </p>
    {/if}
  </div>

  {#if !app.report}
    <div class="card">
      <div class="state">
        <div class="glyph">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.7" />
            <path d="m16.5 16.5 4 4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
          </svg>
        </div>
        <h2>No scan yet</h2>
        <p class="muted small">Run a scan to see findings here.</p>
      </div>
    </div>
  {:else}
    {#if app.report.warnings?.length}
      <section class="card warn">
        <h2 class="warn-text">Online lookup warnings</h2>
        <div class="stack">
          {#each app.report.warnings as w}
            <div class="small muted">{w}</div>
          {/each}
        </div>
      </section>
    {/if}

    {#if total === 0}
      <div class="card ok">
        <div class="state ok">
          <div class="glyph">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M5 12.5 10 17.5 19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </div>
          <h2>No infections found</h2>
          <p class="muted small">Scanned {app.report.repos_scanned} repositories.</p>
        </div>
      </div>
    {:else}
      {#each grouped as [campaign, findings]}
        <section class="card">
          <div class="row between">
            <h2>{campaign}</h2>
            <span class="count">{findings.length}</span>
          </div>
          {#each findings as f, i}
            <div class="finding reveal" style="animation-delay: {Math.min(i, 12) * 25}ms">
              <span class="pill {f.severity}">{f.severity}</span>
              <div class="stack" style="min-width:0;flex:1">
                <div class="path">
                  {f.file ?? "—"}
                  {#if f.git_ref}<span class="chip">branch: {f.git_ref}</span>{/if}
                </div>
                <div class="faint micro mono">{f.repo}</div>
                <div class="muted small">{f.evidence}</div>
                {#if f.online}
                  <div class="small {f.online.malicious ? 'crit' : 'muted'}">
                    OSM: {f.online.malicious ? "MALICIOUS" : "not flagged"}
                    {#if f.online.osm_url}
                      · <a href={f.online.osm_url} target="_blank" rel="noreferrer">{f.online.osm_url}</a>
                    {/if}
                  </div>
                {/if}
              </div>
            </div>
          {/each}
        </section>
      {/each}
    {/if}
  {/if}
</div>
