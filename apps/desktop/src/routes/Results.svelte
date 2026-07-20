<script lang="ts">
  import { app } from "../lib/state.svelte";
  import type { Finding } from "../lib/types";

  const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const rank = (s: string) => SEV_RANK[s] ?? 0;

  const report = $derived(app.report);
  const findings = $derived(report?.findings ?? []);
  const total = $derived(findings.length);
  const cancelled = $derived(report?.cancelled ?? false);

  // Group by campaign; sort findings worst-first, campaigns by worst severity then count.
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

  // Distinct affected repos — not the total scanned.
  const affected = $derived(new Set(findings.map((f) => f.repo)).size);

  const sevCounts = $derived.by(() => {
    const c: Record<string, number> = {};
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return (["critical", "high", "medium", "low", "info"] as const)
      .filter((s) => c[s])
      .map((s) => ({ sev: s, n: c[s] }));
  });

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);
</script>

<div class="page">
  <div class="page-head">
    <div class="row between">
      <h1>Results</h1>
      {#if report && total > 0}
        <button class="btn primary sm" onclick={() => (app.screen = "clean")}>Review &amp; clean →</button>
      {/if}
    </div>
    {#if report && total > 0}
      <p class="lede">
        {total} {plural(total, "finding", "findings")} in {affected} of {report.repos_scanned}
        {plural(report.repos_scanned, "repository", "repositories")} scanned.
      </p>
      <div class="sev-summary">
        {#each sevCounts as s (s.sev)}
          <span class="sev-chip {s.sev}">{s.n} {s.sev}</span>
        {/each}
      </div>
    {/if}
  </div>

  {#if app.scanning}
    <div class="scanning-note" role="status">
      Scan in progress — these results will refresh when it finishes.
    </div>
  {/if}

  {#if !report}
    <div class="card">
      <div class="state">
        <div class="glyph">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.7" />
            <path d="m16.5 16.5 4 4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
          </svg>
        </div>
        <h2>No scan yet</h2>
        <p class="muted micro">Run a scan to see findings here.</p>
        <button class="btn primary sm" onclick={() => (app.screen = "scan")}>Run a scan →</button>
      </div>
    </div>
  {:else}
    {#if cancelled}
      <section class="card danger" role="alert">
        <h2 class="danger-text">Scan stopped early — results are incomplete</h2>
        <p class="muted small">
          Repositories after the stop point were not scanned, so this is not a clean bill of health.
          Run a full scan for a complete picture.
        </p>
      </section>
    {/if}

    {#if report.warnings?.length}
      <section class="card warn">
        <div class="row">
          <span class="warn-glyph" aria-hidden="true">!</span>
          <h2 class="warn-text">Some online checks couldn't run</h2>
        </div>
        <ul class="notes">
          {#each report.warnings as w, i (i)}<li class="micro muted">{w}</li>{/each}
        </ul>
      </section>
    {/if}

    {#if total === 0}
      {#if cancelled}
        <div class="card">
          <div class="state">
            <div class="glyph">◔</div>
            <h2>Scan incomplete</h2>
            <p class="muted micro">
              No infections in the {report.repos_scanned}
              {plural(report.repos_scanned, "repository", "repositories")} scanned so far.
            </p>
          </div>
        </div>
      {:else}
        <div class="card ok">
          <div class="state ok">
            <div class="glyph">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M5 12.5 10 17.5 19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </div>
            <h2>No infections found</h2>
            <p class="muted micro">
              Scanned {report.repos_scanned}
              {plural(report.repos_scanned, "repository", "repositories")}.
            </p>
          </div>
        </div>
      {/if}
    {:else}
      {#each grouped as [campaign, list] (campaign)}
        <section class="card">
          <div class="row between">
            <h2>{campaign}</h2>
            <span class="count sev-{list[0].severity}" aria-label="{list.length} findings">{list.length}</span>
          </div>
          <ul class="findings">
            {#each list as f, i (f.repo + (f.file ?? "") + f.signature_id + i)}
              <li class="finding reveal" style="animation-delay: {Math.min(i, 12) * 25}ms">
                <span class="pill {f.severity}">{f.severity}</span>
                <div class="stack" style="min-width: 0; flex: 1">
                  <div class="repo mono">{f.repo}</div>
                  <div class="path">
                    {#if f.file}{f.file}{:else}<span class="muted">repository-level</span>{/if}
                    {#if f.git_ref}<span class="chip">branch: {f.git_ref}</span>{/if}
                    <span class="tag {f.remediable ? 'fixable' : 'manual'}">
                      {f.remediable ? "Auto-fixable" : "Manual review"}
                    </span>
                  </div>
                  <code class="evidence mono">{f.evidence}</code>
                  {#if f.online}
                    <div class="micro {f.online.malicious ? 'crit' : 'muted'}">
                      OpenSourceMalware:
                      {f.online.malicious ? "flagged as malicious" : "not flagged"}
                      {#if f.online.message}— {f.online.message}{/if}
                      {#if f.online.osm_url}
                        · <a href={f.online.osm_url} target="_blank" rel="noreferrer noopener">View advisory ↗</a>
                      {/if}
                    </div>
                  {/if}
                </div>
              </li>
            {/each}
          </ul>
        </section>
      {/each}
    {/if}
  {/if}
</div>

<style>
  .sev-summary { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 2px; }
  .sev-chip {
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 999px;
    text-transform: capitalize;
  }
  .sev-chip.critical { background: var(--danger); color: #150a0b; }
  .sev-chip.high { background: var(--danger-tint); color: var(--danger); }
  .sev-chip.medium { background: var(--warn-tint); color: var(--warn); }
  .sev-chip.low, .sev-chip.info { background: var(--accent-tint); color: var(--accent-hi); }

  .scanning-note {
    background: var(--surface-2);
    color: var(--muted);
    font-size: 12.5px;
    padding: 10px 14px;
    border-radius: var(--radius-sm);
  }

  .count.sev-critical { background: var(--danger); color: #150a0b; }
  .count.sev-high { background: var(--danger-tint); color: var(--danger); }
  .count.sev-medium { background: var(--warn-tint); color: var(--warn); }

  .warn-text { color: var(--warn); font-size: 14px; }
  .danger-text { color: var(--danger); font-size: 14px; }
  .warn-glyph {
    font-weight: 700;
    color: var(--warn);
    width: 18px; height: 18px;
    display: inline-flex; align-items: center; justify-content: center;
    background: var(--warn-tint); border-radius: 50%;
  }
  .notes { display: flex; flex-direction: column; gap: 4px; list-style: none; }

  .findings { display: flex; flex-direction: column; gap: 10px; list-style: none; }
  .finding { display: flex; gap: 11px; align-items: flex-start; }
  .repo { font-size: 12px; color: var(--fg); word-break: break-all; }
  .path {
    display: flex; align-items: center; gap: 7px; flex-wrap: wrap;
    font-size: 12px; color: var(--muted);
  }
  .chip {
    font-size: 10.5px; color: var(--faint);
    background: var(--surface-2); padding: 1px 7px; border-radius: 999px;
  }
  .tag { font-size: 10px; font-weight: 600; padding: 1px 7px; border-radius: 999px; }
  .tag.fixable { background: var(--ok-tint); color: var(--ok); }
  .tag.manual { background: var(--warn-tint); color: var(--warn); }
  .evidence {
    font-size: 11.5px; color: var(--faint);
    word-break: break-all; line-height: 1.5;
  }
  .crit { color: var(--danger); }
</style>
