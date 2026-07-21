<script lang="ts">
  import type { Finding } from "../types";
  import { fixClass, fixLabel } from "../findings";

  let { finding }: { finding: Finding } = $props();

  const SEV_WORD: Record<string, string> = {
    critical: "Critical threat",
    high: "Serious threat",
    medium: "Threat",
    low: "Minor issue",
    info: "Note",
  };
  const title = $derived(SEV_WORD[finding.severity] ?? "Threat");
  // file:line when the finding knows where it matched; repo as the fallback anchor.
  const where = $derived(
    finding.file ? (finding.excerpt ? `${finding.file}:${finding.excerpt.line}` : finding.file) : finding.repo,
  );
  // auto / branch / manual — the pill must match what the results-screen buttons can do:
  // a branch-tip finding is NOT one-click removable, so it can't read "Removable automatically".
  const cls = $derived(fixClass(finding));
  const label = $derived(fixLabel(finding));
  const pillTone = $derived(cls === "auto" ? "ok" : cls === "branch" ? "info" : "warn");
</script>

<div class="finding-card">
  <div class="fc-top">
    <span class="fc-title sev-{finding.severity}">{title}</span>
    <span class="fc-where mono">{where}</span>
    <span class="fc-label {pillTone}">{label}</span>
  </div>
  <details class="fc-details">
    <summary>Details</summary>
    <dl class="fc-dl">
      <dt>What we found</dt>
      <dd class="mono">{finding.evidence}</dd>
      {#if finding.excerpt}
        <dt>Matched code</dt>
        <dd class="mono snippet">line {finding.excerpt.line}: <code>{finding.excerpt.text}</code></dd>
      {/if}
      <dt>Repository</dt>
      <dd class="mono">{finding.repo}</dd>
      {#if finding.file}
        <dt>File</dt>
        <dd class="mono">{finding.file}{#if finding.excerpt}:{finding.excerpt.line}{/if}</dd>
      {/if}
      <dt>Campaign</dt>
      <dd>{finding.campaign}</dd>
      {#if finding.git_ref}
        <dt>Branch</dt>
        <dd class="mono">{finding.git_ref}</dd>
      {/if}
      {#if finding.online}
        <dt>Online check</dt>
        <dd class={finding.online.malicious ? "crit" : "muted"}>
          OpenSourceMalware: {finding.online.malicious ? "flagged as malicious" : "not flagged"}{#if finding.online.message} — {finding.online.message}{/if}{#if finding.online.osm_url} · <a href={finding.online.osm_url} target="_blank" rel="noreferrer noopener">View advisory ↗</a>{/if}
        </dd>
      {/if}
    </dl>
  </details>
</div>

<style>
  .finding-card { background: var(--surface-2); border-radius: var(--radius-sm); padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; }
  .fc-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .fc-title { font-size: 13px; font-weight: 600; color: var(--fg); }
  .fc-title.sev-critical, .fc-title.sev-high { color: var(--danger); }
  .fc-title.sev-medium { color: var(--warn); }
  .fc-where { font-size: 12px; color: var(--muted); overflow-wrap: anywhere; min-width: 0; }
  .fc-label { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px; margin-left: auto; white-space: nowrap; }
  .fc-label.ok { background: var(--ok-tint); color: var(--ok); }
  .fc-label.warn { background: var(--warn-tint); color: var(--warn); }
  .fc-label.info { background: var(--info-tint, rgba(80,140,255,.14)); color: var(--info, #4c7dff); }
  .fc-details > summary { cursor: pointer; color: var(--muted); font-size: 12px; width: fit-content; }
  .fc-details > summary:hover { color: var(--fg); }
  .fc-dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; margin: 10px 0 0; }
  .fc-dl dt { color: var(--faint); font-size: 11px; }
  .fc-dl dd { margin: 0; color: var(--fg); font-size: 12px; overflow-wrap: anywhere; min-width: 0; }
  .fc-dl dd.mono { font-family: var(--mono); font-size: 11.5px; color: var(--faint); }
  .fc-dl dd.snippet code { display: inline-block; max-width: 100%; background: var(--surface-1, rgba(128,128,128,.12)); border-radius: 4px; padding: 2px 6px; color: var(--fg); word-break: break-all; }
  .fc-dl dd.crit { color: var(--danger); }
  .fc-dl dd.muted { color: var(--muted); }
</style>
