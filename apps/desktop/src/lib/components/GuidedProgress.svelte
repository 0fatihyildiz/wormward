<script lang="ts">
  let {
    label,
    done = 0,
    total = 0,
    indeterminate = false,
  }: { label: string; done?: number; total?: number; indeterminate?: boolean } = $props();

  const pct = $derived(total ? Math.min(100, (done / total) * 100) : 0);
</script>

<div class="guided">
  <p class="guided-label" role="status" aria-live="polite">{label}</p>
  {#if indeterminate}
    <div class="progress indet" role="progressbar" aria-label={label}>
      <span></span>
    </div>
  {:else}
    <div class="progress" role="progressbar" aria-label={label} aria-valuemin="0" aria-valuemax={total} aria-valuenow={done}>
      <span style="width: {pct}%"></span>
    </div>
  {/if}
</div>

<style>
  .guided { display: flex; flex-direction: column; gap: 12px; }
  .guided-label { font-size: 14px; color: var(--fg); text-align: center; }
  .guided .progress { height: 6px; }
</style>
