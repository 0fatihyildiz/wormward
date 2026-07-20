<script lang="ts">
  import type { SurfaceStatus } from "../protection";

  let { label, status, onclick }: { label: string; status: SurfaceStatus; onclick: () => void } =
    $props();

  // aria-hidden mark; status.label carries the same meaning as visible text.
  const mark = $derived(
    status.level === "protected"
      ? "✓"
      : status.level === "attention"
        ? "!"
        : status.level === "threat"
          ? "✕"
          : "?",
  );
</script>

<button class="health-chip" {onclick}>
  <span class="hc-label">{label}</span>
  <span class="hc-status">
    <span
      class="hc-mark"
      class:protected={status.level === "protected"}
      class:attention={status.level === "attention"}
      class:threat={status.level === "threat"}
      class:unknown={status.level === "unknown"}
      aria-hidden="true">{mark}</span
    >
    <span class="hc-word">{status.label}</span>
  </span>
</button>

<style>
  .health-chip {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 5px;
    background: var(--surface);
    border-radius: var(--radius);
    padding: 13px 18px;
    min-width: 148px;
    text-align: left;
  }
  .health-chip:hover {
    background: var(--surface-2);
  }
  .hc-label {
    font-size: 12px;
    color: var(--muted);
    font-weight: 500;
  }
  .hc-status {
    display: inline-flex;
    align-items: center;
    gap: 7px;
  }
  .hc-mark {
    font-weight: 700;
    font-size: 13px;
  }
  .hc-mark.protected {
    color: var(--ok);
  }
  .hc-mark.attention {
    color: var(--warn);
  }
  .hc-mark.threat {
    color: var(--danger);
  }
  .hc-mark.unknown {
    color: var(--faint);
  }
  .hc-word {
    font-size: 13px;
    color: var(--fg);
    font-weight: 600;
  }
</style>
