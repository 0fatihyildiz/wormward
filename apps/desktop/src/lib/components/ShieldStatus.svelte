<script lang="ts">
  import type { ProtectionLevel } from "../protection";

  let { level, heading, sub }: { level: ProtectionLevel; heading: string; sub?: string } = $props();

  // aria-hidden glyph — the status is ALSO conveyed by the .sr word and the visible heading,
  // so color+glyph are never the only signal.
  const glyph = $derived(
    level === "protected" ? "✓" : level === "attention" ? "!" : level === "threat" ? "✕" : "?",
  );
  const word = $derived(
    level === "protected"
      ? "Protected"
      : level === "attention"
        ? "Needs attention"
        : level === "threat"
          ? "Threat"
          : "Unknown",
  );
</script>

<div class="shield {level}">
  <span class="shield-glyph" aria-hidden="true">{glyph}</span>
</div>
<span class="sr">Status: {word}</span>
<h1 class="shield-heading">{heading}</h1>
{#if sub}<p class="shield-sub">{sub}</p>{/if}
