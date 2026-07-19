<script lang="ts">
  import { app } from "./lib/state.svelte";
  import Scan from "./routes/Scan.svelte";
  import Results from "./routes/Results.svelte";
  import Clean from "./routes/Clean.svelte";
  import GitHub from "./routes/GitHub.svelte";
  import Settings from "./routes/Settings.svelte";
  import { fly } from "svelte/transition";
  import { cubicOut } from "svelte/easing";

  const tabs = [
    ["scan", "Scan"],
    ["results", "Results"],
    ["clean", "Clean"],
    ["github", "GitHub"],
    ["settings", "Settings"],
  ] as const;

  // Sliding active-tab indicator: measure the active button and move a single bar.
  let navEl: HTMLElement | undefined = $state();
  let ind = $state({ left: 0, width: 0, ready: false });
  function place() {
    const btn = navEl?.querySelector<HTMLElement>("button.active");
    if (btn) ind = { left: btn.offsetLeft, width: btn.offsetWidth, ready: true };
  }
  // Reposition whenever the active screen changes (runs after the DOM updates).
  $effect(() => {
    app.screen;
    place();
  });
  $effect(() => {
    const on = () => place();
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  });

  // Auto-dismiss the error toast after a while; manual dismiss stays available.
  $effect(() => {
    if (!app.error) return;
    const t = setTimeout(() => (app.error = ""), 7000);
    return () => clearTimeout(t);
  });
</script>

<header class="topbar">
  <div class="brand">
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 4 5.5v6c0 5 3.4 8.4 8 10 4.6-1.6 8-5 8-10v-6L12 2.5Z"
        stroke="var(--accent)"
        stroke-width="1.7"
        stroke-linejoin="round"
      />
      <path d="M9 12.2 11.2 14.4 15 9.8" stroke="var(--accent)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <span class="wordmark">wormward</span>
  </div>
  <nav bind:this={navEl}>
    {#if ind.ready}
      <span class="indicator" style="transform: translateX({ind.left}px); width: {ind.width}px;"></span>
    {/if}
    {#each tabs as [id, label]}
      <button class:active={app.screen === id} onclick={() => (app.screen = id)}>{label}</button>
    {/each}
  </nav>
</header>

{#if app.error}
  <div class="toast-wrap">
    <div class="toast" role="alert">
      <span class="msg">{app.error}</span>
      <button class="x" aria-label="Dismiss" onclick={() => (app.error = "")}>×</button>
    </div>
  </div>
{/if}

<main>
  {#key app.screen}
    <div in:fly={{ y: 8, duration: 200, easing: cubicOut }}>
      {#if app.screen === "scan"}
        <Scan />
      {:else if app.screen === "results"}
        <Results />
      {:else if app.screen === "clean"}
        <Clean />
      {:else if app.screen === "github"}
        <GitHub />
      {:else}
        <Settings />
      {/if}
    </div>
  {/key}
</main>

<style>
  .topbar {
    position: sticky;
    top: 0;
    z-index: 20;
    display: flex;
    align-items: center;
    gap: 22px;
    padding: 11px 24px;
    background: rgba(10, 10, 12, 0.72);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
  }
  .brand { display: flex; align-items: center; gap: 8px; }
  .wordmark {
    font-size: 14px;
    font-weight: 600;
    letter-spacing: -0.02em;
    color: var(--fg);
  }
  nav { position: relative; display: flex; gap: 2px; }
  nav button {
    background: transparent;
    border: none;
    color: var(--muted);
    padding: 7px 13px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 500;
    transition: color var(--fast) var(--ease);
  }
  nav button:hover { color: var(--fg); background: transparent; }
  nav button.active { color: var(--fg); }
  nav .indicator {
    position: absolute;
    bottom: -12px;
    left: 0;
    height: 2px;
    background: var(--accent);
    border-radius: 2px;
    transition: transform var(--med) var(--ease), width var(--med) var(--ease);
  }
  main { min-height: calc(100vh - 49px); }
</style>
