<script lang="ts">
  import { app } from "./lib/state.svelte";
  import Scan from "./routes/Scan.svelte";
  import Results from "./routes/Results.svelte";
  import Clean from "./routes/Clean.svelte";
  import GitHub from "./routes/GitHub.svelte";
  import Settings from "./routes/Settings.svelte";
  import { fly } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import logo from "./assets/logo.png";

  const tabs = [
    ["scan", "Scan"],
    ["results", "Results"],
    ["clean", "Clean"],
    ["github", "GitHub"],
    ["settings", "Settings"],
  ] as const;

  // Respect the user's motion preference for the JS-driven route transition
  // (CSS media query can't reach Svelte transitions).
  const reduce =
    typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches;

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
    <img class="logo" src={logo} alt="" aria-hidden="true" width="20" height="20" />
    <span class="wordmark">wormward</span>
  </div>
  <nav bind:this={navEl}>
    {#if ind.ready}
      <span class="indicator" style="transform: translateX({ind.left}px); width: {ind.width}px;"></span>
    {/if}
    {#each tabs as [id, label]}
      <button
        class:active={app.screen === id}
        aria-current={app.screen === id ? "page" : undefined}
        onclick={() => (app.screen = id)}>{label}</button>
    {/each}
  </nav>
</header>

{#if app.error}
  <div class="toast-wrap">
    <div class="toast" role="alert" out:fly={{ y: -10, duration: reduce ? 0 : 160, easing: cubicOut }}>
      <span class="dot"></span>
      <span class="msg">{app.error}</span>
      <button class="x" aria-label="Dismiss" onclick={() => (app.error = "")}>×</button>
    </div>
  </div>
{/if}

<main>
  {#key app.screen}
    <div in:fly={{ y: reduce ? 0 : 8, duration: reduce ? 0 : 200, easing: cubicOut }}>
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
    height: var(--topbar-h);
    display: flex;
    align-items: center;
    gap: 22px;
    padding: 0 24px;
    background: rgba(10, 10, 12, 0.7);
    backdrop-filter: blur(12px);
  }
  .brand { display: flex; align-items: center; gap: 8px; }
  .logo { width: 20px; height: 20px; border-radius: 5px; display: block; }
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
    bottom: -17px;
    left: 0;
    height: 2px;
    background: var(--accent);
    border-radius: 2px;
    transition: transform var(--med) var(--ease), width var(--med) var(--ease);
  }
  main { min-height: calc(100vh - var(--topbar-h)); }
</style>
