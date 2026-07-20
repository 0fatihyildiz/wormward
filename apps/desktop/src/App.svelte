<script lang="ts">
  import { app, dismiss, notify } from "./lib/state.svelte";
  import Workspace from "./routes/Workspace.svelte";
  import GitHub from "./routes/GitHub.svelte";
  import Doctor from "./routes/Doctor.svelte";
  import Settings from "./routes/Settings.svelte";
  import { fly } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import logo from "./assets/logo.png";
  import { isTauri } from "./lib/env";
  import type { Component } from "svelte";

  const tabs = [
    ["scan", "Scan"],
    ["github", "GitHub"],
    ["doctor", "Doctor"],
    ["settings", "Settings"],
  ] as const;

  // Respect the user's motion preference for the JS-driven route transitions (CSS media
  // queries can't reach Svelte transitions). Reactive, so toggling the OS setting mid-session
  // applies immediately and stays in sync with the CSS @media block.
  let reduce = $state(
    typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
  $effect(() => {
    if (typeof matchMedia === "undefined") return;
    const mq = matchMedia("(prefers-reduced-motion: reduce)");
    const on = () => (reduce = mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  });

  // Keep each screen mounted after its first visit so its local state (scan results, live log,
  // clean plans, form inputs) survives tab switches — only the active one is shown. Lazy, so an
  // unvisited tab runs no work at startup.
  const screens: Record<string, Component> = {
    scan: Workspace,
    github: GitHub,
    doctor: Doctor,
    settings: Settings,
  };
  let visited = $state<Record<string, boolean>>({});
  $effect(() => {
    visited[app.screen] = true;
  });

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
  // Re-align the pill once web fonts settle — button widths can shift after first paint.
  $effect(() => {
    if (typeof document !== "undefined" && document.fonts) document.fonts.ready.then(place);
  });

  // Notifications: failures persist until dismissed; non-error notices auto-clear (see notify()).
  // Surface any uncaught JS error / rejection instead of failing silently. De-duped and
  // guarded to script errors so a repeated error can't spin up a toast loop.
  $effect(() => {
    const seen = new Set<string>();
    const report = (msg: string) => {
      if (seen.has(msg)) return;
      seen.add(msg);
      notify("error", msg);
    };
    const onErr = (e: ErrorEvent) => {
      if (e.error) report(`Unexpected error: ${e.message}`);
    };
    const onRej = (e: PromiseRejectionEvent) => report(`Unexpected error: ${String(e.reason)}`);
    window.addEventListener("error", onErr);
    window.addEventListener("unhandledrejection", onRej);
    return () => {
      window.removeEventListener("error", onErr);
      window.removeEventListener("unhandledrejection", onRej);
    };
  });
</script>

<a class="skip" href="#main">Skip to content</a>

<header class="topbar">
  <div class="brand">
    <img class="logo" src={logo} alt="Wormward" width="46" height="46" />
  </div>
  <nav bind:this={navEl} aria-label="Primary">
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

{#if !isTauri}
  <div class="env-banner" role="status">
    <strong>Browser preview</strong> — scanning, cleaning, and GitHub actions run in the Wormward
    desktop app. Open it on your desktop to use them.
  </div>
{/if}

{#if app.toasts.length}
  <div class="toast-wrap">
    {#each app.toasts as t (t.id)}
      <div
        class="toast {t.kind}"
        role={t.kind === "error" ? "alert" : "status"}
        in:fly={{ y: -8, duration: reduce ? 0 : 150, easing: cubicOut }}
        out:fly={{ y: -10, duration: reduce ? 0 : 150, easing: cubicOut }}
      >
        <span class="dot"></span>
        <div class="body">
          <span class="msg">{t.message}</span>
          {#if t.detail}<span class="detail">{t.detail}</span>{/if}
        </div>
        <button class="x" aria-label="Dismiss" onclick={() => dismiss(t.id)}>×</button>
      </div>
    {/each}
  </div>
{/if}

<main id="main" tabindex="-1">
  {#each tabs as [id]}
    <div class="screen" hidden={app.screen !== id}>
      {#if visited[id]}
        {@const Screen = screens[id]}
        <div in:fly={{ y: reduce ? 0 : 8, duration: reduce ? 0 : 200, easing: cubicOut }}>
          <Screen />
        </div>
      {/if}
    </div>
  {/each}
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
  .brand { display: flex; align-items: center; }
  .logo { width: 46px; height: 46px; border-radius: 10px; display: block; }
  .skip {
    position: absolute;
    left: 12px;
    top: -48px;
    z-index: 100;
    background: var(--accent);
    color: #0a0a12;
    padding: 8px 14px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 600;
    transition: top var(--fast) var(--ease);
  }
  .skip:focus { top: 10px; }
  main:focus { outline: none; }
  nav { position: relative; display: flex; gap: 2px; }
  nav button {
    position: relative;
    z-index: 1; /* text rides above the sliding pill */
    background: transparent;
    border: none;
    color: var(--muted);
    padding: 7px 13px;
    border-radius: 9px;
    font-size: 13px;
    font-weight: 500;
    transition: color var(--fast) var(--ease);
  }
  nav button:hover { color: var(--fg); background: transparent; }
  nav button.active { color: var(--fg); }
  /* Rounded pill that slides BEHIND the active tab's text. */
  nav .indicator {
    position: absolute;
    top: 0;
    left: 0;
    height: 100%;
    background: var(--surface-2);
    border-radius: 9px;
    z-index: 0;
    transition: transform var(--med) var(--ease), width var(--med) var(--ease);
  }
  .env-banner {
    padding: 9px 24px;
    background: var(--surface-warn);
    color: var(--warn);
    font-size: 12.5px;
    line-height: 1.5;
  }
  main { min-height: calc(100vh - var(--topbar-h)); }
  .screen[hidden] { display: none; }
</style>
