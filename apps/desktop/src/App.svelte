<script lang="ts">
  import { app, dismiss, notify, go } from "./lib/state.svelte";
  import type { View } from "./lib/state.svelte";
  import Home from "./routes/Home.svelte";
  import Workspace from "./routes/Workspace.svelte";
  import ScanFlow from "./routes/ScanFlow.svelte";
  import Advanced from "./routes/Advanced.svelte";
  import Doctor from "./routes/Doctor.svelte";
  import Settings from "./routes/Settings.svelte";
  import { fly } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import logo from "./assets/logo.png";
  import { isTauri } from "./lib/env";
  import type { Component } from "svelte";

  // Canonical view router. Later phases swap INDIVIDUAL entries for the real component
  // (flow→ScanFlow, machine→MachineDetail, repos→RepositoriesDetail, advanced→Advanced);
  // never re-typedef this map or convert it to an {#if} chain. The temporary entries keep
  // every current capability reachable so nothing is lost this phase.
  const views: Record<View, Component> = {
    home: Home,
    flow: ScanFlow,
    machine: Doctor,
    repos: Workspace,
    advanced: Advanced,
    settings: Settings,
  };

  // Respect the user's motion preference for the JS-driven toast transitions (CSS media
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

  // Move keyboard/screen-reader focus to the freshly-rendered view on every view change so
  // focus lands on the new content instead of document.body. Skip the very first run — on
  // initial load focus belongs to the page as delivered.
  let mainEl = $state<HTMLElement | undefined>();
  let firstView = true;
  $effect(() => {
    app.view;
    if (firstView) {
      firstView = false;
      return;
    }
    queueMicrotask(() => mainEl?.focus());
  });

  // ⚙ menu: PLAIN buttons in a labelled container. We deliberately do NOT use
  // role=menu/menuitem (that advertises arrow-key semantics we don't implement). Escape and
  // any outside click close it. On close via Escape/outside-click we return focus to the gear
  // trigger (C4) so keyboard focus doesn't fall to document.body.
  let menuOpen = $state(false);
  let menuWrap = $state<HTMLElement | undefined>();
  let gearEl = $state<HTMLButtonElement | undefined>();
  $effect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (menuWrap && !menuWrap.contains(e.target as Node)) {
        menuOpen = false;
        gearEl?.focus();
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        menuOpen = false;
        gearEl?.focus();
      }
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  });
  function pick(view: View) {
    menuOpen = false;
    go(view);
  }

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
  <div class="spacer"></div>
  <div class="menu-wrap" bind:this={menuWrap}>
    <button
      class="gear"
      bind:this={gearEl}
      aria-label="More options"
      aria-expanded={menuOpen}
      aria-controls={menuOpen ? "app-menu" : undefined}
      onclick={() => (menuOpen = !menuOpen)}>⚙</button
    >
    {#if menuOpen}
      <div id="app-menu" class="menu" role="group" aria-label="More options">
        <button onclick={() => pick("advanced")}>Advanced</button>
        <button onclick={() => pick("settings")}>Settings</button>
      </div>
    {/if}
  </div>
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

<main id="main" tabindex="-1" bind:this={mainEl}>
  {#key app.view}
    {@const Current = views[app.view]}
    <Current />
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
    gap: 14px;
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
  main { min-height: calc(100vh - var(--topbar-h)); }

  .menu-wrap { position: relative; }
  .gear {
    background: transparent;
    color: var(--muted);
    font-size: 18px;
    line-height: 1;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
  }
  .gear:hover { color: var(--fg); background: var(--surface-2); }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 30;
    min-width: 168px;
    background: var(--surface-2);
    border-radius: var(--radius-sm);
    padding: 5px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .menu button {
    background: transparent;
    color: var(--fg);
    justify-content: flex-start;
    width: 100%;
    padding: 8px 12px;
    font-weight: 500;
  }
  .menu button:hover { background: var(--surface-3); }

  .env-banner {
    padding: 9px 24px;
    background: var(--surface-warn);
    color: var(--warn);
    font-size: 12.5px;
    line-height: 1.5;
  }
</style>
