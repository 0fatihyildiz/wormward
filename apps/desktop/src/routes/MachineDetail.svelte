<script lang="ts">
  import { onDestroy } from "svelte";
  import { doctor, doctorClearCache, doctorHardenTriggers } from "../lib/api";
  import { app, fail, go } from "../lib/state.svelte";
  import { device, machineSupported } from "../lib/platform";
  import { dialog } from "../lib/modal";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  let running = $state(false);
  let watching = $state(false);
  let hardening = $state(false);
  let clearing = $state<string | null>(null);
  let confirmDir = $state<string | null>(null);
  let timer: ReturnType<typeof setInterval> | null = null;

  // The machine report lives in shared state so Home / chips stay in sync.
  const report = $derived(app.machineReport);
  const procHits = $derived(report?.processes.length ?? 0);
  const cacheHits = $derived(report?.caches.length ?? 0);
  const exposed = $derived(report?.triggers.filter((t) => t.exposed).length ?? 0);
  const scriptsExposed = $derived(
    report?.triggers.some((t) => t.name.includes("ignore-scripts") && t.exposed) ?? false,
  );
  // Shorten $HOME to ~ for readable paths.
  const short = (p: string) => p.replace(/^\/Users\/[^/]+/, "~").replace(/^\/home\/[^/]+/, "~");

  async function runCheck() {
    if (running) return;
    running = true;
    try {
      app.machineReport = await doctor();
    } catch (e) {
      fail(e);
    } finally {
      running = false;
    }
  }

  function stopWatch() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    watching = false;
  }
  function toggleWatch() {
    if (watching) {
      stopWatch();
    } else {
      watching = true;
      runCheck();
      timer = setInterval(runCheck, 5000);
    }
  }
  onDestroy(stopWatch);

  async function harden() {
    hardening = true;
    try {
      await doctorHardenTriggers();
      await runCheck();
    } catch (e) {
      fail(e);
    } finally {
      hardening = false;
    }
  }

  async function clearCache(dir: string) {
    confirmDir = null;
    clearing = dir;
    try {
      await doctorClearCache(dir);
      await runCheck();
    } catch (e) {
      fail(e);
    } finally {
      clearing = null;
    }
  }
</script>

<div class="page" aria-busy={running}>
  <button class="back" onclick={() => go("home")}>← Home</button>
  <div class="page-head">
    <h1>This {device}</h1>
    <p class="lede">
      Check this computer for malware that's running right now, infected app caches, and settings
      that let malware come back.
    </p>
  </div>

  {#if machineSupported}
    <div class="row">
      <button class="btn primary" onclick={runCheck} disabled={running}>
        {#if running}<span class="spinner"></span>Checking this {device}…{:else}{report ? "Check again" : "Run a check"}{/if}
      </button>
      <label class="switch">
        <input type="checkbox" checked={watching} onchange={toggleWatch} />
        <span class="track"></span>
        <span class="lbl">Live monitoring <span class="muted">— re-checks every few seconds</span></span>
      </label>
    </div>
  {/if}

  {#if !machineSupported}
    <div class="state">
      <span class="glyph">◎</span>
      <h2>Machine check isn't available on this platform yet</h2>
      <p class="muted micro">
        Wormward's machine check — running threats, infected toolchain caches, and re-infection
        triggers — runs on macOS and Windows. Your code is still scanned normally from Home.
      </p>
    </div>
  {:else if !report && !running}
    <div class="state">
      <span class="glyph">◎</span>
      <h2>This {device} hasn't been checked yet</h2>
      <p class="muted micro">
        Run a check to look for malware running right now, infected app caches, and risky settings.
      </p>
    </div>
  {:else if !report && running}
    <div class="state" role="status">
      <span class="spinner"></span>
      <p>Checking this {device}…</p>
    </div>
  {:else if report}
    <!-- Worst-first: an active threat is the most urgent thing to surface. A newly -->
    <!-- discovered running threat interrupts (assertive/alert); the clean state is polite. -->
    <section
      class="card"
      class:danger={procHits}
      role={procHits ? "alert" : null}
      aria-live={procHits ? "assertive" : "polite"}
    >
      <div class="row between">
        <h2>Is a threat running right now?</h2>
        <span class="count" class:hot={procHits} aria-label="{procHits} {plural(procHits, 'threat', 'threats')} running">{procHits}</span>
      </div>
      {#if procHits === 0}
        <div class="state ok">
          <span class="glyph">✓</span>
          <p>Nothing malicious is running right now.</p>
          <p class="lede">
            A one-time check isn't proof. Turn on Live monitoring, then open your editor and projects
            to catch malware that only starts on a trigger.
          </p>
        </div>
      {:else}
        {#each report.processes as p (p.pid)}
          <div class="hit">
            <div class="row between">
              <strong>Program {p.pid}</strong>
              <span class="pill critical">threat</span>
            </div>
            <p class="muted micro">{p.reason}</p>
            <code class="snippet mono">{p.snippet}</code>
          </div>
        {/each}
      {/if}
    </section>

    <section class="card" class:danger={cacheHits} aria-live="polite">
      <div class="row between">
        <h2>Infected app caches</h2>
        <span class="count" class:hot={cacheHits} aria-label="{cacheHits} infected {plural(cacheHits, 'cache', 'caches')}">{cacheHits}</span>
      </div>
      {#if cacheHits === 0}
        <div class="state ok">
          <span class="glyph">✓</span>
          <p>No infected files in your developer tool caches.</p>
        </div>
      {:else}
        {#each report.caches as c (c.path)}
          <div class="hit">
            <code class="snippet mono">{short(c.path)}</code>
            <p class="muted micro">{c.reason}</p>
          </div>
        {/each}
        <div class="row">
          {#each report.cache_dirs as dir (dir)}
            <button class="btn danger sm" onclick={() => (confirmDir = dir)} disabled={clearing !== null}>
              {#if clearing === dir}<span class="spinner"></span>Cleaning up…{:else}Clean up {short(dir)}{/if}
            </button>
          {/each}
        </div>
        <p class="lede">These caches rebuild cleanly the next time you use them.</p>
      {/if}
    </section>

    <section class="card" class:warn={exposed} aria-live="polite">
      <div class="row between">
        <h2>Risky settings that let malware come back</h2>
        <span class="count" class:warnc={exposed} aria-label="{exposed} risky {plural(exposed, 'setting', 'settings')}">{exposed}</span>
      </div>
      {#if report.triggers.length === 0}
        <p class="muted micro">No settings to check on this computer.</p>
      {:else}
        <ul class="triggers">
          {#each report.triggers as t (t.name)}
            <li class:exposed={t.exposed}>
              <span class="mark" aria-hidden="true">{t.exposed ? "⚠" : "✓"}</span>
              <div>
                <strong>{t.name}</strong>
                <span class="sr">{t.exposed ? "risky" : "protected"}</span>
                <p class="muted micro">{t.detail}</p>
              </div>
            </li>
          {/each}
        </ul>
        {#if scriptsExposed}
          <button class="btn primary sm" onclick={harden} disabled={hardening}>
            {#if hardening}<span class="spinner"></span>Turning on protection…{:else}Turn on protection{/if}
          </button>
        {/if}
      {/if}
    </section>
  {/if}
</div>

{#if confirmDir}
  <div class="modal-backdrop">
    <div
      class="modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cache-clean-title"
      tabindex="-1"
      use:dialog={() => (confirmDir = null)}
    >
      <h3 id="cache-clean-title">Clean up this cache?</h3>
      <p class="lede">
        Deletes the infected files in <code>{short(confirmDir)}</code>. The cache rebuilds cleanly
        the next time you use those tools.
      </p>
      <div class="row">
        <button class="btn ghost" onclick={() => (confirmDir = null)}>Cancel</button>
        <button class="btn danger" onclick={() => clearCache(confirmDir!)}>Clean up</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .back {
    align-self: flex-start;
    background: none;
    color: var(--muted);
    font-size: 13px;
    padding: 4px 0;
  }
  .back:hover { color: var(--fg); background: none; }
  .hit {
    display: flex;
    flex-direction: column;
    gap: 5px;
    padding: 11px 13px;
    background: var(--inset);
    border-radius: var(--radius-sm);
  }
  .hit + .hit { margin-top: 8px; }
  .snippet {
    font-size: 11.5px;
    color: var(--fg);
    word-break: break-all;
    line-height: 1.5;
  }
  .count.hot { background: var(--danger-tint); color: var(--danger); }
  .count.warnc { background: var(--warn-tint); color: var(--warn); }
  .triggers {
    display: flex;
    flex-direction: column;
    gap: 9px;
    list-style: none;
  }
  .triggers li { display: flex; gap: 10px; align-items: flex-start; }
  .triggers .mark {
    flex: none;
    font-weight: 700;
    color: var(--ok);
    line-height: 1.4;
  }
  .triggers li.exposed .mark { color: var(--warn); }
  .triggers strong { font-size: 13px; }
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
</style>
