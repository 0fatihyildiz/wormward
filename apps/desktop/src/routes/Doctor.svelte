<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { doctor, doctorClearCache, doctorHardenTriggers } from "../lib/api";
  import type { DoctorReport } from "../lib/types";
  import { app, fail } from "../lib/state.svelte";

  let report = $state<DoctorReport | null>(null);
  let running = $state(false);
  // Honest state: never show an "all clear" until a check has actually run.
  let scanned = $state(false);
  let watching = $state(false);
  let hardening = $state(false);
  let clearing = $state<string | null>(null);
  let timer: ReturnType<typeof setInterval> | null = null;

  async function runCheck() {
    if (running) return;
    running = true;
    try {
      report = await doctor();
      scanned = true;
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

  onMount(() => {
    runCheck();
  });

  const procHits = $derived(report?.processes.length ?? 0);
  const cacheHits = $derived(report?.caches.length ?? 0);
  const exposed = $derived(report?.triggers.filter((t) => t.exposed).length ?? 0);
  const scriptsExposed = $derived(
    report?.triggers.some((t) => t.name.includes("ignore-scripts") && t.exposed) ?? false,
  );
  // Shorten $HOME to ~ for readable paths.
  const short = (p: string) => p.replace(/^\/Users\/[^/]+/, "~").replace(/^\/home\/[^/]+/, "~");
</script>

<div class="page" aria-busy={running}>
  <div class="page-head">
    <h1>Doctor</h1>
    <p class="lede">
      Check this machine for an active worm — a running loader, tainted toolchain caches, and the
      editor settings that let it come back. Complements the repository scan.
    </p>
  </div>

  <div class="row">
    <button class="btn primary" onclick={runCheck} disabled={running}>
      {#if running}<span class="spinner"></span>Checking…{:else}Run check{/if}
    </button>
    <label class="switch">
      <input type="checkbox" checked={watching} onchange={toggleWatch} />
      <span class="track"></span>
      <span class="lbl">Watch <span class="muted">— re-check every 5s to catch respawns</span></span>
    </label>
  </div>

  {#if !scanned && !running}
    <div class="state">
      <span class="glyph">◎</span>
      <p>Run a check to inspect this machine.</p>
    </div>
  {:else if report}
    <section class="card" class:danger={procHits} aria-live="polite">
      <div class="row between">
        <h2>Running loader</h2>
        {#if scanned}<span class="count" class:hot={procHits}>{procHits}</span>{/if}
      </div>
      {#if procHits === 0}
        <div class="state ok">
          <span class="glyph">✓</span>
          <p>No loader process running right now.</p>
          <p class="lede">
            A point-in-time check isn't proof. Turn on Watch and open your editor and projects to
            catch a loader that only respawns on a trigger.
          </p>
        </div>
      {:else}
        {#each report.processes as p (p.pid)}
          <div class="hit">
            <div class="row between">
              <strong>Process {p.pid}</strong>
              <span class="pill critical">loader</span>
            </div>
            <p class="muted micro">{p.reason}</p>
            <code class="snippet mono">{p.snippet}</code>
          </div>
        {/each}
      {/if}
    </section>

    <section class="card" class:danger={cacheHits} aria-live="polite">
      <div class="row between">
        <h2>Toolchain caches</h2>
        {#if scanned}<span class="count" class:hot={cacheHits}>{cacheHits}</span>{/if}
      </div>
      {#if cacheHits === 0}
        <div class="state ok">
          <span class="glyph">✓</span>
          <p>No tainted files in the npx or TypeScript caches.</p>
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
            <button class="btn danger sm" onclick={() => clearCache(dir)} disabled={clearing !== null}>
              {#if clearing === dir}<span class="spinner"></span>Clearing…{:else}Clear {short(dir)}{/if}
            </button>
          {/each}
        </div>
        <p class="lede">These caches regenerate cleanly the next time you use them.</p>
      {/if}
    </section>

    <section class="card" class:warn={exposed} aria-live="polite">
      <div class="row between">
        <h2>Re-infection triggers</h2>
        {#if scanned}<span class="count" class:warnc={exposed}>{exposed}</span>{/if}
      </div>
      {#if report.triggers.length === 0}
        <p class="muted micro">No trigger checks available on this platform.</p>
      {:else}
        <ul class="triggers">
          {#each report.triggers as t (t.name)}
            <li class:exposed={t.exposed}>
              <span class="mark" aria-hidden="true">{t.exposed ? "⚠" : "✓"}</span>
              <div>
                <strong>{t.name}</strong>
                <span class="sr">{t.exposed ? "exposed" : "protected"}</span>
                <p class="muted micro">{t.detail}</p>
              </div>
            </li>
          {/each}
        </ul>
        {#if scriptsExposed}
          <button class="btn primary sm" onclick={harden} disabled={hardening}>
            {#if hardening}<span class="spinner"></span>Hardening…{:else}Block install scripts (npm &amp; pnpm){/if}
          </button>
        {/if}
      {/if}
    </section>
  {/if}
</div>

<style>
  .hit {
    display: flex;
    flex-direction: column;
    gap: 5px;
    padding: 11px 13px;
    background: var(--inset);
    border-radius: var(--radius-sm);
  }
  .hit + .hit {
    margin-top: 8px;
  }
  .snippet {
    font-size: 11.5px;
    color: var(--fg);
    word-break: break-all;
    line-height: 1.5;
  }
  .count.hot {
    background: var(--danger-tint);
    color: var(--danger);
  }
  .count.warnc {
    background: var(--warn-tint);
    color: var(--warn);
  }
  .triggers {
    display: flex;
    flex-direction: column;
    gap: 9px;
    list-style: none;
  }
  .triggers li {
    display: flex;
    gap: 10px;
    align-items: flex-start;
  }
  .triggers .mark {
    flex: none;
    font-weight: 700;
    color: var(--ok);
    line-height: 1.4;
  }
  .triggers li.exposed .mark {
    color: var(--warn);
  }
  .triggers strong {
    font-size: 13px;
  }
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
</style>
