<script lang="ts">
  import { app, fail, clearErrors } from "../lib/state.svelte";
  import {
    scan,
    pickDirs,
    cancelScan,
    cleanPreview,
    cleanApply,
    restore,
    cleanBranchesPreview,
    cleanBranchesApply,
  } from "../lib/api";
  import { listen } from "@tauri-apps/api/event";
  import { dialog } from "../lib/modal";
  import type {
    ScanProgress,
    Finding,
    RepoPlan,
    BranchCleanPreview,
    BranchSelection,
    BranchCleanResult,
  } from "../lib/types";

  const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

  // ---------------- scan ----------------
  let deep = $state(false);
  let online = $state(false);
  let stopping = $state(false);
  let scanned = $state(false);
  let repoLog = $state<ScanProgress[]>([]);
  let progress = $state<ScanProgress | null>(null);
  let bodyEl = $state<HTMLDivElement | null>(null);
  const noOsmToken = $derived(online && !localStorage.getItem("osm_token"));
  const pct = $derived(progress && progress.total ? (progress.done / progress.total) * 100 : 0);
  const hasDirs = $derived(app.dirs.length > 0);

  // ---------------- results (from app.report) ----------------
  const report = $derived(app.report);
  const findings = $derived(report?.findings ?? []);
  const total = $derived(findings.length);
  const cancelled = $derived(report?.cancelled ?? false);
  const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const rank = (s: string) => SEV_RANK[s] ?? 0;
  const grouped = $derived.by(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      if (!map.has(f.campaign)) map.set(f.campaign, []);
      map.get(f.campaign)!.push(f);
    }
    for (const list of map.values()) list.sort((a, b) => rank(b.severity) - rank(a.severity));
    return [...map.entries()].sort(
      (a, b) => rank(b[1][0].severity) - rank(a[1][0].severity) || b[1].length - a[1].length,
    );
  });
  const affected = $derived(new Set(findings.map((f) => f.repo)).size);
  const sevCounts = $derived.by(() => {
    const c: Record<string, number> = {};
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return (["critical", "high", "medium", "low", "info"] as const)
      .filter((s) => c[s])
      .map((s) => ({ sev: s, n: c[s] }));
  });

  // ---------------- clean ----------------
  let plans = $state<RepoPlan[]>([]);
  let previewing = $state(false);
  let busy = $state(false);
  let busyKind = $state<"apply" | "restore" | "branches" | "">("");
  let confirming = $state(false);
  let restoreConfirm = $state(false);
  let cleanResult = $state("");
  const applicable = $derived(plans.filter((p) => p.actions.length));
  const fixableRepos = $derived(applicable.map((p) => p.repo));
  const manualCount = $derived(plans.reduce((n, p) => n + p.manual.length, 0));

  // ---------------- advanced: branches + restore ----------------
  let showAdvanced = $state(false);
  let branchPlans = $state<BranchCleanPreview[]>([]);
  let branchSel = $state<Record<string, boolean>>({});
  let pushBranches = $state(false);
  let branchLoading = $state(false);
  let confirmingBranches = $state(false);
  let branchResults = $state<BranchCleanResult[]>([]);
  let branchSummary = $state("");
  let branchesScanned = $state(false);
  const branchKey = (b: { repo: string; branch: string }) => `${b.repo}\n${b.branch}`;
  const selectedBranches = $derived<BranchSelection[]>(
    branchPlans.filter((b) => branchSel[branchKey(b)]).map((b) => ({ repo: b.repo, branch: b.branch })),
  );

  async function choose() {
    try {
      const picked = await pickDirs();
      if (picked.length) app.dirs = picked;
    } catch (e) {
      fail(e);
    }
  }

  async function run() {
    if (!app.dirs.length) return;
    clearErrors();
    app.scanning = true;
    repoLog = [];
    progress = null;
    cleanResult = "";
    branchesScanned = false;
    branchResults = [];
    const unlisten = await listen<ScanProgress>("local-scan-progress", (e) => {
      const p = e.payload;
      if (!progress || p.done > progress.done) progress = p;
      const idx = repoLog.findIndex((r) => r.repo === p.repo);
      if (idx >= 0) repoLog[idx] = p;
      else repoLog = [...repoLog, p];
    });
    try {
      const token = localStorage.getItem("osm_token") || undefined;
      app.report = await scan(app.dirs, deep, online, token);
      scanned = true;
      // Auto-preview the remediation plan so findings and fixes flow on one screen.
      await preview();
    } catch (e) {
      fail(e);
    } finally {
      unlisten();
      app.scanning = false;
      stopping = false;
      progress = null;
    }
  }

  async function stop() {
    stopping = true;
    try {
      await cancelScan();
    } catch (e) {
      fail(e);
    }
  }

  async function preview() {
    if (!app.dirs.length) return;
    previewing = true;
    try {
      plans = await cleanPreview(app.dirs);
    } catch (e) {
      fail(e);
    } finally {
      previewing = false;
    }
  }

  async function apply() {
    confirming = false;
    busy = true;
    busyKind = "apply";
    cleanResult = "";
    clearErrors();
    try {
      const s = await cleanApply(fixableRepos);
      cleanResult =
        `Cleaned ${s.repos} ${plural(s.repos, "repo", "repos")}: ${s.applied} ${plural(s.applied, "action", "actions")} applied` +
        (s.skipped.length ? `, ${s.skipped.length} skipped` : "") +
        (s.backups.length ? `. Backup saved` : "");
      // Re-scan so findings + plans reflect the cleaned tree.
      await run();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
    }
  }

  async function doRestore() {
    restoreConfirm = false;
    busy = true;
    busyKind = "restore";
    cleanResult = "";
    clearErrors();
    try {
      const s = await restore(app.dirs);
      cleanResult =
        s.restored > 0
          ? `Restored ${s.restored} ${plural(s.restored, "file", "files")} across ${s.repos} ${plural(s.repos, "repo", "repos")}.`
          : "No backup found to restore.";
      await run();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
    }
  }

  async function previewBranches() {
    branchLoading = true;
    clearErrors();
    try {
      branchPlans = await cleanBranchesPreview(app.dirs);
      const sel: Record<string, boolean> = {};
      for (const b of branchPlans) sel[branchKey(b)] = true;
      branchSel = sel;
      branchesScanned = true;
    } catch (e) {
      fail(e);
    } finally {
      branchLoading = false;
    }
  }

  async function applyBranches() {
    confirmingBranches = false;
    busy = true;
    busyKind = "branches";
    branchSummary = "";
    clearErrors();
    try {
      const s = await cleanBranchesApply(selectedBranches, pushBranches);
      branchResults = s.results;
      branchSummary =
        `Cleaned ${s.cleaned} ${plural(s.cleaned, "branch", "branches")}` +
        (s.skipped ? `, ${s.skipped} skipped` : "") +
        (s.failed ? `, ${s.failed} failed` : "") +
        ".";
      await previewBranches();
    } catch (e) {
      fail(e);
    } finally {
      busy = false;
      busyKind = "";
    }
  }

  // Keep the log pinned to its latest line.
  $effect(() => {
    void progress;
    void repoLog.length;
    if (bodyEl) bodyEl.scrollTop = bodyEl.scrollHeight;
  });
</script>

<div class="page">
  <div class="page-head">
    <h1>Scan &amp; clean</h1>
    <p class="lede">Find supply-chain worms across your repositories and remove them — all here.</p>
  </div>

  <!-- 1 · Target & options -->
  <section class="card">
    <div class="field">
      <div class="row between">
        <span class="field-label">
          Target folders {#if hasDirs}<span class="muted">({app.dirs.length})</span>{/if}
        </span>
        <div class="row" style="gap: 6px">
          {#if hasDirs}
            <button class="btn ghost sm" onclick={() => (app.dirs = [])} disabled={app.scanning || busy}>Clear</button>
          {/if}
          <button class="btn sm" onclick={choose} disabled={app.scanning || busy}>Choose folders…</button>
        </div>
      </div>
      {#if hasDirs}
        <div class="chips">
          {#each app.dirs as d (d)}
            <span class="folder-chip mono" title={d}>
              <span class="fc-path">{d}</span>
              <button
                class="fc-x"
                aria-label="Remove {d}"
                disabled={app.scanning || busy}
                onclick={() => (app.dirs = app.dirs.filter((x) => x !== d))}>×</button
              >
            </span>
          {/each}
        </div>
      {:else}
        <p class="path-preview mono empty">No folder chosen — pick one to scan.</p>
      {/if}
    </div>

    <fieldset class="opts">
      <legend class="sr">Scan options</legend>
      <label class="switch">
        <input type="checkbox" bind:checked={deep} disabled={app.scanning || busy} />
        <span class="track"></span>
        <span class="lbl">Deep scan <span class="muted">— check the latest commit on every branch</span></span>
      </label>
      <label class="switch">
        <input type="checkbox" bind:checked={online} disabled={app.scanning || busy} />
        <span class="track"></span>
        <span class="lbl">Online cross-check <span class="muted">— check packages against OpenSourceMalware</span></span>
      </label>
      {#if online}
        <p class="opt-note">
          Sends the names of packages found in your scan to opensourcemalware.com.{#if noOsmToken} Needs a token — add one in Settings.{/if}
        </p>
      {/if}
    </fieldset>

    <div class="row">
      {#if app.scanning}
        <button class="btn primary" disabled aria-busy="true"><span class="spinner"></span>Scanning…</button>
        <button class="btn danger" onclick={stop} disabled={stopping}>{stopping ? "Stopping…" : "Stop"}</button>
      {:else}
        <button class="btn primary" onclick={run} disabled={!hasDirs || busy}>
          {scanned ? "Re-scan" : "Scan"} →
        </button>
        {#if !hasDirs}<span class="muted micro">Choose a folder to scan.</span>{/if}
      {/if}
    </div>

    {#if app.scanning}
      <div class="scan-status" role="status" aria-live="polite">
        {#if progress}<strong>{progress.done} of {progress.total}</strong> repositories scanned{:else}Discovering repositories…{/if}
      </div>
      <div class="progress" class:indet={!progress} role="progressbar" aria-valuemin="0" aria-valuemax={progress?.total ?? 0} aria-valuenow={progress?.done ?? 0}>
        <span style="width: {progress ? pct : 35}%"></span>
      </div>
    {/if}
  </section>

  <!-- 2 · Live log -->
  {#if app.scanning || repoLog.length}
    <section class="terminal">
      <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
      <div class="term-body" bind:this={bodyEl} tabindex="0" role="log" aria-label="Scan progress log">
        {#each repoLog as r (r.repo)}
          {#if r.phase === "scanning"}
            <div class="line scanning"><span class="spinner"></span><span class="tag">scanning</span><span class="repo" title={r.repo}>{r.repo}</span></div>
          {:else}
            <div class="line" class:hit={r.findings}>
              <span class="mark {r.findings ? 'hit' : 'ok'}" aria-hidden="true">{r.findings ? "✗" : "✓"}</span>
              <span class="sr">{r.findings ? "threats found:" : "clean:"}</span>
              <span class="repo" title={r.repo}>{r.repo}</span>
              {#if r.findings}<span class="crit">{r.findings} {plural(r.findings, "finding", "findings")}</span>{/if}
            </div>
          {/if}
        {/each}
        {#if !repoLog.length}<div class="line dim"><span class="tag">discovering repositories…</span></div>{/if}
      </div>
    </section>
  {/if}

  <!-- 3 · Findings + inline clean -->
  {#if scanned && !app.scanning}
    {#if cancelled}
      <section class="card danger" role="alert">
        <h2 class="danger-text">Scan stopped early — results are incomplete</h2>
        <p class="muted small">Repositories after the stop point weren't scanned. Re-scan for a complete picture.</p>
      </section>
    {/if}
    {#if report?.warnings?.length}
      <section class="card warn">
        <h2 class="warn-text">Some online checks couldn't run</h2>
        <ul class="notes">{#each report.warnings as w, i (i)}<li class="micro muted">{w}</li>{/each}</ul>
      </section>
    {/if}

    {#if total === 0}
      <div class="card {cancelled ? '' : 'ok'}">
        <div class="state {cancelled ? '' : 'ok'}">
          <div class="glyph">{cancelled ? "◔" : "✓"}</div>
          <h2>{cancelled ? "Scan incomplete" : "No infections found"}</h2>
          <p class="muted micro">
            {cancelled ? "No infections in the repositories scanned so far." : `Scanned ${report?.repos_scanned ?? 0} ${plural(report?.repos_scanned ?? 0, "repository", "repositories")}.`}
          </p>
        </div>
      </div>
    {:else}
      <!-- summary + one-click clean -->
      <section class="card">
        <div class="row between">
          <div class="stack" style="gap: 4px">
            <h2>{total} {plural(total, "finding", "findings")} in {affected} of {report?.repos_scanned ?? 0} {plural(report?.repos_scanned ?? 0, "repository", "repositories")}</h2>
            <div class="sev-summary">{#each sevCounts as s (s.sev)}<span class="sev-chip {s.sev}">{s.n} {s.sev}</span>{/each}</div>
          </div>
          {#if applicable.length}
            <button class="btn primary" onclick={() => (confirming = true)} disabled={busy}>
              {#if busyKind === "apply"}<span class="spinner"></span>Cleaning…{:else}Clean {applicable.length} {plural(applicable.length, "repo", "repos")}{/if}
            </button>
          {/if}
        </div>
        {#if previewing}<p class="muted micro"><span class="spinner"></span> Preparing remediation…</p>{/if}
        {#if manualCount}
          <p class="manual-note">⚠ {manualCount} {plural(manualCount, "finding", "findings")} need manual review — they can't be removed automatically.</p>
        {/if}
        {#if cleanResult}<p class="ok-text small">{cleanResult}</p>{/if}
      </section>

      {#each grouped as [campaign, list] (campaign)}
        <section class="card">
          <div class="row between">
            <h2>{campaign}</h2>
            <span class="count sev-{list[0].severity}" aria-label="{list.length} findings">{list.length}</span>
          </div>
          <ul class="findings">
            {#each list as f, i (f.repo + (f.file ?? "") + f.signature_id + i)}
              <li class="finding">
                <span class="pill {f.severity}">{f.severity}</span>
                <div class="stack" style="min-width: 0; flex: 1">
                  <div class="repo-name mono">{f.repo}</div>
                  <div class="path">
                    {#if f.file}{f.file}{:else}<span class="muted">repository-level</span>{/if}
                    {#if f.git_ref}<span class="chip">branch: {f.git_ref}</span>{/if}
                    <span class="tag2 {f.remediable ? 'fixable' : 'manual'}">{f.remediable ? "Auto-fixable" : "Manual review"}</span>
                  </div>
                  <code class="evidence mono">{f.evidence}</code>
                  {#if f.online}
                    <div class="micro {f.online.malicious ? 'crit' : 'muted'}">
                      OpenSourceMalware: {f.online.malicious ? "flagged as malicious" : "not flagged"}{#if f.online.message} — {f.online.message}{/if}{#if f.online.osm_url} · <a href={f.online.osm_url} target="_blank" rel="noreferrer noopener">View advisory ↗</a>{/if}
                    </div>
                  {/if}
                </div>
              </li>
            {/each}
          </ul>
        </section>
      {/each}
    {/if}

    <!-- Advanced -->
    <section class="card">
      <button class="adv-toggle" onclick={() => (showAdvanced = !showAdvanced)} aria-expanded={showAdvanced}>
        <span class="chev" class:open={showAdvanced}>▸</span> Advanced — other branches &amp; restore
      </button>
      {#if showAdvanced}
        <div class="adv-body">
          <div class="stack">
            <p class="lede">
              Deep-scan every branch tip and rewrite infected tips on a fresh commit (old tip kept in
              a <code>refs/wormward-backup/…</code> ref). Push force-pushes rewritten tips.
            </p>
            <div class="row">
              <button class="btn sm" onclick={previewBranches} disabled={branchLoading || busy || !hasDirs}>
                {#if branchLoading}<span class="spinner"></span>Scanning branches…{:else}Scan other branches{/if}
              </button>
              <button class="btn primary sm" onclick={() => (confirmingBranches = true)} disabled={busy || selectedBranches.length === 0}>
                {#if busyKind === "branches"}<span class="spinner"></span>Cleaning…{:else}Clean {selectedBranches.length} {plural(selectedBranches.length, "branch", "branches")}{/if}
              </button>
              <label class="switch sm">
                <input type="checkbox" bind:checked={pushBranches} />
                <span class="track"></span>
                <span class="lbl small">Push <span class="muted">— force-push tips</span></span>
              </label>
            </div>
            {#if branchSummary}<p class="ok-text small">{branchSummary}</p>{/if}
            {#if branchPlans.length === 0}
              {#if branchesScanned}<p class="muted micro">No infected branch tips found.</p>{/if}
            {:else}
              {#each branchPlans as b (branchKey(b))}
                <label class="switch item">
                  <input type="checkbox" bind:checked={branchSel[branchKey(b)]} />
                  <span class="track"></span>
                  <span class="lbl small"><span class="mono">{b.repo}</span> <span class="chip">branch: {b.branch}</span> <span class="muted">— {b.action_count} {plural(b.action_count, "action", "actions")}</span></span>
                </label>
              {/each}
            {/if}
            {#if branchResults.length}
              <div class="stack" style="margin-top: 4px">
                {#each branchResults as r, i (i)}
                  <div class="branch-res {r.status}"><span class="dot"></span><span class="mono">{r.branch}</span> — {r.status}{r.pushed ? " (pushed)" : ""}{#if r.message} — {r.message}{/if}</div>
                {/each}
              </div>
            {/if}
          </div>

          <hr class="sep" />
          <div class="row between">
            <p class="muted small">Undo a clean by restoring the last backup (re-introduces the removed payloads).</p>
            <button class="btn danger sm" onclick={() => (restoreConfirm = true)} disabled={busy || !hasDirs}>
              {#if busyKind === "restore"}<span class="spinner"></span>Restoring…{:else}Restore last backup{/if}
            </button>
          </div>
        </div>
      {/if}
    </section>
  {/if}
</div>

{#if confirming}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirming = false)}>
      <h3>Clean {applicable.length} {plural(applicable.length, "repository", "repositories")}?</h3>
      <p class="lede">
        Strips payloads, deletes dropped artifacts, and fixes <code>.gitignore</code> in the working
        tree of: {applicable.map((p) => p.repo).join(", ")}. Originals are backed up under
        <code>.wormward-backup/</code>. Does not touch git history or push anything.
      </p>
      <div class="row">
        <button class="btn ghost" onclick={() => (confirming = false)}>Cancel</button>
        <button class="btn primary" onclick={apply}>Clean now</button>
      </div>
    </div>
  </div>
{/if}

{#if restoreConfirm}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (restoreConfirm = false)}>
      <h3>Restore the last backup?</h3>
      <p class="crit small"><strong>This re-writes the backed-up originals over the current files</strong> — including the malware that was cleaned. Only do this if a clean went wrong.</p>
      <p class="muted small">If no backup exists, nothing changes.</p>
      <div class="row">
        <button class="btn ghost" onclick={() => (restoreConfirm = false)}>Cancel</button>
        <button class="btn danger" onclick={doRestore}>Restore &amp; re-introduce</button>
      </div>
    </div>
  </div>
{/if}

{#if confirmingBranches}
  <div class="modal-backdrop">
    <div class="modal" role="dialog" aria-modal="true" tabindex="-1" use:dialog={() => (confirmingBranches = false)}>
      <h3>Rewrite branch tips?</h3>
      <p class="lede">Rewrites the tips of {selectedBranches.length} selected {plural(selectedBranches.length, "branch", "branches")} with a new clean commit. The old tip of each is kept in a <code>refs/wormward-backup/…</code> ref.</p>
      {#if pushBranches}
        <p class="crit small"><strong>Push is ON:</strong> cleaned tips will be <strong>force-pushed</strong>, overwriting remote history.</p>
      {:else}
        <p class="muted small">Push is OFF — local branches rewritten in place; remote-tracking branches are reported as skipped.</p>
      {/if}
      <div class="row">
        <button class="btn ghost" onclick={() => (confirmingBranches = false)}>Cancel</button>
        <button class="btn {pushBranches ? 'danger' : 'primary'}" onclick={applyBranches}>{pushBranches ? "Clean & force-push" : "Clean branches"}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .field { display: flex; flex-direction: column; gap: 8px; }
  .field-label { font-size: 12px; color: var(--muted); font-weight: 500; }
  .path-preview { font-size: 12px; color: var(--fg); background: var(--inset); border-radius: var(--radius-sm); padding: 9px 12px; word-break: break-all; }
  .path-preview.empty { color: var(--faint); }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .folder-chip { display: inline-flex; align-items: center; gap: 6px; max-width: 100%; font-size: 11.5px; color: var(--fg); background: var(--inset); border-radius: var(--radius-sm); padding: 4px 4px 4px 10px; }
  .fc-path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .fc-x { flex: none; background: none; color: var(--faint); font-size: 15px; line-height: 1; padding: 0 5px; border-radius: 4px; }
  .fc-x:hover:not(:disabled) { color: var(--danger); background: var(--danger-tint); }
  .opts { display: flex; flex-direction: column; gap: 4px; padding: 2px 0; margin: 0; border: 0; min-width: 0; }
  .opt-note { font-size: 11.5px; color: var(--muted); background: var(--inset); padding: 7px 11px; border-radius: var(--radius-sm); line-height: 1.5; }
  .scan-status { font-size: 12.5px; color: var(--fg); }
  .scan-status strong { font-variant-numeric: tabular-nums; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }

  .terminal { background: var(--inset); border-radius: var(--radius); overflow: hidden; font-family: var(--mono); }
  .term-body { padding: 14px; max-height: 300px; overflow-y: auto; font-size: 12px; line-height: 1.7; color: var(--fg); scroll-behavior: smooth; }
  .line { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .line .spinner { width: 11px; height: 11px; flex: none; border-color: var(--ok-tint); border-top-color: var(--ok); }
  .tag { flex: none; color: var(--faint); }
  .repo { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--fg); }
  .scanning .repo { color: var(--muted); }
  .mark { flex: none; font-weight: 700; }
  .mark.ok { color: var(--ok); }
  .mark.hit { color: var(--danger); }
  .crit { flex: none; color: var(--danger); }
  .dim .tag { color: var(--faint); }
  .line.hit { background: var(--surface-danger); margin: 0 -6px; padding: 2px 6px; border-radius: 5px; }

  .sev-summary { display: flex; gap: 6px; flex-wrap: wrap; }
  .sev-chip { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 999px; text-transform: capitalize; }
  .sev-chip.critical { background: var(--danger); color: #150a0b; }
  .sev-chip.high { background: var(--danger-tint); color: var(--danger); }
  .sev-chip.medium { background: var(--warn-tint); color: var(--warn); }
  .sev-chip.low, .sev-chip.info { background: var(--accent-tint); color: var(--accent-hi); }
  .count.sev-critical { background: var(--danger); color: #150a0b; }
  .count.sev-high { background: var(--danger-tint); color: var(--danger); }
  .count.sev-medium { background: var(--warn-tint); color: var(--warn); }
  .manual-note { color: var(--warn); font-size: 12.5px; }
  .warn-text { color: var(--warn); }
  .danger-text { color: var(--danger); }
  .notes { display: flex; flex-direction: column; gap: 4px; list-style: none; }

  .findings { display: flex; flex-direction: column; gap: 10px; list-style: none; }
  .finding { display: flex; gap: 11px; align-items: flex-start; }
  .repo-name { font-size: 12px; color: var(--fg); word-break: break-all; }
  .path { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; font-size: 12px; color: var(--muted); }
  .chip { font-size: 10.5px; color: var(--faint); background: var(--surface-2); padding: 1px 7px; border-radius: 999px; }
  .tag2 { font-size: 10px; font-weight: 600; padding: 1px 7px; border-radius: 999px; }
  .tag2.fixable { background: var(--ok-tint); color: var(--ok); }
  .tag2.manual { background: var(--warn-tint); color: var(--warn); }
  .evidence { font-size: 11.5px; color: var(--faint); word-break: break-all; line-height: 1.5; }

  .adv-toggle { background: none; color: var(--muted); font-size: 13px; font-weight: 500; padding: 0; display: flex; align-items: center; gap: 8px; }
  .adv-toggle:hover { color: var(--fg); background: none; }
  .chev { display: inline-block; transition: transform var(--fast) var(--ease); }
  .chev.open { transform: rotate(90deg); }
  .adv-body { display: flex; flex-direction: column; gap: 14px; margin-top: 14px; }
  .sep { border: 0; height: 1px; background: var(--surface-3); margin: 2px 0; }
  .switch.sm .lbl { font-size: 12px; }

  .branch-res { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
  .branch-res .dot { flex: none; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .branch-res.cleaned { color: var(--ok); }
  .branch-res.cleaned .dot { background: var(--ok); }
  .branch-res.skipped .dot { background: var(--warn); }
  .branch-res.failed { color: var(--danger); }
  .branch-res.failed .dot { background: var(--danger); }
  .branch-res.planned .dot { background: var(--accent); }
</style>
