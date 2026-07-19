<script lang="ts">
  import { app } from "./lib/state.svelte";
  import Scan from "./routes/Scan.svelte";
  import Results from "./routes/Results.svelte";
  import Clean from "./routes/Clean.svelte";
  import GitHub from "./routes/GitHub.svelte";
  import Settings from "./routes/Settings.svelte";

  const tabs = [
    ["scan", "Scan"],
    ["results", "Results"],
    ["clean", "Clean"],
    ["github", "GitHub"],
    ["settings", "Settings"],
  ] as const;
</script>

<header>
  <h1>🐛🛡️ Wormward</h1>
  <nav>
    {#each tabs as [id, label]}
      <button class:active={app.screen === id} onclick={() => (app.screen = id)}>{label}</button>
    {/each}
  </nav>
</header>

{#if app.error}
  <div class="error" role="alert">
    <span>{app.error}</span>
    <button aria-label="dismiss" onclick={() => (app.error = "")}>×</button>
  </div>
{/if}

<main>
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
</main>
