/**
 * True only inside the Tauri desktop webview, where the `invoke` IPC bridge exists.
 * In a plain browser (e.g. opening the Vite dev server at localhost:5173 directly) the
 * bridge is absent, so every backend command would fail — the UI renders but nothing works.
 */
export const isTauri =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
