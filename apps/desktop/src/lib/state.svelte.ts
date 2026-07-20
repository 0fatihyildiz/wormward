import type { ScanReport } from "./types";

export type ToastKind = "error" | "warn" | "info" | "ok";
export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  detail?: string;
}

let seq = 0;

export const app = $state({
  screen: "scan" as "scan" | "results" | "clean" | "github" | "doctor" | "settings",
  dirs: [] as string[],
  report: null as ScanReport | null,
  scanning: false,
  toasts: [] as Toast[],
});

/** Map raw backend / GitHub errors to plain language; pass anything else through. */
export function humanizeError(e: unknown): string {
  const s = String(e);
  if (/\b401\b|unauthorized|bad credentials/i.test(s))
    return "Authentication failed — check your token in Settings.";
  if (/\b403\b|forbidden|rate limit/i.test(s))
    return "GitHub refused the request — token permissions or rate limit. Check the token's scope, or wait and retry.";
  if (/network|timed? ?out|connection|dns|failed to (fetch|connect|resolve)/i.test(s))
    return "Network error — couldn't reach the server. Check your connection and retry.";
  if (/requires an? (osm|opensourcemalware) token|online scan requires/i.test(s))
    return "Online cross-check needs an OpenSourceMalware token — add one in Settings.";
  return s.replace(/^error:\s*/i, "");
}

/** Push a notification. Failures persist until dismissed (WCAG 2.2.1); notices auto-clear. */
export function notify(kind: ToastKind, message: string, detail?: string): number {
  const id = ++seq;
  app.toasts.push({ id, kind, message, detail });
  if (kind !== "error") setTimeout(() => dismiss(id), 6000);
  return id;
}

/** Report a caught failure as a persistent, humanized error toast. */
export function fail(e: unknown, detail?: string): number {
  return notify("error", humanizeError(e), detail);
}

export function dismiss(id: number) {
  app.toasts = app.toasts.filter((t) => t.id !== id);
}

/** Clear lingering error toasts, e.g. when starting a fresh action. */
export function clearErrors() {
  app.toasts = app.toasts.filter((t) => t.kind !== "error");
}
