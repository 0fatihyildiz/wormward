import type { ScanReport } from "./types";
import { humanizeError } from "./errors";

// Re-exported so existing importers keep working; impl now lives in ./errors.
export { humanizeError };

export type ToastKind = "error" | "warn" | "info" | "ok";
export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  detail?: string;
}

let seq = 0;

export const app = $state({
  screen: "scan" as "scan" | "github" | "doctor" | "settings",
  dirs: [] as string[],
  report: null as ScanReport | null,
  scanning: false,
  toasts: [] as Toast[],
});

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
