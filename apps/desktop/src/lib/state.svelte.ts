import type { ScanReport, DoctorReport } from "./types";
import { humanizeError } from "./errors";
import { loadLocations } from "./locations";

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

export type View = "home" | "flow" | "machine" | "repos" | "advanced" | "settings";
export type FlowStep = "scanning" | "results" | "cleaning" | "clean";

export const app = $state({
  view: "home" as View,
  flow: null as FlowStep | null,
  dirs: [] as string[],
  /** Which surfaces a Full Scan covers. Both on by default — a Full Scan checks everything; a user
   *  can narrow it to just this machine or just their code. Persisted below. */
  scanMac: true,
  scanRepos: true,
  /** Opt-in OpenSourceMalware cross-check for Full Scan (needs an OSM token). Off by default —
   *  online mode sends the names of flagged packages to a third party. Hydrated + persisted below. */
  online: false,
  /** Also pickaxe full git history for scrubbed-but-reachable payloads (slower). Off by default. */
  history: false,
  /** Gate lockfiles against OSV via the external `osv-scanner`, if installed. Off by default. */
  osv: false,
  /** Include lower-confidence, community-sourced IOC leads (suppressed by default). */
  community: false,
  report: null as ScanReport | null,
  machineReport: null as DoctorReport | null,
  lastScanAt: null as number | null,
  scanning: false,
  toasts: [] as Toast[],
});

// "dirs" ARE the protected locations (name kept for api.scan compatibility).
app.dirs = loadLocations();
app.scanMac = localStorage.getItem("scan_mac") !== "0"; // both surfaces on by default
app.scanRepos = localStorage.getItem("scan_repos") !== "0";
app.online = localStorage.getItem("online_scan") === "1";
app.history = localStorage.getItem("scan_history") === "1";
app.osv = localStorage.getItem("scan_osv") === "1";
app.community = localStorage.getItem("scan_community") === "1";

export function go(view: View) {
  app.view = view;
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
