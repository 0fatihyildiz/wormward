import type { DoctorReport, ScanReport } from "./types";

export type ProtectionLevel = "protected" | "attention" | "threat" | "unknown";

export interface SurfaceStatus {
  level: ProtectionLevel;
  label: string;
}

export function levelRank(l: ProtectionLevel): number {
  switch (l) {
    case "threat":
      return 3;
    case "attention":
      return 2;
    case "protected":
      return 1;
    default:
      return 0;
  }
}

export function machineStatus(report: DoctorReport | null): SurfaceStatus {
  if (report === null) return { level: "unknown", label: "Not checked" };
  if (report.processes.length > 0)
    return { level: "threat", label: "Active threat running" };
  if (report.caches.length > 0 || report.triggers.some((t) => t.exposed))
    return { level: "attention", label: "Needs attention" };
  return { level: "protected", label: "No active threats" };
}

export function reposStatus(report: ScanReport | null): SurfaceStatus {
  if (report === null) return { level: "unknown", label: "Not scanned" };
  if (report.findings.some((f) => f.severity === "critical"))
    return { level: "threat", label: "Critical threat found" };
  if (report.findings.length > 0)
    return { level: "attention", label: "Threats found" };
  if (report.cancelled) return { level: "unknown", label: "Scan incomplete" };
  return { level: "protected", label: "No threats" };
}

export function overallLevel(
  machine: SurfaceStatus,
  repos: SurfaceStatus,
): ProtectionLevel {
  if (machine.level === "threat" || repos.level === "threat") return "threat";
  if (machine.level === "attention" || repos.level === "attention")
    return "attention";
  if (machine.level === "unknown" || repos.level === "unknown") return "unknown";
  return "protected";
}
