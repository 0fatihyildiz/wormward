import type { ScanReport } from "./types";

export const app = $state({
  screen: "scan" as "scan" | "results" | "clean" | "github" | "doctor" | "settings",
  dirs: [] as string[],
  report: null as ScanReport | null,
  scanning: false,
  error: "",
});
