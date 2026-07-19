import type { ScanReport } from "./types";

export const app = $state({
  screen: "scan" as "scan" | "results" | "clean" | "github" | "settings",
  dirs: [] as string[],
  report: null as ScanReport | null,
  scanning: false,
  error: "",
});
