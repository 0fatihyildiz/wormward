import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import type {
  ScanReport,
  PackInfo,
  RepoPlan,
  CleanSummary,
  RestoreSummary,
} from "./types";

export const scan = (dirs: string[], deep: boolean, online: boolean, token?: string) =>
  invoke<ScanReport>("scan", { dirs, deep, online, token: token ?? null });

export const listPacks = () => invoke<PackInfo[]>("list_packs");

export const cleanPreview = (dirs: string[]) =>
  invoke<RepoPlan[]>("clean_preview", { dirs });

export const cleanApply = (dirs: string[]) =>
  invoke<CleanSummary>("clean_apply", { dirs });

export const restore = (dirs: string[]) =>
  invoke<RestoreSummary>("restore", { dirs });

export async function pickDirs(): Promise<string[]> {
  const sel = await open({ directory: true, multiple: true });
  if (!sel) return [];
  return Array.isArray(sel) ? sel : [sel];
}
