import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import type {
  ScanReport,
  PackInfo,
  RepoPlan,
  CleanSummary,
  RestoreSummary,
  BranchCleanPreview,
  BranchSelection,
  BranchCleanApplySummary,
  GithubRepoView,
  GithubFixView,
  DoctorReport,
} from "./types";

export const scan = (dirs: string[], deep: boolean, online: boolean, token?: string) =>
  invoke<ScanReport>("scan", { dirs, deep, online, token: token ?? null });

export const cancelScan = () => invoke<void>("cancel_scan");

export const listPacks = () => invoke<PackInfo[]>("list_packs");

export const cleanPreview = (dirs: string[]) =>
  invoke<RepoPlan[]>("clean_preview", { dirs });

export const cleanApply = (repos: string[]) =>
  invoke<CleanSummary>("clean_apply", { repos });

export const restore = (dirs: string[]) =>
  invoke<RestoreSummary>("restore", { dirs });

export const cleanBranchesPreview = (dirs: string[]) =>
  invoke<BranchCleanPreview[]>("clean_branches_preview", { dirs });

export const cleanBranchesApply = (selected: BranchSelection[], push: boolean) =>
  invoke<BranchCleanApplySummary>("clean_branches_apply", { selected, push });

export const githubOrgs = (token: string | undefined) =>
  invoke<string[]>("github_orgs", { token: token ?? null });

export const githubScan = (token: string | undefined, includeForks: boolean, orgs: string[]) =>
  invoke<GithubRepoView[]>("github_scan", { token: token ?? null, includeForks, orgs });

export const githubFix = (selected: string[]) =>
  invoke<GithubFixView[]>("github_fix", { selected });

export const cancelGithubScan = () => invoke<void>("cancel_github_scan");

// Machine-level check (`doctor`).
export const doctor = () => invoke<DoctorReport>("doctor");
export const doctorClearCache = (dir: string) =>
  invoke<void>("doctor_clear_cache", { dir });
export const doctorHardenTriggers = () => invoke<string[]>("doctor_harden_triggers");

export async function pickDirs(): Promise<string[]> {
  const sel = await open({ directory: true, multiple: true });
  if (!sel) return [];
  return Array.isArray(sel) ? sel : [sel];
}
