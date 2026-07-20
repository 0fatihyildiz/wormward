export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface OnlineVerdict {
  malicious: boolean;
  severity?: string | null;
  osm_url: string;
  threat_id?: string | null;
  message?: string | null;
}

export interface Finding {
  campaign: string;
  severity: Severity;
  repo: string;
  file?: string | null;
  signature_id: string;
  kind: string;
  evidence: string;
  remediable: boolean;
  online?: OnlineVerdict;
  git_ref?: string;
}

export interface ScanReport {
  findings: Finding[];
  repos_scanned: number;
  /** Non-fatal OSM online-lookup warnings (auth / rate-limit / network). */
  warnings?: string[];
  /** True when the scan was stopped early via cancel_scan (report is partial). */
  cancelled?: boolean;
}

export interface PackInfo {
  id: string;
  name: string;
  description: string;
}

export type RemediationAction =
  | { StripPayload: { file: string; markers: string[]; strip_lines: string[] } }
  | { DeleteFile: { file: string } }
  | { RemoveGitignoreLine: { file: string; line: string } };

export interface RepoPlan {
  repo: string;
  actions: RemediationAction[];
  manual: Finding[];
}

export interface CleanSummary {
  repos: number;
  applied: number;
  skipped: { action: string; reason: string }[];
  backups: string[];
}

export interface RestoreSummary {
  repos: number;
  restored: number;
}

// Feature B: cross-branch cleaning.
export interface BranchCleanPreview {
  repo: string;
  branch: string;
  backup_ref: string;
  action_count: number;
}

export interface BranchSelection {
  repo: string;
  branch: string;
}

export interface BranchCleanResult {
  repo: string;
  branch: string;
  status: "cleaned" | "skipped" | "failed" | "planned";
  pushed: boolean;
  backup_ref?: string | null;
  message?: string | null;
}

export interface BranchCleanApplySummary {
  results: BranchCleanResult[];
  cleaned: number;
  skipped: number;
  failed: number;
}

// Feature C: GitHub account mode.
export interface GithubRepoView {
  full_name: string;
  findings: number;
  campaigns: string[];
  fixable: boolean;
}

export interface GithubFixView {
  full_name: string;
  fixed: boolean;
  pushed: string[];
  actions: string[];
  error?: string | null;
  manual_review: boolean;
}

export type ScanProgress = {
  phase: "scanning" | "scanned";
  done: number;
  total: number;
  repo: string;
  findings: number;
};

// Machine-level check (`doctor`).
export interface ProcHit {
  pid: number;
  reason: string;
  snippet: string;
}
export interface CacheHit {
  path: string;
  reason: string;
}
export interface TriggerCheck {
  name: string;
  exposed: boolean;
  detail: string;
}
export interface DoctorReport {
  processes: ProcHit[];
  caches: CacheHit[];
  triggers: TriggerCheck[];
  /** Distinct cache dirs holding tainted files — the deletable units. */
  cache_dirs: string[];
}
