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
}

export interface PackInfo {
  id: string;
  name: string;
  description: string;
}

export type RemediationAction =
  | { StripPayload: { file: string; markers: string[] } }
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
