import type { Finding } from "./types";
import type { BranchSelection } from "./types";

/**
 * How a finding can be remediated. This is the single source of truth the results screen and
 * FindingCard share, so the pill label and the action buttons can never disagree again.
 *
 * - `auto`   — a working-tree file the one-click "Remove threats safely" strip removes
 *              (`remediable`, no branch ref).
 * - `branch` — remediable, but the payload lives on a branch TIP (`git_ref` set). The
 *              working-tree strip can't touch it; only the branch cleaner can, and that
 *              rewrites history + force-pushes to the remote.
 * - `manual` — no automatic action exists; needs human review.
 */
export type FixClass = "auto" | "branch" | "manual";

export function fixClass(f: Finding): FixClass {
  if (!f.remediable) return "manual";
  return f.git_ref ? "branch" : "auto";
}

const LABELS: Record<FixClass, string> = {
  auto: "Removable automatically",
  branch: "Removable on branch",
  manual: "Needs your attention",
};

export function fixLabel(f: Finding): string {
  return LABELS[fixClass(f)];
}

/**
 * The unique (repo, branch) pairs the branch cleaner should target: every remediable
 * branch-tip finding, deduped. Working-tree and non-remediable findings are excluded.
 */
export function branchSelections(findings: Finding[]): BranchSelection[] {
  const seen = new Set<string>();
  const out: BranchSelection[] = [];
  for (const f of findings) {
    if (fixClass(f) !== "branch" || !f.git_ref) continue;
    const key = `${f.repo}\n${f.git_ref}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ repo: f.repo, branch: f.git_ref });
  }
  return out;
}
