import { describe, it, expect } from "vitest";
import type { Finding } from "./types";
import { fixClass, fixLabel, branchSelections } from "./findings";

function finding(p: Partial<Finding> = {}): Finding {
  return {
    campaign: "polinrider",
    severity: "critical",
    repo: "r",
    signature_id: "s",
    kind: "content_signature",
    evidence: "e",
    remediable: true,
    ...p,
  };
}

describe("fixClass", () => {
  it("remediable working-tree finding is auto", () => {
    expect(fixClass(finding({ remediable: true, git_ref: undefined }))).toBe("auto");
  });
  it("remediable branch-tip finding is branch, not auto", () => {
    // The bug: this used to read as 'Removable automatically' though the one-click
    // working-tree strip can never touch a branch-tip finding.
    expect(fixClass(finding({ remediable: true, git_ref: "origin/main" }))).toBe("branch");
  });
  it("non-remediable finding is manual regardless of ref", () => {
    expect(fixClass(finding({ remediable: false }))).toBe("manual");
    expect(fixClass(finding({ remediable: false, git_ref: "origin/x" }))).toBe("manual");
  });
});

describe("fixLabel", () => {
  it("gives a distinct label per class; branch is not 'Removable automatically'", () => {
    expect(fixLabel(finding({ git_ref: undefined }))).toBe("Removable automatically");
    expect(fixLabel(finding({ git_ref: "origin/main" }))).not.toBe("Removable automatically");
    expect(fixLabel(finding({ remediable: false }))).toBe("Needs your attention");
  });
});

describe("branchSelections", () => {
  it("returns unique (repo, branch) pairs for remediable branch findings only", () => {
    const findings: Finding[] = [
      finding({ repo: "a", git_ref: "origin/main" }),
      finding({ repo: "a", git_ref: "origin/main" }), // dup collapses
      finding({ repo: "a", git_ref: "origin/dev" }),
      finding({ repo: "b", git_ref: "origin/main" }),
      finding({ repo: "a", git_ref: undefined }), // working-tree: excluded
      finding({ repo: "c", remediable: false, git_ref: "origin/x" }), // non-remediable: excluded
    ];
    const sel = branchSelections(findings);
    expect(sel).toEqual([
      { repo: "a", branch: "origin/main" },
      { repo: "a", branch: "origin/dev" },
      { repo: "b", branch: "origin/main" },
    ]);
  });
});
