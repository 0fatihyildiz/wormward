import { describe, it, expect } from "vitest";
import type { DoctorReport, ScanReport, Finding } from "./types";
import {
  levelRank,
  machineStatus,
  reposStatus,
  overallLevel,
  type SurfaceStatus,
} from "./protection";

function doctor(p: Partial<DoctorReport> = {}): DoctorReport {
  return { processes: [], caches: [], triggers: [], cache_dirs: [], ...p };
}
function report(p: Partial<ScanReport> = {}): ScanReport {
  return { findings: [], repos_scanned: 1, ...p };
}
function finding(severity: Finding["severity"]): Finding {
  return {
    campaign: "c",
    severity,
    repo: "r",
    signature_id: "s",
    kind: "k",
    evidence: "e",
    remediable: true,
  };
}
const surf = (level: SurfaceStatus["level"]): SurfaceStatus => ({ level, label: "x" });

describe("levelRank", () => {
  it("ranks threat > attention > protected > unknown", () => {
    expect(levelRank("threat")).toBe(3);
    expect(levelRank("attention")).toBe(2);
    expect(levelRank("protected")).toBe(1);
    expect(levelRank("unknown")).toBe(0);
  });
});

describe("machineStatus", () => {
  it("null => unknown / Not checked", () => {
    expect(machineStatus(null)).toEqual({ level: "unknown", label: "Not checked" });
  });
  it("a running process => threat", () => {
    expect(machineStatus(doctor({ processes: [{ pid: 1, reason: "r", snippet: "s" }] }))).toEqual(
      { level: "threat", label: "Active threat running" },
    );
  });
  it("tainted caches => attention", () => {
    expect(machineStatus(doctor({ caches: [{ path: "p", reason: "r" }] }))).toEqual(
      { level: "attention", label: "Needs attention" },
    );
  });
  it("an exposed trigger => attention", () => {
    expect(
      machineStatus(doctor({ triggers: [{ name: "n", exposed: true, detail: "d" }] })),
    ).toEqual({ level: "attention", label: "Needs attention" });
  });
  it("nothing wrong => protected", () => {
    expect(
      machineStatus(doctor({ triggers: [{ name: "n", exposed: false, detail: "d" }] })),
    ).toEqual({ level: "protected", label: "No active threats" });
  });
  it("a running process beats tainted caches => threat (precedence)", () => {
    expect(
      machineStatus(
        doctor({ processes: [{ pid: 1, reason: "r", snippet: "s" }], caches: [{ path: "p", reason: "r" }] }),
      ),
    ).toEqual({ level: "threat", label: "Active threat running" });
  });
});

describe("reposStatus", () => {
  it("null => unknown / Not scanned", () => {
    expect(reposStatus(null)).toEqual({ level: "unknown", label: "Not scanned" });
  });
  it("a critical finding => threat", () => {
    expect(reposStatus(report({ findings: [finding("critical")] }))).toEqual({
      level: "threat",
      label: "Critical threat found",
    });
  });
  it("non-critical findings => attention", () => {
    expect(reposStatus(report({ findings: [finding("high")] }))).toEqual({
      level: "attention",
      label: "Threats found",
    });
  });
  it("cancelled with no findings => unknown / Scan incomplete", () => {
    expect(reposStatus(report({ findings: [], cancelled: true }))).toEqual({
      level: "unknown",
      label: "Scan incomplete",
    });
  });
  it("clean completed scan => protected", () => {
    expect(reposStatus(report({ findings: [], cancelled: false }))).toEqual({
      level: "protected",
      label: "No threats",
    });
  });
  it("cancelled but with a critical finding => threat (findings beat incomplete)", () => {
    expect(reposStatus(report({ findings: [finding("critical")], cancelled: true }))).toEqual({
      level: "threat",
      label: "Critical threat found",
    });
  });
});

describe("overallLevel", () => {
  it("both protected => protected", () => {
    expect(overallLevel(surf("protected"), surf("protected"))).toBe("protected");
  });
  it("one unknown => unknown", () => {
    expect(overallLevel(surf("protected"), surf("unknown"))).toBe("unknown");
  });
  it("one attention => attention", () => {
    expect(overallLevel(surf("attention"), surf("protected"))).toBe("attention");
  });
  it("any threat => threat", () => {
    expect(overallLevel(surf("protected"), surf("threat"))).toBe("threat");
  });
  it("threat beats attention", () => {
    expect(overallLevel(surf("threat"), surf("attention"))).toBe("threat");
  });
});
