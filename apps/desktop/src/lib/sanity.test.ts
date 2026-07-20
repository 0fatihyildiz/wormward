import { describe, it, expect } from "vitest";

describe("vitest runner", () => {
  it("runs and asserts", () => {
    expect(1 + 1).toBe(2);
  });

  it("has a jsdom localStorage", () => {
    expect(typeof localStorage).toBe("object");
  });
});
