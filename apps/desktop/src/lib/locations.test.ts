import { describe, it, expect, beforeEach } from "vitest";
import { loadLocations, saveLocations, hasLocations } from "./locations";

const KEY = "protected_locations";

describe("locations", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("loadLocations returns [] when the key is missing", () => {
    expect(loadLocations()).toEqual([]);
  });

  it("loadLocations returns [] on invalid JSON", () => {
    localStorage.setItem(KEY, "{not json");
    expect(loadLocations()).toEqual([]);
  });

  it("loadLocations returns [] when the stored value is not an array", () => {
    localStorage.setItem(KEY, JSON.stringify({ a: 1 }));
    expect(loadLocations()).toEqual([]);
  });

  it("loadLocations returns the stored array when valid", () => {
    localStorage.setItem(KEY, JSON.stringify(["/a", "/b"]));
    expect(loadLocations()).toEqual(["/a", "/b"]);
  });

  it("saveLocations persists and round-trips through loadLocations", () => {
    saveLocations(["/x", "/y"]);
    expect(localStorage.getItem(KEY)).toBe(JSON.stringify(["/x", "/y"]));
    expect(loadLocations()).toEqual(["/x", "/y"]);
  });

  it("hasLocations is false when there are none", () => {
    expect(hasLocations()).toBe(false);
  });

  it("hasLocations is true when at least one is stored", () => {
    saveLocations(["/only"]);
    expect(hasLocations()).toBe(true);
  });
});
