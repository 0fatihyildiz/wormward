const KEY = "protected_locations";

/** JSON.parse localStorage["protected_locations"]; [] on missing/invalid-JSON/non-array. */
export function loadLocations(): string[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw === null) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as string[]) : [];
  } catch {
    return [];
  }
}

export function saveLocations(dirs: string[]): void {
  localStorage.setItem(KEY, JSON.stringify(dirs));
}

export function hasLocations(): boolean {
  return loadLocations().length > 0;
}
