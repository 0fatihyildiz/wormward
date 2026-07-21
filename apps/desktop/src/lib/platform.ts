/**
 * Best-effort host-OS detection from the webview user-agent. It's enough to pick a platform-correct
 * device noun and to gate the macOS-only machine check, without pulling in an extra Tauri plugin.
 *
 * The repo/code scan is cross-platform (it drives `git` + file walking). The machine check runs on
 * macOS (ps + ~/Library/toolchain caches + launchd triggers) and Windows (PowerShell process query
 * + %APPDATA%/%LOCALAPPDATA% caches + npm triggers). Linux/other aren't wired up yet, so there we
 * scan code and honestly mark the machine surface as unsupported rather than reporting a false clean.
 */
export type OS = "macos" | "windows" | "linux" | "other";

function detect(): OS {
  const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
  if (/Mac|iPhone|iPad/i.test(ua)) return "macos";
  if (/Windows/i.test(ua)) return "windows";
  if (/Linux|X11/i.test(ua)) return "linux";
  return "other";
}

export const os: OS = detect();

/** The local machine, named for the platform: "Mac" / "PC" / "computer". */
export const device = os === "macos" ? "Mac" : os === "windows" ? "PC" : "computer";

/** The machine check (loader processes, toolchain caches, re-infection triggers) runs on macOS and
 *  Windows; Linux/other aren't wired up yet. */
export const machineSupported = os === "macos" || os === "windows";
