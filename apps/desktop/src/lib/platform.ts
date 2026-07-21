/**
 * Best-effort host-OS detection from the webview user-agent. It's enough to pick a platform-correct
 * device noun and to gate the macOS-only machine check, without pulling in an extra Tauri plugin.
 *
 * The repo/code scan is cross-platform (it drives `git` + file walking). The machine check
 * (running loader processes via `ps`, macOS toolchain caches, launchd/LaunchAgent triggers) is
 * macOS-only for now — so on Windows/Linux we scan code and honestly mark the machine surface as
 * unsupported rather than reporting a false "no threats".
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

/** The machine check (loader processes, toolchain caches, re-infection triggers) is macOS-only. */
export const machineSupported = os === "macos";
