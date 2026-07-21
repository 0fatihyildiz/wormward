//! Child-process spawning that never pops a console window.
//!
//! On Windows, a GUI (non-console) parent — the Tauri desktop app — gets a NEW visible console
//! window for every child it spawns unless `CREATE_NO_WINDOW` is set. A directory scan spawns
//! git per repo (the reflog check, branch enumeration, `cat-file --batch` readers), which
//! flashed dozens of console windows across the screen; window creation is also real overhead
//! per spawn. Route EVERY production child-process spawn through [`command`]/[`git`] so no
//! spawn site can regress. Test-only spawns (fixtures) run from console test binaries and are
//! exempt.

use std::ffi::OsStr;
use std::process::Command;

/// A [`Command`] that spawns without creating a console window on Windows. Piped/captured
/// stdio (`.output()`, `Stdio::piped()`) is unaffected — only the visible window is suppressed.
pub fn command(program: impl AsRef<OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// A `git` [`Command`] with the no-console-window flag applied.
pub fn git() -> Command {
    command("git")
}
