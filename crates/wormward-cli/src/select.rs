//! Interactive multi-select for choosing which infected repos to fix.
//!
//! The pure decision logic (bypass / non-interactive → keep all candidates) lives in
//! [`select_repos`] and is unit-testable without a TTY. Only the [`prompt_multiselect`]
//! wrapper touches `dialoguer`, and it is reached solely on the interactive path.

use std::io::IsTerminal;

/// How to resolve a selection among infected repos.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelectOpts {
    /// `--all`: skip the prompt and keep every candidate (silent).
    pub bypass: bool,
    /// No TTY (or a machine-readable output mode): keep every candidate and print a
    /// one-line note to stderr so the user knows the prompt was skipped.
    pub non_interactive: bool,
}

/// True only when both stdin and stdout are real terminals, so an interactive prompt
/// can be shown and answered.
pub fn stdio_is_tty() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Choose which candidates to keep.
///
/// - `bypass` (from `--all`) → return ALL candidates unchanged, silently.
/// - `non_interactive` (no TTY / JSON output) → return ALL candidates unchanged and
///   print a one-line note to stderr.
/// - otherwise → show an interactive multi-select (every item pre-checked) and return
///   the user's selection.
///
/// `label` renders each candidate for the interactive list; it is never called on the
/// bypass / non-interactive paths, which keeps those branches unit-testable off a TTY.
pub fn select_repos<T>(
    candidates: Vec<T>,
    opts: SelectOpts,
    label: impl Fn(&T) -> String,
) -> Vec<T> {
    if opts.bypass {
        return candidates;
    }
    if opts.non_interactive {
        eprintln!("non-interactive: fixing all {} infected repos", candidates.len());
        return candidates;
    }
    let labels: Vec<String> = candidates.iter().map(&label).collect();
    let keep = prompt_multiselect(&labels);
    candidates
        .into_iter()
        .enumerate()
        .filter(|(i, _)| keep.contains(i))
        .map(|(_, c)| c)
        .collect()
}

/// Thin `dialoguer` wrapper: a multi-select with every item checked by default. Returns
/// the indices the user left selected. On any I/O error, falls back to keeping all
/// (fail-safe: better to over-fix than silently skip an infected repo).
fn prompt_multiselect(labels: &[String]) -> Vec<usize> {
    let items: Vec<(&str, bool)> = labels.iter().map(|l| (l.as_str(), true)).collect();
    dialoguer::MultiSelect::new()
        .with_prompt("Select repos to fix (space toggles, enter confirms)")
        .items_checked(&items)
        .interact()
        .unwrap_or_else(|_| (0..labels.len()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_keeps_all_candidates() {
        let out = select_repos(vec!["a", "b", "c"], SelectOpts { bypass: true, non_interactive: false }, |_| {
            panic!("label must not be called on the bypass path")
        });
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn non_interactive_keeps_all_candidates() {
        let out = select_repos(
            vec!["x/one".to_string(), "x/two".to_string()],
            SelectOpts { bypass: false, non_interactive: true },
            |_| panic!("label must not be called on the non-interactive path"),
        );
        assert_eq!(out, vec!["x/one".to_string(), "x/two".to_string()]);
    }

    #[test]
    fn bypass_takes_precedence_over_non_interactive() {
        let out = select_repos(
            vec![1, 2, 3],
            SelectOpts { bypass: true, non_interactive: true },
            |_| panic!("label must not be called"),
        );
        assert_eq!(out, vec![1, 2, 3]);
    }
}
