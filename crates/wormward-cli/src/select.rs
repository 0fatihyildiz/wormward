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
/// - `bypass` (from `--all`) → return ALL candidates unchanged, silently (`Some`).
/// - `non_interactive` (no TTY / JSON output) → return ALL candidates unchanged and
///   print a one-line note to stderr (`Some`).
/// - otherwise → show an interactive multi-select (every item pre-checked) and return
///   the user's selection (`Some`). If the user deselects everything, that is an empty
///   `Some(vec![])` — a deliberate "fix nothing".
///
/// Returns `None` when the interactive prompt is aborted (Ctrl-C / interrupt / I/O
/// error). This FAILS CLOSED: an aborted prompt selects NOTHING, so callers must treat
/// `None` as "fix no repos and exit cleanly" — never as "fix everything".
///
/// `label` renders each candidate for the interactive list; it is never called on the
/// bypass / non-interactive paths, which keeps those branches unit-testable off a TTY.
pub fn select_repos<T>(
    candidates: Vec<T>,
    opts: SelectOpts,
    label: impl Fn(&T) -> String,
) -> Option<Vec<T>> {
    if opts.bypass {
        return Some(candidates);
    }
    if opts.non_interactive {
        eprintln!("non-interactive: fixing all {} infected repos", candidates.len());
        return Some(candidates);
    }
    let labels: Vec<String> = candidates.iter().map(&label).collect();
    resolve_selection(candidates, prompt_multiselect(&labels))
}

/// Pure selection core: map the prompt's outcome onto the candidate list.
///
/// - `None` (aborted prompt) → `None`: nothing is selected, the abort propagates.
/// - `Some(indices)` → keep exactly those candidates. An empty `indices` yields an empty
///   `Some(vec![])` ("user deselected everything"), which is distinct from an abort.
///
/// Kept separate from the `dialoguer` call so the abort→"fix nothing" propagation is
/// unit-testable without a TTY.
fn resolve_selection<T>(candidates: Vec<T>, keep: Option<Vec<usize>>) -> Option<Vec<T>> {
    let keep = keep?;
    Some(
        candidates
            .into_iter()
            .enumerate()
            .filter(|(i, _)| keep.contains(i))
            .map(|(_, c)| c)
            .collect(),
    )
}

/// Thin `dialoguer` wrapper: a multi-select with every item checked by default. Returns
/// `Some(indices)` for the indices the user left selected, or `None` on any interrupt /
/// I/O error. FAILS CLOSED: an error/abort selects nothing rather than defaulting to all,
/// so a Ctrl-C at the picker can never silently fix (or force-push) every repo.
fn prompt_multiselect(labels: &[String]) -> Option<Vec<usize>> {
    let items: Vec<(&str, bool)> = labels.iter().map(|l| (l.as_str(), true)).collect();
    dialoguer::MultiSelect::new()
        .with_prompt("Select repos to fix (space toggles, enter confirms)")
        .items_checked(&items)
        .interact()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_keeps_all_candidates() {
        let out = select_repos(vec!["a", "b", "c"], SelectOpts { bypass: true, non_interactive: false }, |_| {
            panic!("label must not be called on the bypass path")
        });
        assert_eq!(out, Some(vec!["a", "b", "c"]));
    }

    #[test]
    fn non_interactive_keeps_all_candidates() {
        let out = select_repos(
            vec!["x/one".to_string(), "x/two".to_string()],
            SelectOpts { bypass: false, non_interactive: true },
            |_| panic!("label must not be called on the non-interactive path"),
        );
        assert_eq!(out, Some(vec!["x/one".to_string(), "x/two".to_string()]));
    }

    #[test]
    fn bypass_takes_precedence_over_non_interactive() {
        let out = select_repos(
            vec![1, 2, 3],
            SelectOpts { bypass: true, non_interactive: true },
            |_| panic!("label must not be called"),
        );
        assert_eq!(out, Some(vec![1, 2, 3]));
    }

    // The abort path FAILS CLOSED: a `None` from the prompt wrapper (Ctrl-C / interrupt /
    // I/O error) must resolve to "nothing selected" — never to "all candidates".
    #[test]
    fn aborted_prompt_selects_nothing() {
        let out = resolve_selection(vec!["a", "b", "c"], None);
        assert_eq!(out, None, "an aborted prompt must fix no repos, not all of them");
    }

    #[test]
    fn deselecting_everything_is_empty_not_abort() {
        // An explicit empty selection ("user unchecked everything") is distinct from an
        // abort: it is `Some(vec![])` (fix nothing, but not an interrupt).
        let out = resolve_selection(vec!["a", "b", "c"], Some(vec![]));
        assert_eq!(out, Some(Vec::<&str>::new()));
    }

    #[test]
    fn kept_indices_filter_candidates() {
        let out = resolve_selection(vec!["a", "b", "c"], Some(vec![0, 2]));
        assert_eq!(out, Some(vec!["a", "c"]));
    }
}
