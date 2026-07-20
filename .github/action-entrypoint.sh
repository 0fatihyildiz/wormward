#!/bin/sh
# Entrypoint for the Wormward GitHub Action. Runs a read-only scan of the checked-out repo, writes
# a job-summary + optional SARIF, and exits non-zero on findings so the check fails.
set -u

TARGET="${INPUT_PATH:-.}"

# Build optional flags from inputs.
set --
[ "${INPUT_HISTORY:-false}" = "true" ] && set -- "$@" --history
[ "${INPUT_INCLUDE_COMMUNITY:-false}" = "true" ] && set -- "$@" --include-community

# One scan for the human-readable report + exit code.
wormward scan "$TARGET" "$@" --deep --format text > scan.txt 2>&1
code=$?
cat scan.txt

# GitHub job summary.
{
  echo "## 🛡️ Wormward supply-chain scan"
  echo
  if [ "$code" -eq 0 ]; then
    echo "✅ No infections found."
  else
    echo "🚨 Findings detected — see below. This check is failing."
  fi
  echo
  echo '```'
  cat scan.txt
  echo '```'
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

# Optional SARIF for the Security tab.
if [ "${INPUT_SARIF:-true}" = "true" ]; then
  wormward scan "$TARGET" "$@" --deep --format sarif > wormward.sarif 2>/dev/null || true
fi

exit "$code"
