# Wormward CI integration

Wormward ships a GitHub Action (`action.yml` at the repo root) that runs a **read-only** supply-chain
scan on every push / pull request and **fails the build on findings**. It never executes scanned
code, so it is safe to run against untrusted pull requests.

## Quick start (consumer repo)

```yaml
# .github/workflows/supply-chain.yml
name: Supply-chain scan
on:
  push:
    branches: [main, master]
  pull_request:
  schedule:
    - cron: '0 6 * * *'   # daily — re-infection with rotated variants has been observed

permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload step

jobs:
  wormward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # required for history: 'true'
      - name: Wormward scan
        uses: OpenSourceMalware/wormward@<COMMIT_SHA>   # PIN to a reviewed commit SHA
        with:
          history: 'true'
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: wormward.sarif
```

Then make **"Wormward scan"** a **required status check** (Settings → Branches → branch protection),
and enable *"Do not allow bypassing the above settings"*.

## Why this is tamper-proof

- **Read-only by construction.** Wormward greps/parses files and git objects; it never runs a
  `postinstall`, a config file, or anything from the scanned tree. A malicious PR cannot get code to
  execute inside the scan.
- **The scanner comes from a trusted, pinned ref.** GitHub checks the action out from *wormward's*
  repository at the SHA you pin — not from the pull request. A PR editing its own `action.yml` or
  workflow cannot alter the scanner that gates it. (This is why you should pin `@<SHA>`, not `@main`.)
- **Least privilege.** The scan job needs only `contents: read` (plus `security-events: write` for
  the optional SARIF upload). No token is handed to scanned code.

## Inputs

| input | default | description |
|---|---|---|
| `path` | `.` | Directory to scan. |
| `history` | `false` | Also pickaxe git history for payloads scrubbed from the tip (needs `fetch-depth: 0`). |
| `sarif` | `true` | Write `wormward.sarif` for the Security tab. |
| `include-community` | `false` | Include lower-confidence community IOC leads. |

## Exporting rules instead

If you run your own YARA / Sigma / Suricata pipeline, export wormward's IOC catalog as rules rather
than running the binary:

```
wormward export-rules --format yara     > wormward.yar
wormward export-rules --format sigma    > wormward.sigma.yml
wormward export-rules --format suricata > wormward.rules
```
