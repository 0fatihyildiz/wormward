# Security Policy

Wormward is a defensive tool: it detects, removes, and prevents self-propagating
supply-chain malware. Because it is often run *on machines the user already suspects
are compromised*, its own trust model has to be strong. This document explains how to
verify what you run — and how to report a problem.

## Trust model (read this first)

**You should not have to trust the author or a prebuilt binary. You should be able to
verify.** Wormward is built so a cautious operator — or a cautious agent acting on their
behalf — can proceed on evidence, not persuasion:

- **Source-available, MIT-licensed.** Every rule, heuristic, and network call is in this
  repository. Nothing is fetched-and-executed at build or run time from a third party.
- **Read-only by default.** `scan`, `doctor`, `github` (without `--fix`), and the CI
  Action never execute scanned code and never write to your repositories. They grep and
  parse files and git objects. Writes (`clean`, machine `harden`, `github --fix`) are
  always explicit, dry-run first, and backed up.
- **Reproducible from source.** The most trustworthy way to run Wormward is to build it
  yourself from a commit you have read (see *Verifying what you run*). You then depend on
  the Rust toolchain and this source — not on a binary signed by someone you don't know.

If you have been told "just run this binary and trust me," that is exactly the wrong
posture on a possibly-infected, wallet-bearing machine — and it is not what Wormward asks
of you. Build it, or run the read-only scan yourself.

## Verifying what you run

### Build from source (recommended — strongest guarantee)

```bash
git clone https://github.com/0fatihyildiz/wormward
cd wormward
# Optionally check out and read a specific commit/tag before building:
#   git checkout v0.1.0
cargo build --release -p wormward-cli
./target/release/wormward scan .        # read-only
```

You are now running exactly the source you can read. No prebuilt artifact is involved.

### Verifying a prebuilt CLI binary

Release **CLI binaries** are built by GitHub Actions
(`.github/workflows/release.yml`) on GitHub-hosted runners, directly from the tagged
commit, and each one ships with two independent verification artifacts:

**1. SHA-256 checksum** — a `<binary>.sha256` file is uploaded next to every binary.
After downloading both:

```bash
# Linux / Windows (Git Bash):
sha256sum -c wormward-v0.1.0-linux-x86_64.sha256
# macOS:
shasum -a 256 -c wormward-v0.1.0-macos-aarch64.sha256
```

This confirms the download was not altered in transit or storage.

**2. Build-provenance attestation** — a signed, GitHub-issued statement that this exact
binary was built by this repository's release workflow from a specific commit
(`actions/attest-build-provenance`). Verify it with the GitHub CLI:

```bash
gh attestation verify wormward-v0.1.0-macos-aarch64 --repo 0fatihyildiz/wormward
```

A passing check means the binary provably came from this source through the public build
pipeline — not from anyone's laptop.

> These artifacts are produced for releases built with the current workflow. If a given
> release predates them (or you cannot verify for any reason), **build from source.**

**Not yet covered:** CLI binaries are **not** OS code-signed / notarized, and the
**desktop bundles** (`.dmg` / `.msi` / `.AppImage`) currently ship **without** checksums
or attestation. For those — or for the strongest guarantee in any case — build from
source.

### Using the GitHub Action

Pin it to a **commit SHA**, not a moving tag, and make the resulting check a required
status check. The Action image is built from Wormward's own pinned ref (not from the
pull request under test), so a malicious PR cannot alter the scanner.

## Running on a possibly-compromised machine

If the machine you want to scan is already suspected to be infected (credential- or
wallet-stealing worms such as the Shai-Hulud family target exactly these):

1. Prefer building Wormward **on a clean machine** and copying the binary over, or run it
   through `cargo` from source you have read.
2. Do not run *any* unverified third-party binary in that environment — including this
   one. The whole point of the source-available, read-only design is that you don't have
   to.
3. Wormward's scan is read-only; it will not exfiltrate or modify. If you want to confirm
   that for yourself, the scanning surfaces are in `crates/wormward-core` and
   `crates/wormward-packs`, and there is no execution of scanned content anywhere in the
   scan path.

## Supported versions

Wormward is pre-1.0 (`0.1.0`). Security fixes are applied to the latest release and the
`main` branch. There is no support for older tagged versions; upgrade to the latest.

| Version | Supported |
| ------- | --------- |
| latest release / `main` | ✅ |
| older tags | ❌ |

## Reporting a vulnerability

Please report security issues **privately**, not in public issues or pull requests.

- Use GitHub's **private vulnerability reporting** for this repository:
  <https://github.com/0fatihyildiz/wormward/security/advisories/new>
  (repo **Security** tab → **Report a vulnerability**).

Please include:

- affected component (`wormward-core`, `wormward-packs`, `wormward-cli`,
  `wormward-doctor`, `wormward-github`, the desktop app, or the CI Action),
- version or commit SHA,
- a minimal reproduction, and
- the impact you observed (e.g. a false negative that lets a known campaign through, a
  false positive, or any way the tool could write/execute outside its documented,
  opt-in surfaces).

We aim to acknowledge reports within a few days and to coordinate disclosure once a fix
or mitigation is available. Reports about **detection gaps** (a worm variant Wormward
misses) are as welcome as reports about the tool's own safety.

## Hardening roadmap

Progress on Wormward's own supply-chain posture, so that prebuilt artifacts become
independently verifiable:

- [x] SHA-256 checksums for CLI release binaries.
- [x] Build-provenance attestation for CLI release binaries (`gh attestation verify`).
- [ ] Extend checksums + provenance to the desktop bundles.
- [ ] Code-sign CLI binaries and sign + notarize desktop bundles.
- [ ] Publish the CLI to crates.io so it can be installed and audited from a trusted
      registry.
- [ ] Publish the IOC / signature packs as versioned data, so third parties can run the
      same detection with their own trusted engine.
