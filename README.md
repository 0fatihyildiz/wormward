# Wormward

Detect and remove self-propagating supply-chain malware ("worms") from your
local git repositories. Each campaign (PolinRider, Shai-Hulud, …) ships as a
modular signature pack, so one tool covers the whole family.

> This release focuses on detection. Automated remediation and a desktop GUI
> are on the roadmap.

## Install

```bash
cargo install --path crates/wormward-cli
```

## Usage

```bash
wormward scan ~                 # scan your home directory (read-only)
wormward scan . --format json   # machine-readable output for CI
wormward list-packs             # show bundled campaign packs
```

Exit codes: `0` clean, `1` infections found, `2` error.

## How detection works

For every git repo under the scan root, each active pack checks:
- target config files for content signatures (literal / regex / sha256),
- known dropped artifacts (e.g. `temp_auto_push.bat`),
- `.gitignore` tampering and malicious npm dependencies,
- amended commits in `git reflog` (only when corroborated by another finding),
- an optional campaign-specific analyzer for high-confidence confirmation.

## Contributing a campaign pack

Most worms need only a data file. Add `crates/wormward-packs/src/<id>/pack.yaml`
and register it in `builtin_packs()`. See `polinrider/pack.yaml` for the schema.

## License

MIT
