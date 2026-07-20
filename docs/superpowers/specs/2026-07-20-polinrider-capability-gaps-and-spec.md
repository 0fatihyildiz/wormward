# PolinRider Capability Gap Analysis & Implementation Spec

**Date:** 2026-07-20
**Author:** wormward team
**Status:** Draft for review
**Scope:** Detection, remediation, machine-hygiene, prevention, and delivery capabilities for the PolinRider (DPRK / Contagious-Interview) supply-chain campaign and its merged siblings (TasksJacker, Glassworm, the Axios/BlueNoroff cluster).

---

## 0. How this document was produced

Nineteen independent research agents were run in parallel:

- **1** deep inventory of wormward's current code (file:line census of every PolinRider capability).
- **18** analyses of external open-source PolinRider tools (one per repo, full-fidelity clone + source read), plus a vendor-advisory background sweep (Socket, The Hacker News, Sonatype, Wiz, lazarus.day, OpenSourceMalware).

Every gap claim in §4 was then adversarially re-verified against wormward's actual source before inclusion. IOCs are **confidence-tiered**: `[V]` = vendor-confirmed (Socket / OpenSourceMalware / Sonatype / Wiz / rr-research byte-exact), `[C]` = community-sourced (single-tool or gist, treat as leads), `[X]` = cross-confirmed by ≥2 independent tools.

### Repos surveyed

| Repo | Type | Highest-value contribution |
|---|---|---|
| `OpenSourceMalware/PolinRider` | corpus + scanner + IR guide | Source-of-record IOC catalog; `temp_auto_push.bat` full source; Windows Stage-4 stealer |
| `sam1am/polinrider` | mirror of OSM | Same corpus; documents a real FP (`stamparm/maltrail`) |
| `rr-research/polinrider-analysis` | technical analysis | Full kill chain, XOR keys, blockchain C2, 8 SHA256 hashes, Suricata/Sigma/YARA, exfil IPs |
| `amir-budaychiev/polinrider-detection-examples` | payload corpus | Verbatim injected payload; two-stage decoder internals; long-line + log-based detection |
| `Innovative-VAS/polinrider-cleanup` (v2.0) | cleanup + CI + org-sweep | Read-only never-execute architecture; PR-mode remediation; `.env` untrack; font magic-bytes; SARIF |
| `richkazz/Operation-PolinRider` | Python Docker GitHub Action | GlassWorm/Unicode/Trojan-Source; magic-byte validation; git date-skew; Solana C2; git-filter-repo history rewrite; `$GITHUB_STEP_SUMMARY` |
| `branch8/PolinRiderScanner` | git-archaeology scanner suite | Bare-clone `git grep` all-refs; `git log --all -S` pickaxe HISTORY state; PyPI + Axios; AI-agent-config threats |
| `Saif-Arshad/polinrider-monitor` | Windows GUI scanner | Live process detection; C2 IP-connection check; firewall hardening |
| `Louay24/polinshield` | macOS prevention app | `/etc/hosts` sinkhole; global pre-commit hook; force-push propagation monitor; `ignore-scripts` |
| `sidvekariya510/homebrew-mac-security` | macOS launchd tool | Anti-false-clean (TCC); LaunchAgent baseline-drift; osv-scanner lockfile gate; shell-rc scan; clone-guard |
| `DevAdeelAhmad/polinrider-removal-guide` | methodology | Full manual checklist; trigger-path attribution; keychain-theft correlation; assume-breach rotation |
| `AbdulMoizKhan/polinrider-malware-fix` | fix + YARA + husky | Standalone YARA rule; Husky pre-commit/pre-push enforcement |
| `abdullahranginwala/`, `zer0Tokens/`, `charlie-goldenowl/` | OSM v1.1 bash forks | TasksJacker `.vscode/tasks.json` 2-of-3; asset-decoy `-a` binary grep |
| `theeurbanlegend/polinRiderScanner` | bash + PS + cleanup | v2 variant labelling; force-push cleanup; expanded 7-package list |
| `richkazz` (marketplace mirror) | validation mirror | (identical to primary) |
| `luxodd/global-ci` | CI gate | Tamper-proof `pull_request_target`; committed-tree `git grep HEAD`; `task.allowAutomaticTasks` |

---

## 1. Campaign reference (authoritative)

**PolinRider** is a North-Korea-linked (DPRK) **Contagious Interview** supply-chain campaign. It is **not** a classic npm-token self-publishing worm; its defining behavior is:

1. **Injection** of an obfuscated JS loader appended after `export default` / `module.exports` in build/config files (`postcss.config.mjs` ≈ 62% of hits), hidden behind a 200+ space padding run — or embedded in a fake `.woff2` font, or auto-run via `.vscode/tasks.json` `runOn: folderOpen` → `curl | bash`.
2. **Blockchain dead-drop C2** — the loader reads an encrypted second stage from immutable transaction data on **TRON → Aptos → BSC** (and, in the Glassworm sibling, **Solana Memo**), strips a `3f 2e 3f` header/trailer, XOR-decrypts with an embedded key, and `eval()`s it.
3. **Stage-4 stealer** (BeaverTail / DEV#POPPER / OmniStealer) harvests GitHub tokens, SSH keys, `~/.npmrc`, env vars, browser session/wallet data — and **re-injects into `@vscode/deviceid` and `Cursor.app`**.
4. **Self-propagation** via `temp_auto_push.bat`: rewinds the system clock, `git commit --amend --no-verify`, `git push -uf --no-verify` — so the malicious diff appears inside an untouched-looking historical commit. The GitHub **Activity log** (force-push, `size==0`) is the reliable tell, not the commit view.

**Two canonical obfuscator variants** (both load-bearing for detection):

| | v1 (original) | v2 (rotated, Apr 2026) |
|---|---|---|
| marker | `rmcej%otb%` `[V]` | `Cot%3t=shtP` `[V]` |
| decoder fn | `_$_1e42` `[V]` | `MDy` / `function MDy(f)` `[V]` |
| seed L1 / L2 | `2857687` / `2667686` `[V]` | `1111436` / `3896884` `[V]` |
| global key | `global['!']='8-270-2'` `[V]` | `global['_V']='8-st1..8-st59'`, `8-413/683/778/974` `[V]` |
| ESM shim | `global['r']=require`, `global['m']=module`, `createRequire(import.meta.url)`, `Function.constructor("require")` `[V]` | (same) |

**Do NOT conflate** these merged-but-distinct clusters (different IOCs → separate packs):
- **TasksJacker** — Vercel `curl|bash` via `tasks.json`, StakingGame/ShoeVista interview templates.
- **Glassworm** — invisible-Unicode (variation selectors `U+FE00–FE0F`, `U+E0100–E01EF`) obfuscation, **Solana Memo** C2, `eval(Buffer.from(...))` decoder.
- **Axios/BlueNoroff** (2026-03-31) — `axios@1.14.1/0.30.4`, C2 `142.11.206.73`, XOR key `OrDeR_7077`, `/tmp/ld.py` RAT.

---

## 2. Master IOC catalog (consolidated) — wormward coverage column

Legend: ✅ present · ⚠️ partial/generic · ❌ missing. "Generic" = caught by the structural analyzer or capability engine without an enumerated literal (still fires, but not a named signature).

### 2.1 Obfuscation markers / decoders / seeds

| IOC | Conf | wormward | Notes |
|---|---|---|---|
| `("rmcej%otb%",2857687)` | V | ✅ `pack.yaml:39` primary | |
| `global['!']='8-270-2';var _$_1e42=` | V | ✅ `pack.yaml:42` secondary | |
| `Cot%3t=shtP` | V | ✅ `pack.yaml:45` variant-april | |
| `_$_1e42` / `_\$_[0-9a-f]{4,}` | V | ✅ `pack.yaml:48,73` + analyzer | |
| `MDy` decoder | V | ⚠️ analyzer `strong_decoder` only (`analyzer.rs:42`); not a named pack signature | keep |
| seeds `2667686`,`1111436`,`3896884` | V | ⚠️ analyzer `seed_re \b\d{6,7}\b` catches generically | **add as named seeds** |
| seeds `4573868`,`4289487`,`1884551`,`219896`,`6626290` | V (rr) | ⚠️ generic seed_re | **add (variant enumeration)** |
| `global['_V']`, `global['r']=require`, `global['m']=module` | V | ⚠️ analyzer `marker_re` (`analyzer.rs:6`) catches | keep |
| `String.fromCharCode(127)` | V | ✅ analyzer `strong_decoder` (`analyzer.rs:43`) | |
| `createRequire(import.meta.url)` shim | V | ✅ analyzer `has_shim` (`analyzer.rs:49`) | |
| `Function.constructor("require")` | V | ❌ | **add to analyzer shim set** |
| staged entrypoints `Tgw(2509)`, `nWk(9608)` | X | ❌ | low value (per-build); optional |
| XOR keys `2[gWfGj;<:-93Z^C`, `m6:tTh^D)cBz?NM]` | V | ✅ `pack.yaml:51,54` | |
| ciphertext framing `3f 2e 3f` | V (rr) | ❌ | optional; only visible in decrypted intel |

### 2.2 Blockchain / network C2

| IOC | Conf | wormward | Notes |
|---|---|---|---|
| TRON `TMfKQEd7…`, `TXfxHUet9…` | V | ✅ `pack.yaml:57,60` | |
| TRON `TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v`, `TLmj13VL4p6NQ7jpxz8d9uYY6FUKCYatSe` | V/C | ❌ | **add** |
| Aptos `0xbe037…`, `0x3f0e…` | V | ✅ `pack.yaml:63,66` | |
| RPC hosts trongrid/aptoslabs/bsc-dataseed | V | ⚠️ `on_chain_resolve` regex (`capability.rs:197`) | fine |
| `bsc-rpc.publicnode.com`, `bsc-dataseed1.bnbchain.org` | V | ⚠️ partial | **add to regex/domains** |
| **Solana** `api.mainnet-beta.solana.com`, `MemoSq4gq`, `aptos-mainnet.nodereal` | V (richkazz) | ❌ | **add — Solana chain missing** |
| exfil IP `23.27.20.187` | (existing) | ✅ `pack.yaml:75` | |
| exfil IP `136.0.9.8`, `166.88.54.158` | V (rr, OSM IR) | ❌ | **add — primary Evoxt exfil servers** |
| Telegram exfil `api.telegram.org`, `149.154.160.0/20` | V (OSM IR) | ❌ | **add (Stage-4)** |
| community 20-IP list (166.88.4.2, 136.0.9.8, 45.140.184.41, …) | C | ❌ | **add behind `--online`/opt-in only** |

### 2.3 HTTP C2 domains (TasksJacker)

| IOC | Conf | wormward |
|---|---|---|
| `default-configuration.vercel.app` (≈106 refs), `260120.vercel.app`, `vscode-settings-bootstrap/config`, `vscode-bootstrapper`, `vscode-load-config.vercel.app` | V | ✅ `pack.yaml:108-114` (6 domains) |
| `auth-con-firm.vercel.app`, `auth-rho-dun.vercel.app` | V (Louay24) | ❌ **add** |
| `coingecko-liard`, `chalk-logger`, `cloudflare-protection`, `locate-my-ip.vercel.app` | V (vendor) | ❌ **add** |
| `sfrclak.com`, `callnrwise.com` | C (branch8) | ❌ **add [C]** |
| URL shape `…vercel.app/settings/(mac\|linux\|win)?flag=N` | V | ⚠️ domains only — **add as regex** |
| base64 C2 `aHR0cHM6Ly9hdXRoLWNvbi1maXJt…` | V (Louay24) | ❌ **add** |

### 2.4 Malicious packages (cross-ecosystem)

| IOC | Conf | wormward |
|---|---|---|
| npm: `tailwindcss-style-animate@1.1.6`, `tailwind-mainanimation`, `tailwind-autoanimation`, `tailwind-animationbased`, `tailwindcss-typography-style`, `tailwindcss-style-modify`, `tailwindcss-animate-style` | V | ✅ `pack.yaml:99-106` (7, no versions) |
| npm `tailwind-stylecss` (8th) | X (sidvekariya) | ❌ **add** |
| npm `@common-stack/generate-plugin@9.0.2-alpha.21/22` (Sonatype-2026-003277) | V | ❌ **add** |
| npm graph*/bigmath* cluster, `plain-crypto-js@4.2.1` | C (branch8) | ❌ **add [C]** |
| **PyPI** graph*/bignum* cluster | C (branch8) | ❌ **new ecosystem** |
| **Packagist** `thiio/kubernetes-php-sdk`, `sevenspan/*`, `roberts/leads`, … (10) | V (Rescana) | ❌ **new ecosystem** |
| **Go** modules (~61–80) | V (THN) | ❌ **new ecosystem** |
| package versions (not just names) | V | ❌ — **detection is name-only; add version-aware lockfile gate** |

### 2.5 Artifacts / templates / triggers

| IOC | Conf | wormward |
|---|---|---|
| `temp_auto_push.bat`, `config.bat` | V | ✅ `pack.yaml:90-94` |
| `temp_interactive_push.bat`, `branch_structure.json` | X | ❌ **add** |
| `.bat` content `LAST_COMMIT_DATE`/`--amend`/`git push -uf`/`--no-verify` | V | ⚠️ propagation capability (`capability.rs:169`) catches the git-behavior shape | keep |
| `.gitignore` injects `config.bat` | V | ✅ `pack.yaml:96` |
| `.gitignore` injects `temp_auto_push.bat`, `temp_interactive_push.bat`, `branch_structure.json` | X | ❌ **add** |
| StakingGame UUID `e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9` | V | ✅ `pack.yaml:69` |
| ShoeVista names (`shoevista`, `Test-west-shoe`, `Test-002`, `product-catalog`, `mern-app`, pkg name `"client"`) | V | ❌ **add repo/template heuristic** |
| `.vscode/tasks.json` `runOn:folderOpen` | V | ✅ TasksJson surface (`surface.rs`) + gate |
| `.vscode/settings.json` `task.allowAutomaticTasks:true` | V (luxodd) | ❌ **add second VS Code auto-run vector** |
| fake-font names `fa-solid-400.woff2`, font strings `BlockchainFont`,`TechMono` | X | ❌ — pack deliberately excludes `.woff2` (`pack.yaml:9-11`); revisit via magic-byte detector (§5.2) |
| macOS persistence `com.bablu.helper.plist` (trgrip) | V (vendor) | ❌ **add (doctor)** |
| Stage-4 staging `%USERPROFILE%\.npm\{user}${host}_{ts}\` + `ext/login/login-db/spf/firefox`, `_credentials.json`, lock `tmp7A863DD1.tmp` | V (OSM IR) | ❌ Windows-only; optional doctor-win |

---

## 3. Capability comparison matrix (wormward vs. the field)

| Capability | wormward today | Best external exemplar | Verdict |
|---|---|---|---|
| Structural/variant-agnostic confirmation | ✅ analyzer (marker+decoder+seed, FP-safe) | branch8 (grep+`git show` compound) | **wormward leads** |
| Capability/behavioral engine (13 detectors, surface-aware gate) | ✅ `capability.rs` | (none — all others are literal grep) | **wormward unique** |
| FP-safety discipline | ✅ (shim-only, entropy 7.0, `.woff2` excluded) | OSM admits FPs (maltrail, self) | **wormward leads** |
| Literal IOC breadth | ⚠️ solid but stale in spots | OSM/sidvekariya | gap §5.1 |
| `.woff2`/binary magic-byte disguise | ⚠️ token-only `magic_mismatch` | Innovative-VAS, richkazz | gap §5.2 |
| Invisible-Unicode / Glassworm | ❌ | richkazz | gap §5.3 |
| git author/committer date-skew | ❌ | richkazz | gap §5.3 |
| Full git-history pickaxe (`log --all -S`) | ❌ (tips only) | branch8 | gap §5.4 |
| Lockfile / cross-ecosystem packages | ❌ (npm `package.json` only) | branch8, sidvekariya (osv) | gap §5.4 |
| Auto-clean malicious `tasks.json` / `.env` untrack | ❌ | Innovative-VAS | gap §5.5 |
| git-history rewrite (filter-repo) | ❌ (tips/worktree only) | richkazz | gap §5.5 |
| PR-mode remediation (respect branch protection) | ❌ (direct force-push) | Innovative-VAS | gap §5.5 |
| Machine hygiene: process scan | ✅ doctor | Saif-Arshad, sidvekariya | parity |
| Machine hygiene: cache coverage | ⚠️ 2 dirs only | sidvekariya, removal-guide | gap §5.6 |
| Machine hygiene: launchd/cron/persistence | ❌ | sidvekariya, branch8 | gap §5.6 |
| Machine hygiene: live C2 net-connection check | ❌ | Saif-Arshad, sidvekariya | gap §5.6 |
| Machine hygiene: keychain-theft, global npm, shell-rc | ❌ | removal-guide, sidvekariya | gap §5.6 |
| Anti-false-clean (unreadable-root refusal) | ❌ | sidvekariya | gap §5.6 |
| Prevention: `ignore-scripts` hardening | ✅ doctor `fix_triggers` | Louay24 | parity |
| Prevention: `/etc/hosts` sinkhole, pre-commit hook, force-push monitor | ❌ | Louay24 | gap §5.7 |
| Delivery: GitHub Action / CI gate | ❌ (CLI only) | richkazz, luxodd, Innovative-VAS | gap §5.8 |
| Delivery: SARIF | ❌ | Innovative-VAS, richkazz | gap §5.8 |
| Rule export: YARA / Suricata / Sigma | ❌ | rr-research, AbdulMoiz | gap §5.8 |
| Own-operation git hardening (hooks off, no-verify, `GIT_CONFIG_NOSYSTEM`) | ⚠️ verify | Innovative-VAS | gap §5.8 |
| Victim-hunting via code search (`fork:true`) | ❌ | OSM/sam1am | out of scope (§6) |

**Headline:** wormward's *detection engine* is ahead of every tool surveyed. The gaps are in **coverage breadth, git-history depth, machine hygiene, prevention, and packaging/integration** — not in the core detector.

---

## 4. Gap list (prioritized)

Each gap: **evidence** (which tools), **wormward state** (verified against code), **impact**.

### P0 — correctness / coverage holes that let a real infection pass or a clean-claim lie

- **G1. Full git-history blind spot.** wormward deep-scans only branch/remote **tips** (`scanner.rs` `deep_scan_repo` / `branch_commits`). The malware's `temp_auto_push.bat` rewrites history and force-pushes; a payload committed then scrubbed from the tip (branch8's `HISTORY` state) is invisible. *Evidence: branch8 `git log --all -S`.*
- **G2. Lockfile / installed-dependency blind spot.** Malicious-package detection reads only `package.json` `"name"` occurrences (`scanner.rs:106-134`); `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` and `node_modules/<pkg>` are not gated. The campaign *ships inside deps* (`@common-stack/generate-plugin`, hijacked). *Evidence: sidvekariya (osv-scanner), branch8, vendor.*
- **G3. Stale/narrow IOC set.** Missing primary exfil IPs (`136.0.9.8`, `166.88.54.158`), Solana C2, TRON wallets #3/#4, `@common-stack/generate-plugin`, 8th package, new Vercel domains, and cross-ecosystem (PyPI/Composer/Go) packages. *Evidence: rr-research, OSM, vendor, branch8, sidvekariya.*
- **G4. `doctor` can silently false-clean.** No refusal when scan roots are unreadable (TCC / permissions). *Evidence: sidvekariya A0.* And cache coverage is 2 dirs only (`~/.npm/_npx`, TS cache) — misses pnpm store, yarn, global node_modules where the dropper lives.

### P1 — high-value detections wormward entirely lacks

- **G5. Invisible-Unicode / Trojan-Source / Glassworm.** No detection of variation selectors, bidi overrides (U+202E), zero-width chars, or the Solana-Memo Glassworm sibling. *Evidence: richkazz.*
- **G6. git date-skew forensics.** No author/committer timestamp-gap detector to catch clock-rewound amended commits (the highest-confidence residual of `temp_auto_push.bat`). *Evidence: richkazz.*
- **G7. Machine-hygiene depth (doctor).** No launchd/LaunchDaemons/cron/systemd persistence scan, no live C2 network-connection check (`lsof`/`netstat`), no keychain-theft process correlation, no global-npm-package scan, no shell-rc injection scan. *Evidence: sidvekariya, Saif-Arshad, removal-guide, branch8, Louay24.*
- **G8. `.vscode/tasks.json` / `.env` not auto-remediable.** A confirmed malicious `tasks.json` is a Capability finding (`remediable:false`); `.env` re-protection / untrack is absent. *Evidence: Innovative-VAS.*

### P2 — prevention & delivery (new surface area, high leverage)

- **G9. No prevention layer.** No `/etc/hosts` C2 sinkhole, no global git pre-commit hook installer, no force-push propagation monitor. (Note: `ignore-scripts` hardening already exists in `doctor fix_triggers` — good.) *Evidence: Louay24, AbdulMoiz.*
- **G10. No CI / GitHub Action packaging.** wormward is CLI-only; three tools ship a CI gate (tamper-proof `pull_request_target`, `$GITHUB_STEP_SUMMARY`, exit-code gating, negative-control regression test). *Evidence: richkazz, luxodd, Innovative-VAS.*
- **G11. No SARIF, no rule export.** No SARIF for the GitHub Security tab; no YARA/Suricata/Sigma emission for teams that consume rules, not a binary. *Evidence: Innovative-VAS, rr-research, AbdulMoiz.*
- **G12. Remediation delivery is force-push-only.** No PR mode that respects branch protection; no full-history rewrite (`git-filter-repo`) for the enterprise-recovery case. *Evidence: Innovative-VAS, richkazz.*

### P3 — hardening, breadth, and siblings

- **G13. Binary magic-byte validation.** `magic_mismatch` only greps JS tokens; add real font/image signature + printable-ratio validation so `.woff2` decoys can be flagged FP-safely (unblocks the deliberately-excluded font vector). *Evidence: Innovative-VAS, richkazz.*
- **G14. Own-operation git hardening.** Ensure wormward's own clone/commit path runs with hooks disabled, `--no-verify`, `GIT_CONFIG_NOSYSTEM`, `GIT_TERMINAL_PROMPT=0` (Innovative-VAS's safe-exec model) so a scanned repo can't execute code during remediation.
- **G15. Sibling campaigns as packs.** Glassworm (Unicode/Solana) and Axios/BlueNoroff (`axios@1.14.1/0.30.4`, `142.11.206.73`, `/tmp/ld.py`) as first-class packs, kept structurally separate from PolinRider.
- **G16. AI-agent-config threats.** Prompt-injection / credential-exfil in `.claude`/`.cursor` configs. *Evidence: branch8.* (Speculative for this campaign; low priority.)
- **G17. Log-based behavioral detection.** Optional scan of shell histories / `auth.log` for `git --amend` + force-push + encoded PowerShell. *Evidence: amir.* (Low priority.)

---

## 5. The spec (implementation design, per area)

All work is **TDD** (RED→GREEN) and must preserve wormward's **FP-safety** posture: every new literal IOC ships with a clean-corpus regression assertion, and any new heuristic must justify its false-positive story (the campaign's own tooling FP'd on `stamparm/maltrail` and self-flagged — the cautionary baseline).

### 5.1 Detection pack — IOC refresh & multi-ecosystem (G3)

**Goal:** bring the literal catalog current and version/ecosystem-aware without weakening FP-safety.

**Design:**
- Extend `crates/wormward-packs/src/polinrider/pack.yaml`:
  - `content_signatures`: add named seeds (`2667686`, `1111436`, `3896884`, `4573868`, `4289487`, `1884551`, `219896`, `6626290`), the exfil IPs (`136.0.9.8`, `166.88.54.158`), Solana strings, the URL-shape regex `…vercel.app/settings/(mac|linux|win)?flag=`, and the base64 C2.
  - `ioc_domains`: add `auth-con-firm`, `auth-rho-dun`, `coingecko-liard`, `chalk-logger`, `cloudflare-protection`, `locate-my-ip.vercel.app`, `bsc-rpc.publicnode.com`, `bsc-dataseed1.bnbchain.org`, `api.mainnet-beta.solana.com`; `[C]` domains (`sfrclak.com`, `callnrwise.com`) gated behind a `confidence: community` field so `scan` can suppress them by default.
  - `artifacts`: add `temp_interactive_push.bat`, `branch_structure.json`; `gitignore_injections`: add all three.
  - `c2_wallets`: add TRON #3/#4.
- **Confidence tiering in the pack schema.** Add an optional `confidence: vendor|community` to each signature; `IocDomain`/community IPs stay Medium and non-remediable, and `scan` gets `--include-community` (default off) so leads never cause a hard "infected" verdict. This is the mechanism that keeps the 20-IP gist list *available* without eroding precision.
- **Cross-ecosystem packages.** Generalize `bad_npm_packages` → `bad_packages` keyed by ecosystem:
  ```yaml
  bad_packages:
    npm:    [ {name: tailwindcss-style-animate, versions: ["1.1.6"]}, {name: "@common-stack/generate-plugin", versions: ["9.0.2-alpha.21","9.0.2-alpha.22"]}, ... ]
    pypi:   [ ... ]
    composer: [ thiio/kubernetes-php-sdk, sevenspan/*, ... ]
    go:     [ ... ]
  ```
  `versions: []` = any version (name-only, current behavior). This is the schema G2 depends on.

**Tests:** one RED per new signature asserting it fires on a fixture and does **not** fire on the clean corpus; a version-aware test asserting `@common-stack/generate-plugin@9.0.1` is *not* flagged while `@9.0.2-alpha.21` is.

### 5.2 Capability engine — binary magic-byte validation (G13)

**Goal:** flag payload-carrying fake fonts/images FP-safely, unblocking the currently-excluded `.woff2` vector.

**Design:** In `capability.rs`, upgrade the BinaryAsset path. Add a `FONT_MAGIC`/`IMAGE_MAGIC` table (`wOF2`, `wOFF`, `OTTO`, `\x00\x01\x00\x00`, `\x89PNG`, `\xFF\xD8\xFF`, …). New detector `magic_invalid`: a `BinaryAsset` whose extension implies a magic that its first bytes don't match **and** whose printable-ratio > 0.75 **and** which contains a `js_tokens_re` hit → fire. Keep the existing token-only path as a weaker signal. Gate stays: BinaryAsset fires on `magic_mismatch || magic_invalid`. Because this requires *both* an invalid magic and embedded code, a legitimate `fa-solid-400.woff2` (valid `wOF2` magic) never trips — resolving the FP concern that caused `pack.yaml:9-11` to exclude fonts.

**Tests:** RED: a `.woff2` with `wOF2` magic + normal binary body → no finding; a `.woff2` with text/`global[` body and no magic → critical finding.

### 5.3 Capability engine — Unicode stego + git date-skew (G5, G6)

**Unicode detector (new `unicode_stego` in `capability.rs`):** flag any file whose text contains chars in `[U+200B–U+200F]`, `[U+202A–U+202E]`, `[U+2060–U+206F]`, `[U+FE00–U+FE0F]`, `[U+E0100–U+E01EF]`, or `[U+E000–U+F8FF]`, with richkazz's **emoji/keycap allowlist** (ZWJ between `So`/`Sk`, variation selectors after symbols/digits+`U+20E3`) to kill the obvious FPs. This is the **Glassworm** detector; it feeds a separate `glassworm` pack (§5.9), not PolinRider.

**git date-skew (new signal in `scanner.rs` deep path):** for each commit tree scanned, compare author vs committer time; `abs(delta) > 24h` → Medium `GitDateSkew` finding ("committer/author timestamp gap, consistent with clock-rewound `--amend`"). Pairs with the existing reflog-amend heuristic. Non-remediable, corroborating.

**Tests:** RED per Unicode range + an emoji-allowlist negative; RED for a fixture repo with a 48h author/committer skew.

### 5.4 Scanning scope — history pickaxe + lockfiles (G1, G2)

**Git-history pickaxe (`scanner.rs`):** add an opt-in `--history` (and GitHub `--deep-history`) that runs, per repo, the branch8 model:
- `git log --all -S <marker>` for each pack marker → collect `hash|date|author|email|subject`.
- Emit a distinct `HistoryHit` finding kind (Medium, non-remediable, `git_ref = <commit>`), rendered as a separate "past-infection (reachable via checkout)" section — never conflated with a live working-tree finding.
- Reuse the persistent `git cat-file --batch` reader already in `repo_files.rs` for blob confirmation (compound: grep candidate → structural analyzer on the blob) to stay FP-safe.
- **Bounded:** cap commits examined; `log()`-equivalent surface what was truncated (no silent cap). Reflog *content* / stash / dangling-object scanning remain explicitly out of scope for v1 (documented; branch8 also skips them). Note wormward already has a narrow reflog *amend-existence* heuristic (`git.rs` `reflog_has_amend` → corroborating `GitReflog` finding, `scanner.rs:522`); `--history` adds per-commit **content** scanning, which that heuristic does not do.

**Lockfile & dependency gate (`scanner.rs`):**
- Parse `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` and match `bad_packages.npm` name+version (the §5.1 schema). Add `pypi`/`composer`/`go` lockfiles (`poetry.lock`, `Pipfile.lock`, `composer.lock`, `go.sum`) behind the same table.
- Optionally scan `node_modules/<pkg>/package.json` + entrypoint (`src/index.js`) for the appended payload (the campaign injects there), reusing the analyzer — but keep `node_modules` file-walk pruning for everything else (perf).
- **Optional osv-scanner bridge** (sidvekariya's idea): if `osv-scanner` is on PATH, offer `--osv` to gate lockfiles against Google OSV `MAL-*` advisories. Additive, not required.

**Tests:** RED: fixture repo clean at tip but with an infected historical commit → `HistoryHit` only under `--history`. RED: `pnpm-lock.yaml` pinning `@common-stack/generate-plugin@9.0.2-alpha.21` → flagged.

### 5.5 Remediation — tasks.json / .env / PR-mode / history-rewrite (G8, G12)

- **Auto-clean `.vscode/tasks.json`:** make a confirmed-malicious `tasks.json` remediable. Add `RemediationAction::DeleteFile` wiring for TasksJson **when** the folderOpen+download-exec gate confirmed it (mirror Innovative-VAS's whole-`.vscode`-dir removal only when a member is malicious). Backup first (existing `.wormward-backup` flow).
- **`.gitignore`/`.env` hygiene** (Innovative-VAS): add `hardenGitignore`-style action — remove injected artifact lines (already partially done) **and** re-add missing `.env*` patterns; `untrackEnv` runs `git rm --cached` on tracked `.env*`. New `RemediationAction::HardenGitignore` + `UntrackPath`.
- **PR-mode delivery** (`wormward-github`): add `--pr` as an alternative to the current direct force-push (`fix_scanned`). Create `wormward/remediate-<ts>` branch, commit, push, `gh pr create --label security` (retry without label if absent), respect branch protection (leave blocked PRs open + reported — never bypass). Keep force-push behind explicit `--push` as today.
- **Full-history rewrite (enterprise recovery, guarded):** a `wormward clean --rewrite-history` that shells `git filter-repo` (if present) with a blob callback stripping payload lines + Unicode ranges, operating on a `--mirror` clone, `--dry-run` default, mandatory backup ref. High-blast-radius → gated behind `--yes` + a printed warning; documented as last-resort. (richkazz `surgical-clean.py` is the reference.)

**Tests:** RED: infected `tasks.json` → deleted + backed up; committed `.env` tracked → untracked, `.gitignore` re-hardened; PR-mode on a branch-protected repo → PR opened, no force-push.

### 5.6 `doctor` — machine hygiene depth + anti-false-clean (G4, G7)

Extend `crates/wormward-doctor/src/lib.rs`:

- **Anti-false-clean:** before certifying clean, verify each scan root is readable (the `ls` vs `ls -d` TCC distinction on macOS). Unreadable root → `DoctorReport` gains an `Unscanned { path, reason }` state; `has_findings()`/exit is non-zero. Never print "clean" over an unreadable root.
- **Cache coverage:** expand `cache_targets()` to pnpm store (`~/Library/pnpm`, `~/.local/share/pnpm`, `$PNPM_HOME`), yarn cache (`~/Library/Caches/Yarn`, `~/.cache/yarn`), general `~/.npm`, `~/.node-gyp`, and global `node_modules` (`/opt/homebrew/lib/node_modules`, `npm root -g`). Same bounded fingerprint scan.
- **Persistence scan:** diff `~/Library/LaunchAgents` + `/Library/LaunchAgents` + `/Library/LaunchDaemons` against a first-run baseline; grep new/changed plists (and `crontab -l`, `~/.config/systemd`) for `polinrider|openclaw|claw|node -e|curl.*\|.*sh` and for `polinrider_fingerprint`. Emit `PersistenceHit`.
- **Live C2 check:** `lsof -nP -iTCP` / `netstat -an` → match established connections against the pack's C2 IPs/hosts → `NetworkHit`. (Read-only; no firewall changes in `doctor` — see §5.7 for prevention.)
- **Keychain-theft correlation:** flag processes matching `find-internet-password.*github` and (macOS) surface the recurring `github.com` keychain-access pattern as advisory. `security find-internet-password` is read-only.
- **Global npm & editor extensions:** `npm ls -g --depth=0` (+ pnpm) matched against `bad_packages`; scan VS Code/Cursor extension dirs and the known re-injection targets (`@vscode/deviceid/dist/index.js`, `Cursor.app/Contents/Resources/app`) with the analyzer.
- **Shell-rc injection:** scan `~/.zshrc`,`.bashrc`,`.bash_profile`,`.profile`,`.zshenv` for `curl.*\|.*sh`, `eval.*\$\(.*base64`, `nc -e`, `/tmp/.*\.(sh|js)` → `ShellRcHit`.

All new checks are read-only and additive to `DoctorReport`. `--fix` continues to only touch caches + `ignore-scripts` (persistence/keychain remain advisory — surfacing, not auto-deleting launchd/keychain entries).

**Tests:** unit tests over synthetic `ps`/`lsof`/plist/`.zshrc` fixtures (the existing `scan_process_lines` test pattern); an unreadable-root test asserting non-zero exit + `Unscanned`.

### 5.7 Prevention (new `wormward harden` subcommand) (G9)

**Goal:** stop/monitor infection before and during spread — the posture Louay24 demonstrates that wormward lacks.

**Design:** new `wormward harden` with opt-in, individually-revertible actions (each prints exactly what it will change; `--dry-run` default):
- `--ignore-scripts` — reuse `doctor fix_triggers` (npm+pnpm global `ignore-scripts=true`).
- `--hosts-sinkhole` — append `0.0.0.0 <C2 domain>` for the pack's vendor-confirmed C2 domains to `/etc/hosts` (sudo; idempotent, clearly-delimited block, `--unharden` removes it). Community domains excluded by default.
- `--pre-commit-hook` — install a global `core.hooksPath` pre-commit that greps staged files against pack markers + forbidden filenames + staged `.env` and exits non-zero (Louay24/AbdulMoiz model). Documented `--no-verify` bypass caveat.
- `--watch-force-pushes` — poll GitHub Events API for `PushEvent` with `size==0 && before!=head` on your repos (the worm's propagation tell) and report. Lives in `wormward-github`.

Everything reversible via `wormward harden --unharden`. Prevention is **never** applied silently — this is outward-facing machine mutation and stays behind explicit flags + confirmation.

**Tests:** hosts-block idempotency (apply twice = one block; `--unharden` removes exactly it); pre-commit hook blocks an infected staged file in a temp repo; force-push watcher parses a synthetic Events payload.

### 5.8 Delivery & integration — Action, SARIF, rules, git-hardening (G10, G11, G14)

- **GitHub Action + CI gate.** Ship `action.yml` (Docker, wraps the existing `wormward` binary) with inputs `path`, `format`, `history`, and a **tamper-proof reusable workflow** modeled on luxodd (`pull_request_target`, separate trusted checkout of the scanner, read-only scan of untrusted PR tree, SHA-pinned actions, `permissions: contents: read`). Exit-code gates the build; write a `$GITHUB_STEP_SUMMARY` table and `$GITHUB_OUTPUT` (`findings-count`, `highest-severity`, `has-findings`). Add a **negative-control** CI step (richkazz) that fails if the bundled vulnerable fixture stops tripping — a detector-regression guard.
- **SARIF output.** Add `--format sarif` to `scan`/`github` so findings land in the GitHub Security tab (Innovative-VAS/richkazz parity). Straight serialization of existing `Finding`s.
- **Rule export.** `wormward export-rules --format yara|sigma|suricata` emitting from the pack catalog: YARA (multi-variant `any of ($marker_*) or (...)` per rr-research/OSM), Sigma (process-creation `node -e` + markers; Sysmon DNS/network for C2), Suricata (outbound to trongrid/aptos/BSC wallets + exfil IPs). Lets rule-consumers use wormward's IOC catalog without the binary. Network rules are export-only — wormward stays a host scanner (no live network sniffing).
- **Own-operation git hardening (G14).** Audit `wormward-github`'s clone/commit/push path; ensure `core.hooksPath=<devnull>`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<devnull>`, `GIT_TERMINAL_PROMPT=0`, and `--no-verify` on commit/push (Innovative-VAS `safe-exec` model) so a malicious scanned repo can't execute a hook during remediation. This is defensive hardening of code we already run.

**Tests:** SARIF schema-validates; `export-rules` YARA compiles (if `yara` available) and matches a v1+v2 fixture; Action smoke test (scan a fixture, assert exit code + step-summary content).

### 5.9 Sibling campaigns as packs (G15)

- **`glassworm` pack** — driven by the §5.3 Unicode detector + Solana Memo C2 (`api.mainnet-beta.solana.com`, `MemoSq4gq`, wallet `G2YxRa…`) + its distinct npm names (`@aifabrix/miso-client`, `react-native-country-select`, …). Structurally separate signatures; **must not** cross-fire with PolinRider (the vendor's explicit warning).
- **`axios-bluenoroff` pack** — `axios@1.14.1/0.30.4`, `plain-crypto-js@4.2.1`, C2 `142.11.206.73`, XOR `OrDeR_7077`, campaign id `6202033`, `/tmp/ld.py`.

Both reuse the existing pack/analyzer/engine machinery; they are additive packs in `crates/wormward-packs/src/`.

---

## 6. Non-goals (explicitly out of scope)

- **Victim-hunting across the public ecosystem** (OSM/sam1am `fork:true` GitHub-code-search enumeration) — wormward scans assets you own/point it at, not the world. Offensive OSINT is a different product.
- **Executing/deobfuscating live payloads** (rr-research's sandbox `charCodeAt` oracle) — wormward is read-only-never-execute by construction; keep it that way.
- **Full EDR** — live process kill, browser-DB forensics, Windows registry/credential-manager IR (OSM Windows guide) beyond read-only surfacing.
- **AI-agent-config prompt-injection scanning (G16)** and **log-based behavioral detection (G17)** — parked as future/low-priority; not this spec.
- **Reflog/stash/dangling-object history scanning** — v1 `--history` covers `--all` refs via pickaxe; deeper object walking is a later increment.

---

## 7. Phasing

| Phase | Gaps | Theme | Rationale |
|---|---|---|---|
| **1** | G3, G1, G2, G4 | Close coverage holes | Highest risk: an infection that passes, or a clean-claim that lies. Pack refresh + history pickaxe + lockfiles + anti-false-clean. |
| **2** | G5, G6, G7, G8 | New detections + hygiene depth | Unicode/date-skew detectors, doctor persistence/network/keychain, tasks.json/.env remediation. |
| **3** | G10, G11, G12 | Delivery & integration | GitHub Action + CI gate, SARIF, rule export, PR-mode/history-rewrite remediation. |
| **4** | G9, G13, G14, G15 | Prevention, hardening, siblings | `wormward harden`, magic-byte validation, own-git hardening, Glassworm/Axios packs. |

Each phase is independently shippable and TDD-gated; each new IOC/heuristic carries a clean-corpus regression.

---

## 8. Open questions for review

1. **Prevention scope (G9):** should `wormward harden` (hosts-sinkhole, global pre-commit hook) ship at all, or is that outside wormward's "scanner" identity? It mutates the machine/repo — arguably a separate posture from detect-and-clean.
2. **Community-IOC policy (G3):** default-suppress `[C]` IOCs (20-IP gist, extra package names) behind `--include-community`, or omit them entirely to protect precision?
3. **History rewrite (G12):** is `git filter-repo` full-history rewrite in-scope, or should wormward stop at tip/worktree/PR remediation and merely *report* historical hits?
4. **Sibling campaigns (G15):** fold Glassworm/Axios into wormward now, or keep this spec PolinRider-only and spin siblings into their own specs?
5. **Cross-ecosystem depth (G2):** how far into PyPI/Composer/Go do we go — full lockfile parity, or npm-first with the others as name-only lists?
6. **osv-scanner bridge (§5.4):** acceptable to add an *optional* external-tool dependency, or keep wormward fully self-contained?
