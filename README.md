# Wormward

Detect, remove, and prevent self-propagating supply-chain malware ("worms") across your local
repositories, your GitHub org, and your dev machine. Each campaign (PolinRider, Shai-Hulud,
Glassworm, Axios/BlueNoroff, …) ships as a modular signature pack, so one tool covers the whole
family — with a behavioral capability engine that catches variants no literal signature knows yet.

**Read-only by default.** `scan`, `doctor`, `github` (without `--fix`), and the CI Action never
execute scanned code and never write to your repos. Cleaning, pushing, and machine hardening are
always explicit, backed up, and dry-run first.

Precision is a first-class goal: every signature is designed not to false-positive on legitimate
code (lockfiles, WASM/Emscripten glue, minified bundles, popular dependencies). See
[docs/superpowers/specs/2026-07-20-wormward-fp-hardening.md](docs/superpowers/specs/2026-07-20-wormward-fp-hardening.md).

## Install

**CLI from source:**
```bash
cargo install --path crates/wormward-cli
# or: cargo build --release -p wormward-cli   →   target/release/wormward
```

**Prebuilt binaries & desktop app:** the [Releases](https://github.com/0fatihyildiz/wormward/releases)
page — CLI binaries (macOS / Linux / Windows) and desktop bundles (`.dmg` / `.msi` / `.AppImage`).

**Desktop app (Tauri + Svelte) from source:**
```bash
cd apps/desktop && pnpm install && pnpm tauri build   # or: pnpm tauri dev
```

## Scan

```bash
wormward scan ~                     # scan every git repo under your home dir (read-only)
wormward scan .                     # scan the current project
wormward scan . --format json       # machine-readable output for CI
wormward scan . --format sarif      # SARIF 2.1.0 for the GitHub Security tab
wormward scan ~ --deep              # also scan every branch tip (worms hide on non-default branches)
wormward scan ~ --history           # also pickaxe full git history for scrubbed-but-reachable payloads
wormward scan . --osv               # also gate lockfiles via `osv-scanner` (if installed)
wormward scan . --include-community # include lower-confidence community IOC leads (off by default)
```

Exit codes: `0` clean, `1` infections found, `2` error. A single scan covers:

- **content signatures** (literal / regex / sha256) on target config/entry files,
- a **capability engine** — value-independent behavioral detectors (obfuscation, credential access,
  network egress, process spawn, on-chain C2 resolution, self-propagation, download-and-exec,
  invisible-Unicode / Trojan-Source stego, fake-asset magic-byte mismatch, …) with a surface-aware
  gate, so **new variants** are caught without a literal signature,
- a campaign **analyzer** for high-confidence, variant-agnostic confirmation,
- **lockfiles** (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `composer.lock`, `go.sum`,
  Pipfile.lock, requirements.txt) matched **version-aware** against known-malicious packages,
- **`node_modules`** dependency entrypoints (the malware ships inside installed deps),
- dropped artifacts (`temp_auto_push.bat`), `.gitignore` tampering, and — with `--history` — git
  **author/committer date-skew** (anti-dated / clock-rewound commits).

`--deep` is diff-based: each branch tip is scanned only for what it changes vs HEAD (content shared
with HEAD is covered by the working-tree pass), so it stays fast and low-heat even on many-branch repos.

## Clean

```bash
wormward clean .                              # preview removals (dry-run)
wormward clean . --apply                      # strip payloads, delete artifacts, fix .gitignore (backup on)
wormward clean . --apply --all-branches --yes # also clean infected tips of other branches (via worktrees)
wormward clean . --apply --push --yes         # + commit and push the cleaned state
wormward clean . --apply --push --rewrite --yes        # + amend HEAD and force-with-lease (DANGEROUS)
wormward clean . --rewrite-history --yes      # rewrite ALL git history (git-filter-repo) to redact
                                              #   injection markers — for a committed-then-force-pushed
                                              #   payload. Dry-run unless --yes; tags a backup ref.
wormward restore .                            # revert the last clean from backup
```

Remediation is surgical (strip the appended payload, keep the legit config), always backed up to
`.wormward-backup/`, and verified after stripping (a residual re-flags rather than silently passing).

## Scan GitHub (org / account)

```bash
wormward github                        # scan every repo you own or belong to (clone-free, via the API)
wormward github --org my-org           # restrict to an org
wormward github --audit                # + read-only account-persistence audit (token scopes, SSH/GPG
                                       #   keys, app installs, per-repo webhooks/deploy-keys/runners)
wormward github --fix --push --yes     # remediate infected default branches (backs up, verifies, pushes)
```

Scans every branch tip clone-free through the GitHub API; a truncated (very large) tree falls back to
a local clone. Own git operations are hardened (hooks disabled, `--no-verify`, `GIT_CONFIG_NOSYSTEM`)
so a malicious scanned repo can't execute a hook during remediation. A push is gated behind the
account audit (fail-closed until you `--i-rotated`).

## Machine check (`doctor`)

Complements the repo scan by looking at the *machine* — read-only, macOS-first:

```bash
wormward doctor                 # running loader processes, tainted toolchain caches, trigger paths,
                                #   persistence (launchd/cron), live C2 connections, shell-rc injection,
                                #   globally-installed malicious packages, keychain-theft activity
wormward doctor --watch 180     # poll for 3 min to catch a loader that only respawns on a trigger
wormward doctor --fix           # clear tainted caches + set npm/pnpm ignore-scripts=true
wormward doctor --osv           # also gate discovered lockfiles against OSV
```

`doctor` fails closed: if a scan root exists but can't be read (macOS Full Disk Access / TCC), it
reports an **unscanned** blind spot rather than certifying "clean."

## Prevent (`harden`)

```bash
wormward harden                 # dry-run: show what would be hardened
wormward harden --apply         # install a global pre-commit guard + set npm/pnpm ignore-scripts
```

`harden` makes only safe, user-local changes automatically; system/global steps (a `/etc/hosts` C2
sinkhole, enabling the global hooks path) are **printed for you to run**, never executed silently.

## Export detection rules

Consume wormward's IOC catalog in your own pipeline instead of running the binary:

```bash
wormward export-rules --format yara      > wormward.yar
wormward export-rules --format sigma     > wormward.sigma.yml
wormward export-rules --format suricata  > wormward.rules
```

## CI integration

Ship the read-only scan as a GitHub Action that fails the build on findings and uploads SARIF. It is
safe on untrusted pull requests (never executes scanned code; the scanner comes from a pinned trusted
ref, not the PR). See [docs/ci-integration.md](docs/ci-integration.md).

## Online verification (opt-in)

Cross-check findings against the live OpenSourceMalware database (needs a free `OSM_API_KEY`):

```bash
export OSM_API_KEY=osm_...
wormward scan ~ --online                            # enrich npm/domain findings with live OSM data
wormward check --type package --ecosystem npm left-pad
```

Opt-in only: without `--online` nothing leaves your machine, and even then only the npm-package names
and domains your local packs already flagged are sent — nothing else.

## Campaigns covered

`wormward list-packs`

- **PolinRider** — DPRK / Contagious-Interview supply-chain worm: obfuscated JS appended to config
  files, blockchain dead-drop C2 (TRON/Aptos/BSC), `temp_auto_push.bat` history-rewriting
  propagation, cross-ecosystem malicious packages.
- **Shai-Hulud** — npm self-propagating worm (dropper + lifecycle scripts, CI exfil).
- **Glassworm** — invisible-Unicode / Trojan-Source stego with Solana-Memo C2 (kept structurally
  separate from PolinRider; the stego is caught by the capability engine).
- **Axios / BlueNoroff** — specific compromised `axios` versions delivering a Linux RAT (flagged
  strictly by version, never by name).

## Contributing a campaign pack

Most worms need only a data file: add `crates/wormward-packs/src/<id>/pack.yaml` and register it in
`builtin_packs()`. See `polinrider/pack.yaml` for the full schema (target files, content signatures,
version-aware `bad_packages`, artifacts, IOC domains, remediation). Before adding a signature, run
the FP checklist in the hardening spec — a signature that fires on a clean install of a popular
dependency is a bug, and every pack change ships with a clean-corpus regression test.

## Observed infections (PolinRider — GitHub corpus, 2026-07-21)

A detection-development record, not a shame list: most repos below are **victims** whose
build was compromised through a malicious npm dependency. It exists so the algorithm can be
hardened against real variants. Built by a rate-limit-paced, IOC-seeded GitHub code-search
sweep (wormward's own PolinRider IOCs — TRON/Aptos wallets, C2 `*.vercel.app` domains, the
`temp_auto_push.bat`/`config.bat` droppers, the `_$_` decoder, eight malicious `tailwind*`
packages), then a **clone-free** fetch + scan of every matched file.

| Metric | Count |
|---|---:|
| Candidate repos discovered | 1,124 |
| **Confirmed infected** | **761** |
| — by content/structure scan | 642 |
| — by dropper artifact only | 121 |
| Research / IOC-documentation repos (correctly not flagged) | ~360 |

**Version-tag families observed** (`global.X='<family>-…'`). The originally-tracked `5-3-*`
is a *minority* — the family rotates the tag every wave, which is exactly why detection keys
on structure, not the constant:

> `8-270-*`, `8-2699-*`, `8-4163-*`, `9-4365-*`, `9-0674-*`, `9-5607-*`, `9-0479-*`, `9-5334-*`, `9-3690-*`, `9-5536-*`, `9-5682-*`, `9-0016-*`, `9-825-*`, `9-0736-*`, `10-590-*`, `5-3-*`, …
>
> Decoders: `_$_1e42` (dominant), `_$_ccfc`, `_$_2d00`, `_$_abcd` — all caught by the generic `_$_[0-9a-f]{4,}` identifier.

**Algorithm-development finding.** ~14% of infected repos carried the payload ONLY in
non-config source (`server.js`, `routes/*.js`, `Gruntfile.js`, `.prettierrc.mjs`,
controllers) — which the surface-scoped passes missed. This drove the repo-wide structural
pass (`scan_injection_structure`), taking scan-detection from 573 → 643 repos. See
[the FP-hardening spec](docs/superpowers/specs/2026-07-20-wormward-fp-hardening.md).

<details>
<summary><b>Full confirmed-infected repo list (761)</b> — click to expand</summary>

- `16navigabraham/stakely-backend`
- `17ishan/my-portfolio-`
- `AHMED168-ENG/chat-back`
- `AKDebug-UX/whatsapp-bot-master`
- `ALGORYCLLC/openhome-examples`
- `ALPHAMAN-0/Document_Editor`
- `AYAN-SHAH/PORTFOLIO`
- `AYAN-SHAH/healthcare-translate`
- `AYAN-SHAH/syslab-task`
- `Abdelkaderbzz/ramadan-tracker`
- `Abdul-Muneeb-Qureshi/fyp-backend`
- `AbdullahAymanMSRE/e-store`
- `Abdulsadiqsamadani/Event-identify-web`
- `Abhinav-not-found/portfolio`
- `AccumulateNetwork/explorer`
- `Adan-Asim/E-commerce-Admin-App-Backend`
- `Ahmed14z/Ahmed14z` · dropper-only
- `AliHaider3820/AAA_SD_FYP`
- `AllZone-Technologies/canteen-pwa`
- `Am4n-Ull4h/MyBaby6D_NextJS_Project`
- `Aman-scripts/NugenEmployabilityTest`
- `Ameer-Hamza289/AI_Rate_My_Professor`
- `Ammar-Abid92/my-CRUD-api-with-mongo`
- `Anasibnyounis/complete-staffing-solution`
- `Andre1917/challenge`
- `Anshukk687/React-Capacitor-Android`
- `Anshuman-Jha/Toku_Assestment`
- `Anthem-InfoTech-Pvt-Ltd/chat-backend` · dropper-only
- `ArnoldEsquivel/best-city436-poc`
- `ArslanUlfat/custom-gpt`
- `ArturSargsyan1995/Test`
- `ArturSargsyan1995/Test-commit`
- `ArturSargsyan1995/arm-logic`
- `ArturSargsyan1995/cart`
- `ArturSargsyan1995/one-click-hugo-cms`
- `ArturSargsyan1995/stax-tracker2`
- `AslanovRustam/games-tournament`
- `Atik203/VocabPrep`
- `Ayesha-Siddiqui1234/katy-youth-hackathon-2025-dev-post-`
- `AyshaUrmi0/Dev-question`
- `Ayu200git/Ayu200git`
- `AyushG701/production-grade-react-app`
- `BenjaminSetton/PHOENIX` · dropper-only
- `BernardOnuh/Warthug-DB`
- `BernardOnuh/rubic-test1`
- `BigMarketDao/bigmarket-dao`
- `BigMarketDao/bigmarket-mr`
- `Bioconductor/BBS` · dropper-only
- `C0kke/API-NGINX` · dropper-only
- `Cataclypsme/old-web3-project`
- `Chakradharkolipaka/ozonehub_test_assesment`
- `Charles-Abasimfon/fyn-the-fox-web`
- `Chetan1204/Todo-Front-React`
- `ChiraniSiriwardhana/Thumblify-backend`
- `Cogni-Capital-Chain/SociFi-MVP`
- `Computadores-Para-Todos/computers-4-all-manager`
- `CrazyDev13/school-management`
- `Cyber-Advance-Soliution/rtcServer`
- `CyberMarinesTeam/umurava_challenge_frontend`
- `CyberMarinesTeam/vulnerability_checker`
- `DarioKolic/dario-kolic-v2`
- `David1Savitsky/cal-eco-platform`
- `Dawit212119/Devodemy`
- `Dawit212119/LMS`
- `Dawit212119/Natours`
- `Dayones-Live/DayOnes`
- `DbHridoy/Easyrenting` · dropper-only
- `DbHridoy/golf-pro-backend` · dropper-only
- `DbHridoy/nicholas_cook9-backend` · dropper-only
- `Deepanshu7-bit/nugen-interns`
- `Dev-Logic-max/ecommerce-frontend`
- `DevIbrahim07/patient-caregiver-dashboard`
- `DevWizardHQ/laravel-localizer-react`
- `DevWizardHQ/laravel-react-permissions`
- `Devba/W3agregador`
- `Devba/lmng-top-`
- `Devsed-official/Visa-agent`
- `Devsed-official/quba`
- `Dominion116/API-Test`
- `Dominion116/LimboStark`
- `Dominion116/Smile-TEST`
- `Dominion116/Smile-TEST-2`
- `Dominion116/futureblock`
- `Dominion116/my-portfolio`
- `EponymousBearer/backend`
- `FSDTeam-SAA/heart-bridge-dialogue`
- `FSDTeam-SAA/rayb_23-backend`
- `FabrikCreations/fabrik-lightbox`
- `Farhanasharna2000/B7A1` · dropper-only
- `Farhanasharna2000/CampusNest` · dropper-only
- `Farhanasharna2000/FMart` · dropper-only
- `Farhanasharna2000/Farhanasharna2000` · dropper-only
- `Farhanasharna2000/Friendify` · dropper-only
- `Farhanasharna2000/My_Embedded_SDK` · dropper-only
- `Farhanasharna2000/QueryConnect-Backend` · dropper-only
- `Farhanasharna2000/QueryConnect-Frontend` · dropper-only
- `Farhanasharna2000/Real-State` · dropper-only
- `Farhanasharna2000/Typescript-Practice` · dropper-only
- `Farhanasharna2000/redux-nextjs-practice` · dropper-only
- `FlowBondTech/flowb`
- `GARAGE-POS/GarageCustomerAdmin`
- `Goutam245/-Digital-health-brand-`
- `Goutam245/-digital-health-brand`
- `Goutam245/ACS-Modern-Portfolio-Website`
- `Goutam245/ACS-modern-portfolio-website-`
- `Goutam245/AI-Agent`
- `Goutam245/APEX-FUNDED`
- `Goutam245/ASCENDRX-V1`
- `Goutam245/ASCENDRX-Version1`
- `Goutam245/Affiliate-Warehouse`
- `Goutam245/Affiliate-Warehouse-v2`
- `Goutam245/Affiliate-Warehouse1`
- `Goutam245/Affordable-Housing`
- `Goutam245/Aurum-Torino`
- `Goutam245/AutoElite-Torino`
- `Goutam245/Blowbubbles-Academy-`
- `Goutam245/Cloudascent`
- `Goutam245/Container-Fabrication-Website`
- `Goutam245/Container-Fabrication-Website-1`
- `Goutam245/Core-Banking`
- `Goutam245/DarkViolet-Elite`
- `Goutam245/Direct-Bank-Transfer-SWIFT-`
- `Goutam245/Direct-Bank-Transfer-SWIFT--`
- `Goutam245/Dual-E-commerce-Site`
- `Goutam245/Dual-E-commerce-Site-1`
- `Goutam245/Enhance-Winlandia.io`
- `Goutam245/Enhance-Winlandia.io-`
- `Goutam245/Fluid-Network`
- `Goutam245/Fluid-Networks`
- `Goutam245/ForgeWorks-Heavy-Duty-Power-Equipment`
- `Goutam245/Gair-Legal`
- `Goutam245/Gair-Legal-`
- `Goutam245/Gair-Legal-v2`
- `Goutam245/Golden-Key-Car-Rental`
- `Goutam245/Greatvacs.com`
- `Goutam245/Greatvacs.com-`
- `Goutam245/HIG-Hotel`
- `Goutam245/HIG-Property-Management`
- `Goutam245/IndustrialEdge`
- `Goutam245/Lead-Gen-Wall-Padding`
- `Goutam245/Lead-Gen-Wall-Padding-1`
- `Goutam245/My-Simple-AI-Agent`
- `Goutam245/Prominence-Bank`
- `Goutam245/QREW-ONLY-1`
- `Goutam245/QREW-ONLY-2`
- `Goutam245/Reliance-Care`
- `Goutam245/Salem-Standard`
- `Goutam245/Salem-Steamer`
- `Goutam245/ShopMax`
- `Goutam245/Spanish-Dental-Clinic`
- `Goutam245/Spanish-Dental-Clinic-Website`
- `Goutam245/Spotless-Trade`
- `Goutam245/Spotless-Trades`
- `Goutam245/Sullivan-County`
- `Goutam245/Sullivan-County-1`
- `Goutam245/Swift-connect-`
- `Goutam245/SwipePages`
- `Goutam245/SwipePages-1`
- `Goutam245/Transition-Page`
- `Goutam245/crypto-fantasy-sports-game-`
- `Goutam245/fi-trading-platform`
- `Goutam245/hig-gateway-`
- `Goutam245/meganmcgill.studio`
- `Goutam245/oooooooooooo`
- `Goutam245/prominence-connect`
- `Goutam245/prominence-swift-`
- `Goutam245/salem-steamer-`
- `Goutam245/shopify`
- `Groot-Software-Solutions/Flutter-Apps`
- `GrootNet-Software-Solutions-Pvt-Ltd/memory_game`
- `Grzafnan/nest-server`
- `Hamid-javed/E-Learn-Backend`
- `Hammad911/DataVisualizationProject`
- `Hamyal/Career-Assessment` · dropper-only
- `HansLove/PanelRespuestasWhats`
- `Harshitpahuja20/play`
- `Harsimran-Nugen/assignment`
- `HasanAlif/Learning_Practice_JavaScript`
- `Hassam-01/WhiteBoardFrontEnd`
- `Hernny/defiguard-wallet-task`
- `Herrcorps/KonanAgent2`
- `HimanshuJain04/portfolio-2.0`
- `Hriday-paul/anyjob-wellcome`
- `ILhankhondaker/todo`
- `Iambilalfaisal/Acme-One-React`
- `Iambilalfaisal/PM-Dev`
- `Iambilalfaisal/glow-aim-tools`
- `Ianwarzai/cotd_cronjob`
- `Innovative-VAS/polinrider-cleanup`
- `JROB774/runner` · dropper-only
- `James-CodeX/SEO-Blogs`
- `Jaskaran2701/Test-1`
- `JesusCova177/09-Omnifood-Optimizations`
- `JordanCpp/Gtk1` · dropper-only
- `JoshKisb/dhis2-dashboard`
- `Jtobyy/qa-forum`
- `Kairo4-organization/shigud-dapp`
- `KaranChouhan018/arxino`
- `KaranChouhan018/dentsi`
- `KaranChouhan018/todo`
- `KeniKT/machinery_management_system`
- `KeshanWijesinghe/yap-mobile-app`
- `KhizerAhmed1/Vehicle-Management-System` · dropper-only
- `Kreliannn/House-Rental-Platform`
- `Kreliannn/MusicPlayer`
- `Kreliannn/grocery-pos-system`
- `Kreliannn/pharmacy-management-backend`
- `Kreliannn/pharmacy-management-frontend`
- `Kvit-Dm/RammSound`
- `LADSoft/OrangeC` · dropper-only
- `LeshanieM/Lavendra-Photography-Management-System` · dropper-only
- `LeshanieM/Leshanie-Portfolio` · dropper-only
- `LomoX-Offical/nginx-openresty-windows` · dropper-only
- `LuigiClemente/calendar_bookings`
- `MAHIR-DEVES/Helth-care-Backend`
- `MOAIZ-UL-ISLAM/Astro-Portfolio`
- `MOTY12/gacatraning`
- `MTS-Services/asalmiah_nextjs_fixing`
- `MTS-Services/rpr2011_2500_cli` · dropper-only
- `MUGISHA-Pascal/Google-Map-Application`
- `Maham-Liaqat/CricketGame`
- `Mamun-Hossain-dev/agency-server`
- `Mamun-Hossain-dev/clinicallymanic-frontend`
- `Mamun-Hossain-dev/quickCart-ecommerce`
- `Maxima24/synthSentry`
- `MdJowelAhmed/redux-toolkit-query-practice`
- `Meharab/scam-origin`
- `Mike-flowbiz/Flowbiz-backend`
- `MikiW03/algorithms_benchmarking` · dropper-only
- `MohamedAshraf701/node-initdb`
- `Moinuddin-dotcom/Moinuddin-Port-Next`
- `Mr-Saadis/PixelPirates`
- `MrSohaibAhmed/interview-assessment`
- `Mshandev/Trello-Clone`
- `MuhammadAnique7535/alira-server`
- `MuhammadAsadAnsari/backend`
- `MuhammadZeeshanAshraf/yapily-integration`
- `Mukela12/CGAZ-website`
- `Muqadas-javed/DummyList`
- `OMBOY33/moonboy`
- `Olamidipupo-favour/thesebasterdshaven_tpaidourmoney`
- `OlegPoloviy/courseWork`
- `OrlandoDuocUc/oftalmetryc_sistema` · dropper-only
- `Pa-ppy/Checkout`
- `Pavel-Shcherbo/defiguard-dev`
- `PecodeAutomation/playwright-demoqa-framework`
- `PradeepKundekar0101/WebRTC-POC`
- `Prakhar6046/Feedflow-New`
- `Prakhar6046/Nethgo-backend`
- `Prakhar6046/json`
- `Prakhar6046/testing`
- `Prakhar6046/ubk-development-official-website-export`
- `Prakhar6046/website`
- `PremShakti/diagram-offline-tool`
- `Professor833/orchestrix`
- `Rahad-Ullah/Re-wears-dashboard`
- `Rahmasamy/Event-system-gateway`
- `RanaRehman7676/my-electron-app2`
- `Reactongraph/challenges`
- `Reactongraph/digital-signature-pad`
- `Rezonality/mutils` · dropper-only
- `Rezonality/zep` · dropper-only
- `Rezonality/zest` · dropper-only
- `Roberto328/TokenPresaleDApp`
- `Ryanyntc2013/usbpcapAI` · dropper-only
- `Rytnix786/OFF-Boarder`
- `S7AWKAT/ClubGrub`
- `S7AWKAT/Tears-of-Yoi---Interactive-GDD-Website`
- `Saarcasmic/BulkEmailCampaignManager` · dropper-only
- `Sabbirnde1/Nava`
- `SagittariusBA/ComfyUI_SetupKit` · dropper-only
- `SeiamAlMahmud/Shop-on-track`
- `ShafiqUllah2233/SCDProject25`
- `ShahbazRamzan/NodeTestApp`
- `ShamratX/AI-Banking`
- `ShantoGUB567/AI-Desktop-Assistant` · dropper-only
- `Shariarhosain/BatteryQK-Backend`
- `Shariarhosain/Batteryqk`
- `Shariarhosain/ibracks_backend`
- `Shimul-12/token-presale-dapp`
- `Shivam29k/portfolio`
- `SimalChaudhari/real-estate`
- `Socheema/bukkahut`
- `Sohaib909/rfid_pos_server`
- `StanislavKhom/ContentAnalyserAI`
- `Stephenanokz/ihmhealth-api`
- `Stephenanokz/stalbertschool-api`
- `SubhamKrGuptaDev/assisment-crypto-card`
- `SubhamKrGuptaDev/crypto-card-project`
- `SubhamKrGuptaDev/crypto-changes-init-value`
- `SumaiyaNishat/B12-A5-Emergency-Hotline`
- `SumaiyaNishat/B12A01-landing-launchpad`
- `SumaiyaNishat/B12A02-Responsive-Flowers`
- `SumaiyaNishat/Financial_Dashboard`
- `SumaiyaNishat/MvcTempData`
- `SumaiyaNishat/Travel-Blog-html-css`
- `SumaiyaNishat/WebFromPractice`
- `SumaiyaNishat/b12-a08-hero-apps`
- `SumaiyaNishat/bbc-bangla`
- `SumaiyaNishat/digit-recognition`
- `SumaiyaNishat/dragon-news-project`
- `SumaiyaNishat/english-janala`
- `SumaiyaNishat/foodie-hub`
- `SumaiyaNishat/freelance-marketplace-client`
- `SumaiyaNishat/freelance-marketplace-server`
- `SumaiyaNishat/g3-architects-website`
- `SumaiyaNishat/html-css`
- `SumaiyaNishat/new-year-offer`
- `SumaiyaNishat/panda-commerce`
- `SumaiyaNishat/payoo-mobile-app`
- `SumaiyaNishat/smart-deals-server`
- `SumaiyaNishat/tea-house-resources`
- `SumaiyaNishat/ticket-booking-platform-server`
- `SumaiyaNishat/web-developer-portfolio`
- `SumaiyaNishat/zap-shift-client`
- `SumaiyaNishat/zap-shift-server`
- `T-MAPY/GenSMD` · dropper-only
- `TemuriTsutskiridze/React-Final`
- `TerraDharitri/drt-template-service`
- `TerraDharitri/drt-workflow-rerun-on-comment`
- `TerraDharitri/x402`
- `TsionTesfaye/assignment`
- `UroojFatim/tMust`
- `Usamahafiz8/CCMB`
- `Usamahafiz8/ios-refferal-to-clipboard`
- `Vacademy-io/vacademy_internal_dashboard`
- `VanessaGikebe/FOMO-app`
- `VitthalGund/Koinos-Test`
- `Vladyslav0060/autopartner`
- `Vladyslav0060/budget-app`
- `Vladyslav0060/challenge-git`
- `Vladyslav0060/comparison-api`
- `Vladyslav0060/cp-authorization`
- `Vladyslav0060/popover-task`
- `Waseem12wa/DentalPrep`
- `WebInventix/avion`
- `WebInventix/marketplace-frontend`
- `Work-TCL/channel-microservice` · dropper-only
- `Work-TCL/product-microservice` · dropper-only
- `XboxUnity/freestyledash` · dropper-only
- `XpertWebApp/BlockterraAssignment`
- `YShokrollahi/polyscope-imaging` · dropper-only
- `Yaroslav781/drainer`
- `Yasiru3875/Shoplytic`
- `YoussefPasha/pages-builder`
- `ZeeshanMehdiDev/texas-2026`
- `Zenncode/ftccmain`
- `aahmedfaraz/ai-linkedin-agent`
- `aamir-786/Legacy-Capsule-website`
- `aamir-786/silicon-savannah-vested`
- `abdallah244/ff`
- `abdulqadeer273/apple-auth-app`
- `abdulrhman-developer0/traf-dashboard-api`
- `abhi-dev78/strapi-cloud-template-blog-0f64e1d1e9`
- `abidhabib/Nalnda-Reader` · dropper-only
- `abidhabib/Windows-Activatior-` · dropper-only
- `abimtad/Customer-feedback`
- `abimtad/upload_file`
- `abrarkhalidofficial/Aigronpages`
- `abrarkhalidofficial/Videoplayer`
- `abusayedwd/property-rental-serverr`
- `addis-ale/July2025Cohorot-Hackathon1`
- `addis-ale/git_learn`
- `addis-ale/gym-app`
- `adityaranjan2005/card-activity`
- `aindrajaya/chainx-docs`
- `aindrajaya/senda-api`
- `aindrajaya/virtual-run-api`
- `ajainoffbeat/offbeat-flutter-ems` · dropper-only
- `ajaypanchal761/dvision` · dropper-only
- `akshat-mechlin/TimeFlow-website-2`
- `alamin-sujon/software-chamber`
- `alaminrifat/company-portfolio`
- `aliff56/ai-code-comment-generator` · dropper-only
- `aliyun/iotkit-embedded` · dropper-only
- `ammarbinshakir/k8s-url-shortener-app`
- `anas-developer01/SolutionRootRepo` · dropper-only
- `anasbinarif/texas-2026`
- `andrewlehmann32/Flask`
- `andrewlehmann32/RSTRockying`
- `anilgoswamistartbitsolutions/travel-platform`
- `anmolcheema836/americanpathways`
- `anmolcheema836/anmolcheema836`
- `anmolcheema836/astronomy`
- `anmolcheema836/carauction`
- `anmolcheema836/carauctionfees`
- `anmolcheema836/contentsure`
- `anmolcheema836/digitalwork`
- `anmolcheema836/do-you-wanna-go-out-with-me`
- `anmolcheema836/downloaddemo`
- `anmolcheema836/drone`
- `anmolcheema836/elite`
- `anmolcheema836/furandfable`
- `anmolcheema836/thirtysixstudio`
- `anmolcheema836/thunderzone`
- `anmolcheema836/will-you-be-my-valentine`
- `antonver/defiguard-dev`
- `arpit01923/inventory-management-backend`
- `ashar160/ashar160`
- `ashar160/email-signature`
- `ashar160/email-template`
- `ashar160/film-maker-portfolio`
- `bhaveshkumbhani0070/string-calculator`
- `bhavin002/shadcn-flipbook`
- `bhnybrohn/cal-eco-platform`
- `bhoomikamehtastartbit/reactchakraui`
- `brainstormforce/edd-purchase-details`
- `brodynelly/mizzou-health-care-dashboard`
- `cashilaa/discord-bot` · dropper-only
- `chetanji028/tradingview2`
- `cletusgizo/genetiq-v2--test-task`
- `cmaughan/morny` · dropper-only
- `codecraftwt/shivaji-university-next`
- `contact474/videeo-ai`
- `corange-lab/Waaree-API-`
- `cto-varun/git-challenge`
- `cto-varun/user-crud-design-nextjs`
- `danishjavedcodes/Data-Pack`
- `desowin/usbpcap` · dropper-only
- `devhub324/React_VideoPlayer`
- `devhub324/react_prisma_Loika`
- `devtag2026/AimDiscover-FrontEnd`
- `devtalhaa/demoportfolio`
- `devthedeveloper/w3glpop`
- `dineshkuma1234/Gimmel`
- `drewroberts/website`
- `dryhurstdigital/invoice-my-clients-cursor-plugin`
- `dsand20142014/openpos` · dropper-only
- `dunkware/dotcom`
- `dv1/ion_player` · dropper-only
- `eagleio786/TheEagles_Backend`
- `eastmade/web3project-momo-token`
- `edtechug/KONEKTA`
- `eferos93/test4`
- `eftakhar-491/merge-cart`
- `ehsan18t/resume-ai`
- `emacs-mirror/emacs` · dropper-only
- `emacsmirror/emacs` · dropper-only
- `erikfva/qgiscode` · dropper-only
- `ethansliu/software_space_skill_test_problem_1`
- `faaizmahmood/eduwise-backend`
- `fahadali503/react-email-templates`
- `fahadsahib786/tts-backend`
- `fahadsahib786/tts-frontend-admin`
- `fahadsahib786/tts-frontend-user`
- `falconpl/falcon` · dropper-only
- `findusman/POS_backend`
- `foisaluddin400/backend_basic_structure` · dropper-only
- `freejob985/elzero_vue` · dropper-only
- `furqan137/whisp-notify`
- `g-zenr/MSA-EXPORT-IMPORT`
- `garrycha/test-job`
- `gauravraisharma/Infobip-sample`
- `gauravraisharma/InventoryManagementSystem`
- `gauravraisharma/Ticketting-System`
- `goldendragon68/Bullana`
- `guitinem/carting_assessment`
- `hajuuk/R7000` · dropper-only
- `haloivanid/monorepo`
- `hambaloch/Carting-assessment`
- `hammad872/review`
- `haroldcalvo/workshop`
- `harshPandey0911/student_education`
- `himanshu077/material-card-ui-test`
- `hrch3k/AI-LegalXpert` · dropper-only
- `huzzy12/Zauf-Labs-Test`
- `hvmgeeks/frontendengine1`
- `iamnasirudeen/E-wallet`
- `icecoldjay/bri`
- `ifshad/shadcn-practise`
- `iftekhar2979/Knitting_Client`
- `ihzhatamamy/-MagicDoor_Property_Rental`
- `ilhamsabir/ilhamsabir`
- `ilhamsabir/mylibs`
- `ilhamsabir/waha-app`
- `irskid5/Computer-Processor` · dropper-only
- `ishanrt119/NFT-Marketplace`
- `ishimwejeanluc/EventStreamingSystem`
- `islamto-mpa101-stack/CarService` · dropper-only
- `ivanwassaf/skill-test`
- `jade0615/Bookme`
- `jade0615/updeal-mvp`
- `jahid123978/Bg-remover_Fast_API` · dropper-only
- `jahid123978/Fast-AI-image-bg-remover` · dropper-only
- `jainchirag1234/backgroundChanger`
- `jareer1/AI-GoogleAds-MVP` · dropper-only
- `jareer1/robolawyer` · dropper-only
- `jareer1/voice-engine-main` · dropper-only
- `jawatech/emacs-24.5` · dropper-only
- `jaxteller2016/Social-App-MVP-Poker-CRA`
- `jbaze/clarity-cover`
- `jdwhite0/jdproductions-saas`
- `jjin43/invelo_assessment`
- `jobayer-hossen/soft_and_cookie_project`
- `johnsonfash/electron-react-sqlite-autoupdate-boilerplate`
- `jonaslim-ucg/nmac-crm`
- `jroimartin/emacs` · dropper-only
- `juggernautsei/calendar_facility_view`
- `juggernautseinc/healthpals`
- `kalanas210/IWB25-274-CodeByte-Backend` · dropper-only
- `kalanas210/Vogues-BackEnd` · dropper-only
- `kalanas210/kalanas210` · dropper-only
- `kalanas210/movie-app` · dropper-only
- `kamiaslam/MM-CompleteFRONTEND` · dropper-only
- `kanchana404/Cypress`
- `kashifali0969082/Finalized-scripts`
- `kashifali0969082/librechat`
- `kashifali0969082/scripts`
- `khaledssbd/KS-University-server`
- `khaledssbd/RideRevolt-project`
- `khaledssbd/SoulSyntax-project`
- `khaledssbd/SwiftCart-APIs` · dropper-only
- `khaledssbd/ThinkGreenly-apis`
- `khaledssbd/TuneTrail-a-bike-service-management-solution-serverside`
- `khaledssbd/khaledssbd` · dropper-only
- `khaledssbd/sfr-claw-code` · dropper-only
- `khan8799/next-claude-app`
- `komangmahendra/rental-prop-task`
- `korvinus777/texas-holdem-ux`
- `laerciosimoes/giit-challenge-laercio`
- `lambeboluwatife/lbdflix`
- `lamdan0901/YouTube-Playlist-Pulse`
- `lasith2003/durdans-lims-frontend` · dropper-only
- `leandrosoaresdesouza/test`
- `leothatguy/ai-processing-text-interface`
- `leothatguy/conference-ticket-generator`
- `leothatguy/devlinks`
- `leothatguy/embeddable-tour-web-app`
- `leothatguy/lendsqr-test`
- `leothatguy/primo-dashboard`
- `leothatguy/transfer-ckb`
- `leothatguy/zetrochat`
- `lilLink/kursova_telegram_bot` · dropper-only
- `lkm1developer/mcp-servers-sse`
- `luckyS330/turbo_assessment`
- `mahadi-zulfiker/Backend-Tour-Management-System`
- `mahadi-zulfiker/REPLIQ-Limited-Task`
- `mahadi-zulfiker/SpaceZee`
- `maihd/ui_programming` · dropper-only
- `maleesha-pramud/saloon_guide_backend`
- `manaknight/backend_mock_fast`
- `maniksarker25/physics-education-website` · dropper-only
- `marinirin909-lang/saasable`
- `markomilivojevic/ethvault_staking`
- `masumhasan/musaabadam_app` · dropper-only
- `md-fahad-ali/idp-project`
- `md-naimul-hassan/Uddoktapay-Payment` · dropper-only
- `md-naimul-hassan/resid-plus-host` · dropper-only
- `md-naimul-hassan/resid-plus-user` · dropper-only
- `mdemong87/my-amino-hub-main-tarak-vai`
- `mdemong87/my-express-boilerplat`
- `mdemong87/picturetv`
- `mdemong87/reqres`
- `mdemong87/tech-fix-services`
- `mehediScriptDev/atarShop`
- `mehediScriptDev/landing-page`
- `metaupspace/Nma-Product-Page-new`
- `metawake/node-task-test`
- `metoo10987/OpenNT-4.5` · dropper-only
- `micymike/AI-assistant` · dropper-only
- `micymike/classic-calculator` · dropper-only
- `micymike/classwork` · dropper-only
- `micymike/instructors-elimu` · dropper-only
- `micymike/tutorial` · dropper-only
- `mirzaghalib4726/committee-backend`
- `mirzaghalib4726/event_management_backend`
- `mjatin-dev/test-task`
- `mlbench-lhr/vendr`
- `mohamedeturki/shigud-clone`
- `mohammadalnajar/markdown-blog`
- `mohsulthana/aurora-reminder-app`
- `monazahmed/Agrismart-project-`
- `motia/GoldenCity`
- `motormouthvis/dream-neighborhood-admin`
- `mr-ammar-1/Project-management-app`
- `mr-ammar-1/ProjectCheck`
- `mr-ammar-1/ammar-farooq`
- `msuhels/Inventory_Managment_react_native`
- `mu-majid/image-cropping`
- `muhammad-sohel131/PostgreSQL_Assignment`
- `muhammad-sohel131/libaray-management-api`
- `muhammad-sohel131/muhammad-sohel131`
- `muhammad-sohel131/ppt`
- `muhammad-sohel131/python_code`
- `mysticvikingr/instagram-monitor` · dropper-only
- `mysticvikingr/medicine-websocket` · dropper-only
- `naksh1414/Googlle-Slides-Converter`
- `namo-usquare/cmc`
- `naymHdev/nobel-sports-dashboard`
- `naymHdev/nobelsport-client`
- `naymHdev/play-top`
- `nelsondev19/defi-property`
- `netmask/emcas-24.3` · dropper-only
- `new-computers/arena-ff-addon`
- `new-computers/arena-toolkit`
- `new-computers/seeder`
- `new-computers/web-of-trust`
- `nhonlvsoict/skill-test-main`
- `nilsrusten-dev/mysite`
- `nimurr/Koukoutsa-Backend2.0`
- `nimurr/Pricely-cusang_commerce-Backend`
- `nimurr/Social-Media-App-Involved-Server`
- `nimurr/supplify-websitee`
- `nishantrepozitory/welcome`
- `noors-code/Flask`
- `noors-code/MovieHouse`
- `noors-code/MovieHouse-api`
- `noors-code/swarrpay-backend`
- `okanaslan/tirios`
- `okshanaby/wonderful-app`
- `olartgabo/studentCommunityDay`
- `ome/bioformats` · dropper-only
- `oscafrica/chapters-directory`
- `oscfcommunity/osd_strapi_cms`
- `oyewoas/smc_lossless_bidding`
- `pacifiquem/idebug`
- `parallax-kal/CognitoVault`
- `parthvaghani/ring-configurator`
- `phillipshepard1/internal-re-crm`
- `prahaladbelavadi/CoinLocatorDemo`
- `praisezee/andreportfolio`
- `pranav033/Flutter`
- `pratapadityasingh/bannerxpress`
- `pratikp72/PhoenixNext`
- `pratikp72/Taoufik_ticket_management`
- `pratikp72/brainbattle`
- `pratikp72/calendar-app`
- `pratiksingh1702/friend` · dropper-only
- `prit-nadoda/vs-ext-injectify`
- `prodsec-opti/badCode`
- `prosigns/dex-data-aggregation`
- `prosigns/nestjs-api-boilerplate`
- `pt67/bond`
- `pt67/node-postgresql`
- `pt67/railstodo`
- `pt67/whope`
- `pushpakpandya3292/QuickBite_Backend`
- `rajaXcodes/Token-Presale-dApp`
- `rajasadeem/raja-sadeem`
- `rakeshkarmaker/mercy-daily-backend-andreia250472`
- `rakeshkarmaker/visualexstasy-CeleBrease`
- `ramkrishnakuldeep/react-test`
- `raoarafat/steelh-website`
- `raverkamp/plsqldiff` · dropper-only
- `rayhanalmim/oveswapclientmainnet`
- `rayhanalmim/xmtp_mvp`
- `rejoan121615/ClientOps`
- `rejoan121615/VA-DISABILITY-RATING-CALCULATOR`
- `rejoan121615/camera-overlay`
- `reksar/SpaceEngineers` · dropper-only
- `ricardomartins9899/SmartPay-Demo`
- `riteshahir28/myfirstproject`
- `rodrigogz64/MagicDoor-Property-Rental-Platform`
- `ron-aoxapps/test-job-old`
- `ronymia/employee-nexus-backend`
- `ronymia/university-management-frontend`
- `saidur1/saidurrahman`
- `saif72437/36-WEEKS-REMOTE-JOB-COURSE`
- `saif72437/36-weeks-remote-jobs-preparation-challenge`
- `saif72437/Airbnb-Clone`
- `saif72437/BeSocially-`
- `saif72437/InnerBeast-Music-Player`
- `saif72437/Lazarev`
- `saif72437/Magma`
- `saif72437/Music-Academy`
- `saif72437/Saif-Blogs`
- `saif72437/airplane-ticket-booking-app`
- `saif72437/diet-plan-app`
- `saif72437/duo-studio`
- `saif72437/eco-brands`
- `saif72437/full-stack-engineering-batch-2`
- `saif72437/linkedin-post-editor`
- `saif72437/medium-clone`
- `saif72437/nft-responsive`
- `saif72437/real-estate-app`
- `saif72437/realtime-chatting-app`
- `saif72437/responsive-music-website`
- `saif72437/saif-portfolio`
- `saif72437/sundown-studio`
- `saif72437/two-good-co`
- `saif72437/utube`
- `saif72437/video-tube`
- `saif72437/voice-and-text-translator-app`
- `saif72437/vu-quiz-app`
- `saif72437/works-studio`
- `saifullah-max/Sound-Cloud-Downloader`
- `saifullah-max/elevate-backend`
- `sailfishos-mirror/emacs` · dropper-only
- `sajib689/university-management-service`
- `salmansarwarr/WonderCard`
- `salmansarwarr/solana-sniper-bot`
- `samirhassen/ToDo-Realtime`
- `sanchuanhehe/fbb_ws63` · dropper-only
- `santos25/institute-report-management`
- `sbshihab24/Agentic--AI` · dropper-only
- `sbshihab24/rag-chatbot-project` · dropper-only
- `semirhamid/travel-rec-web`
- `shakibul22/daily-news`
- `shakilkhan496/omegle-server`
- `shanfei/golden-city`
- `shariyerShazan/nest-crud-postgresql-home-practice-roadmap`
- `shariyerShazan/nestJs-mongodb-second-proj`
- `sheryglitch/challenge-ping-tree`
- `shivc868/text-animations`
- `shreyash-jain/still-lift-zone`
- `simmsb/emacs-mac-31` · dropper-only
- `simon-rock/emacs-23.3b` · dropper-only
- `smit455/Arc`
- `smit455/Task_manager`
- `smit455/big_bazaar-store`
- `splinxplanet/splinx-planet-backend`
- `srrasel/pmchl-medi`
- `stuartcampbell/playpen` · dropper-only
- `surajiiitn/WEB`
- `survos-sites/framework7-bundle-demo`
- `survos-sites/modo`
- `taijulsir/antelier-antelier.io`
- `taijulsir/appifylab-buddy-script-frontend`
- `taijulsir/cineticket-app`
- `taijulsir/package-finance-module`
- `taijulsir/zainab-jahan-fashion-coach-site`
- `tanushbhootra576/MoodSync`
- `tanzid64/test-auth-cache-laravel`
- `teeps-heisenberg/Langchain-Huggingface-Generative-AI`
- `theabhishek4u/building-finance-backend-system`
- `theanuragg/Relayer`
- `thegreaterdev/backend-ai-assessment`
- `thomas-moulard/urbi-debian` · dropper-only
- `tlord101/hck`
- `tokenbot-org/token-contracts`
- `traincapetech/University-Backend` · dropper-only
- `tsol/Open-PoniX` · dropper-only
- `umerasifdevexcel/casino-top`
- `umershafiq19/Connectify`
- `umrasghar/heygen-demo`
- `umrasghar/webflow-automator`
- `unfazed24072005io/youtube-clone`
- `uribresler/Elevated-Spaces-Backend`
- `user2745/Web3Aggregator`
- `user2745/dev-test-kamto-kionos`
- `vb352/koinos-assessment`
- `victordaj/buggy`
- `vishuRizz/kyd-lnm-hacks`
- `vishwaVaghasiya16/boiler-plate` · dropper-only
- `vishwaVaghasiya16/mollie-stripe` · dropper-only
- `vishwaVaghasiya16/monorepo-ts` · dropper-only
- `vnvstore/funtico-labs-assessment-15`
- `wahajansari08/NextDashboard`
- `wasif903/backend-assessment-pluton` · dropper-only
- `wayne931121/Sandbox` · dropper-only
- `williamwen1986/Luakit` · dropper-only
- `wisdomedeki761/YouTube-short-creator-FE`
- `wisdomedeki761/forex-premium-and-discount-bot-integrated-with-telegram`
- `workonlly/interview_bucket`
- `wyrustaaruz/cal-eco-platform`
- `xacq/SISBACK` · dropper-only
- `yujieschool/U3DEventFrame` · dropper-only
- `zafarnajmi1/FWRD`
- `zainhaider-123/betterauth-starter-template`
- `zainjaved-ui/INoteBook`
- `zhm/node-spatialite` · dropper-only

</details>

## License

MIT
