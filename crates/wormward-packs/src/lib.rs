mod polinrider;
mod shai_hulud;

pub use polinrider::polinrider_pack;
pub use shai_hulud::shai_hulud_pack;

use wormward_core::Pack;

/// All campaign packs compiled into this build.
pub fn builtin_packs() -> Vec<Pack> {
    vec![polinrider_pack(), shai_hulud_pack()]
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
            "export default {};\nglobal['!']='8-270-2';var _$_1e42=[];",
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
            "export default {};\nglobal.o='5-3-235-du';var _$_8e2c=[];",
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
}
