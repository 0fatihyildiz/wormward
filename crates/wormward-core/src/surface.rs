//! Auto-run surface classification and one-hop reachability.
//!
//! A [`Surface`] is a place in a repo that runs *without user intent* (build
//! configs, package.json lifecycle scripts, CI workflows, VS Code folder-open
//! tasks, git hooks, dropped propagation scripts) plus the fake-font binary
//! asset vector. Classification is pure and path-based; content scoring lives
//! in [`crate::capability`].

use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    ConfigFile,
    LifecycleScript,
    WorkflowFile,
    TasksJson,
    GitHook,
    PropagationScript,
    DerivedScript,
    BinaryAsset,
}

// Any `*.config.{js,cjs,mjs,ts}` is now treated as a ConfigFile surface (see `classify`), so no
// per-stem allowlist is needed. These are the non-`*.config` auto-run script names the family is
// known to also inject into — they run via package scripts / ts-node without user intent.
const AUTORUN_SCRIPT_STEMS: &[&str] = &["seed", "migrate"];
const CONFIG_EXTS: &[&str] = &["js", "mjs", "cjs", "ts"];
// `App.js` lowercases to `app.js`.
const ENTRY_BASENAMES: &[&str] = &["index.js", "app.js", "truffle.js"];
const PROP_EXTS: &[&str] = &["bat", "cmd", "sh", "ps1"];
const ASSET_EXTS: &[&str] = &["woff", "woff2", "ttf", "otf", "eot", "png", "jpg", "jpeg", "gif", "ico"];
// Shared with the working-tree walk (walk::is_pruned_dir): these dirs are pruned at WALK time so
// multi-GB build outputs (a Rust target/, a bundler dist/) are never enumerated, AND still checked
// per-path here so a GitTree / ApiTree — whose path lists are NOT pre-pruned — scans the same file
// set the WorkingTree does. Without the per-path check, a committed node_modules produces
// deep-scan-only phantom findings.
pub(crate) const EXCLUDED_DIRS: &[&str] = &[
    "dist", "build", ".next", "out", "coverage", "vendor", "node_modules", ".wormward-backup",
    "target", ".output", ".nuxt",
];

const LIFECYCLE_KEYS: &[&str] = &[
    "preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "prepack",
    "postpack",
];

fn basename(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Build-output dirs, vendored deps (`node_modules`), backup dirs, and minified files are
/// excluded from the scan; legitimate obfuscated/minified/third-party code lives here, not
/// in source config. Applied uniformly across every file source (working tree, git tree,
/// API tree) so their scanned file sets match.
pub fn is_excluded_path(path: &Path) -> bool {
    let bn = basename(path);
    if bn.contains(".min.") {
        return true;
    }
    // Source maps: generated build artifacts — enormous, high-entropy JSON, never source. And
    // pnpm/CAS `<hash>-index.json` store metadata (paths + integrity hashes, not code). Neither is
    // an auto-run surface; scanning them is pure FP/noise.
    if bn.ends_with(".map") || bn.ends_with("-index.json") {
        return true;
    }
    // Lockfiles are inert data — package names, URLs, and SHA/integrity hashes, no executable code.
    // Their hashes tripped the decoder/shuffle-seed matcher (a "MDy" substring in base64, digit runs
    // inside a tarball SHA). Never content-scan them; they map to no auto-run surface. (Lockfiles are
    // still PARSED by name for malicious packages in `check_lockfiles` — that path is unaffected.)
    if bn == "yarn.lock"
        || bn == "package-lock.json"
        || bn == "npm-shrinkwrap.json"
        || bn == "pnpm-lock.yaml"
        || bn.ends_with(".lock")
    {
        return true;
    }
    // Content-addressed package-manager stores/caches (pnpm / npm / bun / yarn-berry): blob stores +
    // metadata. Not an install tree — pruned, stale, and NOT executed; scanning them only produced
    // noise and FPs (e.g. legit `@babel/parser` and `node-fetch` under `.bun/install/cache/` tripped
    // the capability engine's `.exec(`/network/trailing-code on ordinary library bundles). Meaningful
    // detection is a package INSTALLED into a project, not a cache blob. The leading-slash prefix
    // normalizes the check so a cache dir at the repo ROOT (`.bun/…`) matches like a nested one.
    let path_str = format!("/{}", path.to_string_lossy().replace('\\', "/"));
    if path_str.contains("/.pnpm/")
        || path_str.contains("/pnpm/store/")
        || path_str.contains("/.npm/_cacache/")
        || path_str.contains("/.bun/install/cache/")
        || path_str.contains("/.yarn/cache/")
        || path_str.contains("/.yarn/unplugged/")
    {
        return true;
    }
    // Bundler asset output and Capacitor native mirrors carry minified/bundled COPIES of the app
    // (a built `index.js`, hashed asset chunks). We scan the SOURCE config, never the mirror — a
    // bundled copy would false-positive (minified/base64) and duplicate the source finding.
    // Lowercased because the iOS mirror path is `ios/App/App/public/` (capitalized).
    let path_lower = path_str.to_lowercase();
    if path_lower.contains("/public/assets/")
        || path_lower.contains("/ios/app/app/public/")
        || path_lower.contains("/android/app/src/main/assets/public/")
    {
        return true;
    }
    path.components().any(|comp| {
        let s = comp.as_os_str().to_string_lossy();
        EXCLUDED_DIRS.iter().any(|d| *d == s)
    })
}

/// Classify a repo-relative path into a file-backed [`Surface`]. Returns the
/// surfaces that map 1:1 to a file; `LifecycleScript`/`DerivedScript` are
/// synthesized by the scanner and never returned here.
pub fn classify(path: &Path) -> Option<Surface> {
    let bn = basename(path);
    let path_str = path.to_string_lossy().replace('\\', "/").to_lowercase();
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // WorkflowFile
    if (path_str.contains(".github/workflows/") && (ext == "yml" || ext == "yaml"))
        || bn == ".gitlab-ci.yml"
    {
        return Some(Surface::WorkflowFile);
    }
    // TasksJson (.vscode/tasks.json)
    if bn == "tasks.json" && path_str.contains(".vscode/") {
        return Some(Surface::TasksJson);
    }
    // GitHook: .husky/* (working-tree .git/hooks handled separately by the scanner)
    if path_str.contains(".husky/") && !bn.is_empty() {
        return Some(Surface::GitHook);
    }
    // PropagationScript
    if PROP_EXTS.contains(&ext.as_str()) {
        return Some(Surface::PropagationScript);
    }
    // BinaryAsset (.svg deliberately absent — it is legitimately text)
    if ASSET_EXTS.contains(&ext.as_str()) {
        return Some(Surface::BinaryAsset);
    }
    // ConfigFile: toolchain configs, gatsby, .eslintrc.{js,cjs}, entry files
    if CONFIG_EXTS.contains(&ext.as_str()) {
        let stem = bn.trim_end_matches(&format!(".{ext}"));
        // ANY `*.config.{js,cjs,mjs,ts}` is an auto-run config surface — not just an allowlisted
        // stem. The family rotates WHICH build/config file it infects (metro/app/drizzle/
        // playwright/svelte/…); enumerating stems is the same brittleness as enumerating version
        // strings. FP-safe: the capability gate still requires a concealment prior or a worm tell,
        // so a CLEAN config of any name never fires.
        if let Some(base) = stem.strip_suffix(".config") {
            if !base.is_empty() {
                return Some(Surface::ConfigFile);
            }
        }
        if stem == "gatsby-config" || stem == "gatsby-node" {
            return Some(Surface::ConfigFile);
        }
        // DB seed / migration scripts run without user intent (package scripts, ts-node) and are a
        // known injection host for this family.
        if AUTORUN_SCRIPT_STEMS.contains(&stem) {
            return Some(Surface::ConfigFile);
        }
    }
    if bn == ".eslintrc.js" || bn == ".eslintrc.cjs" {
        return Some(Surface::ConfigFile);
    }
    if ENTRY_BASENAMES.contains(&bn.as_str()) {
        return Some(Surface::ConfigFile);
    }

    None
}

/// Extract `(lifecycle-key, script-string)` pairs from package.json content.
/// Only the auto-run lifecycle keys are returned; a build/test script is not.
pub fn lifecycle_scripts(package_json: &str) -> Vec<(String, String)> {
    let v: serde_json::Value = match serde_json::from_str(package_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let scripts = match v.get("scripts").and_then(|s| s.as_object()) {
        Some(o) => o,
        None => return Vec::new(),
    };
    LIFECYCLE_KEYS
        .iter()
        .filter_map(|k| {
            scripts
                .get(*k)
                .and_then(|val| val.as_str())
                .map(|s| (k.to_string(), s.to_string()))
        })
        .collect()
}

fn derived_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `node|bun|ts-node|tsx [flags] <path>.{js,cjs,mjs}` — path may be bare
    // (`setup_bun.js`), `./`-relative, or nested (`dist/x.mjs`).
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:^|[\s;&|])(?:node|bun|ts-node|tsx)\s+(?:--?\S+\s+)*['"]?((?:\.?[\\/])?[\w.@-][\w.\\/@-]*\.(?:c|m)?js)"#,
        )
        .unwrap()
    })
}

/// Find local `node ./X.js` targets in an auto-run command / workflow step /
/// tasks.json body. The one hop that lets the engine reach a dropped payload.
/// Windows backslash paths are normalized to `/`.
pub fn derived_targets(command: &str) -> Vec<String> {
    derived_re()
        .captures_iter(command)
        .map(|c| c[1].replace('\\', "/").trim_start_matches("./").to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(p: &str) -> Option<Surface> {
        classify(Path::new(p))
    }

    #[test]
    fn config_toolchain() {
        assert_eq!(c("postcss.config.mjs"), Some(Surface::ConfigFile));
    }

    #[test]
    fn lockfiles_and_stores_excluded_from_content_scan() {
        // Inert package-manager data — never content-scanned (they FP'd the decoder/seed matcher).
        assert!(is_excluded_path(Path::new("frontend/yarn.lock")));
        assert!(is_excluded_path(Path::new("package-lock.json")));
        assert!(is_excluded_path(Path::new("pnpm-lock.yaml")));
        assert!(is_excluded_path(Path::new("Cargo.lock")));
        assert!(is_excluded_path(Path::new("node_modules/.pnpm/foo@1/node_modules/foo/x.js")));
        assert!(is_excluded_path(Path::new(
            "/Users/me/Library/pnpm/store/v3/files/ab/cdef-index.json"
        )));
        assert!(is_excluded_path(Path::new("/Users/me/.npm/_cacache/content-v2/x")));
        // Package-manager caches at the repo ROOT (bun / yarn-berry) — the @rive/@babel/node-fetch
        // FP class: legit library bundles in a CAS cache must not be content-scanned.
        assert!(is_excluded_path(Path::new(".bun/install/cache/@babel/parser@7.29.3@@@1/lib/index.js")));
        assert!(is_excluded_path(Path::new("ws/.bun/install/cache/node-fetch@2.7.0@@@1/lib/index.js")));
        assert!(is_excluded_path(Path::new(".yarn/cache/lodash-npm-4.17.21.zip")));
        assert!(is_excluded_path(Path::new(".yarn/unplugged/sharp/node/index.js")));
        // Real source is NOT excluded.
        assert!(!is_excluded_path(Path::new("postcss.config.mjs")));
        assert!(!is_excluded_path(Path::new("src/index.js")));
    }
    #[test]
    fn config_nested() {
        assert_eq!(c("packages/web/vite.config.ts"), Some(Surface::ConfigFile));
    }

    #[test]
    fn config_generic_any_config_stem() {
        // Version-independence at the FILE layer: the family rotates WHICH build/config file it
        // infects (metro/app/drizzle/playwright/…). Keying on a fixed stem allowlist is the same
        // brittleness as keying on a fixed version string — any `*.config.{js,cjs,mjs,ts}` is an
        // auto-run config surface. (metro/app/drizzle/playwright are NOT in CONFIG_STEMS.)
        assert_eq!(c("metro.config.js"), Some(Surface::ConfigFile));
        assert_eq!(c("app.config.ts"), Some(Surface::ConfigFile));
        assert_eq!(c("drizzle.config.ts"), Some(Surface::ConfigFile));
        assert_eq!(c("apps/mobile/playwright.config.mjs"), Some(Surface::ConfigFile));
    }

    #[test]
    fn config_known_autorun_scripts() {
        // The family also hides in DB seed/migration scripts, which run via package scripts /
        // ts-node without user intent. Classify the well-known names so the capability engine
        // scores them (a clean seed.ts stays silent — the gate needs a concealment prior/worm tell).
        assert_eq!(c("seed.ts"), Some(Surface::ConfigFile));
        assert_eq!(c("prisma/seed.js"), Some(Surface::ConfigFile));
        assert_eq!(c("db/migrate.ts"), Some(Surface::ConfigFile));
    }

    #[test]
    fn excludes_sourcemaps_cas_metadata_and_bundled_assets() {
        // Source maps: generated, huge, high-entropy JSON — never source, must not be scanned.
        assert!(is_excluded_path(Path::new("dist/app.js.map")));
        assert!(is_excluded_path(Path::new("public/index.css.map")));
        // pnpm/CAS `<hash>-index.json` metadata anywhere (not only under a store path).
        assert!(is_excluded_path(Path::new("some/dir/abcdef123-index.json")));
        // Bundler asset output + Capacitor native mirrors carry minified/bundled COPIES of source;
        // scan the SOURCE config, not the mirror, or a bundled `index.js` copy false-positives.
        assert!(is_excluded_path(Path::new("public/assets/index-a1b2c3.js")));
        assert!(is_excluded_path(Path::new("ios/App/App/public/index.js")));
        assert!(is_excluded_path(Path::new(
            "android/app/src/main/assets/public/index.js"
        )));
        // A real source config is still scanned.
        assert!(!is_excluded_path(Path::new("metro.config.js")));
        assert!(!is_excluded_path(Path::new("src/app.config.ts")));
    }
    #[test]
    fn config_eslintrc() {
        assert_eq!(c(".eslintrc.js"), Some(Surface::ConfigFile));
    }
    #[test]
    fn config_entry_files() {
        assert_eq!(c("src/index.js"), Some(Surface::ConfigFile));
        assert_eq!(c("App.js"), Some(Surface::ConfigFile));
        assert_eq!(c("truffle.js"), Some(Surface::ConfigFile));
    }
    #[test]
    fn workflow() {
        assert_eq!(c(".github/workflows/ci.yml"), Some(Surface::WorkflowFile));
    }
    #[test]
    fn tasks_json() {
        assert_eq!(c(".vscode/tasks.json"), Some(Surface::TasksJson));
    }
    #[test]
    fn git_hook() {
        assert_eq!(c(".husky/pre-commit"), Some(Surface::GitHook));
    }
    #[test]
    fn propagation_script() {
        assert_eq!(c("temp_auto_push.bat"), Some(Surface::PropagationScript));
        assert_eq!(c("scripts/deploy.sh"), Some(Surface::PropagationScript));
    }
    #[test]
    fn binary_asset() {
        assert_eq!(c("public/fonts/fa-solid-400.woff2"), Some(Surface::BinaryAsset));
    }
    #[test]
    fn svg_is_not_asset() {
        assert_eq!(c("logo.svg"), None);
    }
    #[test]
    fn readme_is_none() {
        assert_eq!(c("README.md"), None);
    }
    #[test]
    fn excludes_build_dirs() {
        assert!(is_excluded_path(Path::new("dist/postcss.config.js")));
        assert!(is_excluded_path(Path::new("apps/api/.output/server/index.mjs")));
        assert!(is_excluded_path(Path::new(".nuxt/dist/server/server.mjs")));

        assert!(is_excluded_path(Path::new("app.min.js")));
        assert!(!is_excluded_path(Path::new("src/index.js")));
    }

    #[test]
    fn lifecycle_extracts_only_lifecycle_keys() {
        let pj = r#"{"scripts":{"build":"vite build","postinstall":"node setup_bun.js","test":"jest"}}"#;
        let got = lifecycle_scripts(pj);
        assert_eq!(got, vec![("postinstall".to_string(), "node setup_bun.js".to_string())]);
    }
    #[test]
    fn lifecycle_handles_no_scripts() {
        assert!(lifecycle_scripts(r#"{"name":"x"}"#).is_empty());
        assert!(lifecycle_scripts("not json").is_empty());
    }
    #[test]
    fn derived_targets_bare_and_relative() {
        assert_eq!(derived_targets("node setup_bun.js"), vec!["setup_bun.js"]);
        assert_eq!(derived_targets("bun ./scripts/x.mjs && echo ok"), vec!["scripts/x.mjs"]);
        assert!(derived_targets("node --version").is_empty());
        assert!(derived_targets("vite build").is_empty());
    }

    #[test]
    fn derived_targets_windows_backslash() {
        assert_eq!(derived_targets(r"node .\dist\setup_bun.js"), vec!["dist/setup_bun.js"]);
    }
}
