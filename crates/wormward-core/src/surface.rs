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

const CONFIG_STEMS: &[&str] = &[
    "postcss", "vite", "next", "tailwind", "eslint", "svelte", "nuxt", "webpack", "rollup",
    "babel", "astro", "vitest", "jest", "remix", "vue", "gridsome",
];
const CONFIG_EXTS: &[&str] = &["js", "mjs", "cjs", "ts"];
// `App.js` lowercases to `app.js`.
const ENTRY_BASENAMES: &[&str] = &["index.js", "app.js", "truffle.js"];
const PROP_EXTS: &[&str] = &["bat", "cmd", "sh", "ps1"];
const ASSET_EXTS: &[&str] = &["woff", "woff2", "ttf", "otf", "eot", "png", "jpg", "jpeg", "gif", "ico"];
const EXCLUDED_DIRS: &[&str] = &["dist", "build", ".next", "out", "coverage", "vendor"];

const LIFECYCLE_KEYS: &[&str] = &[
    "preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "prepack",
    "postpack",
];

fn basename(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Build-output dirs and minified files are excluded from the capability pass;
/// legitimate obfuscated/minified code lives here, not in source config.
pub fn is_excluded_path(path: &Path) -> bool {
    if basename(path).contains(".min.") {
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
        if let Some(base) = stem.strip_suffix(".config") {
            if CONFIG_STEMS.contains(&base) {
                return Some(Surface::ConfigFile);
            }
        }
        if stem == "gatsby-config" || stem == "gatsby-node" {
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
            r#"(?:^|[\s;&|])(?:node|bun|ts-node|tsx)\s+(?:--?\S+\s+)*['"]?((?:\.?/)?[\w.@-][\w./@-]*\.(?:c|m)?js)"#,
        )
        .unwrap()
    })
}

/// Find local `node ./X.js` targets in an auto-run command / workflow step /
/// tasks.json body. The one hop that lets the engine reach a dropped payload.
pub fn derived_targets(command: &str) -> Vec<String> {
    derived_re()
        .captures_iter(command)
        .map(|c| c[1].trim_start_matches("./").to_string())
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
    fn config_nested() {
        assert_eq!(c("packages/web/vite.config.ts"), Some(Surface::ConfigFile));
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
}
