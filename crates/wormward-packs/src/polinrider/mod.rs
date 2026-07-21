mod analyzer;

pub use analyzer::{polinrider_fingerprint, PolinriderAnalyzer};

use wormward_core::{Pack, PackManifest};

const MANIFEST: &str = include_str!("pack.yaml");

pub fn polinrider_pack() -> Pack {
    let manifest: PackManifest =
        PackManifest::from_yaml(MANIFEST).expect("built-in polinrider manifest must parse");
    Pack {
        manifest,
        analyzer: Some(Box::new(PolinriderAnalyzer)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_and_has_expected_fields() {
        let pack = polinrider_pack();
        assert_eq!(pack.manifest.id, "polinrider");
        // Config coverage is now version-independent globs (`*.config.{js,cjs,mjs,ts}`), not a
        // per-name allowlist — so a new wave's config target (metro/app/drizzle/…) is covered
        // without a pack edit. postcss.config.mjs is matched by `*.config.mjs` at scan time.
        assert!(pack.manifest.target_files.contains(&"*.config.mjs".to_string()));
        assert!(pack.manifest.target_files.contains(&"*.config.ts".to_string()));
        // Non-`*.config` injection hosts the family also uses stay explicit.
        assert!(pack.manifest.target_files.contains(&"seed.ts".to_string()));
        assert!(pack.manifest.target_files.contains(&"migrate.ts".to_string()));
        assert!(pack.manifest.content_signatures.len() >= 3);
        assert!(pack.analyzer.is_some());
    }
}
