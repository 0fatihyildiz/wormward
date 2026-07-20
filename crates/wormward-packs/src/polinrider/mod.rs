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
        assert!(pack
            .manifest
            .target_files
            .contains(&"postcss.config.mjs".to_string()));
        assert!(pack.manifest.content_signatures.len() >= 3);
        assert!(pack.analyzer.is_some());
    }
}
