use wormward_core::{Pack, PackManifest};

const MANIFEST: &str = include_str!("pack.yaml");

pub fn shai_hulud_pack() -> Pack {
    let manifest: PackManifest =
        PackManifest::from_yaml(MANIFEST).expect("built-in shai-hulud manifest must parse");
    Pack { manifest, analyzer: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_and_has_expected_fields() {
        let pack = shai_hulud_pack();
        assert_eq!(pack.manifest.id, "shai-hulud");
        assert!(pack
            .manifest
            .artifacts
            .iter()
            .any(|a| a.path == "setup_bun.js"));
        assert!(pack
            .manifest
            .target_files
            .contains(&"package.json".to_string()));
        assert!(pack.analyzer.is_none());
    }
}
