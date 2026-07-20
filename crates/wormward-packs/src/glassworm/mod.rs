use wormward_core::{Pack, PackManifest};

const MANIFEST: &str = include_str!("pack.yaml");

pub fn glassworm_pack() -> Pack {
    let manifest: PackManifest =
        PackManifest::from_yaml(MANIFEST).expect("built-in glassworm manifest must parse");
    Pack { manifest, analyzer: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_with_expected_packages() {
        let pack = glassworm_pack();
        assert_eq!(pack.manifest.id, "glassworm");
        assert!(pack.manifest.bad_npm_packages.contains(&"@aifabrix/miso-client".to_string()));
        // Risky-name packages are community-tier so they can't hard-fail a clean install.
        let npm = &pack.manifest.bad_packages["npm"];
        assert!(npm
            .iter()
            .any(|p| p.name == "react-native-country-select"
                && p.confidence == wormward_core::matchers::Confidence::Community));
        assert!(pack.analyzer.is_none());
    }
}
