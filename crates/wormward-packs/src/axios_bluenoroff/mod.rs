use wormward_core::{Pack, PackManifest};

const MANIFEST: &str = include_str!("pack.yaml");

pub fn axios_bluenoroff_pack() -> Pack {
    let manifest: PackManifest =
        PackManifest::from_yaml(MANIFEST).expect("built-in axios-bluenoroff manifest must parse");
    Pack { manifest, analyzer: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_pins_malicious_axios_versions_only() {
        let pack = axios_bluenoroff_pack();
        assert_eq!(pack.manifest.id, "axios-bluenoroff");
        let axios = pack.manifest.bad_packages["npm"].iter().find(|p| p.name == "axios").unwrap();
        assert_eq!(axios.versions, vec!["1.14.1".to_string(), "0.30.4".to_string()]);
        // A clean axios (no version pin match) must never be flagged by name.
        assert!(pack.manifest.bad_npm_packages.is_empty());
        assert!(pack.manifest.content_signatures.iter().any(|s| s.value == "142.11.206.73"));
    }
}
