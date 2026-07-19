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
}
