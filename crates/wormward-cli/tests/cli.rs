use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wormward"))
}

#[test]
fn scan_infected_exits_1_and_reports() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("victim");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::write(
        repo.join("postcss.config.mjs"),
        "export default {};\nvar q=(\"rmcej%otb%\",2857687);",
    )
    .unwrap();

    let out = bin().arg("scan").arg(tmp.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("polinrider"));
}

#[test]
fn scan_clean_exits_0() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("clean");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::write(repo.join("postcss.config.mjs"), "export default {};\n").unwrap();

    let out = bin().arg("scan").arg(tmp.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn scan_json_output_is_valid_json() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("victim");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::write(
        repo.join("postcss.config.mjs"),
        "export default {};\nvar q=(\"rmcej%otb%\",2857687);",
    )
    .unwrap();

    let out = bin()
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg(tmp.path())
        .output()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!value["findings"].as_array().unwrap().is_empty());
}

#[test]
fn scan_nonexistent_path_exits_2() {
    let out = bin()
        .arg("scan")
        .arg("/no/such/wormward/path/xyz123")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn scan_online_enriches_from_mock_and_keeps_exit_1() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/check-malicious");
        then.status(200).json_body(serde_json::json!({
            "malicious": true, "osm_url": "https://osm/x", "threat_count": 1,
            "details": { "threat_id": "t", "severity_level": "high", "description": "d" }
        }));
    });

    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("victim");
    fs::create_dir_all(repo.join(".git")).unwrap();
    // A malicious-npm finding (polinrider bad_npm_packages) to enrich.
    fs::write(
        repo.join("package.json"),
        r#"{"dependencies":{"tailwindcss-style-animate":"^1.1.6"}}"#,
    )
    .unwrap();

    let out = bin()
        .env("OSM_BASE_URL", server.base_url())
        .env("OSM_API_KEY", "osm_test")
        .arg("scan")
        .arg("--online")
        .arg("--format")
        .arg("json")
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1)); // local finding still drives exit 1
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let has_online = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["online"]["malicious"] == true);
    assert!(has_online);
}

#[test]
fn scan_online_without_token_exits_2() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("r/.git")).unwrap();
    let out = bin()
        .env_remove("OSM_API_KEY")
        .arg("scan")
        .arg("--online")
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn check_subcommand_reports_malicious() {
    use httpmock::prelude::*;
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET)
            .path("/check-malicious")
            .query_param("report_type", "package");
        then.status(200).json_body(serde_json::json!({
            "malicious": true, "osm_url": "https://osm/y", "threat_count": 1
        }));
    });
    let out = bin()
        .env("OSM_BASE_URL", server.base_url())
        .env("OSM_API_KEY", "osm_test")
        .arg("check")
        .arg("--type")
        .arg("package")
        .arg("--ecosystem")
        .arg("npm")
        .arg("evilpkg")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("malicious: true"));
}

#[test]
fn scan_deep_flags_payload_on_other_branch() {
    use std::process::Command as Cmd;
    fn git(repo: &std::path::Path, args: &[&str]) {
        Cmd::new("git").arg("-C").arg(repo).args(args)
            .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status().unwrap();
    }
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("proj");
    fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("postcss.config.mjs"), "export default {};").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "clean"]);
    git(&repo, &["checkout", "-q", "-b", "evil"]);
    fs::write(repo.join("postcss.config.mjs"), "var q=(\"rmcej%otb%\",2857687);").unwrap();
    git(&repo, &["commit", "-q", "-am", "payload"]);
    git(&repo, &["checkout", "-q", "main"]);

    // Plain scan of the working tree (main) is clean.
    let plain = bin().arg("scan").arg(tmp.path()).output().unwrap();
    assert_eq!(plain.status.code(), Some(0));
    // Deep scan finds it on 'evil'.
    let deep = bin().arg("scan").arg("--deep").arg(tmp.path()).output().unwrap();
    assert_eq!(deep.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&deep.stdout).contains("branch: evil"));
}

#[test]
fn clean_dry_run_reports_without_changing() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("v");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();

    let out = bin().arg("clean").arg(tmp.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(1)); // dry-run with actions
    assert!(String::from_utf8_lossy(&out.stdout).contains("would delete"));
    assert!(repo.join("temp_auto_push.bat").exists()); // untouched
}

#[test]
fn clean_apply_deletes_and_backs_up_then_restore() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("v");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::write(repo.join("temp_auto_push.bat"), "@echo off").unwrap();

    let out = bin().arg("clean").arg("--apply").arg(tmp.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(!repo.join("temp_auto_push.bat").exists());
    assert!(repo.join(".wormward-backup").exists());

    let out2 = bin().arg("restore").arg(tmp.path()).output().unwrap();
    assert_eq!(out2.status.code(), Some(0));
    assert!(repo.join("temp_auto_push.bat").exists());
}
