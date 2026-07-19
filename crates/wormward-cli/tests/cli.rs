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
