use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

#[test]
fn production_vertical_slice_has_a_fail_closed_matrix_runner() {
    let runner = repo_root().join("tests/windows/Invoke-Phase1Matrix.ps1");
    assert!(
        runner.is_file(),
        "the production-provider matrix runner must exist before a vertical slice can run"
    );

    let runner = std::fs::read_to_string(runner).expect("matrix runner is readable");
    let deployer = repo_root().join("scripts/lab/Invoke-Client01Runtime.ps1");
    assert!(
        deployer.is_file(),
        "the approved LAB-CLIENT01 runtime deployer must exist before a vertical slice can run"
    );
    let deployer = std::fs::read_to_string(deployer).expect("runtime deployer is readable");
    for required_contract in [
        "Test-Phase1PrivilegeManifest",
        "LAB-CLIENT01",
        "LAB-DC01",
        "LAB-DC02",
        "LAB-SERVER01",
        "VerticalSlice",
        "Runtime",
        "dlp-drive-host.exe",
        "C:\\Program Files\\DLP\\dlp-drive-host.exe",
        "Get-Phase1Sha256",
        "Get-RemoteSha256",
    ] {
        assert!(
            runner.contains(required_contract) || deployer.contains(required_contract),
            "matrix runner must enforce the {required_contract} production contract"
        );
    }
}
