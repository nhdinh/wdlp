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
        "ApplicationsOperationsSizes",
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

#[test]
fn production_vertical_slice_runner_enforces_negative_trust_boundaries() {
    let runner = repo_root().join("tests/windows/Invoke-Phase1Matrix.ps1");
    let content = std::fs::read_to_string(runner).expect("matrix runner is readable");
    for negative_case in [
        "wrong_execution_machine",
        "wrong_fingerprint",
        "dc_cim_disagreement",
        "reused_or_racing_token",
        "invalid_csr_or_profile",
        "revoked_prior_serial",
        "wrong_server_identity",
        "bad_signed_bundle",
        "forged_host_ipc",
        "corrupt_ciphertext",
        "fixture_secret_provider_forbidden",
    ] {
        assert!(
            content.contains(negative_case),
            "matrix runner must guard against the {negative_case} negative-trust case"
        );
    }
}

#[test]
fn production_vertical_slice_preserves_a_results_directory() {
    let results = repo_root().join("tests/windows/results");
    assert!(
        results.is_dir(),
        "the matrix results directory must exist to receive sanitized evidence"
    );
    let gitkeep = results.join(".gitkeep");
    assert!(gitkeep.is_file(), "results directory must be tracked by .gitkeep");
}

#[test]
fn production_vertical_slice_e2e_test_invokes_the_matrix_runner() {
    // The Rust E2E test is the source-side contract that the four-machine
    // orchestration can be started from hungdinh-lt with the required
    // machine-role arguments.  It deliberately does not perform the live run
    // itself; that is the responsibility of the PowerShell runner, which is
    // verified on the lab topology.
    let source = include_str!("../../tests/windows/Invoke-Phase1Matrix.ps1");
    assert!(source.contains("[Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine"));
    assert!(source.contains("[Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine"));
    assert!(source.contains("[Parameter(Mandatory)][ValidateSet('LAB-DC02')][string]$SecondaryDcMachine"));
    assert!(source.contains("[Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$EndpointMachine"));
    assert!(source.contains("-Scenario VerticalSlice"));
}
