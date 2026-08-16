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
    for required_contract in [
        "Test-Phase1PrivilegeManifest",
        "LAB-CLIENT01",
        "LAB-DC01",
        "LAB-DC02",
        "LAB-SERVER01",
        "VerticalSlice",
        "Runtime",
    ] {
        assert!(
            runner.contains(required_contract),
            "matrix runner must enforce the {required_contract} production contract"
        );
    }
}
