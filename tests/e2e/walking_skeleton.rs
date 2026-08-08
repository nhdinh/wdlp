use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

fn trace_root() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    PathBuf::from("target").join(format!("phase1-smoke-{unique}"))
}

#[test]
fn tracer_happy_path() {
    let root = trace_root();
    let database_url = format!("sqlite:{}", root.join("tracer.sqlite").display());
    let report = dlpctl::run_phase1_smoke(&database_url, &root).expect("tracer succeeds");

    assert_eq!(report.output_hash, report.input_hash);
    assert!(report.marker_scan_was_non_vacuous);
    assert!(report.backing_scan_clean);
    assert!(root.join("tracer.sqlite").is_file());

    fs::remove_dir_all(root).expect("remove task-owned test data");
}
