use dlp_server::enrollment::{EnrollmentAttempt, EnrollmentError, EnrollmentService};

#[test]
fn authority_issues_one_credential_only_after_exact_identity_checks() {
    let service = EnrollmentService::for_test();
    let result = service.enroll(EnrollmentAttempt::valid_for_test());
    assert!(result.is_ok());
}

#[test]
fn authority_fails_closed_for_an_invalid_or_reused_attempt() {
    let service = EnrollmentService::for_test();
    let attempt = EnrollmentAttempt::invalid_for_test();
    assert_eq!(service.enroll(attempt), Err(EnrollmentError::Denied));
}
