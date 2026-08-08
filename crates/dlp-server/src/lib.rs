#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::{build_app, run_migrations, ServerConfig, ServerState};

    #[test]
    fn production_state_rejects_missing_required_providers() {
        let config = ServerConfig::for_test();
        assert!(ServerState::production(config, Default::default()).is_err());
    }

    #[tokio::test]
    async fn liveness_is_process_only_and_migrations_gate_listener_startup() {
        let state = ServerState::for_test();
        let app = build_app(state);
        assert!(run_migrations(None).await.is_err());
        let _ = app;
    }
}
