use dlp_server::{
    ProductionProviders, ServerConfig, check_environment_file, run_migrations_from_environment,
    run_server,
};

#[tokio::main]
async fn main() -> Result<(), dlp_server::ServerError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--check-config")
    {
        let env_file = arguments
            .windows(2)
            .find_map(|pair| (pair[0] == "--env-file").then_some(pair[1].as_str()))
            .ok_or(dlp_server::ServerError::InvalidEnvironmentFile)?;
        return check_environment_file(env_file);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--migrate-only")
    {
        return run_migrations_from_environment().await;
    }
    let config = ServerConfig::from_environment()?;
    let providers = ProductionProviders::from_environment(&config)?;
    run_server(config, providers).await
}
