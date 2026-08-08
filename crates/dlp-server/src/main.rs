use dlp_server::{ProductionProviders, ServerConfig, run_server};

#[tokio::main]
async fn main() -> Result<(), dlp_server::ServerError> {
    let config = ServerConfig::from_environment()?;
    run_server(config, ProductionProviders::default()).await
}
