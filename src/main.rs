use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use log::{debug, error, info, warn};
use rand::prelude::*;
use rusty_paseto::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use tokio_util::io::ReaderStream;

#[derive(Parser)]
#[command(name = "ryansend")]
#[command(about = "A file sharing tool to generate and host authenticated links to download files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long, default_value = "http://localhost:3000")]
        base_url: String,
        #[arg(long, default_value = "3000")]
        port: u16,
    },
    Start,
    Share {
        path: PathBuf,
        #[arg(long, default_value = "3600")]
        expires_in: u64, // seconds, default 1 hour
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    base_url: String,
    port: u16,
    secret_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims {
    path: String,
    exp: DateTime<Utc>,
}

#[derive(Clone)]
struct AppState {
    config: Config,
}

#[derive(Deserialize)]
struct DownloadQuery {
    token: String,
}

async fn load_config() -> Result<Config> {
    let config_content = fs::read_to_string("config.yaml").await.map_err(|_| {
        anyhow!("Failed to read config.yaml. Make sure it exists in the current directory")
    })?;

    let mut config: Config = serde_yaml::from_str(&config_content)
        .map_err(|e| anyhow!("Failed to parse config.yaml: {}", e))?;

    // Override base_url with environment variable if present
    if let Ok(env_base_url) = std::env::var("RYANSEND_BASE_URL") {
        config.base_url = env_base_url;
    }

    // Override port with environment variable if present
    if let Ok(env_port) = std::env::var("RYANSEND_PORT") {
        config.port = env_port.parse().unwrap_or(config.port);
    }

    Ok(config)
}

async fn generate_token(
    config: &Config,
    file_path: &PathBuf,
    expires_in_seconds: u64,
) -> Result<String> {
    // Verify the file exists
    if !file_path.exists() {
        return Err(anyhow!("File does not exist: {}", file_path.display()));
    }

    let now = Utc::now();
    let exp = now + Duration::seconds(expires_in_seconds as i64);

    let claims = TokenClaims {
        path: file_path.to_string_lossy().to_string(),
        exp,
    };

    // Parse PASERK key from config
    let key = PasetoSymmetricKey::<V4, Local>::try_from_paserk_str(&config.secret_key)
        .map_err(|e| anyhow!("Invalid PASERK key in config: {}", e))?;

    // Build PASETO token with claims
    let token = PasetoBuilder::<V4, Local>::default()
        .set_claim(ExpirationClaim::try_from(claims.exp.to_rfc3339())?)
        .set_claim(CustomClaim::try_from(("path", claims.path.clone()))?)
        .build(&key)?;

    Ok(token)
}

async fn verify_token_and_get_path(secret_key: &str, token: &str) -> Result<String> {
    // Parse PASERK key from config
    let key = PasetoSymmetricKey::<V4, Local>::try_from_paserk_str(secret_key)
        .map_err(|e| anyhow!("Invalid PASERK key in config: {}", e))?;

    // Parse and validate PASETO token
    let parsed_token = PasetoParser::<V4, Local>::default().parse(token, &key)?;

    // Extract the path from the custom claim
    let path = parsed_token["path"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing or invalid path claim"))?;

    Ok(path.to_string())
}

async fn download_handler(
    State(state): State<AppState>,
    Query(params): Query<DownloadQuery>,
) -> Result<Response, StatusCode> {
    debug!(
        "Download request with token: {}...",
        &params.token[..std::cmp::min(20, params.token.len())]
    );

    let file_path = match verify_token_and_get_path(&state.config.secret_key, &params.token).await {
        Ok(path) => path,
        Err(e) => {
            warn!("Token verification failed: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let path = PathBuf::from(&file_path);

    if !path.exists() {
        warn!("File not found: {}", file_path);
        return Err(StatusCode::NOT_FOUND);
    }

    let file = match fs::File::open(&path).await {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to open file {}: {}", file_path, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");

    // Get file size for logging and content-length header
    let file_size = match file.metadata().await {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            error!("Failed to get file metadata for {}: {}", file_path, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!(
        "File downloaded: '{}' ({} bytes) from path: {}",
        file_name, file_size, file_path
    );

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file_name))
            .unwrap_or(HeaderValue::from_static("attachment")),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&file_size.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );

    Ok(response)
}

async fn init_config(base_url: String, port: u16) -> Result<()> {
    let mut key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut key_bytes);

    // Create PASETO key and convert to PASERK
    let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(key_bytes));
    let paserk_string = key.to_paserk_string();

    let config = Config {
        base_url: base_url.clone(),
        port,
        secret_key: paserk_string.clone(),
    };

    if tokio::fs::try_exists("config.yaml").await.unwrap_or(false) {
        return Err(anyhow!(
            "config.yaml already exists. Remove it first or use a different directory."
        ));
    }

    let config_content =
        serde_yaml::to_string(&config).map_err(|e| anyhow!("Failed to serialize config: {}", e))?;

    fs::write("config.yaml", config_content)
        .await
        .map_err(|e| anyhow!("Failed to write config.yaml: {}", e))?;

    info!("✅ Created config.yaml with new PASETO key");
    info!("Base URL: {}", base_url);
    debug!("PASERK: {}", paserk_string);

    Ok(())
}

async fn run_server(config: Config) -> Result<()> {
    let state = AppState {
        config: config.clone(),
    };

    let app = Router::new()
        .route("/download", get(download_handler))
        .with_state(state);

    info!("Starting server on http://0.0.0.0:{}", config.port);

    let bind_address = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&bind_address)
        .await
        .map_err(|e| anyhow!("Failed to bind to port {}: {}", config.port, e))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow!("Server error: {}", e))?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { base_url, port } => {
            init_config(base_url, port).await?;
            return Ok(());
        }
        Commands::Start => {
            if !tokio::fs::try_exists("config.yaml").await.unwrap_or(false) {
                info!("Config file not found. Creating new configuration...");
                let base_url = std::env::var("RYANSEND_BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:3000".to_string());
                let port = std::env::var("RYANSEND_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(3000);
                init_config(base_url, port).await?;
            }

            let config = load_config().await?;
            info!(
                "Loaded config - base_url: {}, port: {}",
                config.base_url, config.port
            );
            run_server(config).await?;
        }
        _ => {
            let config = load_config().await?;
            debug!(
                "Loaded config - base_url: {}, port: {}",
                config.base_url, config.port
            );

            match cli.command {
                Commands::Init { .. } => {
                    unreachable!() // Already handled above
                }
                Commands::Start => {
                    unreachable!() // Already handled above
                }
                Commands::Share { path, expires_in } => {
                    match generate_token(&config, &path, expires_in).await {
                        Ok(token) => {
                            let download_url = format!(
                                "{}/download?token={}",
                                config.base_url.trim_end_matches('/'),
                                token
                            );
                            println!("Share URL: {}", download_url);
                            println!("Token expires in {} seconds", expires_in);
                            info!(
                                "Generated share token for file: {} (expires in {}s)",
                                path.display(),
                                expires_in
                            );
                        }
                        Err(e) => {
                            error!("Error generating token: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
