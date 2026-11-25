use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use log::{debug, error, info, warn};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use rustls_pki_types::pem::PemObject;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::config::Config;

/// Storage for ACME challenge tokens
pub type ChallengeStore = Arc<Mutex<HashMap<String, String>>>;

/// Certificate and private key pair
#[derive(Debug)]
pub struct TlsCertificate {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl TlsCertificate {
    /// Create a rustls ServerConfig from this certificate
    pub fn into_server_config(self) -> Result<ServerConfig> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert_chain, self.private_key)
            .map_err(|e| anyhow!("Failed to create TLS server config: {}", e))?;

        Ok(config)
    }
}

/// Generate a self-signed certificate for testing/development
pub fn generate_self_signed_cert(domain: &str) -> Result<(String, String)> {
    // Use the simple generation function from rcgen 0.14
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![domain.to_string()])?;

    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();

    info!("Generated self-signed certificate for domain: {}", domain);
    Ok((cert_pem, key_pem))
}

/// Parse PEM certificate and key into rustls types
pub fn parse_cert_and_key(cert_pem: &str, key_pem: &str) -> Result<TlsCertificate> {
    // Parse certificate chain using new rustls-pki-types API
    let cert_chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

    if cert_chain.is_empty() {
        return Err(anyhow!("No certificates found in PEM data"));
    }

    // Parse private key using new rustls-pki-types API
    let private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

    Ok(TlsCertificate {
        cert_chain,
        private_key,
    })
}

/// Load certificate from config (supports both Let's Encrypt and file-based certs)
pub async fn load_cert_from_config(config: &Config) -> Result<Option<TlsCertificate>> {
    if config.use_letsencrypt_cert {
        // Load from Let's Encrypt config
        if let Some(le_config) = &config.lets_encrypt {
            if let (Some(cert_b64), Some(key_b64)) = (&le_config.cert, &le_config.key) {
                // Decode base64
                let cert_pem =
                    String::from_utf8(general_purpose::STANDARD.decode(cert_b64).map_err(
                        |e| anyhow!("Failed to decode Let's Encrypt certificate: {}", e),
                    )?)?;

                let key_pem =
                    String::from_utf8(general_purpose::STANDARD.decode(key_b64).map_err(|e| {
                        anyhow!("Failed to decode Let's Encrypt private key: {}", e)
                    })?)?;

                let tls_cert = parse_cert_and_key(&cert_pem, &key_pem)?;
                debug!("Loaded TLS certificate from Let's Encrypt config");
                return Ok(Some(tls_cert));
            }
        }
        debug!("use_letsencrypt_cert is true but no Let's Encrypt certificate found in config");
        return Ok(None);
    }

    // Load from file paths
    let cert_path = config.cert_path.as_deref().unwrap_or("cert.pem");
    let key_path = config.cert_key_path.as_deref().unwrap_or("key.pem");

    // Check if files exist
    if !tokio::fs::try_exists(cert_path).await.unwrap_or(false) {
        debug!("Certificate file not found at: {}", cert_path);
        return Ok(None);
    }
    if !tokio::fs::try_exists(key_path).await.unwrap_or(false) {
        debug!("Key file not found at: {}", key_path);
        return Ok(None);
    }

    // Read certificate and key from files
    let cert_pem = tokio::fs::read_to_string(cert_path)
        .await
        .map_err(|e| anyhow!("Failed to read certificate file {}: {}", cert_path, e))?;

    let key_pem = tokio::fs::read_to_string(key_path)
        .await
        .map_err(|e| anyhow!("Failed to read key file {}: {}", key_path, e))?;

    let tls_cert = parse_cert_and_key(&cert_pem, &key_pem)?;
    info!("Loaded TLS certificate from file: {}", cert_path);
    Ok(Some(tls_cert))
}

/// Save certificate to config (base64 encoded)
pub async fn save_cert_to_config(
    config: &mut Config,
    cert_pem: &str,
    key_pem: &str,
    expiry: jiff::Timestamp,
) -> Result<()> {
    // Encode to base64
    let cert_b64 = general_purpose::STANDARD.encode(cert_pem.as_bytes());
    let key_b64 = general_purpose::STANDARD.encode(key_pem.as_bytes());

    // Update or create Let's Encrypt config
    if let Some(le_config) = &mut config.lets_encrypt {
        le_config.cert = Some(cert_b64);
        le_config.key = Some(key_b64);
        le_config.expiry = Some(expiry.to_string());
    } else {
        config.lets_encrypt = Some(crate::config::LetsEncryptConfig {
            cert: Some(cert_b64),
            key: Some(key_b64),
            expiry: Some(expiry.to_string()),
            acme_email: config
                .lets_encrypt
                .as_ref()
                .and_then(|le| le.acme_email.clone()),
        });
    }

    Ok(())
}

/// Load or create an ACME account
async fn get_or_create_account(
    acme_account_file: &str,
    contact_email: &str,
    use_staging: bool,
) -> Result<Account> {
    let directory_url = if use_staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };

    // Try to load existing account credentials
    if let Ok(account_data) = tokio::fs::read_to_string(acme_account_file).await {
        if let Ok(credentials) = serde_json::from_str::<AccountCredentials>(&account_data) {
            info!("📂 Found existing ACME account credentials");
            info!("🔄 Loading account from: {}", acme_account_file);
            let account = Account::builder()
                .map_err(|e| anyhow!("Failed to create account builder: {}", e))?
                .from_credentials(credentials)
                .await?;
            info!("✅ Successfully loaded existing ACME account");
            return Ok(account);
        } else {
            warn!("⚠️  Found account file but couldn't parse credentials, will create new account");
        }
    } else {
        info!("📝 No existing ACME account found");
    }

    // Create new account
    info!("🆕 Creating new ACME account...");
    info!("   Email: {}", contact_email);
    info!(
        "   Directory: {}",
        if use_staging { "Staging" } else { "Production" }
    );
    let (account, credentials) = Account::builder()
        .map_err(|e| anyhow!("Failed to create account builder: {}", e))?
        .create(
            &NewAccount {
                contact: &[&format!("mailto:{}", contact_email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_string(),
            None,
        )
        .await?;

    // Save account credentials for future use
    info!("💾 Saving account credentials...");
    let credentials_json = serde_json::to_string_pretty(&credentials)?;
    tokio::fs::write(acme_account_file, credentials_json).await?;
    info!("✅ ACME account created and saved to {}", acme_account_file);
    info!("📌 This account will be reused for future certificate requests");

    Ok(account)
}

/// Request certificate from Let's Encrypt using ACME protocol
///
/// This function:
/// 1. Creates or loads an ACME account
/// 2. Creates a new certificate order
/// 3. Handles HTTP-01 challenges
/// 4. Generates and submits a CSR
/// 5. Retrieves the issued certificate
///
/// # Arguments
/// * `domain` - The domain name to get a certificate for
/// * `challenge_store` - Storage for HTTP-01 challenge tokens
/// * `use_staging` - Use Let's Encrypt staging environment (for testing)
/// * `contact_email` - Contact email for the ACME account
/// * `acme_account_file` - Path to store ACME account credentials
pub async fn request_letsencrypt_cert(
    domain: &str,
    challenge_store: ChallengeStore,
    use_staging: bool,
    contact_email: &str,
    acme_account_file: &str,
) -> Result<(String, String, jiff::Timestamp)> {
    info!("═══════════════════════════════════════════════════════════════");
    info!("🔐 Starting Let's Encrypt ACME Certificate Request");
    info!("═══════════════════════════════════════════════════════════════");
    info!("📋 Domain: {}", domain);
    info!("📧 Contact Email: {}", contact_email);
    info!(
        "🌍 Environment: {}",
        if use_staging {
            "Staging (Testing)"
        } else {
            "Production"
        }
    );
    info!("📂 Account File: {}", acme_account_file);

    // Validate domain (no localhost or local TLDs for real certificates)
    if !use_staging && (domain.contains("localhost") || domain.ends_with(".local")) {
        warn!("⚠️  Cannot request production certificate for localhost/local domain");
        warn!("⚠️  Falling back to self-signed certificate");
        info!("📝 Self-signed certificates are only for development/testing");
        let (cert_pem, key_pem) = generate_self_signed_cert(domain)?;
        let expiry = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(365 * 24);
        return Ok((cert_pem, key_pem, expiry));
    }

    // Step 1: Get or create ACME account
    info!("───────────────────────────────────────────────────────────────");
    info!("Step 1/8: Creating or loading ACME account...");
    let account = match get_or_create_account(acme_account_file, contact_email, use_staging).await {
        Ok(acc) => {
            info!("✅ ACME account ready");
            acc
        }
        Err(e) => {
            error!("❌ Failed to get/create ACME account: {}", e);
            warn!("⚠️  Falling back to self-signed certificate");
            let (cert_pem, key_pem) = generate_self_signed_cert(domain)?;
            let expiry = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(365 * 24);
            return Ok((cert_pem, key_pem, expiry));
        }
    };

    // Step 2: Create a new order
    info!("───────────────────────────────────────────────────────────────");
    info!("Step 2/8: Creating certificate order...");
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let order_request = NewOrder::new(&identifiers);
    let mut order = account.new_order(&order_request).await?;

    info!("✅ Certificate order created for domain: {}", domain);

    // Step 3: Get authorizations and handle challenges
    info!("───────────────────────────────────────────────────────────────");
    info!("Step 3/8: Processing domain authorization challenges...");
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;

        match authz.status {
            instant_acme::AuthorizationStatus::Valid => {
                info!("✓ Authorization already valid, skipping");
                continue;
            }
            instant_acme::AuthorizationStatus::Pending => {
                info!("⏳ Processing pending authorization");
            }
            instant_acme::AuthorizationStatus::Invalid => {
                error!("❌ Authorization is invalid");
                return Err(anyhow!("Authorization is invalid"));
            }
            _ => {
                warn!("Unexpected authorization status: {:?}", authz.status);
            }
        }

        // Find HTTP-01 challenge
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| anyhow!("No HTTP-01 challenge found"))?;

        // Get the challenge token and key authorization
        let token = challenge.token.to_string();
        let key_auth = challenge.key_authorization();

        info!("🔑 Setting up HTTP-01 challenge");
        info!("   Token: {}", token);
        debug!("   Key Authorization: {}", key_auth.as_str());

        // Store the challenge for the HTTP server to serve
        {
            let mut store = challenge_store.lock().await;
            store.insert(token.clone(), key_auth.as_str().to_string());
        }

        // Notify Let's Encrypt that we're ready
        info!("📤 Notifying Let's Encrypt that challenge is ready...");
        challenge.set_ready().await?;
        info!("✅ Challenge ready notification sent");
        info!("⏳ Waiting for Let's Encrypt to validate challenge (checking every 2 seconds)...");
    }

    // Step 5: Wait for order to be ready
    info!("───────────────────────────────────────────────────────────────");
    info!("Step 5/8: Waiting for order to be ready...");
    let status = order
        .poll_ready(&instant_acme::RetryPolicy::default())
        .await?;

    if status != OrderStatus::Ready {
        error!("❌ Order did not become ready: {:?}", status);
        return Err(anyhow!("Order did not become ready: {:?}", status));
    }

    info!("✅ Order is ready!");

    // Step 6: Finalize the order (this generates the private key and CSR)
    info!("───────────────────────────────────────────────────────────────");
    info!("Step 6/8: Generating CSR and finalizing order...");
    let private_key_pem = order.finalize().await?;
    info!("✅ Order finalized, private key generated");

    // Step 7: Poll for certificate
    info!("───────────────────────────────────────────────────────────────");
    info!("Step 7/8: Waiting for certificate issuance...");
    let cert_chain_pem = order
        .poll_certificate(&instant_acme::RetryPolicy::default())
        .await?;
    info!("✅ Certificate issued!");

    // Step 8: Parse expiry from certificate
    info!("───────────────────────────────────────────────────────────────");
    info!("Step 8/8: Certificate obtained successfully!");
    let expiry = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(90 * 24); // Let's Encrypt certs valid for 90 days

    info!("═══════════════════════════════════════════════════════════════");
    info!("✅ Let's Encrypt Certificate Request Complete!");
    info!("═══════════════════════════════════════════════════════════════");
    info!("📜 Domain: {}", domain);
    info!("📅 Expiry: {}", expiry);
    info!("🔄 Will auto-renew 30 days before expiry");
    Ok((cert_chain_pem, private_key_pem, expiry))
}

/// HTTP-01 challenge handler for serving ACME challenge tokens
pub async fn serve_acme_challenge(token: &str, challenge_store: ChallengeStore) -> Result<String> {
    let store = challenge_store.lock().await;

    if let Some(challenge_response) = store.get(token) {
        debug!("Serving ACME challenge for token: {}", token);
        Ok(challenge_response.clone())
    } else {
        warn!("ACME challenge token not found: {}", token);
        Err(anyhow!("Challenge token not found"))
    }
}

/// Start the certificate renewal background task
pub fn start_renewal_task(
    config: Config,
    challenge_store: ChallengeStore,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(certificate_renewal_task(config, challenge_store))
}

/// Background task to check and renew certificates
pub async fn certificate_renewal_task(mut config: Config, challenge_store: ChallengeStore) {
    info!("Starting certificate renewal background task");

    let mut interval = tokio::time::interval(Duration::from_secs(12 * 60 * 60)); // Check every 12 hours

    loop {
        // Check certificate status (first iteration runs immediately, subsequent ones wait for interval)
        if config.is_cert_renewal_needed() {
            info!("Certificate renewal needed, initiating renewal process");

            if let Ok(domain) = config.get_domain() {
                // Use staging for localhost/development, production for real domains
                let use_staging = domain.contains("localhost") || domain.ends_with(".local");

                // Get contact email from config or use a default
                let contact_email = config
                    .lets_encrypt
                    .as_ref()
                    .and_then(|le| le.acme_email.as_deref())
                    .unwrap_or("admin@example.com");
                let acme_account_file = "data/acme_account.json";

                // Ensure data directory exists
                if let Err(e) = tokio::fs::create_dir_all("data").await {
                    error!("Failed to create data directory: {}", e);
                    continue;
                }

                match request_letsencrypt_cert(
                    &domain,
                    challenge_store.clone(),
                    use_staging,
                    contact_email,
                    acme_account_file,
                )
                .await
                {
                    Ok((cert_pem, key_pem, expiry)) => {
                        match save_cert_to_config(&mut config, &cert_pem, &key_pem, expiry).await {
                            Ok(()) => {
                                info!("Certificate renewed successfully");

                                // Save config to disk to persist the new expiry date
                                match crate::config::save_config(&config).await {
                                    Ok(()) => {
                                        info!("💾 Certificate expiry saved to config.yaml");
                                    }
                                    Err(e) => {
                                        error!("Failed to save config after renewal: {}", e);
                                    }
                                }

                                // TODO: Notify main application to reload certificate
                                // This could be done via a channel or by restarting the TLS listener
                            }
                            Err(e) => {
                                error!("Failed to save renewed certificate: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to renew certificate: {}", e);
                        warn!("Will retry on next check");
                    }
                }
            } else {
                warn!("Cannot renew certificate: invalid domain in base_url");
            }
        } else {
            debug!("Certificate renewal not needed");
        }

        // Wait for next check interval
        interval.tick().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert() {
        let domain = "test.example.com";
        let result = generate_self_signed_cert(domain);

        assert!(result.is_ok());
        let (cert_pem, key_pem) = result.unwrap();

        // Verify PEM format
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_pem.ends_with("-----END PRIVATE KEY-----\n"));

        // Verify we can parse the certificate
        let tls_cert = parse_cert_and_key(&cert_pem, &key_pem);
        assert!(tls_cert.is_ok());
    }

    #[test]
    fn test_parse_cert_and_key() {
        // Generate a test certificate
        let (cert_pem, key_pem) = generate_self_signed_cert("test.example.com").unwrap();

        let result = parse_cert_and_key(&cert_pem, &key_pem);
        assert!(result.is_ok());

        let tls_cert = result.unwrap();
        assert!(!tls_cert.cert_chain.is_empty());

        // Test that we can create a server config
        let server_config = tls_cert.into_server_config();
        assert!(server_config.is_ok());
    }

    #[tokio::test]
    async fn test_save_and_load_cert_config() {
        let mut config = Config {
            base_url: "https://example.com".to_string(),
            port: 3000,
            secret_key: "test-key".to_string(),
            admin: None,
            remove_kofi: false,
            tls_port: Some(3443),
            cert_path: None,
            cert_key_path: None,
            use_letsencrypt_cert: true,
            lets_encrypt: None,
        };

        // Generate test certificate
        let (cert_pem, key_pem) = generate_self_signed_cert("test.example.com").unwrap();

        // Set up Let's Encrypt config with test certificate
        config.lets_encrypt = Some(crate::config::LetsEncryptConfig {
            cert: Some(base64::engine::general_purpose::STANDARD.encode(cert_pem.as_bytes())),
            key: Some(base64::engine::general_purpose::STANDARD.encode(key_pem.as_bytes())),
            expiry: Some(jiff::Timestamp::now().to_string()),
            acme_email: None,
        });

        // Test loading (now async)
        let loaded_cert = load_cert_from_config(&config).await;
        assert!(loaded_cert.is_ok());
        assert!(loaded_cert.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_acme_challenge_store() {
        let challenge_store: ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
        let token = "test-token";
        let response = "test-response";

        // Store challenge
        {
            let mut store = challenge_store.lock().await;
            store.insert(token.to_string(), response.to_string());
        }

        // Serve challenge
        let result = serve_acme_challenge(token, challenge_store.clone()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), response);

        // Test missing token
        let missing_result = serve_acme_challenge("missing-token", challenge_store).await;
        assert!(missing_result.is_err());
    }

    #[tokio::test]
    async fn test_certificate_renewal_detection() {
        use crate::config::Config;

        // Create a config with an expired certificate
        let (cert_pem, key_pem) = generate_self_signed_cert("test.example.com").unwrap();
        let expired_time = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24); // Already expired
        let near_expiry_time = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24); // Expires in 24 hours

        let config_expired = Config {
            base_url: "https://test.example.com".to_string(),
            port: 3000,
            secret_key: "test-key".to_string(),
            admin: None,
            remove_kofi: false,
            tls_port: Some(3443),
            cert_path: None,
            cert_key_path: None,
            use_letsencrypt_cert: true,
            lets_encrypt: Some(crate::config::LetsEncryptConfig {
                cert: Some(base64::engine::general_purpose::STANDARD.encode(cert_pem.as_bytes())),
                key: Some(base64::engine::general_purpose::STANDARD.encode(key_pem.as_bytes())),
                expiry: Some(expired_time.to_string()),
                acme_email: None,
            }),
        };

        let mut config_near_expiry = config_expired.clone();
        if let Some(ref mut le_config) = config_near_expiry.lets_encrypt {
            le_config.expiry = Some(near_expiry_time.to_string());
        }

        // Test that expired certificate is detected as needing renewal
        assert!(config_expired.is_cert_renewal_needed());

        // Test that near-expiry certificate is detected as needing renewal
        assert!(config_near_expiry.is_cert_renewal_needed());

        // Verify that the config has TLS cert configured
        assert!(config_expired.has_tls_cert());
    }

    #[tokio::test]
    async fn test_letsencrypt_fallback_for_localhost() {
        let challenge_store: ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
        let domain = "localhost";
        let contact_email = "test@example.com";
        let acme_account_file = "/tmp/acme_test_account.json";

        // Test that localhost falls back to self-signed cert even in production mode
        let result = request_letsencrypt_cert(
            domain,
            challenge_store,
            false, // production mode
            contact_email,
            acme_account_file,
        )
        .await;

        assert!(result.is_ok());
        let (cert_pem, key_pem, expiry) = result.unwrap();

        // Verify we got valid PEM data
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        // Verify expiry is in the future
        assert!(expiry > jiff::Timestamp::now());

        // Verify we can parse the certificate
        let tls_cert = parse_cert_and_key(&cert_pem, &key_pem);
        assert!(tls_cert.is_ok());
    }
}
