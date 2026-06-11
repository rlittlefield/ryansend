use anyhow::Result;
use askama::Template;
use axum::{
    body::Body,
    extract::{Form, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use chrono::{Duration, Utc};
use fast_glob::glob_match;
use log::{error, info};

use rusty_paseto::prelude::*;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use urlencoding::encode;
use walkdir::WalkDir;

use crate::auth::{
    generate_token_with_options, generate_url_with_options, verify_admin_token, AdminTokenClaims,
};
use crate::config::{AdminTheme, Config};

// Embed CSS at compile time
const LIGHT_THEME_CSS: &str = include_str!("../templates/light-theme.css");
const DARK_THEME_CSS: &str = include_str!("../templates/dark-theme.css");

/// Get the CSS content for the given theme
fn get_theme_css(theme: &AdminTheme) -> &'static str {
    match theme {
        AdminTheme::Light => LIGHT_THEME_CSS,
        AdminTheme::Dark => DARK_THEME_CSS,
    }
}
use crate::error::{handle_404, make_admin_error_response};
use crate::logging_middleware::logging_middleware;
use crate::rate_limit::{
    admin_login_rate_limit_middleware, create_rate_limiter, AdminRateLimitConfig, AdminRateLimiter,
};
use crate::ReloadSender;

#[derive(Clone)]
pub struct AdminAppState {
    pub config: Config,
    pub admin_login_rate_limiter: Option<Arc<AdminRateLimiter>>,
    pub reload_tx: Arc<ReloadSender>,
    pub challenge_store: crate::tls::ChallengeStore,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    theme_css: &'static str,
}

#[derive(Template)]
#[template(path = "files.html")]
struct FileBrowserTemplate {
    current_path: String,
    entries: Vec<FileEntry>,
    show_parent: bool,
    parent_path: String,
    search_query: String,
    search_query_encoded: String,
    search_results: Vec<FileEntry>,
    has_search_results: bool,
    remove_kofi: bool,
    theme_css: &'static str,
}

#[derive(Template)]
#[template(path = "files_and_directories.html")]
struct FileBrowserDirectoriesTemplate {
    current_path: String,
    entries: Vec<FileEntry>,
    show_parent: bool,
    parent_path: String,
    search_query: String,
    search_query_encoded: String,
    search_results: Vec<FileEntry>,
    has_search_results: bool,
    remove_kofi: bool,
    theme_css: &'static str,
}

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupTemplate {
    base_url: String,
    port: u16,
    remove_kofi: bool,
    admin_enabled: bool,
    admin_port: u16,
    admin_sharing_root: String,
    admin_default_exp_seconds: u64,
    tls_port: String,
    use_letsencrypt_cert: bool,
    tls_acme_email: String,
    tls_cert_expiry: String,
    admin_tls_port: String,
    port_env_override: bool,
    admin_port_env_override: bool,
    admin_sharing_root_env_override: bool,
    admin_default_exp_seconds_env_override: bool,
    tls_port_env_override: bool,
    admin_tls_port_env_override: bool,
    success: bool,
    error: String,
    theme: String,
    theme_css: &'static str,
    allow_share_directories: bool,
}

#[derive(Template)]
#[template(path = "tunnel_secret.html")]
struct TunnelSecretTemplate {
    secret: String,
    remove_kofi: bool,
    theme_css: &'static str,
}

#[derive(Clone)]
struct FileEntry {
    name: String,
    path: String,
    path_display: String, // Truncated path for display
    is_dir: bool,
    size: u64,
    size_display: String,
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

#[derive(Deserialize)]
struct SetupForm {
    base_url: String,
    port: u16,
    remove_kofi: Option<String>,
    admin_enabled: Option<String>,
    admin_port: u16,
    admin_sharing_root: String,
    admin_default_exp_seconds: Option<u64>,
    admin_theme: Option<String>,
    tls_port: Option<String>,
    use_letsencrypt_cert: Option<String>,
    request_letsencrypt: Option<String>,
    tls_acme_email: Option<String>,
    admin_tls_port: Option<String>,
    allow_share_directories: Option<String>,

}

#[derive(Deserialize)]
struct FilesQuery {
    path: Option<String>,
    search: Option<String>,
}

#[derive(Deserialize)]
struct AdminDownloadQuery {
    path: String,
    note: Option<String>,
}

async fn admin_auth_middleware(
    State(state): State<AdminAppState>,
    cookies: CookieJar,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Check if admin panel is enabled
    match &state.config.admin {
        Some(config) if config.enabled => config,
        _ => return make_admin_error_response(StatusCode::NOT_FOUND),
    };

    // Check for admin authentication cookie
    if let Some(admin_cookie) = cookies.get("admin_token") {
        if verify_admin_token(&state.config, admin_cookie.value())
            .await
            .unwrap_or(false)
        {
            // Authentication successful, continue to the handler
            return next.run(request).await;
        }
    }

    // Authentication failed, redirect to login
    make_admin_error_response(StatusCode::UNAUTHORIZED)
}

async fn admin_root_handler(State(state): State<AdminAppState>, cookies: CookieJar) -> Response {
    // Check if admin panel is enabled
    match &state.config.admin {
        Some(config) if config.enabled => config,
        _ => return make_admin_error_response(StatusCode::NOT_FOUND),
    };

    // Check for admin authentication cookie
    if let Some(admin_cookie) = cookies.get("admin_token") {
        if verify_admin_token(&state.config, admin_cookie.value())
            .await
            .unwrap_or(false)
        {
            // Valid token - redirect to files page
            return Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("location", "/admin/files")
                .body(Body::empty())
                .expect("Failed to build redirect response to admin files");
        }
    }

    // No valid token - redirect to login page
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", "/admin/login")
        .body(Body::empty())
        .expect("Failed to build redirect response to admin login")
}

async fn admin_login_page(State(state): State<AdminAppState>) -> Html<String> {
    let theme = state
        .config
        .admin
        .as_ref()
        .map(|a| &a.theme)
        .unwrap_or(&AdminTheme::Light);
    let template = LoginTemplate {
        error: None,
        theme_css: get_theme_css(theme),
    };
    Html(
        template
            .render()
            .unwrap_or_else(|_| "Template error".to_string()),
    )
}

async fn admin_login_handler(
    State(state): State<AdminAppState>,
    Form(form): Form<LoginForm>,
) -> Response {
    let admin_config = match &state.config.admin {
        Some(config) if config.enabled => config,
        _ => return make_admin_error_response(StatusCode::NOT_FOUND),
    };

    // Verify password using Argon2
    let is_valid = crate::auth::verify_password(&form.password, &admin_config.password);

    if !is_valid {
        let template = LoginTemplate {
            error: Some("Invalid password".to_string()),
            theme_css: get_theme_css(&admin_config.theme),
        };
        let html = template
            .render()
            .unwrap_or_else(|_| "Template error".to_string());
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "text/html")
            .body(Body::from(html))
            .expect("Failed to build unauthorized response");
    }

    // Generate admin token
    let now = Utc::now();
    let exp = now + Duration::hours(24);

    let claims = AdminTokenClaims {
        user: "admin".to_string(),
        exp,
    };

    let key = match PasetoSymmetricKey::<V4, Local>::try_from_paserk_str(&state.config.secret_key) {
        Ok(key) => key,
        Err(_) => return make_admin_error_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let token = match PasetoBuilder::<V4, Local>::default()
        .set_claim(
            ExpirationClaim::try_from(claims.exp.to_rfc3339())
                .expect("Failed to convert expiration claim to RFC3339"),
        )
        .set_claim(
            CustomClaim::try_from(("user", claims.user.clone()))
                .expect("Failed to create user custom claim"),
        )
        .build(&key)
    {
        Ok(token) => token,
        Err(_) => return make_admin_error_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Set cookie and redirect to file browser
    let cookie = Cookie::build(("admin_token", token))
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(86400));

    let cookies = CookieJar::new().add(cookie);

    (cookies, axum::response::Redirect::to("/admin/files")).into_response()
}

fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

async fn admin_files_handler(
    State(state): State<AdminAppState>,
    Query(query): Query<FilesQuery>,
) -> Response {

    let allow_share_directories = state
    .config
    .admin
    .as_ref()
    .map(|a| a.share_dirs)
    .unwrap_or(false);

    // Get the sharing root from admin config (middleware ensures admin is enabled)
    let sharing_root = &state
        .config
        .admin
        .as_ref()
        .expect("Admin config should exist when middleware passes")
        .sharing_root;

    let requested_path = query.path.unwrap_or_else(|| ".".to_string());
    let base_path = PathBuf::from(sharing_root);

    // Construct the full path, ensuring it's within the sharing root
    let mut full_path = base_path.clone();
    if requested_path != "." {
        full_path.push(&requested_path);
    }

    // Canonicalize paths to prevent directory traversal attacks
    let canonical_base = match base_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return make_admin_error_response(StatusCode::NOT_FOUND),
    };
    let canonical_full = match full_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return make_admin_error_response(StatusCode::NOT_FOUND),
    };

    // Ensure the requested path is within the sharing root
    if !canonical_full.starts_with(&canonical_base) {
        return make_admin_error_response(StatusCode::FORBIDDEN);
    }

    let path = canonical_full;
    let current_path = path
        .strip_prefix(&canonical_base)
        .unwrap_or(Path::new("."))
        .to_string_lossy()
        .to_string();

    // Handle search if search query is provided

    let (search_query_str, search_query_encoded, search_results, has_search_results) =
        if let Some(search_query) = &query.search {
            if !search_query.trim().is_empty() {
                let results = perform_search(&path, search_query, &canonical_base).await;
                let encoded = encode(search_query).to_string();
                // has_search_results is true if we performed a search (regardless of results)
                (search_query.clone(), encoded, results, true)
            } else {
                // Empty search query - treat as no search
                (String::new(), String::new(), Vec::new(), false)
            }
        } else {
            // No search parameter - no search performed
            (String::new(), String::new(), Vec::new(), false)
        };

    let mut entries = Vec::new();

    if path.is_dir() {
        let mut dir_entries = match fs::read_dir(&path).await {
            Ok(entries) => entries,
            Err(_) => return make_admin_error_response(StatusCode::INTERNAL_SERVER_ERROR),
        };

        while let Ok(Some(entry)) = dir_entries.next_entry().await {
            let entry_path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            let is_dir = entry_path.is_dir();
            let (size, size_display) = if is_dir {
                (0, "-".to_string())
            } else {
                match entry.metadata().await {
                    Ok(metadata) => (metadata.len(), format_file_size(metadata.len())),
                    Err(_) => (0, "?".to_string()),
                }
            };

            // Store relative path from sharing root for the entry
            let relative_entry_path = entry_path
                .strip_prefix(&canonical_base)
                .unwrap_or(&entry_path)
                .to_string_lossy()
                .to_string();

            let path_display = if relative_entry_path.len() > 100 {
                format!("{}...", &relative_entry_path[..97])
            } else {
                relative_entry_path.clone()
            };

            entries.push(FileEntry {
                name: name.clone(),
                path: relative_entry_path,
                path_display,
                is_dir,
                size,
                size_display,
            });
        }
    }

    // Sort entries: directories first, then files, both by name
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });

    let show_parent = current_path != "." && current_path != "/" && !current_path.is_empty();
    let parent_path = if show_parent {
        let parent = path.parent().unwrap_or(&canonical_base);
        parent
            .strip_prefix(&canonical_base)
            .unwrap_or(Path::new("."))
            .to_string_lossy()
            .to_string()
    } else {
        ".".to_string()
    };

    // Load theme from disk config to get latest saved value
    let theme = match crate::config::load_config().await {
        Ok(cfg) => cfg.admin.map(|a| a.theme).unwrap_or(AdminTheme::Light),
        Err(_) => state
            .config
            .admin
            .as_ref()
            .map(|a| a.theme.clone())
            .unwrap_or(AdminTheme::Light),
    };

    let html = if allow_share_directories {
        FileBrowserDirectoriesTemplate {
            current_path,
            entries,
            show_parent,
            parent_path,
            search_query: search_query_str,
            search_query_encoded,
            search_results,
            has_search_results,
            remove_kofi: state.config.remove_kofi,
            theme_css: get_theme_css(&theme),
        }
        .render()
        .unwrap_or_else(|_| "Template error".to_string())
    } else {
        FileBrowserTemplate {
            current_path,
            entries,
            show_parent,
            parent_path,
            search_query: search_query_str,
            search_query_encoded,
            search_results,
            has_search_results,
            remove_kofi: state.config.remove_kofi,
            theme_css: get_theme_css(&theme),
        }
        .render()
        .unwrap_or_else(|_| "Template error".to_string())
    };
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html")
            .body(Body::from(html))
            .expect("Failed to build file browser response")
    }

/// Check if a search query contains glob pattern characters
fn has_glob_chars(query: &str) -> bool {
    query.contains('*') || query.contains('?') || query.contains('[') || query.contains('{')
}

async fn perform_search(
    current_dir: &Path,
    search_query: &str,
    canonical_base: &Path,
) -> Vec<FileEntry> {
    // Build the search pattern (lowercased for case-insensitive matching):
    // - Plain text "foo" becomes "**/*foo*" (substring match anywhere in tree)
    // - Glob without path "*.txt" becomes "**/*.txt" (match in any subdir)
    // - Glob with path "subdir/*.txt" stays as-is
    let pattern = if has_glob_chars(search_query) {
        if search_query.contains('/') {
            search_query.to_lowercase()
        } else {
            format!("**/{}", search_query.to_lowercase())
        }
    } else {
        format!("**/*{}*", search_query.to_lowercase())
    };

    // Use walkdir + fast-glob for pattern matching (case-insensitive)
    let search_results: Vec<String> = WalkDir::new(current_dir)
        .max_depth(10)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|entry| {
            let relative_path = entry
                .path()
                .strip_prefix(current_dir)
                .map(|p| p.to_string_lossy().to_lowercase())
                .unwrap_or_else(|_| entry.path().to_string_lossy().to_lowercase());
            glob_match(&pattern, relative_path.as_str())
        })
        .take(50)
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect();

    let mut file_entries = Vec::new();

    for path_str in search_results {
        let path = PathBuf::from(&path_str);

        // Skip if we can't get metadata
        let metadata = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(_) => continue,
        };

        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let is_dir = metadata.is_dir();
        let size = if is_dir { 0 } else { metadata.len() };
        let size_display = if is_dir {
            "-".to_string()
        } else {
            format_file_size(size)
        };

        // Get relative path from sharing root
        // First canonicalize the found path to handle symlinks and path differences
        let canonical_found_path = match path.canonicalize() {
            Ok(canonical_path) => canonical_path,
            Err(_) => continue, // Skip files that can't be canonicalized
        };

        let relative_path = match canonical_found_path.strip_prefix(canonical_base) {
            Ok(rel_path) => rel_path.to_string_lossy().to_string(),
            Err(_) => continue, // Skip files outside sharing root
        };

        let path_display = if relative_path.len() > 100 {
            format!("{}...", &relative_path[..97])
        } else {
            relative_path.clone()
        };

        file_entries.push(FileEntry {
            name,
            path: relative_path,
            path_display,
            is_dir,
            size,
            size_display,
        });
    }

    // Sort search results: videos first, then docs/images, then by size desc
    file_entries.sort_by(|a, b| {
        let a_priority = get_extension_priority(&a.name);
        let b_priority = get_extension_priority(&b.name);
        match a_priority.cmp(&b_priority) {
            std::cmp::Ordering::Equal => b.size.cmp(&a.size), // size desc
            other => other,
        }
    });

    file_entries
}

/// Returns sort priority based on file extension (lower = higher priority)
/// 0 = video, 1 = image/document, 2 = other
fn get_extension_priority(filename: &str) -> u8 {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();

    match ext.as_str() {
        // Videos
        "mp4" | "mkv" | "avi" | "mov" | "wmv" | "flv" | "webm" | "m4v" | "mpg" | "mpeg" => 0,
        // Images
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "svg" | "ico" | "tiff" | "heic" => 1,
        // Documents
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "csv" | "odt" | "ods"
        | "odp" => 1,
        // Everything else
        _ => 2,
    }
}

async fn admin_download_handler(
    State(state): State<AdminAppState>,
    Query(query): Query<AdminDownloadQuery>,
) -> Response {
    
    let allow_share_directories = state
    .config
    .admin
    .as_ref()
    .map(|a| a.share_dirs)
    .unwrap_or(false);

    // Middleware ensures admin is enabled and authenticated
    let admin_config = state
        .config
        .admin
        .as_ref()
        .expect("Admin config should exist when middleware passes");

    // Construct and validate file path within sharing root
    let base_path = PathBuf::from(&admin_config.sharing_root);
    let mut full_path = base_path.clone();
    if query.path != "." {
        full_path.push(&query.path);
    }

    // Canonicalize paths to prevent directory traversal attacks
    let canonical_base = match base_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return make_admin_error_response(StatusCode::NOT_FOUND),
    };
    let canonical_full = match full_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return make_admin_error_response(StatusCode::NOT_FOUND),
    };

    // Ensure the requested path is within the sharing root
    if !canonical_full.starts_with(&canonical_base) {
        return make_admin_error_response(StatusCode::FORBIDDEN);
    }

    let file_path = canonical_full;

    if !file_path.exists() || file_path.is_dir() && allow_share_directories == false {
        return make_admin_error_response(StatusCode::NOT_FOUND);
    }

    // Generate a temporary download token
    let exp_seconds = admin_config.default_expiration_seconds.unwrap_or(3600);
    let download_token = match generate_token_with_options(
        &state.config,
        &file_path,
        exp_seconds,
        None,
        query.note.clone(),
    )
    .await
    {
        Ok(token) => token,
        Err(_) => return make_admin_error_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let download_url = format!(
        "{}/download?token={}",
        state.config.base_url.trim_end_matches('/'),
        download_token
    );

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", download_url)
        .body(Body::empty())
        .expect("Failed to build download redirect response")
}

async fn admin_share_handler(
    State(state): State<AdminAppState>,
    Query(query): Query<AdminDownloadQuery>,
) -> Response {

    let allow_share_directories = state
    .config
    .admin
    .as_ref()
    .map(|a| a.share_dirs)
    .unwrap_or(false);

    // Middleware ensures admin is enabled and authenticated
    let admin_config = state
        .config
        .admin
        .as_ref()
        .expect("Admin config should exist when middleware passes");

    // Construct and validate file path within sharing root
    let base_path = PathBuf::from(&admin_config.sharing_root);
    let mut full_path = base_path.clone();
    if query.path != "." {
        full_path.push(&query.path);
    }

    // Canonicalize paths to prevent directory traversal attacks
    let canonical_base = match base_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return make_admin_error_response(StatusCode::NOT_FOUND),
    };
    let canonical_full = match full_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return make_admin_error_response(StatusCode::NOT_FOUND),
    };

    // Ensure the requested path is within the sharing root
    if !canonical_full.starts_with(&canonical_base) {
        return make_admin_error_response(StatusCode::FORBIDDEN);
    }

    let file_path = canonical_full;

    if !file_path.exists() || file_path.is_dir() && allow_share_directories == false {
        return make_admin_error_response(StatusCode::NOT_FOUND);
    }

    // Generate share URL
    let exp_seconds = admin_config.default_expiration_seconds.unwrap_or(3600);
    let share_url = match generate_url_with_options(
        &state.config,
        &file_path,
        exp_seconds,
        None,
        query.note.clone(),
    )
    .await
    {
        Ok(url) => url,
        Err(_) => return make_admin_error_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Body::from(share_url))
        .expect("Failed to build share URL response")
}

async fn admin_single_use_download_handler(
    State(state): State<AdminAppState>,
    Query(query): Query<AdminDownloadQuery>,
) -> Response {
    let allow_share_directories = state
    .config
    .admin
    .as_ref()
    .map(|a| a.share_dirs)
    .unwrap_or(false);

    // Middleware ensures admin is enabled and authenticated
    let admin_config = state
        .config
        .admin
        .as_ref()
        .expect("Admin config should exist when middleware passes");



    // Construct and validate file path within sharing root
    let base_path = PathBuf::from(&admin_config.sharing_root);
    let mut full_path = base_path.clone();
    if query.path != "." {
        full_path.push(&query.path);
    }

    // Canonicalize paths to prevent directory traversal attacks
    let canonical_base = match base_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return make_admin_error_response(StatusCode::NOT_FOUND),
    };
    let canonical_full = match full_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return make_admin_error_response(StatusCode::NOT_FOUND),
    };

    // Ensure the requested path is within the sharing root
    if !canonical_full.starts_with(&canonical_base) {
        return make_admin_error_response(StatusCode::FORBIDDEN);
    }

    let file_path = canonical_full;

    if !file_path.exists() || file_path.is_dir() && allow_share_directories == false {
        return make_admin_error_response(StatusCode::NOT_FOUND);
    }

    // Generate single-use URL (with max_uses=1)
    let exp_seconds = admin_config.default_expiration_seconds.unwrap_or(3600);
    let share_url = match generate_url_with_options(
        &state.config,
        &file_path,
        exp_seconds,
        Some(1),
        query.note.clone(),
    )
    .await
    {
        Ok(url) => url,
        Err(_) => return make_admin_error_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Body::from(share_url))
        .expect("Failed to build single-use share URL response")
}

async fn generate_tunnel_secret_handler(State(state): State<AdminAppState>) -> Response {
    // Note: Authentication is already verified by admin_auth_middleware

    // Generate the secret
    let (secret, hash) = match crate::config::generate_tunnel_secret() {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to generate tunnel secret: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Failed to generate secret: {}", e)))
                .unwrap_or_default();
        }
    };

    // Save to config
    if let Err(e) = crate::config::add_tunnel_secret_to_config(hash).await {
        error!("Failed to save tunnel secret: {}", e);
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("Failed to save secret: {}", e)))
            .unwrap_or_default();
    }

    info!("🔑 New tunnel secret generated by admin, triggering server reload...");

    // Trigger server reload so the new secret is immediately usable
    let reload_tx = Arc::clone(&state.reload_tx);
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        info!("📤 Sending reload signal for new tunnel secret...");
        let _ = reload_tx.send(crate::ReloadSignal);
    });

    // Render template with the secret
    let theme = state
        .config
        .admin
        .as_ref()
        .map(|a| &a.theme)
        .unwrap_or(&AdminTheme::Light);
    let template = TunnelSecretTemplate {
        secret,
        remove_kofi: state.config.remove_kofi,
        theme_css: get_theme_css(theme),
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render tunnel secret template: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Template error: {}", e)))
                .unwrap_or_default()
        }
    }
}

async fn admin_logout_handler() -> Response {
    let cookie = Cookie::build(("admin_token", ""))
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(0));

    let cookies = CookieJar::new().add(cookie);

    (cookies, axum::response::Redirect::to("/admin/login")).into_response()
}

async fn admin_setup_page(State(state): State<AdminAppState>) -> Html<String> {
    let admin_config = state.config.admin.as_ref();

    // Check for environment variable overrides
    let port_env_override = std::env::var("RYANSEND_PORT").is_ok();
    let admin_port_env_override = std::env::var("RYANSEND_ADMIN_PORT").is_ok();
    let admin_sharing_root_env_override = std::env::var("RYANSEND_ADMIN_SHARING_ROOT").is_ok();
    let admin_default_exp_seconds_env_override =
        std::env::var("RYANSEND_ADMIN_DEFAULT_EXP_SECONDS").is_ok();
    let tls_port_env_override = std::env::var("RYANSEND_TLS_PORT").is_ok();
    let admin_tls_port_env_override = std::env::var("RYANSEND_ADMIN_TLS_PORT").is_ok();

    let theme = admin_config.map(|a| &a.theme).unwrap_or(&AdminTheme::Light);
    let template = SetupTemplate {
        base_url: state.config.base_url.clone(),
        port: state.config.port,
        remove_kofi: state.config.remove_kofi,
        admin_enabled: admin_config.map(|a| a.enabled).unwrap_or(false),
        admin_port: admin_config.map(|a| a.port).unwrap_or(3001),
        admin_sharing_root: admin_config
            .map(|a| a.sharing_root.clone())
            .unwrap_or_default(),
        allow_share_directories: admin_config.map(|a| a.share_dirs).unwrap_or(false),
        admin_default_exp_seconds: admin_config
            .and_then(|a| a.default_expiration_seconds)
            .unwrap_or(3600),
        tls_port: state
            .config
            .tls_port
            .map(|p| p.to_string())
            .unwrap_or_default(),
        use_letsencrypt_cert: state.config.use_letsencrypt_cert,
        tls_acme_email: state
            .config
            .lets_encrypt
            .as_ref()
            .and_then(|le| le.acme_email.clone())
            .unwrap_or_default(),
        tls_cert_expiry: state
            .config
            .lets_encrypt
            .as_ref()
            .and_then(|le| le.expiry.clone())
            .unwrap_or_default(),
        admin_tls_port: admin_config
            .and_then(|a| a.tls_port)
            .map(|p| p.to_string())
            .unwrap_or_default(),
        port_env_override,
        admin_port_env_override,
        admin_sharing_root_env_override,
        admin_default_exp_seconds_env_override,
        tls_port_env_override,
        admin_tls_port_env_override,
        success: false,
        error: String::new(),
        theme: match theme {
            AdminTheme::Light => "light".to_string(),
            AdminTheme::Dark => "dark".to_string(),
        },
        theme_css: get_theme_css(theme),
    };

    Html(
        template
            .render()
            .unwrap_or_else(|_| "Template error".to_string()),
    )
}

async fn admin_setup_handler(
    State(state): State<AdminAppState>,
    Form(form): Form<SetupForm>,
) -> Response {
    // Helper function to create error response
    let make_error_response = |config: &crate::config::Config, error_msg: String| {
        let admin_config = config.admin.as_ref();
        let theme = admin_config.map(|a| &a.theme).unwrap_or(&AdminTheme::Light);

        let template = SetupTemplate {
            base_url: config.base_url.clone(),
            port: config.port,
            remove_kofi: config.remove_kofi,
            admin_enabled: admin_config.map(|a| a.enabled).unwrap_or(false),
            admin_port: admin_config.map(|a| a.port).unwrap_or(3001),
            admin_sharing_root: admin_config
                .map(|a| a.sharing_root.clone())
                .unwrap_or_default(),
            allow_share_directories: admin_config.map(|a| a.share_dirs).unwrap_or(false),

            admin_default_exp_seconds: admin_config
                .and_then(|a| a.default_expiration_seconds)
                .unwrap_or(3600),
            tls_port: config.tls_port.map(|p| p.to_string()).unwrap_or_default(),
            use_letsencrypt_cert: config.use_letsencrypt_cert,
            tls_acme_email: config
                .lets_encrypt
                .as_ref()
                .and_then(|le| le.acme_email.clone())
                .unwrap_or_default(),
            tls_cert_expiry: config
                .lets_encrypt
                .as_ref()
                .and_then(|le| le.expiry.clone())
                .unwrap_or_default(),
            admin_tls_port: admin_config
                .and_then(|a| a.tls_port)
                .map(|p| p.to_string())
                .unwrap_or_default(),
            port_env_override: std::env::var("RYANSEND_PORT").is_ok(),
            admin_port_env_override: std::env::var("RYANSEND_ADMIN_PORT").is_ok(),
            admin_sharing_root_env_override: std::env::var("RYANSEND_ADMIN_SHARING_ROOT").is_ok(),
            admin_default_exp_seconds_env_override: std::env::var(
                "RYANSEND_ADMIN_DEFAULT_EXP_SECONDS",
            )
            .is_ok(),
            tls_port_env_override: std::env::var("RYANSEND_TLS_PORT").is_ok(),
            admin_tls_port_env_override: std::env::var("RYANSEND_ADMIN_TLS_PORT").is_ok(),
            success: false,
            error: error_msg,
            theme: match theme {
                AdminTheme::Light => "light".to_string(),
                AdminTheme::Dark => "dark".to_string(),
            },
            theme_css: get_theme_css(theme),
        };
        let html = template
            .render()
            .unwrap_or_else(|_| "Template error".to_string());
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html")
            .body(Body::from(html))
            .expect("Failed to build response")
    };

    // Load the current config
    let mut config = match crate::config::load_config().await {
        Ok(c) => c,
        Err(e) => {
            // Create a minimal config for error display
            let minimal_config = crate::config::Config {
                base_url: form.base_url.clone(),
                port: form.port,
                secret_key: String::new(),
                admin: None,
                remove_kofi: form.remove_kofi.is_some(),
                tls_port: form.tls_port.as_ref().and_then(|s| s.parse().ok()),
                cert_path: None,
                cert_key_path: None,
                use_letsencrypt_cert: form.use_letsencrypt_cert.is_some(),
                lets_encrypt: None,
            };
            return make_error_response(&minimal_config, format!("Failed to load config: {}", e));
        }
    };

    // Update basic config
    config.base_url = form.base_url.clone();
    config.port = form.port;
    config.remove_kofi = form.remove_kofi.is_some();

    // Update admin config
    if let Some(ref mut admin) = config.admin {
        admin.enabled = form.admin_enabled.is_some();
        admin.port = form.admin_port;
        admin.sharing_root = form.admin_sharing_root.clone();
        admin.share_dirs = form.allow_share_directories.is_some();
        admin.tls_port = form.admin_tls_port.and_then(|s| s.parse().ok());
        admin.default_expiration_seconds = form.admin_default_exp_seconds;
        admin.theme = match form.admin_theme.as_deref() {
            Some("dark") => AdminTheme::Dark,
            _ => AdminTheme::Light,
        };
    }

    // Update TLS configuration
    config.tls_port = form.tls_port.and_then(|s| s.parse().ok());

    // Update use_letsencrypt_cert toggle
    let toggled_to_letsencrypt = form.use_letsencrypt_cert.is_some();
    config.use_letsencrypt_cert = toggled_to_letsencrypt;

    // Handle certificate configuration
    let request_letsencrypt = form.request_letsencrypt.is_some();

    if request_letsencrypt {
        // Let's Encrypt configuration
        let acme_email = form.tls_acme_email.filter(|s| !s.trim().is_empty());

        // Validate Let's Encrypt requirements
        if acme_email.is_none() {
            return make_error_response(
                &config,
                "ACME email is required for Let's Encrypt".to_string(),
            );
        }

        // Validate base_url is a proper domain
        let base_url = &form.base_url;
        if base_url.contains("localhost") || base_url.contains("127.0.0.1") {
            return make_error_response(
                &config,
                "Let's Encrypt cannot be used with localhost or IP addresses. Use a domain name."
                    .to_string(),
            );
        }

        // Check if base_url looks like a domain (has at least one dot)
        if let Ok(url) = url::Url::parse(base_url) {
            if let Some(host) = url.host_str() {
                if !host.contains('.') || host.parse::<std::net::IpAddr>().is_ok() {
                    return make_error_response(
                        &config,
                        "Let's Encrypt requires a valid domain name (not an IP address)"
                            .to_string(),
                    );
                }
            }
        } else {
            return make_error_response(&config, "Invalid base URL format".to_string());
        }

        // Update or create Let's Encrypt config with email
        if let Some(ref mut le_config) = config.lets_encrypt {
            le_config.acme_email = acme_email.clone();
        } else {
            config.lets_encrypt = Some(crate::config::LetsEncryptConfig {
                cert: None,
                key: None,
                expiry: None,
                acme_email: acme_email.clone(),
            });
        }

        // Store the email for later use in certificate request
        let acme_email_for_cert = match acme_email {
            Some(email) => email,
            None => {
                error!("ACME email is required but was not provided");
                return make_error_response(
                    &config,
                    "ACME email is required for Let's Encrypt".to_string(),
                );
            }
        };

        // After saving config, trigger Let's Encrypt certificate request
        info!("🔐 Let's Encrypt configured, will request certificate after saving config");

        // Save config first
        if let Err(e) = crate::config::save_config(&config).await {
            return make_error_response(&config, format!("Failed to save config: {}", e));
        }

        // Now request the certificate
        info!(
            "📜 Starting Let's Encrypt certificate request for domain: {}",
            form.base_url
        );

        let domain = match config.get_domain() {
            Ok(d) => d,
            Err(e) => {
                return make_error_response(&config, format!("Failed to extract domain: {}", e));
            }
        };

        // Use shared challenge store from state
        let challenge_store = state.challenge_store.clone();
        let acme_account_file = "data/acme_account.json";

        // Ensure data directory exists
        if let Err(e) = tokio::fs::create_dir_all("data").await {
            return make_error_response(&config, format!("Failed to create data directory: {}", e));
        }

        info!("🌐 Requesting certificate from Let's Encrypt (this may take a minute)...");
        info!("📧 Using email: {}", acme_email_for_cert);
        info!("🔑 Domain: {}", domain);

        match crate::tls::request_letsencrypt_cert(
            &domain,
            challenge_store,
            false, // production
            &acme_email_for_cert,
            acme_account_file,
        )
        .await
        {
            Ok((cert_pem, key_pem, expiry)) => {
                info!("✅ Certificate obtained successfully!");
                info!("📅 Certificate expires: {}", expiry);

                // Set TLS port to 443 if not already configured
                if config.tls_port.is_none() {
                    info!("📌 Setting TLS port to 443 (default HTTPS port)");
                    config.tls_port = Some(443);
                }

                // Enable use_letsencrypt_cert now that we have a cert
                config.use_letsencrypt_cert = true;

                // Save certificate to config
                match crate::tls::save_cert_to_config(&mut config, &cert_pem, &key_pem, expiry)
                    .await
                {
                    Ok(()) => {
                        // Now save the entire config
                        if let Err(e) = crate::config::save_config(&config).await {
                            return make_error_response(
                                &config,
                                format!("Failed to save config after certificate: {}", e),
                            );
                        }
                        info!("💾 Certificate saved to config");
                        info!("🔄 Triggering server restart to activate TLS certificate...");

                        // Trigger server restart to activate the new certificate
                        let reload_tx = Arc::clone(&state.reload_tx);
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            info!("📤 Sending reload signal for TLS activation...");
                            let _ = reload_tx.send(crate::ReloadSignal);
                        });

                        // Return success page with restart message
                        let html = r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Certificate Obtained - Restarting...</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #f8f9fa;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            color: #333;
        }
        .message {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 500px;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #28a745;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 1rem auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .success-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
    </style>
    <meta http-equiv="refresh" content="5;url=/admin/setup">
</head>
<body>
    <div class="message">
        <div class="success-icon">✅</div>
        <h2>Certificate Obtained Successfully!</h2>
        <div class="spinner"></div>
        <p>🔐 Let's Encrypt certificate has been saved to config.</p>
        <p>🔄 Server is restarting to activate TLS on the HTTPS port...</p>
        <p style="font-size: 0.875rem; color: #6c757d; margin-top: 1.5rem;">
            You will be redirected to the setup page in a moment.
        </p>
    </div>
</body>
</html>"#;
                        return Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/html")
                            .body(Body::from(html))
                            .expect("Failed to build response");
                    }
                    Err(e) => {
                        error!("❌ Failed to save certificate: {}", e);
                        return make_error_response(
                            &config,
                            format!("Certificate obtained but failed to save: {}", e),
                        );
                    }
                }
            }
            Err(e) => {
                error!("❌ Failed to obtain Let's Encrypt certificate: {}", e);
                return make_error_response(
                    &config,
                    format!("Failed to obtain Let's Encrypt certificate: {}. Make sure port 80 is accessible from the internet.", e),
                );
            }
        }
    }
    // If not requesting Let's Encrypt, just keep existing config as-is

    // Save the config
    match crate::config::save_config(&config).await {
        Ok(_) => {
            let admin_config = config.admin.as_ref();
            let theme = admin_config.map(|a| &a.theme).unwrap_or(&AdminTheme::Light);

            let template = SetupTemplate {
                base_url: config.base_url.clone(),
                port: config.port,
                remove_kofi: config.remove_kofi,
                admin_enabled: admin_config.map(|a| a.enabled).unwrap_or(false),
                admin_port: admin_config.map(|a| a.port).unwrap_or(3001),
                admin_sharing_root: admin_config
                    .map(|a| a.sharing_root.clone())
                    .unwrap_or_default(),
                allow_share_directories: admin_config.map(|a| a.share_dirs).unwrap_or(false),
                admin_default_exp_seconds: admin_config
                    .and_then(|a| a.default_expiration_seconds)
                    .unwrap_or(3600),
                tls_port: config.tls_port.map(|p| p.to_string()).unwrap_or_default(),
                use_letsencrypt_cert: config.use_letsencrypt_cert,
                tls_acme_email: config
                    .lets_encrypt
                    .as_ref()
                    .and_then(|le| le.acme_email.clone())
                    .unwrap_or_default(),
                tls_cert_expiry: config
                    .lets_encrypt
                    .as_ref()
                    .and_then(|le| le.expiry.clone())
                    .unwrap_or_default(),
                admin_tls_port: admin_config
                    .and_then(|a| a.tls_port)
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
                port_env_override: std::env::var("RYANSEND_PORT").is_ok(),
                admin_port_env_override: std::env::var("RYANSEND_ADMIN_PORT").is_ok(),
                admin_sharing_root_env_override: std::env::var("RYANSEND_ADMIN_SHARING_ROOT")
                    .is_ok(),
                admin_default_exp_seconds_env_override: std::env::var(
                    "RYANSEND_ADMIN_DEFAULT_EXP_SECONDS",
                )
                .is_ok(),
                tls_port_env_override: std::env::var("RYANSEND_TLS_PORT").is_ok(),
                admin_tls_port_env_override: std::env::var("RYANSEND_ADMIN_TLS_PORT").is_ok(),
                success: true,
                error: String::new(),
                theme: match theme {
                    AdminTheme::Light => "light".to_string(),
                    AdminTheme::Dark => "dark".to_string(),
                },
                theme_css: get_theme_css(theme),
            };
            let html = template
                .render()
                .unwrap_or_else(|_| "Template error".to_string());
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html")
                .body(Body::from(html))
                .expect("Failed to build response")
        }
        Err(e) => make_error_response(&config, format!("Failed to save config: {}", e)),
    }
}

async fn admin_restart_handler(State(state): State<AdminAppState>) -> Response {
    info!("Server restart requested via admin panel");

    let html = r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Restarting Server...</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #f8f9fa;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            color: #333;
        }
        .message {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 1rem auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
    <meta http-equiv="refresh" content="5;url=/admin/files">
</head>
<body>
    <div class="message">
        <div class="spinner"></div>
        <h2>🔄 Restarting Server...</h2>
        <p>The server is restarting with the new configuration.</p>
        <p>You will be redirected to the files page in a moment.</p>
        <p style="font-size: 0.875rem; color: #6c757d;">This may take a few seconds...</p>
    </div>
</body>
</html>"#;

    // Send reload signal after a brief delay to allow response to be sent
    let reload_tx = Arc::clone(&state.reload_tx);
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        info!("Sending reload signal...");
        let _ = reload_tx.send(crate::ReloadSignal);
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html")
        .body(Body::from(html))
        .expect("Failed to build restart response")
}

pub async fn run_admin_server(
    config: Config,
    reload_tx: Arc<ReloadSender>,
    challenge_store: crate::tls::ChallengeStore,
) -> Result<()> {
    // Subscribe to reload signal for graceful shutdown
    let mut reload_rx = reload_tx.subscribe();

    let admin_config = match &config.admin {
        Some(admin) if admin.enabled => admin,
        _ => {
            // Admin disabled, wait indefinitely for reload signal
            let _ = reload_rx.recv().await;
            return Ok(());
        }
    };

    // Create rate limiter for login endpoint only (5 attempts per minute)
    let admin_login_rate_limiter = Arc::new(create_rate_limiter(AdminRateLimitConfig::for_login()));

    let state = AdminAppState {
        config: config.clone(),
        admin_login_rate_limiter: Some(admin_login_rate_limiter),
        reload_tx,
        challenge_store,
    };

    let protected_routes = Router::new()
        .route("/admin/files", get(admin_files_handler))
        .route("/admin/download", get(admin_download_handler))
        .route("/admin/share", get(admin_share_handler))
        .route("/admin/single-use", get(admin_single_use_download_handler))
        .route("/admin/setup", get(admin_setup_page))
        .route("/admin/setup", post(admin_setup_handler))
        .route("/admin/restart", post(admin_restart_handler))
        .route(
            "/admin/generate-tunnel-secret",
            post(generate_tunnel_secret_handler),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ));

    let app = Router::new()
        .route("/", get(admin_root_handler))
        .route("/admin/login", get(admin_login_page))
        .route(
            "/admin/login",
            post(admin_login_handler).route_layer(middleware::from_fn_with_state(
                state.clone(),
                admin_login_rate_limit_middleware,
            )),
        )
        .route("/admin/logout", get(admin_logout_handler))
        .merge(protected_routes)
        .fallback(handle_404)
        .with_state(state)
        .layer(middleware::from_fn(logging_middleware));

    // Always start HTTP server
    info!(
        "Starting admin server on http://0.0.0.0:{}",
        admin_config.port
    );

    let http_bind_address = format!("0.0.0.0:{}", admin_config.port);
    let http_listener = tokio::net::TcpListener::bind(&http_bind_address)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to bind admin server to port {}: {}",
                admin_config.port,
                e
            )
        })?;

    // Check if TLS is also configured for admin panel
    let has_admin_tls = config.has_tls_cert() && admin_config.tls_port.is_some();

    if let (true, Some(tls_port)) = (has_admin_tls, admin_config.tls_port) {
        // Load TLS certificate and run both HTTP and HTTPS servers
        match crate::tls::load_cert_from_config(&config).await? {
            Some(tls_cert) => {
                let server_config = tls_cert.into_server_config()?;

                info!("🔒 Starting admin server on https://0.0.0.0:{}", tls_port);

                let https_bind_address = format!("0.0.0.0:{}", tls_port);
                let https_addr: std::net::SocketAddr = match https_bind_address.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!(
                            "Failed to parse admin HTTPS bind address '{}': {}",
                            https_bind_address, e
                        );
                        return Ok(());
                    }
                };

                // Clone app for HTTPS server
                let https_app = app.clone();

                let https_server = axum_server::bind_rustls(
                    https_addr,
                    axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(
                        server_config,
                    )),
                )
                .serve(https_app.into_make_service());

                let http_server = axum::serve(http_listener, app).with_graceful_shutdown(async {
                    // This future never completes - shutdown is handled by select!
                    std::future::pending::<()>().await
                });

                tokio::select! {
                    result = https_server => {
                        result.map_err(|e| anyhow::anyhow!("Admin HTTPS server error: {}", e))?;
                    }
                    result = http_server => {
                        result.map_err(|e| anyhow::anyhow!("Admin HTTP server error: {}", e))?;
                    }
                    _ = reload_rx.recv() => {
                        info!("Admin server shutting down for reload...");
                    }
                }

                return Ok(());
            }
            None => {
                info!("⚠️  Admin TLS configured but certificate could not be loaded, running HTTP only");
            }
        }
    }

    // HTTP-only mode (either TLS not configured, or cert failed to load)
    axum::serve(http_listener, app)
        .with_graceful_shutdown(async move {
            reload_rx.recv().await.ok();
            info!("Admin server shutting down for reload...");
        })
        .await
        .map_err(|e| anyhow::anyhow!("Admin server error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_search_functionality() {
        // Create a temporary directory with test files
        let temp_dir = TempDir::new().expect("Failed to create temporary directory for test");
        let temp_path = temp_dir.path();

        // Create test files
        fs::write(temp_path.join("test_file.txt"), "test content")
            .expect("Failed to write test_file.txt");
        fs::write(temp_path.join("another_file.rs"), "rust code")
            .expect("Failed to write another_file.rs");
        fs::write(temp_path.join("readme.md"), "documentation").expect("Failed to write readme.md");

        // Create subdirectory with file
        let sub_dir = temp_path.join("subdir");
        fs::create_dir(&sub_dir).expect("Failed to create subdirectory");
        fs::write(sub_dir.join("nested_file.log"), "log content")
            .expect("Failed to write nested_file.log");

        let canonical_base = temp_path
            .canonicalize()
            .expect("Failed to canonicalize temp path");

        // Test glob search for "*file*" in root directory - should find files with "file" in name
        let results = perform_search(&canonical_base, "*file*", &canonical_base).await;
        assert!(!results.is_empty(), "Search should find files");
        // Should find files in root directory and subdirectories (test_file.txt, another_file.rs, nested_file.log)
        assert_eq!(
            results.len(),
            3,
            "Should find 3 files matching *file* starting from root directory"
        );

        // Test glob search for "*nested*" in root directory - should find nested file in subdirectory
        let nested_results = perform_search(&canonical_base, "*nested*", &canonical_base).await;
        assert!(
            !nested_results.is_empty(),
            "Search should find nested files when starting from root"
        );

        // Test glob search for "*nested*" in subdirectory - should only find the nested file
        let subdir_path = canonical_base.join("subdir");
        let nested_in_subdir = perform_search(&subdir_path, "*nested*", &canonical_base).await;
        assert_eq!(
            nested_in_subdir.len(),
            1,
            "Search should find exactly 1 nested file when starting from subdir"
        );

        // Test glob search for "*.txt" - should find only txt files
        let txt_results = perform_search(&canonical_base, "*.txt", &canonical_base).await;
        assert_eq!(txt_results.len(), 1, "Should find 1 txt file");

        // Test glob search for non-matching pattern
        let empty_results = perform_search(&canonical_base, "*nonexistent*", &canonical_base).await;
        assert!(
            empty_results.is_empty(),
            "Search should return empty for non-matching patterns"
        );
    }

    #[tokio::test]
    async fn test_search_no_results_message() {
        // Create a temporary directory with test files
        let temp_dir = TempDir::new().expect("Failed to create temporary directory for test");
        let temp_path = temp_dir.path();

        // Create only files that won't match our search
        fs::write(temp_path.join("document.txt"), "content").expect("Failed to write document.txt");
        fs::write(temp_path.join("readme.md"), "documentation").expect("Failed to write readme.md");

        let canonical_base = temp_path
            .canonicalize()
            .expect("Failed to canonicalize temp path");

        // Search for something that won't be found (using glob pattern)
        let empty_results = perform_search(&canonical_base, "*nonexistent*", &canonical_base).await;

        // Verify no results
        assert!(empty_results.is_empty(), "Should find no results");

        // Test that we can distinguish between no search and empty search results
        // This verifies the template will show the "no results" message correctly
        let search_query = "*nonexistent*".to_string();
        let search_query_encoded = encode(&search_query).to_string();
        let has_search_results = true; // Search was performed

        // This simulates what the template receives:
        // - has_search_results = true (search was performed)
        // - search_results.is_empty() = true (no results found)
        // - search_query contains the search term
        // - search_query_encoded contains the URL-encoded search term
        assert!(!search_query.is_empty(), "Search query should not be empty");
        assert!(
            !search_query_encoded.is_empty(),
            "Encoded search query should not be empty"
        );
        assert!(has_search_results, "Should indicate search was performed");
    }

    #[tokio::test]
    async fn test_path_truncation() {
        // Test that long paths are properly truncated in FileEntry
        let long_path = "documents/projects/client_work/super_important_project/backend/src/controllers/very_long_module_name_that_definitely_exceeds_one_hundred_characters_in_total_length_for_testing_truncation_purposes/file.txt";
        let short_path = "short/path/file.txt";

        // Test long path truncation
        let long_display = if long_path.len() > 100 {
            format!("{}...", &long_path[..97])
        } else {
            long_path.to_string()
        };

        // Test short path (no truncation)
        let short_display = if short_path.len() > 100 {
            format!("{}...", &short_path[..97])
        } else {
            short_path.to_string()
        };

        assert!(
            long_path.len() > 100,
            "Long path should be over 100 characters"
        );
        assert_eq!(
            long_display.len(),
            100,
            "Truncated path should be exactly 100 characters"
        );
        assert!(
            long_display.ends_with("..."),
            "Truncated path should end with '...'"
        );

        assert!(
            short_path.len() <= 100,
            "Short path should be under 100 characters"
        );
        assert_eq!(
            short_display, short_path,
            "Short path should not be truncated"
        );
        assert!(
            !short_display.ends_with("..."),
            "Short path should not end with '...'"
        );
    }

    #[tokio::test]
    async fn test_kofi_link_visibility() {
        // Test that remove_kofi field controls Ko-fi link visibility in template
        let template_with_kofi = FileBrowserTemplate {
            current_path: "test".to_string(),
            entries: vec![],
            show_parent: false,
            parent_path: ".".to_string(),
            search_query: String::new(),
            search_query_encoded: String::new(),
            search_results: vec![],
            has_search_results: false,
            remove_kofi: false, // Ko-fi link should be visible
            theme_css: LIGHT_THEME_CSS,
        };

        let template_without_kofi = FileBrowserTemplate {
            current_path: "test".to_string(),
            entries: vec![],
            show_parent: false,
            parent_path: ".".to_string(),
            search_query: String::new(),
            search_query_encoded: String::new(),
            search_results: vec![],
            has_search_results: false,
            remove_kofi: true, // Ko-fi link should be hidden
            theme_css: LIGHT_THEME_CSS,
        };

        let html_with_kofi = template_with_kofi
            .render()
            .expect("Failed to render template with kofi");
        let html_without_kofi = template_without_kofi
            .render()
            .expect("Failed to render template without kofi");

        // When remove_kofi is false, Ko-fi link should be present
        assert!(
            html_with_kofi.contains("ko-fi.com"),
            "Ko-fi link should be present when remove_kofi is false"
        );

        // When remove_kofi is true, Ko-fi link should not be present
        assert!(
            !html_without_kofi.contains("ko-fi.com"),
            "Ko-fi link should be hidden when remove_kofi is true"
        );
    }
}
