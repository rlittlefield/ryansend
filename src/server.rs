use anyhow::{anyhow, Result};

use crate::auth;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use log::{debug, error, info, warn};
use serde::Deserialize;
use std::io::SeekFrom;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use timedmap::TimedMap;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;

use crate::auth::{verify_token_and_get_claims, TokenSource};
use crate::config::Config;
use crate::error::{handle_404, AppError, AppResult};
use crate::logging_middleware::logging_middleware;
use crate::tls::{self, ChallengeStore};
use crate::tunnel::{TunnelFileInfo, TunnelManager};
use crate::ReloadSignal;

use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipDateTime, ZipEntryBuilder};
use futures::AsyncWriteExt as FuturesAsyncWriteExt;

#[derive(Debug, Clone)]
struct ByteRange {
    start: u64,
    end: Option<u64>,
}

fn parse_range_header(range_header: &str, file_size: u64) -> Option<ByteRange> {
    // Parse "bytes=start-end" format
    if !range_header.starts_with("bytes=") {
        return None;
    }

    let range_spec = &range_header[6..]; // Remove "bytes=" prefix
    let parts: Vec<&str> = range_spec.split('-').collect();

    if parts.len() != 2 {
        return None;
    }

    let start_str = parts[0].trim();
    let end_str = parts[1].trim();

    // Handle different range formats:
    // "start-end", "start-", "-suffix"
    let range = if start_str.is_empty() {
        // Suffix range: "-500" means last 500 bytes
        if let Ok(suffix) = end_str.parse::<u64>() {
            let start = file_size.saturating_sub(suffix);
            ByteRange {
                start,
                end: Some(file_size - 1),
            }
        } else {
            return None;
        }
    } else if let Ok(start) = start_str.parse::<u64>() {
        if start >= file_size {
            return None; // Start beyond file size
        }

        let end = if end_str.is_empty() {
            // "start-" means from start to end of file
            Some(file_size - 1)
        } else if let Ok(end_val) = end_str.parse::<u64>() {
            // "start-end" format
            Some(std::cmp::min(end_val, file_size - 1))
        } else {
            return None;
        };

        ByteRange { start, end }
    } else {
        return None;
    };

    Some(range)
}

/// Extract and verify tunnel secret from Authorization header
fn extract_and_verify_tunnel_secret(headers: &HeaderMap, config: &Config) -> Result<(), AppError> {
    // Get Authorization header
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::unauthorized(anyhow::anyhow!("Missing Authorization header")))?;

    // Extract Bearer token
    let secret = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        AppError::unauthorized(anyhow::anyhow!("Invalid Authorization header format"))
    })?;

    // Verify against admin config
    let admin_config = config
        .admin
        .as_ref()
        .ok_or_else(|| AppError::unauthorized(anyhow::anyhow!("Admin not configured")))?;

    if crate::config::verify_tunnel_secret(secret, &admin_config.hashed_sharing_secrets) {
        Ok(())
    } else {
        Err(AppError::unauthorized(anyhow::anyhow!(
            "Invalid tunnel secret"
        )))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub download_tracker: Arc<Mutex<TimedMap<String, u32>>>,
    pub challenge_store: ChallengeStore,
    pub tunnel_manager: Option<Arc<TunnelManager>>,
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    token: String,
}

/// Handle ACME HTTP-01 challenge requests
/// Path: /.well-known/acme-challenge/{token}
pub async fn acme_challenge_handler(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    debug!("ACME challenge request for token: {}", token);

    match tls::serve_acme_challenge(&token, state.challenge_store).await {
        Ok(key_auth) => {
            info!("Serving ACME challenge for token: {}", token);
            (StatusCode::OK, key_auth)
        }
        Err(e) => {
            warn!("ACME challenge token not found: {} - {}", token, e);
            (StatusCode::NOT_FOUND, "Challenge not found".to_string())
        }
    }
}

/// Handle tunnel file announcement from client
/// POST /tunnel/announce
pub async fn tunnel_announce_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(file_info): axum::Json<TunnelFileInfo>,
) -> AppResult<Response> {
    // Verify tunnel secret
    extract_and_verify_tunnel_secret(&headers, &state.config)?;
    let tunnel_manager = state
        .tunnel_manager
        .as_ref()
        .ok_or_else(|| AppError::not_found(anyhow::anyhow!("Tunnel manager not available")))?;

    info!(
        "Client announcing tunnel file: {} ({} bytes, id: {})",
        file_info.name, file_info.size, file_info.id
    );

    // Default expiration for tunnel files (1 hour)
    let expires_in_seconds = 3600;

    // Generate the signed download URL on the server
    let download_url = auth::generate_tunnel_url(
        &state.config,
        file_info.id.clone(),
        file_info.name.clone(),
        file_info.size,
        expires_in_seconds,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to generate download URL: {}", e))?;

    tunnel_manager
        .register_tunnel(file_info)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to register tunnel: {}", e))?;

    // Return the download URL to the client
    let response_body = serde_json::json!({
        "download_url": download_url,
        "expires_in": expires_in_seconds
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response_body)?))
        .map_err(|e| anyhow::anyhow!("Failed to build response: {}", e))?)
}

/// Handle long polling for upload requests from client
/// GET /tunnel/poll?file_id=xxx
/// This holds the connection open for up to 30 seconds waiting for a download request
pub async fn tunnel_poll_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> AppResult<Response> {
    // Verify tunnel secret
    extract_and_verify_tunnel_secret(&headers, &state.config)?;
    let file_id = params
        .get("file_id")
        .ok_or_else(|| AppError::not_found(anyhow::anyhow!("Missing file_id parameter")))?;

    let tunnel_manager = state
        .tunnel_manager
        .as_ref()
        .ok_or_else(|| AppError::not_found(anyhow::anyhow!("Tunnel manager not available")))?;

    debug!("Client polling for file: {}", file_id);

    // This will hold the connection open for up to 30 seconds
    // Returns Upload if download is requested, or Wait if timeout
    let response = tunnel_manager.poll_for_upload(file_id).await.map_err(|e| {
        warn!("Poll error for file {}: {}", file_id, e);
        AppError::not_found(e)
    })?;

    debug!("Poll response for file {}: {:?}", file_id, response);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&response)?))
        .map_err(|e| anyhow::anyhow!("Failed to build response: {}", e))?)
}

/// Handle streaming file upload from client
/// POST /tunnel/upload?file_id=xxx
/// The entire file is streamed as the request body
pub async fn tunnel_upload_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    body: Body,
) -> AppResult<Response> {
    use futures::StreamExt;

    // Verify tunnel secret
    extract_and_verify_tunnel_secret(&headers, &state.config)?;

    let file_id = params
        .get("file_id")
        .ok_or_else(|| AppError::not_found(anyhow::anyhow!("Missing file_id parameter")))?
        .clone();

    let tunnel_manager = state
        .tunnel_manager
        .as_ref()
        .ok_or_else(|| AppError::not_found(anyhow::anyhow!("Tunnel manager not available")))?;

    info!("Starting to receive streaming upload for file: {}", file_id);

    // Get the sender that pipes to the download response
    let sender = tunnel_manager
        .get_upload_sender(&file_id)
        .await
        .ok_or_else(|| {
            AppError::not_found(anyhow::anyhow!("No active download waiting for this file"))
        })?;

    // Stream the body bytes directly to the download handler
    let mut stream = body.into_data_stream();
    let mut total_bytes = 0u64;

    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(bytes) => {
                total_bytes += bytes.len() as u64;
                if sender.send(Ok(bytes)).await.is_err() {
                    warn!("Download handler disconnected for file: {}", file_id);
                    break;
                }
            }
            Err(e) => {
                error!("Error reading upload stream: {}", e);
                // Close the channel by dropping sender
                drop(sender);
                tunnel_manager.finish_upload(&file_id).await;
                return Err(AppError::from(anyhow::anyhow!(
                    "Upload stream error: {}",
                    e
                )));
            }
        }
    }

    // Signal completion by dropping the sender
    drop(sender);
    tunnel_manager.finish_upload(&file_id).await;

    info!(
        "Upload stream complete: {} bytes for file: {}",
        total_bytes, file_id
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .map_err(|e| anyhow::anyhow!("Failed to build response: {}", e))?)
}

/// Read buffer size used when copying files into a directory ZIP.
const ZIP_CHUNK_SIZE: usize = 64 * 1024;

/// Size of the in-memory pipe between the ZIP writer task and the HTTP response body.
/// This bounds per-download memory: the archive is streamed, never buffered as a whole.
const ZIP_PIPE_SIZE: usize = 256 * 1024;

/// One entry to add to a directory ZIP.
enum ZipItem {
    /// A directory; `name` ends in `/`.
    Dir {
        path: PathBuf,
        name: String,
    },
    File {
        path: PathBuf,
        name: String,
    },
}

/// Lazily walks a directory tree with async I/O, one directory listing at a time, yielding the
/// entries that belong in its ZIP. Symlinks, sockets, FIFOs and device files are skipped, never
/// followed: following a symlink could leak files from outside the shared directory, and opening
/// a FIFO blocks forever. Unreadable subdirectories are skipped with a warning; an unreadable
/// root is an error.
struct ZipWalker {
    root: PathBuf,
    /// Directories still to list, as (absolute path, name prefix inside the archive).
    pending: Vec<(PathBuf, String)>,
    ready: std::collections::VecDeque<ZipItem>,
}

impl ZipWalker {
    fn new(root: PathBuf) -> Self {
        Self {
            pending: vec![(root.clone(), String::new())],
            root,
            ready: std::collections::VecDeque::new(),
        }
    }

    async fn next(&mut self) -> Result<Option<ZipItem>> {
        loop {
            if let Some(item) = self.ready.pop_front() {
                return Ok(Some(item));
            }
            let Some((dir, prefix)) = self.pending.pop() else {
                return Ok(None);
            };
            let mut listing = match fs::read_dir(&dir).await {
                Ok(listing) => listing,
                Err(e) if dir == self.root => return Err(e.into()),
                Err(e) => {
                    warn!(
                        "ZIP: skipping unreadable directory {}: {}",
                        dir.display(),
                        e
                    );
                    continue;
                }
            };
            let mut children = Vec::new();
            loop {
                match listing.next_entry().await {
                    Ok(Some(entry)) => children.push(entry),
                    Ok(None) => break,
                    Err(e) => {
                        warn!("ZIP: error listing {}: {}", dir.display(), e);
                        break;
                    }
                }
            }
            children.sort_by_key(|entry| entry.file_name());

            let mut subdirs = Vec::new();
            for child in children {
                // DirEntry::file_type does not follow symlinks, so a symlink reports as a symlink.
                let file_type = match child.file_type().await {
                    Ok(file_type) => file_type,
                    Err(e) => {
                        warn!("ZIP: skipping {}: {}", child.path().display(), e);
                        continue;
                    }
                };
                let name = format!("{}{}", prefix, zip_name_component(&child.file_name()));
                if file_type.is_dir() {
                    subdirs.push((child.path(), format!("{}/", name)));
                } else if file_type.is_file() {
                    self.ready.push_back(ZipItem::File {
                        path: child.path(),
                        name,
                    });
                } else {
                    debug!(
                        "ZIP: skipping symlink or special file {}",
                        child.path().display()
                    );
                }
            }
            for (path, name) in &subdirs {
                // Explicit directory entries keep empty directories in the extracted archive.
                self.ready.push_back(ZipItem::Dir {
                    path: path.clone(),
                    name: name.clone(),
                });
            }
            // Reverse so the stack pops subdirectories in name order.
            self.pending.extend(subdirs.into_iter().rev());
        }
    }
}

/// Whether the ZIP of `root` could exceed the classic format's limits (4 GiB of offsets or sizes,
/// or 65,535 entries) and therefore needs Zip64.
///
/// async_zip's streamed Zip64 entries can't be opened by macOS Archive Utility (Finder) or
/// `ditto`, so archives that fit are written without Zip64. This is a metadata-only pass that
/// stops as soon as a limit is crossed, so it stays cheap even for huge trees. If files grow
/// between this scan and the write, the writer refuses to exceed the limits and the download is
/// aborted with an error rather than producing a corrupt archive.
async fn directory_needs_zip64(root: &FsPath) -> Result<bool> {
    let mut walker = ZipWalker::new(root.to_path_buf());
    let mut entries: u64 = 0;
    let mut archive_bytes: u64 = 0;
    while let Some(item) = walker.next().await? {
        let (path, name) = match &item {
            ZipItem::Dir { path, name } | ZipItem::File { path, name } => (path, name),
        };
        if let ZipItem::File { .. } = item {
            archive_bytes += fs::symlink_metadata(path)
                .await
                .map(|m| m.len())
                .unwrap_or(0);
        }
        // Generous allowance for the local header, data descriptor, central directory record and
        // a Unicode path extra field, each of which can repeat the name.
        archive_bytes += 4 * name.len() as u64 + 256;
        entries += 1;
        if entries >= u16::MAX as u64 || archive_bytes >= u32::MAX as u64 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Streams `root` and everything beneath it into `writer` as a ZIP archive.
///
/// - Entries come from [`ZipWalker`], which never follows symlinks or opens special files, and
///   each file is re-checked against `root` right before it is opened.
/// - Entries are stored uncompressed, so a ZIP download costs about the same CPU as a plain file
///   download (just CRC32), and concurrent downloads of a share link can't pin the server's cores.
/// - The walk is lazy and async, so neither a huge tree nor a slow client ties up a runtime or
///   blocking-pool thread for the length of the download.
///
/// Unreadable files and subdirectories are skipped with a warning. Any other failure is returned
/// as an error so the caller can abort the response instead of ending it cleanly, which would
/// leave the client with a truncated archive that looks complete.
async fn write_directory_zip<W>(root: PathBuf, writer: W) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let root = fs::canonicalize(&root).await?;
    let mut zip = ZipFileWriter::with_tokio(writer);
    if directory_needs_zip64(&root).await? {
        info!(
            "ZIP of {} exceeds 4 GiB or 65,535 entries; using Zip64, which macOS Archive Utility may not open",
            root.display()
        );
    } else {
        zip = zip.force_no_zip64();
    }

    let mut buf = vec![0u8; ZIP_CHUNK_SIZE];
    let mut walker = ZipWalker::new(root.clone());
    while let Some(item) = walker.next().await? {
        match item {
            ZipItem::Dir { path, name } => {
                let mut builder = ZipEntryBuilder::new(name.into(), Compression::Stored);
                if let Ok(modified) = fs::metadata(&path).await.and_then(|m| m.modified()) {
                    builder = builder.last_modification_date(zip_timestamp(modified));
                }
                zip.write_entry_whole(builder, &[]).await?;
            }
            ZipItem::File { path, name } => {
                add_file_to_zip(&mut zip, &root, &path, name, &mut buf).await?;
            }
        }
    }

    zip.close().await?;
    Ok(())
}

/// Converts one path component into a ZIP entry name component.
///
/// On Unix a backslash is a legal filename character, but Windows extractors treat it as a path
/// separator, so a file named `..\..\evil` could escape the extraction directory on the
/// recipient's machine. Replace it rather than translate it.
fn zip_name_component(name: &std::ffi::OsStr) -> String {
    name.to_string_lossy().replace('\\', "_")
}

/// Copies one regular file into the archive. Files that can't be opened are skipped; failures
/// after the entry has been started are fatal because the entry can't be taken back.
async fn add_file_to_zip<W>(
    zip: &mut ZipFileWriter<W>,
    root: &FsPath,
    path: &FsPath,
    name: String,
    buf: &mut [u8],
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut file = match open_within_root(path, root).await {
        Some(file) => file,
        None => return Ok(()),
    };

    let mut builder = ZipEntryBuilder::new(name.into(), Compression::Stored);
    if let Ok(modified) = file.metadata().await.and_then(|m| m.modified()) {
        builder = builder.last_modification_date(zip_timestamp(modified));
    }

    let mut entry = zip.write_entry_stream(builder).await?;
    loop {
        let n = file.read(buf).await?;
        if n == 0 {
            break;
        }
        entry.write_all(&buf[..n]).await?;
    }
    entry.close().await?;
    Ok(())
}

/// Opens `path` for reading only if it is a regular file whose real location is inside `root`.
async fn open_within_root(path: &FsPath, root: &FsPath) -> Option<fs::File> {
    let canonical = match fs::canonicalize(path).await {
        Ok(canonical) => canonical,
        Err(e) => {
            warn!("ZIP: skipping {}: {}", path.display(), e);
            return None;
        }
    };
    if !canonical.starts_with(root) {
        warn!(
            "ZIP: skipping {}: resolves outside the shared directory",
            path.display()
        );
        return None;
    }
    match fs::symlink_metadata(&canonical).await {
        Ok(meta) if meta.is_file() => {}
        _ => {
            warn!("ZIP: skipping {}: not a regular file", path.display());
            return None;
        }
    }
    match fs::File::open(&canonical).await {
        Ok(file) => Some(file),
        Err(e) => {
            warn!("ZIP: skipping {}: {}", path.display(), e);
            None
        }
    }
}

/// ZIP timestamps are local time with a representable range of 1980 to 2107.
fn zip_timestamp(time: std::time::SystemTime) -> ZipDateTime {
    use chrono::Datelike;
    let local = chrono::DateTime::<chrono::Local>::from(time).naive_local();
    let clamped = if local.year() < 1980 {
        chrono::NaiveDate::from_ymd_opt(1980, 1, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .unwrap_or(local)
    } else if local.year() > 2107 {
        chrono::NaiveDate::from_ymd_opt(2107, 12, 31)
            .and_then(|d| d.and_hms_opt(23, 59, 58))
            .unwrap_or(local)
    } else {
        local
    };
    ZipDateTime::from_chrono(&clamped.and_utc())
}

/// Responds with a streaming ZIP of the directory a filesystem share token points at.
async fn stream_directory_as_zip(
    path: PathBuf,
    claims: &crate::auth::TokenClaims,
) -> AppResult<Response> {
    // Quotes and control characters would break the Content-Disposition header.
    let dir_name: String = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".to_string())
        .chars()
        .map(|c| if c == '"' || c.is_control() { '_' } else { c })
        .collect();
    let zip_name = format!("{}.zip", dir_name);

    let note_info = match &claims.note {
        Some(note) => format!(" (note: \"{}\")", note),
        None => String::new(),
    };
    info!(
        "Directory ZIP started: '{}' from path: {} [token_id: {}]{}",
        zip_name, claims.path, claims.id, note_info
    );

    let (writer, reader) = tokio::io::duplex(ZIP_PIPE_SIZE);
    // If the client disconnects, the reader is dropped and the writer's next write fails with
    // BrokenPipe, which ends this task.
    let zip_task = tokio::spawn(write_directory_zip(path, writer));

    let token_id = claims.id.clone();
    let body_stream = async_stream::stream! {
        use futures::StreamExt;
        let mut chunks = ReaderStream::new(reader);
        while let Some(chunk) = chunks.next().await {
            yield chunk;
        }
        // The writer side has closed. Only end the response cleanly if the archive is complete;
        // otherwise yield an error so the connection is aborted and the client sees a failure.
        let failure = match zip_task.await {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e.to_string()),
            Err(e) => Some(e.to_string()),
        };
        match failure {
            None => info!("Directory ZIP completed: '{}' [token_id: {}]", zip_name, token_id),
            Some(e) => {
                error!("Directory ZIP failed: '{}' [token_id: {}]: {}", zip_name, token_id, e);
                yield Err(std::io::Error::other(e));
            }
        }
    };

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from_stream(body_stream))
        .map_err(|e| anyhow::anyhow!("Failed to build response: {}", e))?;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}.zip\"", dir_name))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"archive.zip\"")),
    );
    Ok(response)
}

pub async fn download_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<DownloadQuery>,
) -> AppResult<Response> {
    debug!(
        "Download request with token: {}...",
        &params.token[..std::cmp::min(20, params.token.len())]
    );

    let claims = verify_token_and_get_claims(&state.config.secret_key, &params.token)
        .await
        .map_err(|e| {
            warn!("Token verification failed: {}", e);
            AppError::not_found(anyhow::anyhow!("Token verification failed"))
        })?;

    // Check if token has max_uses limit
    if let Some(max_uses) = claims.max_uses {
        #[allow(unused_mut)]
        let mut tracker = state.download_tracker.lock().await;
        let current_uses: u32 = tracker.get(&claims.id).unwrap_or_default();

        if current_uses >= max_uses {
            warn!(
                "Token {} has exceeded max uses ({}/{})",
                claims.id, current_uses, max_uses
            );
            return Err(AppError::not_found(anyhow::anyhow!(
                "Token has exceeded maximum uses"
            )));
        }

        // Calculate duration until one minute past token expiration
        let now = chrono::Utc::now();
        let track_until = claims.exp + chrono::Duration::minutes(1);
        let duration_secs = (track_until - now).num_seconds().max(0) as u64;

        // Update usage count
        tracker.insert(
            claims.id.clone(),
            current_uses + 1,
            std::time::Duration::from_secs(duration_secs),
        );

        info!(
            "Token {} usage: {}/{}",
            claims.id,
            current_uses + 1,
            max_uses
        );
    }

    // Check if this is a tunnel-based file or filesystem file
    match claims.source {
        TokenSource::Tunnel => {
            // Handle tunnel-based file transfer
            let tunnel_manager = state.tunnel_manager.as_ref().ok_or_else(|| {
                AppError::not_found(anyhow::anyhow!("Tunnel manager not available"))
            })?;

            let tunnel_conn = tunnel_manager
                .get_connection(&claims.id)
                .await
                .ok_or_else(|| {
                    warn!("Tunnel connection not found for file: {}", claims.id);
                    AppError::not_found(anyhow::anyhow!(
                        "Tunnel connection not found for this file"
                    ))
                })?;

            info!(
                "Streaming file '{}' from tunnel [token_id: {}]",
                claims.path, claims.id
            );

            let file_size = tunnel_conn.file_info.size;
            let file_name = tunnel_conn.file_info.name.clone();

            // Request file stream from tunnel and get byte receiver
            let mut byte_rx = tunnel_manager
                .request_file_stream(&claims.id)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to request file from tunnel: {}", e))?;

            // Convert the byte receiver into a stream that pipes directly from upload
            let stream = async_stream::stream! {
                while let Some(result) = byte_rx.recv().await {
                    match result {
                        Ok(bytes) => {
                            yield Ok::<bytes::Bytes, std::io::Error>(bytes);
                        }
                        Err(_) => {
                            error!("Error receiving bytes from tunnel");
                            yield Err(std::io::Error::other("Upload stream error"));
                            break;
                        }
                    }
                }
            };

            let body = Body::from_stream(stream);

            let mut response = Response::builder()
                .status(StatusCode::OK)
                .body(body)
                .map_err(|e| anyhow::anyhow!("Failed to build response: {}", e))?;

            let response_headers = response.headers_mut();
            response_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            response_headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file_name))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            response_headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&file_size.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("0")),
            );

            return Ok(response);
        }
        TokenSource::FileSystem => {
            // Handle filesystem-based file transfer (existing code)
        }
    }

    let path = PathBuf::from(&claims.path);

    if !path.exists() {
        warn!("File not found: {}", claims.path);
        return Err(AppError::not_found(anyhow::anyhow!(
            "File not found: {}",
            claims.path
        )));
    }

    if path.is_dir() {
        return stream_directory_as_zip(path, &claims).await;
    }

    let file = fs::File::open(&path).await.map_err(|e| {
        error!("Failed to open file {}: {}", claims.path, e);
        anyhow::anyhow!("Failed to open file: {}", e)
    })?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");

    // Get file size for logging and content-length header
    let file_size = file
        .metadata()
        .await
        .map_err(|e| {
            error!("Failed to get file metadata for {}: {}", claims.path, e);
            anyhow::anyhow!("Failed to get file metadata: {}", e)
        })?
        .len();

    // Check for Range header to support resume functionality
    let range_request = headers
        .get(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| parse_range_header(h, file_size));

    // Determine response parameters based on range request
    let (status_code, start, end, content_length, file_reader) = if let Some(range) = range_request
    {
        let start = range.start;
        let end = range.end.unwrap_or(file_size - 1);
        let content_length = end - start + 1;

        debug!(
            "Range request for '{}': bytes {}-{}/{} ({} bytes)",
            file_name, start, end, file_size, content_length
        );

        // Create a new file handle for seeking
        let mut seekable_file = fs::File::open(&path).await.map_err(|e| {
            error!("Failed to reopen file {}: {}", claims.path, e);
            anyhow::anyhow!("Failed to reopen file: {}", e)
        })?;

        // Seek to the start position
        seekable_file
            .seek(SeekFrom::Start(start))
            .await
            .map_err(|e| {
                error!(
                    "Failed to seek to position {} in file {}: {}",
                    start, claims.path, e
                );
                anyhow::anyhow!("Failed to seek to position {}: {}", start, e)
            })?;

        // Take only the requested range
        let limited_file = seekable_file.take(content_length);

        let note_info = match &claims.note {
            Some(note) => format!(" (note: \"{}\")", note),
            None => String::new(),
        };
        info!(
            "Partial file served: '{}' bytes {}-{}/{} ({} bytes) from path: {} [token_id: {}]{}",
            file_name, start, end, file_size, content_length, claims.path, claims.id, note_info
        );

        (
            StatusCode::PARTIAL_CONTENT,
            start,
            end,
            content_length,
            Box::new(limited_file) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        )
    } else {
        // No range request, serve the entire file
        let note_info = match &claims.note {
            Some(note) => format!(" (note: \"{}\")", note),
            None => String::new(),
        };
        info!(
            "File downloaded: '{}' ({} bytes) from path: {} [token_id: {}]{}",
            file_name, file_size, claims.path, claims.id, note_info
        );

        (
            StatusCode::OK,
            0,
            file_size - 1,
            file_size,
            Box::new(file) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        )
    };

    // Create the response stream and body
    let stream = ReaderStream::new(file_reader);
    let body = Body::from_stream(stream);

    let mut response = Response::builder()
        .status(status_code)
        .body(body)
        .map_err(|e| anyhow::anyhow!("Failed to build response: {}", e))?;

    // Set common headers
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", file_name))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    response_headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    response_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    // Add Content-Range header for partial content
    if status_code == StatusCode::PARTIAL_CONTENT {
        response_headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, file_size))
                .unwrap_or_else(|_| HeaderValue::from_static("bytes 0-0/0")),
        );
    }

    Ok(response)
}

pub async fn run_server(
    config: Config,
    mut reload_rx: tokio::sync::broadcast::Receiver<ReloadSignal>,
    challenge_store: tls::ChallengeStore,
) -> Result<()> {
    // Start certificate renewal background task
    let _renewal_task = tls::start_renewal_task(config.clone(), challenge_store.clone());

    // Initialize tunnel manager
    let tunnel_manager = Arc::new(TunnelManager::new());
    info!("🌐 Tunnel manager initialized");
    info!(
        "   Clients can use: ryansend send <file> --server-addr {}",
        config.base_url
    );

    let state = AppState {
        config: config.clone(),
        download_tracker: Arc::new(Mutex::new(TimedMap::new())),
        challenge_store: challenge_store.clone(),
        tunnel_manager: Some(tunnel_manager),
    };

    let app = Router::new()
        .route("/download", get(download_handler))
        .route(
            "/.well-known/acme-challenge/{token}",
            get(acme_challenge_handler),
        )
        .route(
            "/tunnel/announce",
            axum::routing::post(tunnel_announce_handler),
        )
        .route("/tunnel/poll", get(tunnel_poll_handler))
        .route("/tunnel/upload", axum::routing::post(tunnel_upload_handler))
        .fallback(handle_404)
        .with_state(state)
        .layer(middleware::from_fn(logging_middleware));

    // Check if TLS is configured
    let has_tls = config.has_tls_cert() && config.tls_port.is_some();

    if has_tls {
        // Load TLS certificate
        match tls::load_cert_from_config(&config).await? {
            Some(tls_cert) => {
                let server_config = tls_cert.into_server_config()?;
                let tls_port = match config.tls_port {
                    Some(port) => port,
                    None => {
                        error!("TLS port is not configured");
                        return Err(anyhow!("TLS port is required when TLS is enabled"));
                    }
                };

                info!("🔒 Starting HTTPS server on https://0.0.0.0:{}", tls_port);
                info!("🔓 Starting HTTP server on http://0.0.0.0:{}", config.port);

                // Show admin panel info if enabled
                if let Some(admin_config) = &config.admin {
                    if admin_config.enabled {
                        info!(
                            "📋 Admin panel available at: http://localhost:{}/admin/login",
                            admin_config.port
                        );
                    }
                }

                // Start HTTP server for ACME challenges
                let http_bind_address = format!("0.0.0.0:{}", config.port);
                let http_listener = tokio::net::TcpListener::bind(&http_bind_address)
                    .await
                    .map_err(|e| anyhow!("Failed to bind to HTTP port {}: {}", config.port, e))?;

                // Start HTTPS server
                let https_bind_address = format!("0.0.0.0:{}", tls_port);

                // Clone app for both servers
                let http_app = app.clone();
                let https_app = app;

                // Run both servers concurrently with graceful shutdown
                let http_server = async move {
                    axum::serve(http_listener, http_app)
                        .with_graceful_shutdown(async move {
                            reload_rx.recv().await.ok();
                            info!("HTTP server shutting down for reload...");
                        })
                        .await
                        .map_err(|e| anyhow!("HTTP server error: {}", e))
                };

                let https_server = async move {
                    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(
                        std::sync::Arc::new(server_config),
                    );
                    let addr: std::net::SocketAddr = match https_bind_address.parse() {
                        Ok(addr) => addr,
                        Err(e) => {
                            error!(
                                "Failed to parse HTTPS bind address '{}': {}",
                                https_bind_address, e
                            );
                            return Err(anyhow!("Failed to parse HTTPS bind address: {}", e));
                        }
                    };

                    axum_server::bind_rustls(addr, rustls_config)
                        .serve(https_app.into_make_service())
                        .await
                        .map_err(|e| anyhow!("HTTPS server error: {}", e))
                };

                tokio::try_join!(http_server, https_server)?;
                Ok(())
            }
            None => {
                warn!(
                    "TLS configured but certificate could not be loaded, falling back to HTTP only"
                );
                // Fall through to HTTP-only mode
                run_http_only_server(config, app, reload_rx).await
            }
        }
    } else {
        info!("Starting server on http://0.0.0.0:{}", config.port);

        // Show admin panel info if enabled
        if let Some(admin_config) = &config.admin {
            if admin_config.enabled {
                info!(
                    "📋 Admin panel available at: http://localhost:{}/admin/login",
                    admin_config.port
                );
            }
        }

        run_http_only_server(config, app, reload_rx).await
    }
}

/// Run HTTP-only server (fallback when TLS is not configured)
async fn run_http_only_server(
    config: Config,
    app: Router,
    mut reload_rx: tokio::sync::broadcast::Receiver<crate::ReloadSignal>,
) -> Result<()> {
    let bind_address = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&bind_address)
        .await
        .map_err(|e| anyhow!("Failed to bind to port {}: {}", config.port, e))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            reload_rx.recv().await.ok();
            info!("HTTP server shutting down for reload...");
        })
        .await
        .map_err(|e| anyhow!("Server error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod directory_zip_tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Zips `root` into memory and returns each entry's name mapped to its contents.
    async fn zip_entries(root: &FsPath) -> BTreeMap<String, Vec<u8>> {
        let mut out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            write_directory_zip(root.to_path_buf(), &mut out),
        )
        .await
        .expect("zipping timed out")
        .expect("zipping failed");

        let reader = async_zip::base::read::mem::ZipFileReader::new(out)
            .await
            .expect("archive should be readable");
        let mut entries = BTreeMap::new();
        for index in 0..reader.file().entries().len() {
            let mut entry = reader.reader_with_entry(index).await.unwrap();
            let name = entry.entry().filename().as_str().unwrap().to_string();
            let mut data = Vec::new();
            entry.read_to_end_checked(&mut data).await.unwrap();
            entries.insert(name, data);
        }
        entries
    }

    #[tokio::test]
    async fn zips_nested_tree_with_empty_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a.txt"), b"hello").unwrap();
        std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
        std::fs::write(root.join("sub/b.txt"), b"world").unwrap();
        std::fs::write(root.join("sub/deeper/c.bin"), vec![7u8; 200_000]).unwrap();
        std::fs::create_dir(root.join("empty")).unwrap();

        let entries = zip_entries(root).await;
        let names: Vec<&str> = entries.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "a.txt",
                "empty/",
                "sub/",
                "sub/b.txt",
                "sub/deeper/",
                "sub/deeper/c.bin"
            ]
        );
        assert_eq!(entries["a.txt"], b"hello");
        assert_eq!(entries["sub/b.txt"], b"world");
        assert_eq!(entries["sub/deeper/c.bin"], vec![7u8; 200_000]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn skips_symlinks_pointing_outside_the_shared_directory() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"top secret").unwrap();

        let shared = tempfile::tempdir().unwrap();
        let root = shared.path();
        std::fs::write(root.join("ok.txt"), b"fine").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.join("file-link"))
            .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("dir-link")).unwrap();
        // Even a symlink that stays inside the directory is skipped rather than followed.
        std::os::unix::fs::symlink(root.join("ok.txt"), root.join("inner-link")).unwrap();

        let entries = zip_entries(root).await;
        assert_eq!(entries.keys().collect::<Vec<_>>(), ["ok.txt"]);
        assert!(!entries.values().any(|data| data == b"top secret"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn skips_fifos_instead_of_blocking() {
        let shared = tempfile::tempdir().unwrap();
        let root = shared.path();
        std::fs::write(root.join("ok.txt"), b"fine").unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(root.join("pipe"))
            .status()
            .expect("mkfifo should run");
        assert!(status.success());

        let entries = zip_entries(root).await;
        assert_eq!(entries.keys().collect::<Vec<_>>(), ["ok.txt"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backslashes_in_names_cannot_become_path_separators() {
        let shared = tempfile::tempdir().unwrap();
        std::fs::write(shared.path().join("..\\..\\evil.txt"), b"x").unwrap();

        let entries = zip_entries(shared.path()).await;
        assert_eq!(entries.keys().collect::<Vec<_>>(), [".._.._evil.txt"]);
    }

    #[tokio::test]
    async fn uses_zip64_only_when_limits_could_be_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("small.txt"), b"hi").unwrap();
        assert!(!directory_needs_zip64(dir.path()).await.unwrap());

        // A sparse 5 GiB file takes no real disk space but needs Zip64.
        let big = std::fs::File::create(dir.path().join("big.bin")).unwrap();
        big.set_len(5 << 30).unwrap();
        assert!(directory_needs_zip64(dir.path()).await.unwrap());
    }

    #[tokio::test]
    async fn failed_archive_aborts_the_response_body() {
        let missing = tempfile::tempdir().unwrap().path().join("gone");
        let claims = crate::auth::TokenClaims {
            path: missing.to_string_lossy().to_string(),
            exp: chrono::Utc::now() + chrono::Duration::minutes(5),
            id: "test".to_string(),
            max_uses: None,
            note: None,
            source: TokenSource::FileSystem,
        };
        let Ok(response) = stream_directory_as_zip(missing, &claims).await else {
            panic!("building the response should succeed");
        };
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert!(
            body.is_err(),
            "a failed ZIP must error the body, not end it cleanly"
        );
    }

    #[test]
    fn timestamps_outside_zip_range_are_clamped() {
        use chrono::TimeZone;
        let epoch = zip_timestamp(std::time::UNIX_EPOCH);
        assert_eq!(epoch.year(), 1980);
        let modern = chrono::Local
            .with_ymd_and_hms(2024, 6, 1, 12, 30, 10)
            .unwrap();
        let ts = zip_timestamp(modern.into());
        assert_eq!((ts.year(), ts.month(), ts.day()), (2024, 6, 1));
        assert_eq!((ts.hour(), ts.minute(), ts.second()), (12, 30, 10));
    }
}
