//! The web application: shared state, the router and the cross-cutting layers
//! (access log, security headers, sessions + CSRF, static assets).
//!
//! Conventions for the route modules:
//!
//! * Pages are askama templates extending `templates/base.html`. Every
//!   template struct has a `page: Page` field and is turned into a response
//!   with [`render`].
//! * Require a user with the extractors in [`session`]; take forms as
//!   [`session::CsrfForm`].
//! * Redirect after a POST with [`redirect`], which also works for htmx.

pub mod admin;
pub mod auth;
pub mod docs;
pub mod pwa;
pub mod ratelimit;
pub mod scan;
pub mod session;
pub mod settings;

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use askama::Template;
use axum::Router;
use axum::extract::{MatchedPath, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use crate::accounts::Accounts;
use crate::config::Config;
use crate::documents::Documents;
use crate::embed::Engine;
use crate::extract::{EmbedRuntime, ExtractConfig, ExtractQueue, start_workers, wipe_tmp};
use crate::keyring::Keyring;
use crate::quota::Quotas;
use crate::system_db::{SYSTEM_DB_FILE, SystemDb};
use crate::tokens::TokenCache;
use ratelimit::RateLimiter;
use session::{Session, SessionStore, SharedStaging};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

/// Default `Content-Security-Policy`. A route may replace it with [`CspOverride`].
pub const CSP: &str = "default-src 'self'; img-src 'self' data:; object-src 'self'; \
                       frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// Argon2 runs allowed at the same time.
pub const KDF_PERMITS: usize = 2;
/// How long a request waits for a KDF permit before getting a 503.
pub const KDF_WAIT: Duration = Duration::from_secs(10);

/// How often expired sessions and stale rate-limit entries are dropped.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub sys: Arc<SystemDb>,
    pub keyring: Arc<Keyring>,
    pub accounts: Arc<Accounts>,
    pub docs: Arc<Documents>,
    /// Per-user storage usage and limits.
    pub quotas: Arc<Quotas>,
    /// Extraction and embedding jobs.
    pub queue: ExtractQueue,
    /// The one embedding engine, shared with the workers.
    pub engine: Arc<Engine>,
    pub sessions: Arc<SessionStore>,
    /// Shared files waiting for review (`/share`); memory only.
    pub shared: Arc<SharedStaging>,
    pub limiter: Arc<RateLimiter>,
    pub tokens: Arc<TokenCache>,
    /// Bounds concurrent password KDF work (Argon2 uses 64 MiB per run).
    pub kdf_permits: Arc<Semaphore>,
    /// Bounds concurrent MCP `upload_document` calls (each holds the base64
    /// text and the decoded bytes in memory).
    pub mcp_write_permits: Arc<Semaphore>,
    /// MCP `get_page_image` calls per token (memory only).
    pub page_images: Arc<crate::mcp::PageImageLimiter>,
    /// OAuth registration counters (memory only).
    pub oauth: Arc<crate::oauth::OAuthState>,
    /// Bodies of `POST /share` being read at once (try-acquire, 503 when full).
    pub share_permits: Arc<Semaphore>,
}

/// The embedding model is unloaded after this long without use.
const EMBED_IDLE: Duration = Duration::from_secs(10 * 60);

/// Concurrent MCP uploads.
const MCP_WRITE_PERMITS: usize = 2;
/// Concurrent `POST /share` uploads (the route needs no session).
pub const SHARE_PERMITS: usize = 2;

/// Work done on every fresh unlock: drop OAuth grant metadata whose token
/// rows are gone, then let the extraction queue pick up pending documents.
struct UnlockHooks {
    queue: ExtractQueue,
    sys: Arc<SystemDb>,
}

impl crate::keyring::OnUnlock for UnlockHooks {
    fn unlocked(&self, u: &Arc<crate::keyring::Unlocked>) {
        match crate::tokens::prune_orphan_grants(&self.sys, u) {
            Ok(0) => {}
            Ok(n) => tracing::info!(removed = n, "removed orphaned grant metadata"),
            Err(e) => tracing::warn!(error = %e, "could not prune orphaned grants"),
        }
        self.queue.unlocked(u);
    }
}

impl AppState {
    /// Opens the data directory, wipes OCR scratch left by a previous run and
    /// starts the extraction workers and the sweeper. Must be called inside a
    /// tokio runtime.
    pub fn build(cfg: Config) -> anyhow::Result<AppState> {
        let engine = Arc::new(Engine::new(cfg.models_dir.clone(), EMBED_IDLE));
        AppState::build_with_engine(cfg, engine)
    }

    /// [`AppState::build`] with a ready-made embedding engine (tests use one
    /// that talks to a fake model server).
    pub fn build_with_engine(cfg: Config, engine: Arc<Engine>) -> anyhow::Result<AppState> {
        let data_dir = cfg.data_dir.clone();
        std::fs::create_dir_all(&data_dir)?;
        let sys = Arc::new(SystemDb::open(&data_dir.join(SYSTEM_DB_FILE))?);
        let (queue, rx) = ExtractQueue::channel();
        engine.start_idle_reaper();
        let keyring = Arc::new(Keyring::new(
            data_dir.clone(),
            Arc::new(UnlockHooks {
                queue: queue.clone(),
                sys: sys.clone(),
            }),
        ));
        let accounts = Arc::new(Accounts::new(&cfg, sys.clone(), keyring.clone()));
        let quotas = Quotas::new(sys.clone(), data_dir.clone());
        let docs = Arc::new(Documents::new(
            data_dir.clone(),
            cfg.max_upload_bytes,
            Arc::new(queue.clone()),
            quotas.clone(),
        ));

        // No upload can be running yet, so every unfinished one is orphaned.
        let swept = crate::quota::sweep_stale_parts(&data_dir);
        if swept > 0 {
            tracing::warn!(files = swept, "removed unfinished uploads left by a crash");
        }
        let tmp = data_dir.join("tmp");
        wipe_tmp(&tmp)?;
        let extract_cfg =
            ExtractConfig::new(tmp).with_embed(EmbedRuntime::new(engine.clone(), None));
        start_workers(cfg.ocr_workers, extract_cfg, docs.clone(), rx);

        let sessions = Arc::new(SessionStore::new(cfg.session_idle, cfg.session_max));
        let shared = Arc::new(SharedStaging::new(
            cfg.share_ttl,
            cfg.max_upload_bytes as usize,
        ));
        let limiter = Arc::new(RateLimiter::new());
        let tokens = Arc::new(TokenCache::default());
        let oauth = Arc::new(crate::oauth::OAuthState::default());
        spawn_sweeper(
            &sessions, &shared, &limiter, &tokens, &oauth, &sys, &keyring,
        );

        Ok(AppState {
            cfg: Arc::new(cfg),
            sys,
            keyring,
            accounts,
            docs,
            quotas,
            queue,
            engine,
            sessions,
            shared,
            limiter,
            tokens,
            oauth,
            kdf_permits: Arc::new(Semaphore::new(KDF_PERMITS)),
            mcp_write_permits: Arc::new(Semaphore::new(MCP_WRITE_PERMITS)),
            page_images: Arc::new(crate::mcp::PageImageLimiter::default()),
            share_permits: Arc::new(Semaphore::new(SHARE_PERMITS)),
        })
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Background task that ends when the state it sweeps is dropped.
fn spawn_sweeper(
    sessions: &Arc<SessionStore>,
    shared: &Arc<SharedStaging>,
    limiter: &Arc<RateLimiter>,
    tokens: &Arc<TokenCache>,
    oauth: &Arc<crate::oauth::OAuthState>,
    sys: &Arc<SystemDb>,
    keyring: &Arc<Keyring>,
) {
    let (sessions, shared, limiter, tokens, oauth, sys, keyring) = (
        Arc::downgrade(sessions),
        Arc::downgrade(shared),
        Arc::downgrade(limiter),
        Arc::downgrade(tokens),
        Arc::downgrade(oauth),
        Arc::downgrade(sys),
        Arc::downgrade(keyring),
    );
    tokio::spawn(async move {
        // The first sweep is one interval away: `interval` would fire at
        // once and race whatever the app does in its first moments.
        let mut tick =
            tokio::time::interval_at(tokio::time::Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            let (
                Some(sessions),
                Some(shared),
                Some(limiter),
                Some(tokens),
                Some(oauth),
                Some(sys),
                Some(keyring),
            ) = (
                sessions.upgrade(),
                shared.upgrade(),
                limiter.upgrade(),
                tokens.upgrade(),
                oauth.upgrade(),
                sys.upgrade(),
                keyring.upgrade(),
            )
            else {
                break;
            };
            sessions.sweep();
            shared.sweep();
            limiter.sweep();
            tokens.sweep();
            // Codes that expired unused leave a pre-minted grant behind.
            let expired = oauth.sweep();
            let cutoff = unix_now() - crate::oauth::UNUSED_CLIENT_TTL_SECS;
            let sys = sys.clone();
            let keyring = keyring.clone();
            // SQLite is blocking; keep it off the async worker.
            let _ = tokio::task::spawn_blocking(move || {
                if let Err(e) =
                    sys.prune_oauth_clients(cutoff, unix_now() - crate::oauth::IDLE_CLIENT_TTL_SECS)
                {
                    tracing::error!(error = %e, "pruning unused oauth clients failed");
                }
                if let Err(e) = sys.delete_expired_tokens(unix_now()) {
                    tracing::error!(error = %e, "sweeping expired tokens failed");
                }
                for (user_id, grant_id) in expired {
                    let u = keyring.get(&user_id);
                    if let Err(e) =
                        crate::tokens::revoke_grant(&sys, u.as_deref(), &grant_id, &tokens)
                    {
                        tracing::error!(error = %e, "revoking an expired code's grant failed");
                    }
                }
            })
            .await;
        }
    });
}

/// The complete application. Serve it with
/// `into_make_service_with_connect_info::<SocketAddr>()`: handlers that rate
/// limit need the peer address.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .merge(admin::routes())
        .merge(auth::routes())
        .merge(docs::routes(&state))
        .merge(settings::routes())
        .merge(pwa::routes(&state))
        .merge(scan::routes(&state))
        .merge(crate::mcp::routes(&state))
        .merge(crate::oauth::routes())
        .route("/static/{file}", get(static_file))
        .route("/static/icons/{file}", get(icon_file))
        // Container health probe: no body, no auth, not access-logged.
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        // Layers run bottom-up: access log, then headers, then session + CSRF.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session::session_layer,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), origin_guard))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(access_log))
        .with_state(state)
}

/// Binds `cfg.bind` and serves until SIGINT/SIGTERM.
pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(state.cfg.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    let app = build_app(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

// ---------------------------------------------------------------------------
// Helpers for route modules
// ---------------------------------------------------------------------------

/// Whether htmx made this request (`HX-Request: true`).
pub fn is_htmx(headers: &HeaderMap) -> bool {
    headers
        .get("hx-request")
        .is_some_and(|v| v.as_bytes() == b"true")
}

/// Send the browser to `to` after a successful action: `303 See Other`, or
/// for htmx `200` with `HX-Redirect` (htmx would otherwise swap the target
/// page into the current one).
pub fn redirect(headers: &HeaderMap, to: &str) -> Response {
    let to = HeaderValue::from_str(to).expect("redirect targets are plain ASCII");
    if is_htmx(headers) {
        (StatusCode::OK, [("hx-redirect", to)]).into_response()
    } else {
        (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response()
    }
}

/// Response extension that replaces the default [`CSP`] for one response:
/// `resp.extensions_mut().insert(CspOverride("...".into()))`.
#[derive(Clone)]
pub struct CspOverride(pub std::borrow::Cow<'static, str>);

/// What `templates/base.html` needs. Every page template has a `page: Page` field.
pub struct Page {
    /// The session's CSRF token (meta tag and logout form).
    pub csrf: Option<String>,
    /// Set for fully logged-in users; the nav is shown only then.
    pub username: Option<String>,
    pub is_admin: bool,
}

impl Page {
    /// Cache-busting token for `/static` URLs (`?v=...`).
    pub fn v(&self) -> &'static str {
        ASSET_VERSION.as_str()
    }

    /// A page for visitors without a session (login, signup, recover).
    pub fn anonymous() -> Page {
        Page {
            csrf: None,
            username: None,
            is_admin: false,
        }
    }

    /// A page for a session. While the recovery key is unconfirmed the CSRF
    /// token is present but the nav is not.
    pub fn for_session(session: &Session) -> Page {
        let confirmed = session.must_confirm_recovery.is_none();
        Page {
            csrf: Some(session.csrf.clone()),
            username: confirmed.then(|| session.username.clone()),
            is_admin: confirmed && session.is_admin(),
        }
    }
}

/// Why [`run_kdf`] did not return the closure's value.
pub enum KdfError {
    /// No permit became free in time.
    Busy,
    /// The blocking task panicked or was cancelled.
    Failed(tokio::task::JoinError),
}

/// Runs password-KDF work on the blocking pool while holding one of `permits`.
/// The permit is released when the work ends, even if the caller goes away.
pub async fn run_kdf<T: Send + 'static>(
    permits: &Arc<Semaphore>,
    wait: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, KdfError> {
    let permit = match tokio::time::timeout(wait, permits.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        // The semaphore is never closed; treat it like exhaustion.
        Ok(Err(_)) | Err(_) => return Err(KdfError::Busy),
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(KdfError::Failed)
}

/// `503 Service Unavailable` with `Retry-After: 5`.
pub fn service_busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, HeaderValue::from_static("5"))],
        "The server is busy. Try again in a moment.",
    )
        .into_response()
}

/// [`run_kdf`] on the app's permits, with the failure turned into a response.
#[allow(clippy::result_large_err)] // the error is a ready `Response`, as in the route modules
pub async fn kdf_blocking<T: Send + 'static>(
    state: &AppState,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Response> {
    run_kdf(&state.kdf_permits, KDF_WAIT, f)
        .await
        .map_err(|e| match e {
            KdfError::Busy => service_busy(),
            KdfError::Failed(e) => {
                tracing::error!(error = %e, "account task failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        })
}

/// Render a template as an HTML response.
pub fn render(template: &impl Template) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template rendering failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

/// Paths that may receive cross-origin state-changing requests, POST only
/// (the CSRF middleware honours the same list):
///
/// * The OS share target, exact `POST /share`, which merely stages files in
///   memory; saving them (`POST /share/{id}`) stays guarded and needs CSRF.
/// * The OAuth `register`, `token` and `revoke` endpoints, which claude.ai's
///   servers and CLI clients call cross-origin and which grant nothing from
///   ambient cookies. The consent POST (`/oauth/authorize`) is NOT exempt.
const ORIGIN_EXEMPT_PATHS: &[&str] = &[
    pwa::SHARE_PATH,
    "/oauth/register",
    "/oauth/token",
    "/oauth/revoke",
];

/// The only paths that accept bearer-token authentication. A bearer header on
/// any other path gets no origin-guard exemption.
const BEARER_PATHS: &[&str] = &["/mcp", "/api/upload"];

/// `scheme://host[:port]` of a URL, lowercased, without the scheme's default
/// port (`https` 443, `http` 80), so `https://h:443` and `https://h` compare equal.
fn origin_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let authority = match authority.strip_suffix(default_port) {
        Some(host) if !default_port.is_empty() => host,
        _ => &authority,
    };
    format!("{scheme}://{authority}")
}

/// Rejects cross-origin state-changing requests (login CSRF: the cookie-less
/// login/signup/recover posts have no token). When `Sec-Fetch-Site` is present
/// it decides alone: `same-origin` and `none` pass, everything else is 403.
/// Only without it, an `Origin` header must equal the origin of
/// `cfg.public_url` (`null` is rejected). Requests with neither header pass
/// (curl, old browsers). Bearer-authenticated
/// requests without a session cookie to [`BEARER_PATHS`], and
/// [`ORIGIN_EXEMPT_PATHS`], are exempt.
async fn origin_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let headers = req.headers();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.len() > 7 && v[..7].eq_ignore_ascii_case("bearer "));
    if (bearer
        && session::session_id(headers).is_none()
        && BEARER_PATHS.contains(&req.uri().path()))
        || (*req.method() == Method::POST && ORIGIN_EXEMPT_PATHS.contains(&req.uri().path()))
    {
        return next.run(req).await;
    }
    let allowed = match headers.get("sec-fetch-site") {
        // Authoritative when present. Chrome sends `Origin: null` on form
        // posts under `Referrer-Policy: no-referrer`, so Origin is not
        // consulted. `same-site` is rejected: sibling subdomains are other tenants.
        Some(v) => {
            v.as_bytes().eq_ignore_ascii_case(b"same-origin")
                || v.as_bytes().eq_ignore_ascii_case(b"none")
        }
        None => headers.get(header::ORIGIN).is_none_or(|v| {
            v.to_str()
                .is_ok_and(|o| origin_of(o) == origin_of(&state.cfg.public_url))
        }),
    };
    if !allowed {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

/// Sets the security headers on every response and `Cache-Control: no-store`
/// on every response that did not choose its own caching (static assets do).
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let csp = resp
        .extensions()
        .get::<CspOverride>()
        .and_then(|over| HeaderValue::from_str(&over.0).ok())
        .unwrap_or_else(|| HeaderValue::from_static(CSP));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, csp);
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    resp
}

/// Logs method, route template, status and latency. Never the URI: paths
/// carry document ids and queries carry search terms. Requests that match no
/// route are logged as `<unmatched>`.
async fn access_log(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "<unmatched>".to_owned(), |p| p.as_str().to_owned());
    let resp = next.run(req).await;
    // The health probe fires every 30 s; it would only drown the log.
    if path == "/healthz" {
        return resp;
    }
    tracing::info!(
        %method,
        path,
        status = resp.status().as_u16(),
        ms = start.elapsed().as_millis() as u64,
        "request"
    );
    resp
}

// ---------------------------------------------------------------------------
// Static assets (compiled into the binary)
// ---------------------------------------------------------------------------

const JS: &str = "text/javascript; charset=utf-8";
const PNG: &str = "image/png";
const SVG: &str = "image/svg+xml";

/// `(file name, content type, bytes)`. Add new assets here.
const STATIC_FILES: &[(&str, &str, &[u8])] = &[
    (
        "app.css",
        "text/css; charset=utf-8",
        include_bytes!("../../static/app.css"),
    ),
    ("app.js", JS, include_bytes!("../../static/app.js")),
    (
        "scan.css",
        "text/css; charset=utf-8",
        include_bytes!("../../static/scan.css"),
    ),
    ("scan.js", JS, include_bytes!("../../static/scan.js")),
    (
        "htmx.min.js",
        JS,
        include_bytes!("../../static/htmx.min.js"),
    ),
    (
        "offline.html",
        "text/html; charset=utf-8",
        include_bytes!("../../static/offline.html"),
    ),
    (
        "icons/icon.svg",
        SVG,
        include_bytes!("../../static/icons/icon.svg"),
    ),
    (
        "icons/favicon.svg",
        SVG,
        include_bytes!("../../static/icons/favicon.svg"),
    ),
    (
        "icons/favicon-32.png",
        PNG,
        include_bytes!("../../static/icons/favicon-32.png"),
    ),
    (
        "icons/favicon-16.png",
        PNG,
        include_bytes!("../../static/icons/favicon-16.png"),
    ),
    (
        "icons/apple-touch-icon.png",
        PNG,
        include_bytes!("../../static/icons/apple-touch-icon.png"),
    ),
    (
        "icons/icon-192.png",
        PNG,
        include_bytes!("../../static/icons/icon-192.png"),
    ),
    (
        "icons/icon-512.png",
        PNG,
        include_bytes!("../../static/icons/icon-512.png"),
    ),
    (
        "icons/icon-maskable-512.png",
        PNG,
        include_bytes!("../../static/icons/icon-maskable-512.png"),
    ),
];

/// Short content hash over every embedded asset, the manifest and the
/// service-worker source. It names the service-worker cache, so any deploy that changes an
/// asset installs a fresh worker and drops the old shell cache.
pub static ASSET_VERSION: LazyLock<String> = LazyLock::new(|| asset_version(pwa::MANIFEST));

/// [`ASSET_VERSION`] for a given manifest (the manifest is part of what a
/// browser caches, so a change to it must roll the worker too).
fn asset_version(manifest: &str) -> String {
    let mut h = Sha256::new();
    for (name, _, bytes) in STATIC_FILES {
        h.update(name.as_bytes());
        h.update(bytes);
    }
    h.update(pwa::SW_TEMPLATE.as_bytes());
    h.update(manifest.as_bytes());
    hex::encode(&h.finalize()[..6])
}

/// Strong `ETag` (quoted content hash) per [`STATIC_FILES`] entry, same order.
static STATIC_ETAGS: LazyLock<Vec<String>> = LazyLock::new(|| {
    STATIC_FILES
        .iter()
        .map(|(_, _, bytes)| format!("\"{}\"", hex::encode(&Sha256::digest(bytes)[..16])))
        .collect()
});

async fn static_file(Path(file): Path<String>, headers: HeaderMap) -> Response {
    serve_static(&file, &headers)
}

/// `/static/icons/{file}`: the entries of [`STATIC_FILES`] named `icons/...`.
async fn icon_file(Path(file): Path<String>, headers: HeaderMap) -> Response {
    serve_static(&format!("icons/{file}"), &headers)
}

/// Whether `If-None-Match` lists `etag` (or `*`); weak validators compare equal.
fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .map(|t| t.trim().trim_start_matches("W/"))
                .any(|t| t == "*" || t == etag)
        })
}

/// Assets are revalidated on every use (`no-cache` + `ETag`), so a deploy is
/// never hidden behind a day-old browser cache.
fn serve_static(file: &str, req_headers: &HeaderMap) -> Response {
    let Some(i) = STATIC_FILES.iter().position(|(name, ..)| *name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (_, content_type, bytes) = STATIC_FILES[i];
    let etag = STATIC_ETAGS[i].as_str();
    if etag_matches(req_headers, etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [(header::ETAG, etag), (header::CACHE_CONTROL, "no-cache")],
        )
            .into_response();
    }
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
            (header::ETAG, etag),
        ],
        bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn asset_version_covers_the_manifest() {
        assert_eq!(*ASSET_VERSION, asset_version(pwa::MANIFEST));
        assert_ne!(asset_version("{}"), asset_version("{ }"));
    }

    #[test]
    fn origin_of_drops_default_ports_only() {
        assert_eq!(
            origin_of("https://Host.Example:443/x?y"),
            "https://host.example"
        );
        assert_eq!(origin_of("https://host.example"), "https://host.example");
        assert_eq!(origin_of("http://host.example:80"), "http://host.example");
        assert_eq!(
            origin_of("https://host.example:8443"),
            "https://host.example:8443"
        );
        assert_eq!(
            origin_of("http://host.example:443"),
            "http://host.example:443"
        );
        assert_ne!(origin_of("null"), origin_of("https://host.example"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kdf_semaphore_limits_concurrency() {
        let permits = Arc::new(Semaphore::new(KDF_PERMITS));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (permits, running, peak) = (permits.clone(), running.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                run_kdf(&permits, Duration::from_secs(30), move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(40));
                    running.fetch_sub(1, Ordering::SeqCst);
                })
                .await
                .ok()
                .expect("permit within the wait");
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), KDF_PERMITS);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kdf_wait_times_out_with_503_and_retry_after() {
        let permits = Arc::new(Semaphore::new(1));
        let _held = permits.clone().acquire_owned().await.unwrap();
        let r = run_kdf(&permits, Duration::from_millis(50), || ()).await;
        assert!(matches!(r, Err(KdfError::Busy)));
        let resp = service_busy();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()["retry-after"], "5");
    }
}
