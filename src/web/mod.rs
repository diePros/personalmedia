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
pub mod ratelimit;
pub mod session;
pub mod settings;

use std::net::SocketAddr;
use std::sync::Arc;
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
use crate::extract::{ExtractConfig, ExtractQueue, start_workers, wipe_tmp};
use crate::keyring::Keyring;
use crate::system_db::{SYSTEM_DB_FILE, SystemDb};
use crate::tokens::TokenCache;
use ratelimit::RateLimiter;
use session::{Session, SessionStore};

/// Default `Content-Security-Policy`. A route may replace it with [`CspOverride`].
pub const CSP: &str = "default-src 'self'; img-src 'self' data:; object-src 'self'; \
                       frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// How often expired sessions and stale rate-limit entries are dropped.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub sys: Arc<SystemDb>,
    pub keyring: Arc<Keyring>,
    pub accounts: Arc<Accounts>,
    pub docs: Arc<Documents>,
    pub sessions: Arc<SessionStore>,
    pub limiter: Arc<RateLimiter>,
    pub tokens: Arc<TokenCache>,
}

impl AppState {
    /// Opens the data directory, wipes OCR scratch left by a previous run and
    /// starts the extraction workers and the sweeper. Must be called inside a
    /// tokio runtime.
    pub fn build(cfg: Config) -> anyhow::Result<AppState> {
        let data_dir = cfg.data_dir.clone();
        std::fs::create_dir_all(&data_dir)?;
        let sys = Arc::new(SystemDb::open(&data_dir.join(SYSTEM_DB_FILE))?);
        let (queue, rx) = ExtractQueue::channel();
        let keyring = Arc::new(Keyring::new(data_dir.clone(), Arc::new(queue.clone())));
        let accounts = Arc::new(Accounts::new(&cfg, sys.clone(), keyring.clone()));
        let docs = Arc::new(Documents::new(
            data_dir.clone(),
            cfg.max_upload_bytes,
            Arc::new(queue),
        ));

        let tmp = data_dir.join("tmp");
        wipe_tmp(&tmp)?;
        start_workers(cfg.ocr_workers, ExtractConfig::new(tmp), docs.clone(), rx);

        let sessions = Arc::new(SessionStore::new(cfg.session_idle, cfg.session_max));
        let limiter = Arc::new(RateLimiter::new());
        spawn_sweeper(&sessions, &limiter);

        Ok(AppState {
            cfg: Arc::new(cfg),
            sys,
            keyring,
            accounts,
            docs,
            sessions,
            limiter,
            tokens: Arc::new(TokenCache::default()),
        })
    }
}

/// Background task that ends when the state it sweeps is dropped.
fn spawn_sweeper(sessions: &Arc<SessionStore>, limiter: &Arc<RateLimiter>) {
    let (sessions, limiter) = (Arc::downgrade(sessions), Arc::downgrade(limiter));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            let (Some(sessions), Some(limiter)) = (sessions.upgrade(), limiter.upgrade()) else {
                break;
            };
            sessions.sweep();
            limiter.sweep();
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
        .route("/static/{file}", get(static_file))
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
pub fn redirect(headers: &HeaderMap, to: &'static str) -> Response {
    let to = HeaderValue::from_static(to);
    if is_htmx(headers) {
        (StatusCode::OK, [("hx-redirect", to)]).into_response()
    } else {
        (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response()
    }
}

/// Response extension that replaces the default [`CSP`] for one response:
/// `resp.extensions_mut().insert(CspOverride("..."))`.
#[derive(Clone, Copy)]
pub struct CspOverride(pub &'static str);

/// What `templates/base.html` needs. Every page template has a `page: Page` field.
pub struct Page {
    /// The session's CSRF token (meta tag and logout form).
    pub csrf: Option<String>,
    /// Set for fully logged-in users; the nav is shown only then.
    pub username: Option<String>,
    pub is_admin: bool,
}

impl Page {
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

/// Paths that may receive cross-origin state-changing requests (for example
/// an OS share target). Empty for now; Task 18 adds `/share`.
const ORIGIN_EXEMPT_PATHS: &[&str] = &[];

/// `scheme://host[:port]` of a URL, lowercased.
fn origin_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    format!("{scheme}://{authority}").to_ascii_lowercase()
}

/// Rejects cross-origin state-changing requests (login CSRF: the cookie-less
/// login/signup/recover posts have no token). When `Sec-Fetch-Site` is present
/// it decides alone: `same-origin` and `none` pass, everything else is 403.
/// Only without it, an `Origin` header must equal the origin of
/// `cfg.public_url` (`null` is rejected). Requests with neither header pass
/// (curl, old browsers). Bearer-authenticated
/// requests without a session cookie and [`ORIGIN_EXEMPT_PATHS`] are exempt.
async fn origin_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let headers = req.headers();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.len() > 7 && v[..7].eq_ignore_ascii_case("bearer "));
    if (bearer && session::session_id(headers).is_none())
        || ORIGIN_EXEMPT_PATHS.contains(&req.uri().path())
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
                .is_ok_and(|o| o.to_ascii_lowercase() == origin_of(&state.cfg.public_url))
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
        .map_or(CSP, |over| over.0);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(csp),
    );
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

/// `(file name, content type, bytes)`. Add new assets here.
const STATIC_FILES: &[(&str, &str, &[u8])] = &[
    (
        "app.css",
        "text/css; charset=utf-8",
        include_bytes!("../../static/app.css"),
    ),
    ("app.js", JS, include_bytes!("../../static/app.js")),
    (
        "htmx.min.js",
        JS,
        include_bytes!("../../static/htmx.min.js"),
    ),
];

async fn static_file(Path(file): Path<String>) -> Response {
    let Some((_, content_type, bytes)) = STATIC_FILES.iter().find(|(name, ..)| *name == file)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, *content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        *bytes,
    )
        .into_response()
}
