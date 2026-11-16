//! PWA entry points served from the site root: the web app manifest and the
//! app-shell service worker (see `static/sw.js`).

use axum::Router;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::AppState;

/// Colors match `static/app.css`: `--accent` (light) and `--bg` (light).
const MANIFEST: &str = r##"{
  "name": "Personal Media",
  "short_name": "Media",
  "start_url": "/documents",
  "scope": "/",
  "display": "standalone",
  "theme_color": "#1d4ed8",
  "background_color": "#fafaf9",
  "icons": [
    {"src": "/static/icons/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
    {"src": "/static/icons/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
    {"src": "/static/icons/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}
  ]
}
"##;

const SW: &str = include_str!("../../static/sw.js");

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/manifest.webmanifest", get(manifest))
        .route("/sw.js", get(service_worker))
}

async fn manifest() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/manifest+json"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        MANIFEST,
    )
        .into_response()
}

/// `no-cache` so browsers revalidate on every update check; the scope header
/// is belt and braces (the worker already lives at `/`).
async fn service_worker() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            (
                header::HeaderName::from_static("service-worker-allowed"),
                "/",
            ),
        ],
        SW,
    )
        .into_response()
}
