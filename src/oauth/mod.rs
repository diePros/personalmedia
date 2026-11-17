//! OAuth 2.1 for the MCP endpoint (spec 13b): metadata, dynamic client
//! registration and, in later tasks, authorize/token/revoke.
//!
//! `/oauth/register`, `/oauth/token` and `/oauth/revoke` are called
//! cross-origin by nature (claude.ai's servers, the Hermes CLI); they are the
//! only routes exempt from the origin guard and CSRF (POST only, see
//! `web::ORIGIN_EXEMPT_PATHS`). They carry no cookie-based authority.

pub mod metadata;
pub mod register;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};

use crate::web::AppState;

/// Scopes the server knows about.
pub const SCOPES: &[&str] = &["mcp:read", "mcp:write", "content:full", "offline_access"];

/// Redirect URIs of Claude's connectors (exact match).
const CLAUDE_REDIRECTS: &[&str] = &[
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
];

/// Registrations allowed per IP per hour.
pub const DCR_PER_IP_PER_HOUR: usize = 10;
const DCR_WINDOW: Duration = Duration::from_secs(3600);
/// Most registered clients at once.
pub const MAX_CLIENTS: usize = 200;
/// Clients that never got a grant are dropped after this long.
pub const UNUSED_CLIENT_TTL_SECS: i64 = 24 * 3600;
/// Longest stored client name, in characters.
pub const CLIENT_NAME_MAX_CHARS: usize = 64;

/// In-memory OAuth state shared through [`AppState`].
#[derive(Default)]
pub struct OAuthState {
    dcr_hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl OAuthState {
    /// Counts one registration attempt for `key`; `Err(retry_after)` when the
    /// hourly allowance is used up.
    pub fn dcr_hit(&self, key: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let mut map = self.dcr_hits.lock().unwrap_or_else(|e| e.into_inner());
        let hits = map.entry(key.to_owned()).or_default();
        hits.retain(|t| now.duration_since(*t) < DCR_WINDOW);
        if hits.len() >= DCR_PER_IP_PER_HOUR {
            let oldest = hits[0];
            return Err(DCR_WINDOW.saturating_sub(now.duration_since(oldest)));
        }
        hits.push(now);
        Ok(())
    }

    /// Drops registration counters that have aged out.
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut map = self.dcr_hits.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, hits| {
            hits.retain(|t| now.duration_since(*t) < DCR_WINDOW);
            !hits.is_empty()
        });
    }
}

pub fn dcr_key(ip: IpAddr) -> String {
    crate::web::ratelimit::ip_key(ip)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata::protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(metadata::protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::authorization_server),
        )
        .route(
            "/oauth/register",
            post(register::register).layer(DefaultBodyLimit::max(register::BODY_LIMIT)),
        )
        // Implemented in the next task.
        .route("/oauth/token", post(not_implemented))
        .route("/oauth/revoke", post(not_implemented))
}

async fn not_implemented() -> Response {
    StatusCode::NOT_IMPLEMENTED.into_response()
}

/// A JSON response with `Cache-Control: no-store`.
pub fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body.to_string(),
    )
        .into_response()
}

/// An RFC 6749 / 7591 error body. `description` must never hold secrets.
pub fn oauth_error(status: StatusCode, code: &str, description: &str) -> Response {
    json_response(
        status,
        &json!({"error": code, "error_description": description}),
    )
}

/// The URL of the MCP endpoint, which is also the protected resource.
pub fn mcp_url(public_url: &str) -> String {
    format!("{public_url}/mcp")
}

/// `{public_url}/.well-known/oauth-protected-resource`
pub fn resource_metadata_url(public_url: &str) -> String {
    format!("{public_url}/.well-known/oauth-protected-resource")
}

/// Whether `s` is `host[:port]` made of lowercase letters, digits, `-` and `.`.
fn lowercase_host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// A path-and-query tail: starts with `/`, printable ASCII, no fragment,
/// backslash or whitespace.
fn tail_ok(tail: &str) -> bool {
    tail.starts_with('/')
        && tail
            .bytes()
            .all(|b| (0x21..0x7f).contains(&b) && b != b'#' && b != b'\\')
}

/// Whether `uri` may be registered or used as a redirect target (spec 13b):
/// Claude's two callbacks (exact), loopback `http://127.0.0.1:{port}{path}` or
/// `http://localhost:{port}{path}` with any port, or an `https://` URL on one
/// of `extra_hosts` (`PM_OAUTH_EXTRA_REDIRECT_HOSTS`, lowercase). Hosts must be
/// lowercase; fragments and user info are rejected.
pub fn redirect_uri_allowed(uri: &str, extra_hosts: &[String]) -> bool {
    if CLAUDE_REDIRECTS.contains(&uri) {
        return true;
    }
    if let Some(rest) = uri.strip_prefix("http://") {
        let Some(slash) = rest.find('/') else {
            return false;
        };
        let (authority, tail) = rest.split_at(slash);
        let Some((host, port)) = authority.split_once(':') else {
            return false;
        };
        return (host == "127.0.0.1" || host == "localhost")
            && !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|p| p > 0)
            && tail_ok(tail);
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        let Some(slash) = rest.find('/') else {
            return false;
        };
        let (authority, tail) = rest.split_at(slash);
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let port_ok = port.is_none_or(|p| {
            !p.is_empty()
                && p.len() <= 5
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|p| p > 0)
        });
        return port_ok
            && lowercase_host_ok(host)
            && extra_hosts.iter().any(|h| h == host)
            && tail_ok(tail);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_validator_cases() {
        let extra = vec!["app.example.org".to_string()];
        let ok = |u: &str| redirect_uri_allowed(u, &extra);
        assert!(ok("https://claude.ai/api/mcp/auth_callback"));
        assert!(ok("https://claude.com/api/mcp/auth_callback"));
        assert!(ok("http://127.0.0.1:8123/cb"));
        assert!(ok("http://localhost:1/cb/x?y=1"));
        assert!(ok("https://app.example.org/cb"));
        assert!(ok("https://app.example.org:8443/cb"));
        assert!(!ok("https://claude.ai/api/mcp/auth_callback/"));
        assert!(!ok("https://claude.ai/other"));
        assert!(!ok("http://claude.ai/api/mcp/auth_callback"));
        assert!(!ok("http://127.0.0.1/cb"));
        assert!(!ok("http://127.0.0.1:0/cb"));
        assert!(!ok("http://127.0.0.1:99999/cb"));
        assert!(!ok("http://127.0.0.1.evil.com:80/cb"));
        assert!(!ok("http://evil.com@127.0.0.1:80/cb"));
        assert!(!ok("http://localhost:80"));
        assert!(!ok("http://LOCALHOST:80/cb"));
        assert!(!ok("https://APP.example.org/cb"));
        assert!(!ok("https://other.example.org/cb"));
        assert!(!ok("https://app.example.org.evil.com/cb"));
        assert!(!ok("https://user@app.example.org/cb"));
        assert!(!ok("https://app.example.org/cb#frag"));
        assert!(!ok("javascript:alert(1)"));
        assert!(!ok("ftp://app.example.org/cb"));
        assert!(!redirect_uri_allowed("https://app.example.org/cb", &[]));
    }
}
