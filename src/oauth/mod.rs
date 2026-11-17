//! OAuth 2.1 for the MCP endpoint (spec 13b): metadata, dynamic client
//! registration, authorize/consent, token (authorization code with PKCE and
//! rotating refresh tokens) and revoke.
//!
//! `/oauth/register`, `/oauth/token` and `/oauth/revoke` are called
//! cross-origin by nature (claude.ai's servers, the Hermes CLI); they are the
//! only routes exempt from the origin guard and CSRF (POST only, see
//! `web::ORIGIN_EXEMPT_PATHS`). They carry no cookie-based authority.

pub mod authorize;
pub mod metadata;
pub mod register;
pub mod token;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use data_encoding::BASE64URL_NOPAD;
use zeroize::Zeroizing;

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

/// Authorization codes live this long.
pub const CODE_TTL: Duration = Duration::from_secs(60);
/// A pending authorize request (waiting for login or consent) lives this long.
pub const REQUEST_TTL: Duration = Duration::from_secs(10 * 60);
/// Most pending authorize requests held at once; the oldest is dropped beyond it.
const MAX_REQUESTS: usize = 1000;
/// Consumed refresh tokens remembered for reuse detection.
const CONSUMED_REFRESH_CAP: usize = 4096;

/// A validated `GET /oauth/authorize` request, held server-side while the user
/// logs in and consents. The browser only carries its random id.
#[derive(Clone)]
pub struct AuthRequest {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub challenge: String,
    /// Requested scopes; they only pre-select the consent form.
    pub scopes: Vec<String>,
    created: Instant,
}

impl AuthRequest {
    pub fn new(
        client_id: String,
        client_name: String,
        redirect_uri: String,
        state: Option<String>,
        challenge: String,
        scopes: Vec<String>,
    ) -> AuthRequest {
        AuthRequest {
            client_id,
            client_name,
            redirect_uri,
            state,
            challenge,
            scopes,
            created: Instant::now(),
        }
    }
}

/// An issued authorization code. The grant (rows and metadata) already
/// exists; the plaintext tokens are only held here, zeroized on drop.
pub struct CodeEntry {
    pub user_id: String,
    pub grant_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub challenge: String,
    pub scope: String,
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub created: Instant,
}

#[derive(Default)]
struct Consumed {
    order: VecDeque<String>,
    /// token id -> (SHA-256 of the full token, user id, grant id)
    map: HashMap<String, ([u8; 32], String, String)>,
}

/// In-memory OAuth state shared through [`AppState`].
pub struct OAuthState {
    dcr_hits: Mutex<HashMap<String, Vec<Instant>>>,
    requests: Mutex<HashMap<String, AuthRequest>>,
    codes: Mutex<HashMap<String, CodeEntry>>,
    /// Consumed refresh tokens, for reuse detection. Memory only: a schema
    /// table would need system DB v4. After a restart a replayed consumed
    /// token is simply unknown (`invalid_grant`) and does not revoke the
    /// grant; the grant then ends when its newest refresh token expires, or
    /// when the user revokes it in Settings.
    consumed: Mutex<Consumed>,
    code_ttl_ms: AtomicU64,
}

impl Default for OAuthState {
    fn default() -> Self {
        OAuthState {
            dcr_hits: Mutex::default(),
            requests: Mutex::default(),
            codes: Mutex::default(),
            consumed: Mutex::default(),
            code_ttl_ms: AtomicU64::new(CODE_TTL.as_millis() as u64),
        }
    }
}

/// 32 random bytes as unpadded base64url (43 characters).
pub fn random_id() -> String {
    let mut b = [0u8; 32];
    crate::crypto::fill_random(&mut b);
    BASE64URL_NOPAD.encode(&b)
}

impl OAuthState {
    /// Test hook: how long authorization codes live.
    #[doc(hidden)]
    pub fn set_code_ttl(&self, ttl: Duration) {
        self.code_ttl_ms
            .store(ttl.as_millis() as u64, Ordering::Relaxed);
    }

    fn code_ttl(&self) -> Duration {
        Duration::from_millis(self.code_ttl_ms.load(Ordering::Relaxed))
    }

    /// Stores a pending authorize request; returns its id.
    pub fn put_request(&self, req: AuthRequest) -> String {
        let id = random_id();
        let mut map = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_REQUESTS
            && let Some(oldest) = map
                .iter()
                .min_by_key(|(_, r)| r.created)
                .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
        map.insert(id.clone(), req);
        id
    }

    pub fn request(&self, id: &str) -> Option<AuthRequest> {
        let map = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        map.get(id)
            .filter(|r| r.created.elapsed() < REQUEST_TTL)
            .cloned()
    }

    /// Removes and returns a pending request (consent is single use).
    pub fn take_request(&self, id: &str) -> Option<AuthRequest> {
        let mut map = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(id).filter(|r| r.created.elapsed() < REQUEST_TTL)
    }

    /// Stores a code entry; returns the code.
    pub fn put_code(&self, entry: CodeEntry) -> String {
        let code = random_id();
        self.codes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(code.clone(), entry);
        code
    }

    /// Removes and returns a code entry (codes are single use, even when the
    /// exchange then fails). `None` when unknown or older than the code TTL;
    /// an expired entry is returned as `Err` so the caller can revoke it.
    pub fn take_code(&self, code: &str) -> Option<Result<CodeEntry, CodeEntry>> {
        let entry = self
            .codes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(code)?;
        if entry.created.elapsed() >= self.code_ttl() {
            Some(Err(entry))
        } else {
            Some(Ok(entry))
        }
    }

    /// Remembers a refresh token that was just exchanged.
    pub fn note_consumed_refresh(
        &self,
        token_id: &str,
        token_hash: [u8; 32],
        user_id: &str,
        grant_id: &str,
    ) {
        let mut c = self.consumed.lock().unwrap_or_else(|e| e.into_inner());
        if c.order.len() >= CONSUMED_REFRESH_CAP
            && let Some(old) = c.order.pop_front()
        {
            c.map.remove(&old);
        }
        c.order.push_back(token_id.to_owned());
        c.map.insert(
            token_id.to_owned(),
            (token_hash, user_id.to_owned(), grant_id.to_owned()),
        );
    }

    /// `(user id, grant id)` when `token_id` was consumed and `token_hash` is
    /// the hash of the very token string that was consumed (so knowing an id
    /// alone cannot revoke a grant).
    pub fn consumed_refresh(
        &self,
        token_id: &str,
        token_hash: &[u8; 32],
    ) -> Option<(String, String)> {
        let c = self.consumed.lock().unwrap_or_else(|e| e.into_inner());
        let (h, user, grant) = c.map.get(token_id)?;
        ct_eq(h, token_hash).then(|| (user.clone(), grant.clone()))
    }

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

    /// Drops registration counters, stale pending requests and expired codes.
    /// Returns `(user_id, grant_id)` of the codes that expired unused: their
    /// grants must be revoked.
    pub fn sweep(&self) -> Vec<(String, String)> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, r| r.created.elapsed() < REQUEST_TTL);
        let ttl = self.code_ttl();
        let mut expired = Vec::new();
        {
            let mut codes = self.codes.lock().unwrap_or_else(|e| e.into_inner());
            let dead: Vec<String> = codes
                .iter()
                .filter(|(_, c)| c.created.elapsed() >= ttl)
                .map(|(k, _)| k.clone())
                .collect();
            for k in dead {
                if let Some(c) = codes.remove(&k) {
                    expired.push((c.user_id.clone(), c.grant_id.clone()));
                }
            }
        }
        let now = Instant::now();
        let mut map = self.dcr_hits.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, hits| {
            hits.retain(|t| now.duration_since(*t) < DCR_WINDOW);
            !hits.is_empty()
        });
        expired
    }
}

/// Constant-time equality of two byte strings.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
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
        .route(
            "/oauth/authorize",
            get(authorize::authorize_get)
                .post(authorize::authorize_post)
                .layer(DefaultBodyLimit::max(authorize::BODY_LIMIT)),
        )
        .route("/oauth/authorize/resume", get(authorize::resume))
        .route(
            "/oauth/token",
            post(token::token).layer(DefaultBodyLimit::max(token::BODY_LIMIT)),
        )
        .route(
            "/oauth/revoke",
            post(token::revoke).layer(DefaultBodyLimit::max(token::BODY_LIMIT)),
        )
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
