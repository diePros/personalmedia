//! Browser sessions: the in-memory store, the session cookie, CSRF checks and
//! the extractors handlers use to require a logged-in user.
//!
//! # How a request gets its session
//!
//! [`session_layer`] runs for every request. It looks up the `pm_session`
//! cookie once and, if the session is alive, puts a [`Session`] snapshot into
//! the request extensions. The extractors below only read that extension.
//!
//! # CSRF
//!
//! Every non-GET/HEAD request that carries a live session must present the
//! session's CSRF token. There are two ways, and the split is fixed:
//!
//! * **Header `X-CSRF-Token`**, checked by [`session_layer`] before the
//!   handler runs. `static/app.js` sets it on every htmx request and in
//!   `pmFetch`. The header is *required* for anything that is not a plain HTML
//!   form post: htmx requests (`HX-Request`), JSON, multipart uploads and
//!   bodiless requests are rejected with 403 without it.
//! * **Form field `csrf`**, for plain `application/x-www-form-urlencoded`
//!   posts made without JavaScript. The middleware cannot read the body, so it
//!   lets these through and the handler must check the field. Handlers do that
//!   by taking the form as [`CsrfForm<T>`] instead of `axum::Form<T>`.
//!   (`check_csrf` is the underlying function for the rare handler that parses
//!   a body itself.)
//!
//! So: a session-authenticated POST handler either takes `CsrfForm<T>` or is
//! only reachable with the header. A plain `Form<T>` on such a route is a bug.
//! Requests without a session (login, signup) carry no CSRF token.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{AppState, is_htmx};
use crate::crypto::{RecoveryKey, fill_random};
use crate::keyring::Unlocked;
use crate::system_db::{Role, UserRow};

pub const SESSION_COOKIE: &str = "pm_session";
pub const CSRF_HEADER: &str = "x-csrf-token";
/// Name of the hidden form field carrying the CSRF token.
pub const CSRF_FIELD: &str = "csrf";

/// One browser session. Holding it keeps the user's keys unlocked.
///
/// Handlers get a snapshot (a clone) of the stored session; change the stored
/// one through [`SessionStore`].
#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub role: Role,
    pub unlocked: Arc<Unlocked>,
    pub csrf: String,
    pub created: Instant,
    pub last_seen: Instant,
    /// Set until the user confirms having saved this recovery key. Until then
    /// only [`PendingUser`] routes are reachable.
    pub must_confirm_recovery: Option<RecoveryKey>,
    /// TOTP secret (base32) between "begin setup" and "confirm code".
    pub pending_totp_secret: Option<String>,
}

impl Session {
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

/// 32 bytes from the OS CSPRNG as unpadded base64url (43 characters).
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    BASE64URL_NOPAD.encode(&bytes)
}

/// In-memory sessions keyed by session id. A restart drops them all.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    idle: Duration,
    max: Duration,
}

impl SessionStore {
    /// `idle`: lifetime without requests. `max`: absolute lifetime.
    pub fn new(idle: Duration, max: Duration) -> SessionStore {
        SessionStore {
            sessions: Mutex::new(HashMap::new()),
            idle,
            max,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        // A poisoned lock only means another thread panicked; the map is still usable.
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn expired(&self, s: &Session, now: Instant) -> bool {
        now.duration_since(s.last_seen) >= self.idle || now.duration_since(s.created) >= self.max
    }

    /// Start a session. Returns `(cookie value, csrf token)`; send the cookie
    /// with [`session_cookie`].
    pub fn create(
        &self,
        user: &UserRow,
        unlocked: Arc<Unlocked>,
        must_confirm: Option<RecoveryKey>,
    ) -> (String, String) {
        let now = Instant::now();
        let session = Session {
            id: random_token(),
            user_id: user.id.clone(),
            username: user.username.clone(),
            role: user.role,
            unlocked,
            csrf: random_token(),
            created: now,
            last_seen: now,
            must_confirm_recovery: must_confirm,
            pending_totp_secret: None,
        };
        let out = (session.id.clone(), session.csrf.clone());
        self.lock().insert(session.id.clone(), session);
        out
    }

    /// The live session for `id`, with `last_seen` refreshed. An expired
    /// session is removed and `None` returned.
    pub fn get(&self, id: &str) -> Option<Session> {
        let now = Instant::now();
        let mut sessions = self.lock();
        let s = sessions.get_mut(id)?;
        if self.expired(s, now) {
            let dead = sessions.remove(id);
            drop(sessions);
            drop(dead); // may close the user's index DB; not under the lock
            return None;
        }
        s.last_seen = now;
        Some(s.clone())
    }

    /// The user confirmed saving the recovery key: forget it and make the
    /// session a normal one.
    pub fn confirm_recovery(&self, id: &str) {
        let key = self
            .lock()
            .get_mut(id)
            .and_then(|s| s.must_confirm_recovery.take());
        drop(key);
    }

    pub fn set_pending_totp(&self, id: &str, secret: Option<String>) {
        if let Some(s) = self.lock().get_mut(id) {
            s.pending_totp_secret = secret;
        }
    }

    /// Logout.
    pub fn remove(&self, id: &str) {
        let dead = self.lock().remove(id);
        drop(dead);
    }

    /// End every session of a user (disable, delete, password change).
    pub fn remove_user(&self, user_id: &str) {
        self.remove_where(|s| s.user_id == user_id);
    }

    /// Drop expired sessions. Run every minute by a background task, so keys
    /// do not stay unlocked just because nobody asked for the session again.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.remove_where(|s| self.expired(s, now));
    }

    fn remove_where(&self, dead: impl Fn(&Session) -> bool) {
        let removed: Vec<Session> = {
            let mut sessions = self.lock();
            let ids: Vec<String> = sessions
                .values()
                .filter(|s| dead(s))
                .map(|s| s.id.clone())
                .collect();
            ids.iter().filter_map(|id| sessions.remove(id)).collect()
        };
        drop(removed);
    }
}

/// `Set-Cookie` value that stores session id `value` in the browser.
pub fn session_cookie(value: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={value}; HttpOnly; Secure; SameSite=Strict; Path=/"
    ))
    .expect("session ids are base64url")
}

/// `Set-Cookie` value that deletes the session cookie.
pub fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static("pm_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
}

pub(crate) fn session_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == SESSION_COOKIE).then_some(value)
        })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Checks the session's CSRF token. If the `X-CSRF-Token` header is present
/// it decides alone; otherwise `form_value` (the `csrf` form field) must
/// match. Fails with 403.
pub fn check_csrf(
    session: &Session,
    headers: &HeaderMap,
    form_value: Option<&str>,
) -> Result<(), StatusCode> {
    let presented = match headers.get(CSRF_HEADER) {
        Some(h) => Some(h.as_bytes()),
        None => form_value.map(str::as_bytes),
    };
    match presented {
        Some(token) if constant_time_eq(token, session.csrf.as_bytes()) => Ok(()),
        _ => Err(StatusCode::FORBIDDEN),
    }
}

fn is_urlencoded_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| {
            mime.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// Middleware: resolves the session cookie into a [`Session`] request
/// extension and enforces the header half of the CSRF rule (see the module
/// docs). Applied to the whole router, so it also covers routes added later.
pub async fn session_layer(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let session = session_id(req.headers()).and_then(|id| state.sessions.get(id));
    if let Some(session) = session {
        if !matches!(*req.method(), Method::GET | Method::HEAD) {
            let headers = req.headers();
            let allowed = if headers.contains_key(CSRF_HEADER) {
                check_csrf(&session, headers, None).is_ok()
            } else {
                // Only a plain HTML form may defer to the handler's field check.
                is_urlencoded_form(headers) && !is_htmx(headers)
            };
            if !allowed {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        req.extensions_mut().insert(session);
    }
    next.run(req).await
}

/// Why an extractor turned a request away.
pub enum AuthRejection {
    /// No session: go to `/login`.
    Login { htmx: bool },
    /// The recovery key is not confirmed yet: go to `/recovery-key`.
    ConfirmRecovery { htmx: bool },
    /// Logged in, but not an admin.
    Forbidden,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (htmx, to) = match self {
            AuthRejection::Login { htmx } => (htmx, "/login"),
            AuthRejection::ConfirmRecovery { htmx } => (htmx, "/recovery-key"),
            AuthRejection::Forbidden => return StatusCode::FORBIDDEN.into_response(),
        };
        if htmx {
            // htmx does not follow 3xx to a full page load; HX-Redirect does.
            (
                StatusCode::UNAUTHORIZED,
                [("hx-redirect", HeaderValue::from_static(to))],
            )
                .into_response()
        } else {
            (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, HeaderValue::from_static(to))],
            )
                .into_response()
        }
    }
}

fn any_session(parts: &Parts) -> Result<Session, AuthRejection> {
    parts
        .extensions
        .get::<Session>()
        .cloned()
        .ok_or(AuthRejection::Login {
            htmx: is_htmx(&parts.headers),
        })
}

fn confirmed_session(parts: &Parts) -> Result<Session, AuthRejection> {
    let session = any_session(parts)?;
    if session.must_confirm_recovery.is_some() {
        return Err(AuthRejection::ConfirmRecovery {
            htmx: is_htmx(&parts.headers),
        });
    }
    Ok(session)
}

/// Any session, including one that still has to confirm its recovery key.
/// Only for the recovery-key confirmation routes and logout.
pub struct PendingUser(pub Session);

/// A fully logged-in user. The extractor for normal pages.
pub struct CurrentUser(pub Session);

/// A fully logged-in admin; everyone else gets 403.
pub struct AdminUser(pub Session);

impl<S: Send + Sync> FromRequestParts<S> for PendingUser {
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        any_session(parts).map(PendingUser)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for CurrentUser {
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        confirmed_session(parts).map(CurrentUser)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AdminUser {
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let session = confirmed_session(parts)?;
        if !session.is_admin() {
            return Err(AuthRejection::Forbidden);
        }
        Ok(AdminUser(session))
    }
}

macro_rules! deref_session {
    ($($t:ty),*) => {$(
        impl Deref for $t {
            type Target = Session;
            fn deref(&self) -> &Session {
                &self.0
            }
        }
    )*};
}
deref_session!(PendingUser, CurrentUser, AdminUser);

/// A urlencoded form from a logged-in user whose CSRF token has been checked
/// (header or `csrf` field). Use it instead of `axum::Form` on every
/// session-authenticated POST route; `T` does not need a `csrf` field.
///
/// It only checks the token. Combine it with [`CurrentUser`], [`AdminUser`]
/// or [`PendingUser`] to say who may call the route; it must be the last
/// argument because it consumes the body.
pub struct CsrfForm<T>(pub T);

/// For forms that carry nothing but the CSRF token: `CsrfForm<NoFields>`.
#[derive(Deserialize)]
pub struct NoFields {}

#[derive(Deserialize)]
struct CsrfField {
    csrf: Option<String>,
}

impl<S, T> FromRequest<S> for CsrfForm<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let session = any_session(&parts).map_err(IntoResponse::into_response)?;
        let headers = std::mem::take(&mut parts.headers);
        // `Bytes` applies the router's body size limit.
        let body = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(IntoResponse::into_response)?;
        let field = serde_urlencoded::from_bytes::<CsrfField>(&body)
            .ok()
            .and_then(|f| f.csrf);
        check_csrf(&session, &headers, field.as_deref()).map_err(IntoResponse::into_response)?;
        serde_urlencoded::from_bytes::<T>(&body)
            .map(CsrfForm)
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY.into_response())
    }
}
