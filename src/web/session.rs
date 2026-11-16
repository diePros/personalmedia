//! Browser sessions: the in-memory store, the session cookie, CSRF checks and
//! the extractors handlers use to require a logged-in user.
//!
//! # How a request gets its session
//!
//! [`session_layer`] runs for every request. It looks up the `__Host-pm_session`
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

use std::collections::{HashMap, HashSet};
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
use zeroize::Zeroizing;

use super::{AppState, is_htmx};
use crate::crypto::{RecoveryKey, fill_random};
use crate::keyring::Unlocked;
use crate::system_db::{Role, UserRow};

/// The `__Host-` prefix makes browsers refuse a cookie set by a sibling
/// subdomain (other nodes of the tailnet share the `ts.net` parent): it must
/// be `Secure`, have `Path=/` and no `Domain`.
pub const SESSION_COOKIE: &str = "__Host-pm_session";
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
    pub pending_totp_secret: Option<Zeroizing<String>>,
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

    /// Require the user to confirm a freshly generated recovery key before
    /// using the session for anything else.
    pub fn set_must_confirm_recovery(&self, id: &str, key: Option<RecoveryKey>) {
        let old = self
            .lock()
            .get_mut(id)
            .map(|s| std::mem::replace(&mut s.must_confirm_recovery, key));
        drop(old);
    }

    pub fn set_pending_totp(&self, id: &str, secret: Option<Zeroizing<String>>) {
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

    /// End every session of a user except `keep` (password change).
    pub fn remove_user_except(&self, user_id: &str, keep: &str) {
        self.remove_where(|s| s.user_id == user_id && s.id != keep);
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
    HeaderValue::from_static(
        "__Host-pm_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
    )
}

fn cookie_value<'a>(headers: &'a HeaderMap, cookie: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == cookie).then_some(value)
        })
}

pub(crate) fn session_id(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, SESSION_COOKIE)
}

/// Remembers a staged share (see [`SharedStaging`]) across the login detour:
/// `POST /share` without a session sets it, login consumes it.
///
/// `SameSite=Lax` on purpose: it is set by the response to the OS-originated
/// cross-site POST, and the browser must send it back on the following
/// same-site requests. It holds only the unguessable staging id, which is
/// worthless without a session of the user the share gets bound to.
pub const CONTINUE_COOKIE: &str = "__Host-pm_continue";

pub fn continue_cookie(staging_id: &str, ttl: Duration) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{CONTINUE_COOKIE}={staging_id}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        ttl.as_secs()
    ))
    .expect("staging ids are base64url")
}

pub fn clear_continue_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-pm_continue=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    )
}

/// The staging id in the continue cookie, if it has the shape of one.
pub fn continue_id(headers: &HeaderMap) -> Option<&str> {
    cookie_value(headers, CONTINUE_COOKIE).filter(|id| is_staging_id(id))
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
        // The OS share target posts multipart without our token. That one
        // route only stages the files in server memory; saving them needs the
        // CSRF-protected form on the review page. Exact path, POST only.
        let share_target =
            *req.method() == Method::POST && req.uri().path() == super::pwa::SHARE_PATH;
        if !matches!(*req.method(), Method::GET | Method::HEAD) && !share_target {
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

// ---------------------------------------------------------------------------
// Shared files waiting for review
// ---------------------------------------------------------------------------

/// Most files one share may carry.
pub const MAX_SHARED_FILES: usize = 20;

/// Most bytes anonymous (no session) staging may hold in total, and per entry.
pub const ANON_STAGING_MAX: usize = 25 * 1024 * 1024;

/// A staging id is 32 random bytes as unpadded base64url.
pub fn is_staging_id(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// One file handed over by the OS share sheet. The bytes are wiped on drop.
pub struct StagedFile {
    pub filename: String,
    pub mime: Option<String>,
    pub bytes: Zeroizing<Vec<u8>>,
}

/// A staged share as it is taken out of the store for saving.
pub struct Staged {
    pub files: Vec<StagedFile>,
    pub title: Option<String>,
}

/// What the review page may show: names and sizes, never the bytes.
pub struct StagedView {
    pub files: Vec<(String, usize)>,
    /// Never set for an anonymous share: its text is not the user's own.
    pub title: Option<String>,
    /// Staged before any login (the sender is unproven).
    pub anonymous: bool,
}

/// Who a staging budget is charged to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    /// Staged with a session: charged to that user.
    User(String),
    /// Staged without one: charged to the client (the `ratelimit::ip_key`).
    Anon(String),
}

/// The share does not fit a budget or the client already has one waiting.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// A size cap (entry, per-user, anonymous or global) would be exceeded.
    OverBudget,
    /// This client already has a live anonymous share.
    AnonBusy,
}

struct Entry {
    /// `None` until a logged-in user claims it with the continue cookie.
    bound: Option<String>,
    /// Who the bytes are charged to.
    charged: Owner,
    files: Vec<StagedFile>,
    title: Option<String>,
    created: Instant,
    /// Bytes charged for this entry.
    total: usize,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// Bytes reserved while streaming plus bytes of live entries.
    global: usize,
    anon: usize,
    per_user: HashMap<String, usize>,
    /// Clients with an in-flight or live anonymous share.
    anon_clients: HashSet<String>,
}

impl Inner {
    fn charge(&mut self, owner: &Owner, n: usize) {
        self.global += n;
        match owner {
            Owner::Anon(_) => self.anon += n,
            Owner::User(u) => *self.per_user.entry(u.clone()).or_default() += n,
        }
    }

    fn refund(&mut self, owner: &Owner, n: usize) {
        self.global = self.global.saturating_sub(n);
        match owner {
            Owner::Anon(_) => self.anon = self.anon.saturating_sub(n),
            Owner::User(u) => {
                if let Some(v) = self.per_user.get_mut(u) {
                    *v = v.saturating_sub(n);
                    if *v == 0 {
                        self.per_user.remove(u);
                    }
                }
            }
        }
    }

    /// Takes an entry out and gives its bytes and client slot back.
    fn remove(&mut self, id: &str) -> Option<Entry> {
        let e = self.entries.remove(id)?;
        self.refund(&e.charged, e.total);
        if let Owner::Anon(ip) = &e.charged {
            self.anon_clients.remove(ip);
        }
        Some(e)
    }
}

/// Files shared to the app (Web Share Target) that wait for the user's
/// review. They live **only in memory** (wiped on drop) and expire after the
/// configured TTL.
///
/// # Memory budget
///
/// `POST /share` is reachable without a session, so memory is counted
/// **while the body streams in** ([`Reservation::reserve`]), not when the
/// share is complete, and handed back when the request fails or the entry is
/// saved, discarded or expires:
///
/// * anonymous: at most [`ANON_STAGING_MAX`] (also per entry) in total, and one
///   live or in-flight anonymous share per client;
/// * logged in: at most `max_upload_bytes` per user (in flight plus staged);
/// * everything together: at most twice `max_upload_bytes`.
///
/// Residual (spec §5 accepts that the operator can read process memory): the
/// multipart parser's chunk buffers and a regrown `Vec` are freed without
/// being wiped; the staged bytes themselves are pre-sized from `Content-Length`
/// to avoid regrowth and are wiped on drop.
///
/// An entry belongs to one user: the one it was staged by, or for an
/// anonymous share the user whose browser carries its continue cookie.
pub struct SharedStaging {
    inner: Mutex<Inner>,
    ttl: Duration,
    entry_max: usize,
}

/// Bytes reserved for one share while it streams in. Dropping it (the request
/// failed or was cut off) gives them back; [`Reservation::commit`] turns them
/// into a staged entry.
pub struct Reservation<'a> {
    staging: &'a SharedStaging,
    owner: Owner,
    reserved: usize,
    committed: bool,
}

impl SharedStaging {
    pub fn new(ttl: Duration, entry_max: usize) -> SharedStaging {
        SharedStaging {
            inner: Mutex::new(Inner::default()),
            ttl,
            entry_max,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Bytes currently reserved or staged (for tests and diagnostics).
    pub fn budget_used(&self) -> usize {
        self.lock().global
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn live(&self, e: &Entry, now: Instant) -> bool {
        now.duration_since(e.created) < self.ttl
    }

    /// Removes expired entries. The caller drops the result after releasing
    /// the lock (wiping can take a moment).
    fn purge(&self, inner: &mut Inner) -> Vec<Entry> {
        let now = Instant::now();
        let ids: Vec<String> = inner
            .entries
            .iter()
            .filter(|(_, e)| !self.live(e, now))
            .map(|(id, _)| id.clone())
            .collect();
        ids.iter().filter_map(|id| inner.remove(id)).collect()
    }

    fn entry_cap(&self, owner: &Owner) -> usize {
        match owner {
            Owner::Anon(_) => self.entry_max.min(ANON_STAGING_MAX),
            Owner::User(_) => self.entry_max,
        }
    }

    /// Starts a share for `owner`. An anonymous client that already has a live
    /// or in-flight share is refused.
    pub fn begin(&self, owner: Owner) -> Result<Reservation<'_>, Refused> {
        let mut inner = self.lock();
        let dead = self.purge(&mut inner);
        if let Owner::Anon(ip) = &owner
            && !inner.anon_clients.insert(ip.clone())
        {
            drop(inner);
            drop(dead);
            return Err(Refused::AnonBusy);
        }
        drop(inner);
        drop(dead);
        Ok(Reservation {
            staging: self,
            owner,
            reserved: 0,
            committed: false,
        })
    }

    /// Whether a live entry exists that `user_id` may continue to: their own,
    /// or an unbound one named by the continue cookie (`proof`).
    pub fn exists_for(&self, id: &str, user_id: &str, proof: Option<&str>) -> bool {
        let inner = self.lock();
        inner.entries.get(id).is_some_and(|e| {
            self.live(e, Instant::now())
                && match &e.bound {
                    Some(owner) => owner == user_id,
                    None => proof == Some(id),
                }
        })
    }

    /// Looks `id` up for `user_id`. An unbound (anonymous) entry is bound only
    /// by a request that carries its continue cookie (`proof == Some(id)`);
    /// without it, or for a foreign or expired entry, the answer is `None`.
    fn claim<'a>(
        &self,
        inner: &'a mut Inner,
        id: &str,
        user_id: &str,
        proof: Option<&str>,
    ) -> Option<&'a mut Entry> {
        let entry = inner.entries.get_mut(id)?;
        if !self.live(entry, Instant::now()) {
            return None;
        }
        match &entry.bound {
            Some(owner) if owner != user_id => None,
            Some(_) => Some(entry),
            None if proof == Some(id) => {
                entry.bound = Some(user_id.to_owned());
                Some(entry)
            }
            None => None,
        }
    }

    /// Names and sizes of a share, for its review page.
    pub fn view(&self, id: &str, user_id: &str, proof: Option<&str>) -> Option<StagedView> {
        let mut inner = self.lock();
        let e = self.claim(&mut inner, id, user_id, proof)?;
        let anonymous = matches!(e.charged, Owner::Anon(_));
        Some(StagedView {
            files: e
                .files
                .iter()
                .map(|f| (f.filename.clone(), f.bytes.len()))
                .collect(),
            title: if anonymous { None } else { e.title.clone() },
            anonymous,
        })
    }

    /// Removes a share (to save or discard it) and releases its budget. One
    /// caller wins; a second gets `None`.
    pub fn take(&self, id: &str, user_id: &str, proof: Option<&str>) -> Option<Staged> {
        let mut inner = self.lock();
        self.claim(&mut inner, id, user_id, proof)?;
        let e = inner.remove(id)?;
        drop(inner);
        Some(Staged {
            files: e.files,
            title: e.title,
        })
    }

    /// Drops expired shares (every minute, so bytes do not linger unread).
    pub fn sweep(&self) {
        let dead = {
            let mut inner = self.lock();
            self.purge(&mut inner)
        };
        drop(dead);
    }
}

impl Reservation<'_> {
    /// The most bytes this share may hold.
    pub fn cap(&self) -> usize {
        self.staging.entry_cap(&self.owner)
    }

    pub fn reserved(&self) -> usize {
        self.reserved
    }

    /// Reserves `n` more bytes; call it for every chunk **before** keeping
    /// the chunk. `Err` means stop reading the body.
    pub fn reserve(&mut self, n: usize) -> Result<(), Refused> {
        let s = self.staging;
        if self.reserved.saturating_add(n) > self.cap() {
            return Err(Refused::OverBudget);
        }
        let fits = |inner: &Inner| {
            let owner_ok = match &self.owner {
                Owner::Anon(_) => inner.anon.saturating_add(n) <= ANON_STAGING_MAX,
                Owner::User(u) => {
                    inner
                        .per_user
                        .get(u)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(n)
                        <= s.entry_max
                }
            };
            owner_ok && inner.global.saturating_add(n) <= s.entry_max.saturating_mul(2)
        };
        let mut inner = s.lock();
        let mut dead = Vec::new();
        if !fits(&inner) {
            // Expired entries may be what is in the way.
            dead = s.purge(&mut inner);
        }
        if !fits(&inner) {
            drop(inner);
            drop(dead);
            return Err(Refused::OverBudget);
        }
        inner.charge(&self.owner, n);
        self.reserved += n;
        drop(inner);
        drop(dead);
        Ok(())
    }

    /// Stages `files` and returns the staging id. The reserved bytes now
    /// belong to the entry.
    pub fn commit(mut self, files: Vec<StagedFile>, title: Option<String>) -> String {
        let id = random_token();
        let mut inner = self.staging.lock();
        let (bound, charged) = match &self.owner {
            Owner::User(u) => (Some(u.clone()), self.owner.clone()),
            Owner::Anon(_) => (None, self.owner.clone()),
        };
        inner.entries.insert(
            id.clone(),
            Entry {
                bound,
                charged,
                files,
                title,
                created: Instant::now(),
                total: self.reserved,
            },
        );
        self.committed = true;
        id
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut inner = self.staging.lock();
        inner.refund(&self.owner, self.reserved);
        if let Owner::Anon(ip) = &self.owner {
            inner.anon_clients.remove(ip);
        }
    }
}
