//! Signup via invite, recovery-key confirmation, login, logout and recovery.
//!
//! Login, signup and recover POSTs have no session yet, so they carry no CSRF
//! token (they use a plain `Form`); `SameSite=Strict` and `form-action 'self'`
//! cover them. The recovery-key confirmation and logout have a session and use
//! `CsrfForm`.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::Router;
use axum::extract::{ConnectInfo, Form, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::ratelimit::{client_ip, ip_key, too_many_requests, user_key};
use super::session::{
    CsrfForm, NoFields, PendingUser, clear_continue_cookie, clear_device_cookie,
    clear_session_cookie, continue_id, device_cookie, device_cookie_id, device_token,
    session_cookie,
};
use super::{AppState, Page, kdf_blocking, redirect, render};
use crate::accounts::AccountError;
use crate::system_db::InviteError;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/invite/{token}", get(signup_page).post(signup))
        .route(
            "/recovery-key",
            get(recovery_key_page).post(recovery_key_confirm),
        )
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/recover", get(recover_page).post(recover))
}

const INVALID_LOGIN: &str = "Invalid username, password or code";
const DISABLED: &str = "This account is disabled";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

async fn index() -> Redirect {
    Redirect::to("/documents")
}

fn internal(e: &AccountError) -> Response {
    tracing::error!(error = %e, "account operation failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// Cookie + redirect for a freshly created session.
fn start_session(
    state: &AppState,
    headers: &HeaderMap,
    user: &crate::system_db::UserRow,
    unlocked: std::sync::Arc<crate::keyring::Unlocked>,
    recovery: Option<crate::crypto::RecoveryKey>,
    remember: Option<&str>,
) -> Response {
    let pending_key = recovery.is_some();
    let to = if pending_key {
        "/recovery-key"
    } else {
        "/documents"
    };
    // A previous session on this browser must not outlive the new login.
    if let Some(old) = super::session::session_id(headers).and_then(|id| state.sessions.take(id))
        && let Some(device_id) = &old.device_id
    {
        // The old login's remembered device must not outlive it.
        revoke_logged(state, &old.unlocked, device_id);
    }
    // So must the device named by this browser's cookie (it can be a different
    // one than the session's, or there may be no session at all). Only a
    // device of the user logging in can be revoked here.
    if let Some(id) = device_cookie_id(headers) {
        revoke_logged(state, &unlocked, id);
    }
    // A share staged before login (`POST /share` without a session) continues
    // on its review page, once. Not after signup/recovery, which first have to
    // show the recovery key; the continue cookie is kept until that is
    // confirmed (`recovery_key_confirm` then follows it).
    let proof = continue_id(headers);
    let share = recovery
        .is_none()
        .then_some(proof)
        .flatten()
        .filter(|id| state.shared.exists_for(id, &user.id, Some(id)));
    // An OAuth authorize request that was waiting for this login continues on
    // the consent page (the same cookie names a pending request instead).
    let oauth = share.is_none()
        && recovery.is_none()
        && proof.is_some_and(|id| state.oauth.request(id).is_some());
    // "Remember this device": a device token, kept in a second cookie.
    let device = remember.and_then(|label| {
        match crate::devices::create_device(&state.sys, &unlocked, label, now()) {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::error!(error = %e, "could not remember device");
                None
            }
        }
    });
    let device_id = device
        .as_deref()
        .and_then(|t| crate::tokens::split_token(t, "pmd_"))
        .map(|(id, _)| id.to_owned());
    let (cookie, _csrf) = state.sessions.create(user, unlocked, recovery, device_id);
    // The review and consent pages need the cookie as proof, and clear it themselves.
    let followed = share.is_some() || oauth;
    let mut resp = match share {
        Some(id) => redirect(headers, &format!("/share/{id}")),
        None if oauth => redirect(headers, "/oauth/authorize/resume"),
        None => redirect(headers, to),
    };
    resp.headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&cookie));
    if proof.is_some() && !pending_key && !followed {
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_continue_cookie());
    }
    if let Some(token) = device {
        resp.headers_mut()
            .append(header::SET_COOKIE, device_cookie(&token));
    } else if device_token(headers).is_some() {
        // Not remembering now: a cookie left over from before must go.
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_device_cookie());
    }
    resp
}

fn revoke_logged(state: &AppState, unlocked: &crate::keyring::Unlocked, device_id: &str) {
    if let Err(e) = crate::devices::revoke_device(&state.sys, unlocked, device_id) {
        tracing::error!(error = %e, "could not revoke device");
    }
}

/// The device label when the "Remember this device" box was ticked.
fn remember_label(headers: &HeaderMap, remember: Option<&str>) -> Option<String> {
    (remember == Some("on")).then(|| {
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        crate::devices::device_label(ua)
    })
}

/// The last step of login, signup and recover: re-reads the user row right
/// before the session is created. The Argon2 unwrap that precedes it takes
/// about a second, so an admin may have disabled or deleted the account in
/// the meantime; disable and delete write the system DB first and then cut the
/// sessions that exist, so this re-check is what stops a login in flight from
/// outliving them. On `Err` the `Unlocked` is dropped and no session exists.
pub fn finish_login(
    state: &AppState,
    headers: &HeaderMap,
    user_id: &str,
    unlocked: std::sync::Arc<crate::keyring::Unlocked>,
    recovery: Option<crate::crypto::RecoveryKey>,
    remember: Option<&str>,
) -> Result<Response, AccountError> {
    let row = state
        .sys
        .user_by_id(user_id)?
        .ok_or(AccountError::InvalidCredentials)?;
    if row.disabled {
        return Err(AccountError::Disabled);
    }
    // A recovery key the user never confirmed is shown again, whatever the login.
    let recovery = match recovery {
        Some(key) => Some(key),
        None => state.accounts.pending_recovery(&unlocked)?,
    };
    Ok(start_session(
        state, headers, &row, unlocked, recovery, remember,
    ))
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "signup.html")]
struct SignupPage {
    page: Page,
    token: String,
    username: String,
    error: Option<String>,
}

#[derive(Deserialize)]
struct SignupForm {
    username: String,
    password: String,
    password_confirm: String,
    /// "on" when the "I understand my documents are lost" box is ticked.
    #[serde(default)]
    understand: String,
}

fn invite_hash(token: &str) -> Option<[u8; 32]> {
    let mut raw = [0u8; 32];
    if token.len() != 64 || hex::decode_to_slice(token, &mut raw).is_err() {
        return None;
    }
    Some(Sha256::digest(raw).into())
}

async fn signup_page(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let valid = invite_hash(&token).is_some_and(|h| state.sys.invite_status(h, now()).is_ok());
    if !valid {
        return not_found();
    }
    render(&SignupPage {
        page: Page::anonymous(),
        token,
        username: String::new(),
        error: None,
    })
}

async fn signup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(form): Form<SignupForm>,
) -> Response {
    let rerender = |status: StatusCode, msg: &str, token: String, username: String| {
        let mut resp = render(&SignupPage {
            page: Page::anonymous(),
            token,
            username,
            error: Some(msg.to_owned()),
        });
        if resp.status() == StatusCode::OK {
            *resp.status_mut() = status;
        }
        resp
    };
    if form.password != form.password_confirm {
        return rerender(
            StatusCode::BAD_REQUEST,
            "The passwords do not match",
            token,
            form.username,
        );
    }
    if form.understand != "on" {
        return rerender(
            StatusCode::BAD_REQUEST,
            "Confirm that you understand your documents are lost without your password and recovery key",
            token,
            form.username,
        );
    }
    let accounts = state.accounts.clone();
    let (t, u, p) = (token.clone(), form.username.clone(), form.password);
    let result = match kdf_blocking(&state, move || accounts.signup(&t, &u, &p, now())).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match result {
        Ok((unlocked, user, recovery)) => {
            match finish_login(&state, &headers, &user.id, unlocked, Some(recovery), None) {
                Ok(resp) => resp,
                Err(AccountError::Disabled) => {
                    rerender(StatusCode::FORBIDDEN, DISABLED, token, form.username)
                }
                Err(AccountError::Internal(e)) => internal(&AccountError::Internal(e)),
                Err(_) => not_found(),
            }
        }
        Err(AccountError::Invite(InviteError::Internal)) => {
            internal(&AccountError::Invite(InviteError::Internal))
        }
        Err(AccountError::Invite(_)) => not_found(),
        Err(AccountError::UsernameTaken) => rerender(
            StatusCode::CONFLICT,
            "That username is already taken",
            token,
            form.username,
        ),
        Err(AccountError::InvalidUsername) => rerender(
            StatusCode::BAD_REQUEST,
            "Usernames are 3 to 32 characters: letters, digits, dot, dash or underscore",
            token,
            form.username,
        ),
        Err(AccountError::WeakPassword) => rerender(
            StatusCode::BAD_REQUEST,
            "The password must be at least 10 characters",
            token,
            form.username,
        ),
        Err(e) => internal(&e),
    }
}

// ---------------------------------------------------------------------------
// Recovery key confirmation
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "recovery_key.html")]
struct RecoveryKeyPage {
    page: Page,
    key: String,
    csrf: String,
    error: Option<String>,
}

#[derive(Deserialize)]
struct RecoveryConfirmForm {
    saved: Option<String>,
}

fn recovery_page(session: &super::session::Session, error: Option<&str>) -> Response {
    let Some(key) = &session.must_confirm_recovery else {
        return Redirect::to("/documents").into_response();
    };
    let mut resp = render(&RecoveryKeyPage {
        page: Page::for_session(session),
        key: key.to_display(),
        csrf: session.csrf.clone(),
        error: error.map(str::to_owned),
    });
    if error.is_some() && resp.status() == StatusCode::OK {
        *resp.status_mut() = StatusCode::BAD_REQUEST;
    }
    resp
}

async fn recovery_key_page(PendingUser(session): PendingUser) -> Response {
    recovery_page(&session, None)
}

async fn recovery_key_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    PendingUser(session): PendingUser,
    CsrfForm(form): CsrfForm<RecoveryConfirmForm>,
) -> Response {
    if session.must_confirm_recovery.is_none() {
        return redirect(&headers, "/documents");
    }
    if form.saved.as_deref() != Some("on") {
        return recovery_page(
            &session,
            Some("Confirm that you have saved your recovery key"),
        );
    }
    if let Err(e) = state.accounts.confirm_recovery(&session.user_id) {
        return internal(&AccountError::Internal(e));
    }
    state.sessions.confirm_recovery(&session.id);
    // A share that was waiting for this login continues now.
    let proof = continue_id(&headers);
    match proof.filter(|id| state.shared.exists_for(id, &session.user_id, Some(id))) {
        Some(id) => redirect(&headers, &format!("/share/{id}")),
        None if proof.is_some_and(|id| state.oauth.request(id).is_some()) => {
            redirect(&headers, "/oauth/authorize/resume")
        }
        None => redirect(&headers, "/documents"),
    }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    page: Page,
    username: String,
    error: Option<String>,
    /// Return to `/scan` after logging in (`?next=scan`).
    next_scan: bool,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    code: String,
    /// The only accepted value is `scan`; anything else is ignored.
    #[serde(default)]
    next: String,
    /// "on" when "Remember this device" is ticked.
    remember: Option<String>,
}

#[derive(Deserialize)]
struct LoginQuery {
    #[serde(default)]
    next: String,
}

fn login_error(status: StatusCode, username: String, msg: &str, next_scan: bool) -> Response {
    let mut resp = render(&LoginPage {
        page: Page::anonymous(),
        username,
        error: Some(msg.to_owned()),
        next_scan,
    });
    if resp.status() == StatusCode::OK {
        *resp.status_mut() = status;
    }
    resp
}

/// `GET /login`. A browser that is already logged in and carries the continue
/// cookie of a live share it may claim (the session cookie did not reach the
/// cross-site `POST /share`, but did reach this follow-up) goes straight to
/// the review page.
async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<LoginQuery>,
    session: Option<axum::Extension<super::session::Session>>,
) -> Response {
    if let Some(axum::Extension(s)) = &session
        && s.must_confirm_recovery.is_none()
        && let Some(id) = continue_id(&headers)
        && state.shared.exists_for(id, &s.user_id, Some(id))
    {
        return redirect(&headers, &format!("/share/{id}"));
    }
    if let Some(axum::Extension(s)) = &session
        && s.must_confirm_recovery.is_none()
        && continue_id(&headers).is_some_and(|id| state.oauth.request(id).is_some())
    {
        return redirect(&headers, "/oauth/authorize/resume");
    }
    render(&LoginPage {
        page: Page::anonymous(),
        username: String::new(),
        error: None,
        next_scan: q.next == "scan",
    })
}

fn limiter_keys(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    username: &str,
) -> [String; 2] {
    let ip = client_ip(peer, headers, state.cfg.trusted_proxy);
    [ip_key(ip), user_key(username)]
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let next_scan = form.next == "scan";
    let label = remember_label(&headers, form.remember.as_deref());
    let keys = limiter_keys(&state, peer, &headers, &form.username);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
    let accounts = state.accounts.clone();
    let (u, p, c) = (
        form.username.clone(),
        form.password,
        form.code.trim().to_owned(),
    );
    let result = match kdf_blocking(&state, move || {
        let code = (!c.is_empty()).then_some(c.as_str());
        accounts.login(&u, &p, code)
    })
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match result {
        Ok((unlocked, user)) => {
            match finish_login(&state, &headers, &user.id, unlocked, None, label.as_deref()) {
                Ok(mut resp) => {
                    attempt.success();
                    // Back to the scanner, but only where the login would have
                    // gone to the documents page (not the recovery key, a share
                    // or an OAuth consent that is waiting).
                    if next_scan
                        && resp
                            .headers()
                            .get(header::LOCATION)
                            .is_some_and(|l| l == "/documents")
                    {
                        resp.headers_mut()
                            .insert(header::LOCATION, HeaderValue::from_static("/scan"));
                    }
                    resp
                }
                Err(AccountError::Disabled) => {
                    attempt.failure();
                    login_error(StatusCode::FORBIDDEN, form.username, DISABLED, next_scan)
                }
                Err(AccountError::Internal(e)) => internal(&AccountError::Internal(e)),
                Err(_) => {
                    attempt.failure();
                    login_error(
                        StatusCode::UNAUTHORIZED,
                        form.username,
                        INVALID_LOGIN,
                        next_scan,
                    )
                }
            }
        }
        Err(AccountError::Disabled) => {
            attempt.failure();
            login_error(StatusCode::FORBIDDEN, form.username, DISABLED, next_scan)
        }
        Err(AccountError::Internal(e)) => internal(&AccountError::Internal(e)),
        Err(_) => {
            attempt.failure();
            login_error(
                StatusCode::UNAUTHORIZED,
                form.username,
                INVALID_LOGIN,
                next_scan,
            )
        }
    }
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    PendingUser(session): PendingUser,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    state.sessions.remove(&session.id);
    // Only this device is forgotten; other remembered devices stay. The
    // cookie goes whether or not this session was started from it, so the
    // browser cannot fall back into the account after logout.
    let mut ids: Vec<String> = session.device_id.iter().cloned().collect();
    if let Some(id) = device_cookie_id(&headers)
        && !ids.iter().any(|i| i == id)
    {
        ids.push(id.to_owned());
    }
    if !ids.is_empty() {
        let st = state.clone();
        let unlocked = session.unlocked.clone();
        let res = tokio::task::spawn_blocking(move || {
            for id in &ids {
                // Revokes only devices of this user.
                crate::devices::revoke_device(&st.sys, &unlocked, id)?;
            }
            anyhow::Ok(())
        })
        .await;
        if !matches!(res, Ok(Ok(()))) {
            tracing::error!("could not revoke device on logout");
        }
    }
    let had_cookie = device_token(&headers).is_some() || session.device_id.is_some();
    let mut resp = redirect(&headers, "/login");
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie());
    if had_cookie {
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_device_cookie());
    }
    resp
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "recover.html")]
struct RecoverPage {
    page: Page,
    username: String,
    error: Option<String>,
}

#[derive(Deserialize)]
struct RecoverForm {
    username: String,
    recovery_key: String,
    new_password: String,
    new_password_confirm: String,
    /// "on" when "Remember this device" is ticked.
    remember: Option<String>,
}

fn recover_error(status: StatusCode, username: String, msg: &str) -> Response {
    let mut resp = render(&RecoverPage {
        page: Page::anonymous(),
        username,
        error: Some(msg.to_owned()),
    });
    if resp.status() == StatusCode::OK {
        *resp.status_mut() = status;
    }
    resp
}

async fn recover_page() -> Response {
    render(&RecoverPage {
        page: Page::anonymous(),
        username: String::new(),
        error: None,
    })
}

async fn recover(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<RecoverForm>,
) -> Response {
    if form.new_password != form.new_password_confirm {
        return recover_error(
            StatusCode::BAD_REQUEST,
            form.username,
            "The passwords do not match",
        );
    }
    let keys = limiter_keys(&state, peer, &headers, &form.username);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
    let accounts = state.accounts.clone();
    let (u, k, p) = (form.username.clone(), form.recovery_key, form.new_password);
    let result = match kdf_blocking(&state, move || accounts.recover(&u, &k, &p)).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match result {
        Ok((unlocked, user, new_key)) => {
            // The old password may be compromised: no other session or cached
            // token unlock survives the recovery.
            state.sessions.remove_user(&user.id);
            state.tokens.evict_user(&user.id);
            // Remembered devices were granted under the old credentials. A
            // new remember below still works: it creates a fresh device.
            let (sys, u2) = (state.sys.clone(), unlocked.clone());
            match tokio::task::spawn_blocking(move || crate::devices::revoke_all_devices(&sys, &u2))
                .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return internal(&AccountError::Internal(e)),
                Err(e) => {
                    return internal(&AccountError::Internal(anyhow::anyhow!(
                        "device revocation task failed: {e}"
                    )));
                }
            }
            let label = remember_label(&headers, form.remember.as_deref());
            match finish_login(
                &state,
                &headers,
                &user.id,
                unlocked,
                Some(new_key),
                label.as_deref(),
            ) {
                Ok(resp) => {
                    attempt.success();
                    resp
                }
                Err(AccountError::Disabled) => {
                    attempt.failure();
                    recover_error(StatusCode::FORBIDDEN, form.username, DISABLED)
                }
                Err(AccountError::Internal(e)) => internal(&AccountError::Internal(e)),
                Err(_) => {
                    attempt.failure();
                    recover_error(
                        StatusCode::UNAUTHORIZED,
                        form.username,
                        "Invalid username or recovery key",
                    )
                }
            }
        }
        // The recovery key was right, so this is not a guess: settle as success.
        Err(AccountError::WeakPassword) => {
            attempt.success();
            recover_error(
                StatusCode::BAD_REQUEST,
                form.username,
                "The password must be at least 10 characters",
            )
        }
        Err(AccountError::Disabled) => {
            attempt.failure();
            recover_error(StatusCode::FORBIDDEN, form.username, DISABLED)
        }
        Err(AccountError::Internal(e)) => internal(&AccountError::Internal(e)),
        Err(_) => {
            attempt.failure();
            recover_error(
                StatusCode::UNAUTHORIZED,
                form.username,
                "Invalid username or recovery key",
            )
        }
    }
}
