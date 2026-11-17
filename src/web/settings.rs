//! Settings: access defaults, hidden documents, MCP tokens, TOTP, password,
//! recovery key and the ZIP export, all on one page (`GET /settings`).
//!
//! Every POST takes a [`CsrfForm`]. Failed actions re-render the settings
//! page with an error message and an error status; successful ones redirect
//! to `/settings?notice=...` (a fixed set of keys, see [`notice_text`]).
//! Actions that check a password or a code share the login rate limiter.

#![allow(clippy::result_large_err)] // helpers return a ready `Response` as the error

use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::docs::{channel_body, format_date};
use super::ratelimit::{client_ip, ip_key, too_many_requests, user_key};
use super::session::{CsrfForm, CurrentUser, NoFields, Session, clear_device_cookie};
use super::{AppState, Page, kdf_blocking, redirect, render};
use crate::accounts::{AccountError, TotpSetup};
use crate::documents::{DocError, validate_meta};
use crate::export;
use crate::tokens::{create_token, revoke_grant, revoke_token};
use crate::user_db::tag_ids as tag_ids_for;
use crate::user_db::vectors::{SemanticStatus, semantic_status};
use crate::user_db::{
    Access, Channel, Content, Level, TokenScope, document_overrides, get_access_defaults,
    get_token_meta, hidden_from, list_tags, list_tags_visible, list_token_meta,
    set_access_defaults,
};
use crate::user_db::{AccessDefaults, ListFilter, TokenMeta};

const CHUNK: usize = 64 * 1024;
const TOKEN_NAME_MAX_CHARS: usize = 100;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings", get(page))
        .route("/settings/access", post(set_defaults))
        .route("/settings/password", post(change_password))
        .route("/settings/recovery", post(regenerate_recovery))
        .route("/settings/totp/begin", post(totp_begin))
        .route("/settings/totp/enable", post(totp_enable))
        .route("/settings/totp/disable", post(totp_disable))
        .route("/settings/tokens", post(create_token_route))
        .route("/settings/ios", post(ios_setup_route))
        .route("/settings/tokens/{id}/revoke", post(revoke_token_route))
        .route("/settings/grants/{id}/revoke", post(revoke_grant_route))
        .route("/settings/export", post(export_zip))
        .route("/settings/devices/{id}/revoke", post(revoke_device_route))
        .route(
            "/settings/devices/revoke-others",
            post(revoke_other_devices),
        )
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "settings request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// Runs blocking work (Argon2, SQLite, file I/O) off the async threads.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

fn limiter_keys(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    session: &Session,
) -> [String; 2] {
    let ip = client_ip(peer, headers, state.cfg.trusted_proxy);
    [ip_key(ip), user_key(&session.username)]
}

/// Checks the account password under the KDF semaphore. `Err` is a ready
/// response (503 or 500); `Ok(Err(..))` is the verification result.
async fn check_password(
    state: &AppState,
    session: &Session,
    password: String,
) -> Result<Result<(), AccountError>, Response> {
    let accounts = state.accounts.clone();
    let user_id = session.user_id.clone();
    kdf_blocking(state, move || accounts.verify_password(&user_id, &password)).await
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

struct Opt {
    value: &'static str,
    label: &'static str,
    selected: bool,
}

struct ChannelRow {
    name: &'static str,
    label: &'static str,
    options: Vec<Opt>,
}

struct HiddenRow {
    id: String,
    title: String,
    date: String,
    /// What "Show in web" posts for each channel. The access route needs all
    /// three, so the other channels keep their current override.
    web: &'static str,
    mcp: &'static str,
    semantic_index: &'static str,
}

struct TokenRow {
    id: String,
    name: String,
    summary: String,
    created: String,
    last_used: String,
}

/// One connected OAuth app. Holds metadata only, never a token string.
struct GrantRow {
    id: String,
    client_name: String,
    summary: String,
    redirect_host: String,
    created: String,
    last_used: String,
}

/// One remembered device.
struct DeviceRow {
    id: String,
    label: String,
    added: String,
    last_used: String,
    current: bool,
}

struct TagBox {
    id: i64,
    name: String,
}

struct SetupView {
    secret: String,
    qr: String,
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    page: Page,
    notice: Option<&'static str>,
    error: Option<String>,
    channels: Vec<ChannelRow>,
    hidden: Vec<HiddenRow>,
    tokens: Vec<TokenRow>,
    grants: Vec<GrantRow>,
    devices: Vec<DeviceRow>,
    tags: Vec<TagBox>,
    totp_enabled: bool,
    totp_setup: Option<SetupView>,
    semantic: SemanticStatus,
    storage: String,
}

#[derive(Template)]
#[template(path = "ios_setup.html")]
struct IosSetupPage {
    page: Page,
    shortcut_url: Option<String>,
    setup_code: String,
}

#[derive(Template)]
#[template(path = "token_created.html")]
struct TokenCreatedPage {
    page: Page,
    name: String,
    token: String,
    public_url: String,
}

/// Message for a `?notice=` key. Unknown keys show nothing.
fn notice_text(key: &str) -> Option<&'static str> {
    Some(match key {
        "access" => "Access defaults saved.",
        "password" => {
            "Password changed. Other sessions and all remembered devices were signed out. Existing MCP tokens keep working; revoke them in Settings if needed."
        }
        "device_revoked" => "Device signed out.",
        "devices_revoked" => "All other devices signed out.",
        "totp_on" => "Two-factor authentication is on.",
        "totp_off" => "Two-factor authentication is off.",
        "token_revoked" => "Token revoked.",
        "grant_revoked" => "App disconnected. Its access and refresh tokens no longer work.",
        _ => return None,
    })
}

/// "5 minutes ago", "2 days ago", for the device list.
fn ago(ts: i64, now: i64) -> String {
    let d = (now - ts).max(0);
    let (n, unit) = match d {
        0..=59 => return "just now".to_owned(),
        60..=3599 => (d / 60, "minute"),
        3600..=86399 => (d / 3600, "hour"),
        _ => (d / 86400, "day"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

fn device_rows(
    u: &crate::keyring::Unlocked,
    sys: &crate::system_db::SystemDb,
    current: Option<&str>,
) -> anyhow::Result<Vec<DeviceRow>> {
    // Only devices with a live system row count; stray metadata is tidied.
    let live = sys.token_ids_for_user(&u.user_id)?;
    let metas = u.with_db(|c| -> anyhow::Result<_> {
        crate::user_db::prune_device_meta(c, &live)?;
        crate::user_db::list_device_meta(c)
    })?;
    let t = now();
    Ok(metas
        .into_iter()
        .filter(|d| live.contains(&d.id))
        .map(|d| DeviceRow {
            current: current == Some(d.id.as_str()),
            added: format_date(d.created_at),
            last_used: d.last_used_at.map_or("never".to_owned(), |ts| ago(ts, t)),
            label: d.label,
            id: d.id,
        })
        .collect())
}

const CHANNELS: [(Channel, &str); 3] = [
    (Channel::Web, "Web"),
    (Channel::Mcp, "MCP (AI assistants)"),
    (Channel::SemanticIndex, "Semantic index"),
];

fn level_label(l: Level) -> &'static str {
    match l {
        Level::Off => "Off",
        Level::Metadata => "Metadata only",
        Level::Full => "Full",
    }
}

/// The user-default rows. MCP has none: a token's or app's own scope governs
/// (Ruling AJ), so only Web and the semantic index have defaults.
fn channel_rows(defaults: &AccessDefaults) -> Vec<ChannelRow> {
    CHANNELS
        .iter()
        .filter(|(ch, _)| *ch != Channel::Mcp)
        .map(|(ch, label)| ChannelRow {
            name: ch.as_str(),
            label,
            options: [Level::Off, Level::Metadata, Level::Full]
                .into_iter()
                .map(|l| Opt {
                    value: l.as_str(),
                    label: level_label(l),
                    selected: defaults.level(*ch) == l,
                })
                .collect(),
        })
        .collect()
}

/// `"default"` or the level's name, as the per-document access form posts it.
fn override_value(over: Option<Level>) -> &'static str {
    over.map_or("default", Level::as_str)
}

fn hidden_rows(
    c: &rusqlite::Connection,
    defaults: &AccessDefaults,
) -> anyhow::Result<Vec<HiddenRow>> {
    let mut rows = Vec::new();
    for d in hidden_from(c, Channel::Web)? {
        let over = document_overrides(c, &d.id)?;
        rows.push(HiddenRow {
            id: d.id.clone(),
            title: d.title.clone(),
            date: d
                .document_date
                .clone()
                .unwrap_or_else(|| format_date(d.created_at)),
            // If the default itself hides the web channel, `default` would
            // leave the document hidden.
            web: if defaults.level(Channel::Web) == Level::Off {
                "full"
            } else {
                "default"
            },
            mcp: override_value(over.get(&Channel::Mcp).copied()),
            semantic_index: override_value(over.get(&Channel::SemanticIndex).copied()),
        });
    }
    Ok(rows)
}

fn token_row(t: &TokenMeta, tags: &[(i64, String)]) -> TokenRow {
    let access = match t.scope.access {
        Access::Read => "read only",
        Access::ReadWrite => "read and write",
    };
    let content = match t.scope.content {
        Content::MetadataOnly => "metadata only",
        Content::FullText => "full text",
    };
    let scope_tags = match &t.scope.tags {
        None => "all documents".to_owned(),
        Some(ids) => {
            let names: Vec<&str> = tags
                .iter()
                .filter(|(id, _)| ids.contains(id))
                .map(|(_, n)| n.as_str())
                .collect();
            format!("tags: {}", names.join(", "))
        }
    };
    TokenRow {
        id: t.id.clone(),
        name: t.name.clone(),
        summary: format!("{access} · {content} · {scope_tags}"),
        created: format_date(t.created_at),
        last_used: t.last_used_at.map_or("never used".to_owned(), |ts| {
            format!("last used {}", format_date(ts))
        }),
    }
}

/// "Read · Metadata only · Tags: inbox" in plain words.
fn grant_summary(scope: &TokenScope, tags: &[(i64, String)]) -> String {
    let access = match scope.access {
        Access::Read => "Read",
        Access::ReadWrite => "Read and write",
    };
    let content = match scope.content {
        Content::MetadataOnly => "Metadata only",
        Content::FullText => "Full text",
    };
    let scope_tags = match &scope.tags {
        None => "All documents".to_owned(),
        Some(ids) => {
            let names: Vec<&str> = tags
                .iter()
                .filter(|(id, _)| ids.contains(id))
                .map(|(_, n)| n.as_str())
                .collect();
            format!("Tags: {}", names.join(", "))
        }
    };
    format!("{access} · {content} · {scope_tags}")
}

fn grant_row(t: &TokenMeta, tags: &[(i64, String)]) -> Option<GrantRow> {
    let g = t.grant.as_ref()?;
    Some(GrantRow {
        id: t.id.clone(),
        client_name: g.client_name.clone(),
        summary: grant_summary(&t.scope, tags),
        redirect_host: g.redirect_host.clone(),
        created: format_date(t.created_at),
        last_used: t.last_used_at.map_or("never used".to_owned(), |ts| {
            format!("last used {}", format_date(ts))
        }),
    })
}

#[derive(Default)]
struct View {
    notice: Option<&'static str>,
    error: Option<String>,
    setup: Option<TotpSetup>,
}

/// Renders the settings page with `status` (anything but 200 only with an error).
async fn settings_response(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    view: View,
) -> Response {
    let (u, accounts) = (session.unlocked.clone(), state.accounts.clone());
    let (sys, current_device) = (state.sys.clone(), session.device_id.clone());
    let user_id = session.user_id.clone();
    let used = state.quotas.usage(&user_id).await;
    let storage = match state.quotas.limit_for_async(&user_id).await {
        Some(limit) => format!(
            "{} of {}",
            crate::quota::human_bytes(used),
            crate::quota::human_bytes(limit)
        ),
        None => format!("{} (unlimited)", crate::quota::human_bytes(used)),
    };
    let loaded = blocking(move || -> anyhow::Result<_> {
        let (defaults, hidden, tokens, grants, tags, semantic) =
            u.with_db(|c| -> anyhow::Result<_> {
                let defaults = get_access_defaults(c)?;
                let hidden = hidden_rows(c, &defaults)?;
                let all_tags = list_tags(c)?;
                let metas = list_token_meta(c)?;
                let tokens: Vec<TokenRow> = metas
                    .iter()
                    .filter(|t| t.grant.is_none())
                    .map(|t| token_row(t, &all_tags))
                    .collect();
                let grants: Vec<GrantRow> = metas
                    .iter()
                    .filter_map(|t| grant_row(t, &all_tags))
                    .collect();
                // The token form offers tags attached to at least one document.
                let tags = list_tags_visible(c, &ListFilter::default())?;
                let semantic = semantic_status(c)?;
                Ok((defaults, hidden, tokens, grants, tags, semantic))
            })?;
        let devices = device_rows(&u, &sys, current_device.as_deref())?;
        Ok((
            defaults,
            hidden,
            tokens,
            grants,
            tags,
            semantic,
            accounts.totp_enabled(&user_id),
            devices,
        ))
    })
    .await;
    let (defaults, hidden, tokens, grants, tags, semantic, totp_enabled, devices) = match loaded {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return internal(e),
        Err(r) => return r,
    };
    let mut resp = render(&SettingsPage {
        page: Page::for_session(session),
        notice: view.notice,
        error: view.error,
        channels: channel_rows(&defaults),
        hidden,
        tokens,
        grants,
        devices,
        tags: tags
            .into_iter()
            .map(|(id, name)| TagBox { id, name })
            .collect(),
        totp_enabled,
        semantic,
        storage,
        totp_setup: view.setup.map(|s| SetupView {
            secret: s.secret_b32,
            qr: s.qr_png_base64,
        }),
    });
    if resp.status() == StatusCode::OK {
        *resp.status_mut() = status;
    }
    resp
}

async fn failure(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    msg: impl Into<String>,
) -> Response {
    settings_response(
        state,
        session,
        status,
        View {
            error: Some(msg.into()),
            ..View::default()
        },
    )
    .await
}

#[derive(Deserialize)]
struct PageQuery {
    notice: Option<String>,
}

async fn page(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Query(q): Query<PageQuery>,
) -> Response {
    let view = View {
        notice: q.notice.as_deref().and_then(notice_text),
        ..View::default()
    };
    settings_response(&state, &session, StatusCode::OK, view).await
}

// ---------------------------------------------------------------------------
// Access defaults
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DefaultsForm {
    web: String,
    /// Accepted and ignored so old forms keep working (Ruling AJ).
    #[allow(dead_code)]
    #[serde(default)]
    mcp: String,
    semantic_index: String,
}

async fn set_defaults(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<DefaultsForm>,
) -> Response {
    let (Some(web), Some(sem)) = (Level::parse(&form.web), Level::parse(&form.semantic_index))
    else {
        return failure(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid access level",
        )
        .await;
    };
    let u = session.unlocked.clone();
    let u2 = u.clone();
    let saved = blocking(move || {
        u.with_db(|c| {
            // The stored mcp default is unused now; keep whatever is there.
            let mcp = get_access_defaults(c)?.level(Channel::Mcp);
            let defaults = AccessDefaults(
                [
                    (Channel::Web, web),
                    (Channel::Mcp, mcp),
                    (Channel::SemanticIndex, sem),
                ]
                .into(),
            );
            set_access_defaults(c, &defaults)
        })
    })
    .await;
    match saved {
        Ok(Ok(())) => {
            // Lowering already deleted vectors inside set_access_defaults.
            let queue = state.queue.clone();
            let _ = blocking(move || queue.enqueue_embeds_needed(&u2)).await;
            redirect(&headers, "/settings?notice=access")
        }
        Ok(Err(e)) => internal(e),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------------------
// Password
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PasswordForm {
    current: String,
    new: String,
    new_confirm: String,
}

async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<PasswordForm>,
) -> Response {
    let keys = limiter_keys(&state, peer, &headers, &session);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
    if form.new != form.new_confirm {
        return failure(
            &state,
            &session,
            StatusCode::BAD_REQUEST,
            "The new passwords do not match",
        )
        .await;
    }
    let accounts = state.accounts.clone();
    let user_id = session.user_id.clone();
    let result = match kdf_blocking(&state, move || {
        accounts.change_password(&user_id, &form.current, &form.new)
    })
    .await
    {
        Ok(r) => r,
        Err(r) => return r,
    };
    match result {
        Ok(()) => {
            attempt.success();
            // The password is the credential of the other browsers, so they go.
            state
                .sessions
                .remove_user_except(&session.user_id, &session.id);
            state.tokens.evict_user(&session.user_id);
            // Remembered devices were granted under the old password, this
            // browser's included: the session lives on, no longer remembered.
            let (sys, u) = (state.sys.clone(), session.unlocked.clone());
            match blocking(move || crate::devices::revoke_all_devices(&sys, &u)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return internal(e),
                Err(r) => return r,
            }
            state.sessions.clear_device(&session.id);
            let mut resp = redirect(&headers, "/settings?notice=password");
            resp.headers_mut()
                .append(header::SET_COOKIE, clear_device_cookie());
            resp
        }
        Err(AccountError::InvalidCredentials) => {
            attempt.failure();
            failure(
                &state,
                &session,
                StatusCode::UNAUTHORIZED,
                "The current password is wrong",
            )
            .await
        }
        Err(AccountError::WeakPassword) => {
            // The current password was right: not a guess.
            attempt.success();
            failure(
                &state,
                &session,
                StatusCode::BAD_REQUEST,
                "The new password must be at least 10 characters",
            )
            .await
        }
        Err(e) => internal(e),
    }
}

// ---------------------------------------------------------------------------
// Recovery key
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RecoveryForm {
    password: String,
}

/// Verifies the password, replaces the recovery key and hands the new one to
/// the `/recovery-key` page, which shows it once and asks for confirmation.
async fn regenerate_recovery(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<RecoveryForm>,
) -> Response {
    let keys = limiter_keys(&state, peer, &headers, &session);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
    let accounts = state.accounts.clone();
    let (u, user_id) = (session.unlocked.clone(), session.user_id.clone());
    let result = match kdf_blocking(&state, move || {
        accounts.verify_password(&user_id, &form.password)?;
        accounts.regenerate_recovery(&u)
    })
    .await
    {
        Ok(r) => r,
        Err(r) => return r,
    };
    match result {
        Ok(key) => {
            attempt.success();
            state
                .sessions
                .set_must_confirm_recovery(&session.id, Some(key));
            redirect(&headers, "/recovery-key")
        }
        Err(AccountError::InvalidCredentials) => {
            attempt.failure();
            failure(
                &state,
                &session,
                StatusCode::UNAUTHORIZED,
                "The password is wrong",
            )
            .await
        }
        Err(e) => internal(e),
    }
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TotpEnableForm {
    code: String,
    #[serde(default)]
    password: String,
}

async fn totp_begin(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    let accounts = state.accounts.clone();
    let (user_id, username) = (session.user_id.clone(), session.username.clone());
    let result = blocking(move || {
        if accounts.totp_enabled(&user_id) {
            None
        } else {
            Some(accounts.totp_begin(&username))
        }
    })
    .await;
    match result {
        Ok(Some(setup)) => {
            state
                .sessions
                .set_pending_totp(&session.id, Some(Zeroizing::new(setup.secret_b32.clone())));
            settings_response(
                &state,
                &session,
                StatusCode::OK,
                View {
                    setup: Some(setup),
                    ..View::default()
                },
            )
            .await
        }
        Ok(None) => {
            failure(
                &state,
                &session,
                StatusCode::CONFLICT,
                "Two-factor authentication is already on. Turn it off first.",
            )
            .await
        }
        Err(r) => r,
    }
}

/// Re-renders the settings page with the pending TOTP setup still on screen
/// (the same secret, so the authenticator stays valid) and an error.
async fn totp_setup_error(
    state: &AppState,
    session: &Session,
    secret: Zeroizing<String>,
    status: StatusCode,
    msg: &str,
) -> Response {
    let accounts = state.accounts.clone();
    let username = session.username.clone();
    let setup = blocking(move || accounts.totp_resume(&username, &secret).ok())
        .await
        .ok()
        .flatten();
    settings_response(
        state,
        session,
        status,
        View {
            error: Some(msg.to_owned()),
            setup,
            ..View::default()
        },
    )
    .await
}

async fn totp_enable(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<TotpEnableForm>,
) -> Response {
    let Some(secret) = session.pending_totp_secret.clone() else {
        return failure(
            &state,
            &session,
            StatusCode::BAD_REQUEST,
            "Start the setup first",
        )
        .await;
    };
    let keys = limiter_keys(&state, peer, &headers, &session);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
    match check_password(&state, &session, form.password).await {
        Err(r) => return r,
        Ok(Err(AccountError::InvalidCredentials)) => {
            attempt.failure();
            return totp_setup_error(
                &state,
                &session,
                secret,
                StatusCode::UNAUTHORIZED,
                "The password is wrong",
            )
            .await;
        }
        Ok(Err(e)) => return internal(e),
        Ok(Ok(())) => {}
    }
    let accounts = state.accounts.clone();
    let (u, code, secret2) = (session.unlocked.clone(), form.code, secret.clone());
    let result = match blocking(move || accounts.totp_enable(&u, &secret2, &code)).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    match result {
        Ok(()) => {
            attempt.success();
            state.sessions.set_pending_totp(&session.id, None);
            redirect(&headers, "/settings?notice=totp_on")
        }
        Err(AccountError::InvalidCredentials) => {
            attempt.failure();
            totp_setup_error(
                &state,
                &session,
                secret,
                StatusCode::UNAUTHORIZED,
                "That code is not correct. Try the next one.",
            )
            .await
        }
        Err(AccountError::TotpAlreadyEnabled) => {
            attempt.success();
            state.sessions.set_pending_totp(&session.id, None);
            failure(
                &state,
                &session,
                StatusCode::CONFLICT,
                "Two-factor authentication is already on.",
            )
            .await
        }
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct TotpDisableForm {
    code: String,
    /// A resumed session has not proven the password, so turning off the
    /// second factor asks for it. Missing counts as wrong.
    #[serde(default)]
    password: String,
}

async fn totp_disable(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<TotpDisableForm>,
) -> Response {
    let keys = limiter_keys(&state, peer, &headers, &session);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
    match check_password(&state, &session, form.password).await {
        Err(r) => return r,
        Ok(Err(AccountError::InvalidCredentials)) => {
            attempt.failure();
            return failure(
                &state,
                &session,
                StatusCode::UNAUTHORIZED,
                "The password is wrong",
            )
            .await;
        }
        Ok(Err(e)) => return internal(e),
        Ok(Ok(())) => {}
    }
    let accounts = state.accounts.clone();
    let (u, code) = (session.unlocked.clone(), form.code);
    let result = match blocking(move || accounts.totp_disable(&u, &code)).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    match result {
        Ok(()) => {
            attempt.success();
            redirect(&headers, "/settings?notice=totp_off")
        }
        Err(AccountError::InvalidCredentials) => {
            attempt.failure();
            failure(
                &state,
                &session,
                StatusCode::UNAUTHORIZED,
                "That code is not correct",
            )
            .await
        }
        Err(e) => internal(e),
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// The token form has repeated `tags[]` fields, which `serde_urlencoded`
/// cannot map to a struct, so it is read as a list of pairs.
type Pairs = Vec<(String, String)>;

fn field<'a>(pairs: &'a Pairs, name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Validates the token form fields, checks the password and mints the token.
/// `Err` is a ready response. Shared by the generic token form and the
/// iPhone setup. Returns the token name and the secret.
async fn issue_token(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    session: &Session,
    pairs: Pairs,
) -> Result<(String, String), Response> {
    let bad = |msg: &'static str| failure(state, session, StatusCode::BAD_REQUEST, msg);
    let name = field(&pairs, "name").unwrap_or_default().trim().to_owned();
    if name.is_empty() || name.chars().count() > TOKEN_NAME_MAX_CHARS {
        return Err(bad("The token name is required and at most 100 characters").await);
    }
    let access = match field(&pairs, "access").unwrap_or("read") {
        "read" => Access::Read,
        "read_write" => Access::ReadWrite,
        _ => return Err(bad("Invalid access").await),
    };
    let content = match field(&pairs, "content").unwrap_or("metadata_only") {
        "metadata_only" => Content::MetadataOnly,
        "full_text" => Content::FullText,
        _ => return Err(bad("Invalid content level").await),
    };
    let mut tag_ids: Vec<i64> = Vec::new();
    for (k, v) in &pairs {
        if k == "tags[]" {
            match v.parse::<i64>() {
                Ok(id) if !tag_ids.contains(&id) => tag_ids.push(id),
                Ok(_) => {}
                Err(_) => return Err(bad("Invalid tag").await),
            }
        }
    }

    // An optional new tag the token is restricted to (created if needed), so a
    // dedicated token needs no existing tag.
    let new_tag = field(&pairs, "new_tag")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if !new_tag.is_empty() {
        let names = std::slice::from_ref(&new_tag);
        if let Err(DocError::InvalidInput(msg)) = validate_meta(None, None, names) {
            return Err(bad(msg).await);
        }
    }

    // A token outlives logout and password changes, so minting one asks for
    // the password again.
    let keys = limiter_keys(state, peer, headers, session);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return Err(too_many_requests(retry)),
    };
    let password = field(&pairs, "password").unwrap_or_default().to_owned();
    match check_password(state, session, password).await {
        Err(r) => return Err(r),
        Ok(Err(AccountError::InvalidCredentials)) => {
            attempt.failure();
            return Err(failure(
                state,
                session,
                StatusCode::UNAUTHORIZED,
                "The password is wrong",
            )
            .await);
        }
        Ok(Err(e)) => return Err(internal(e)),
        Ok(Ok(())) => attempt.success(),
    }

    let (u, sys, display_name) = (session.unlocked.clone(), state.sys.clone(), name.clone());
    let created = blocking(move || -> anyhow::Result<Option<String>> {
        let known = u.with_db(|c| list_tags_visible(c, &ListFilter::default()))?;
        if tag_ids.iter().any(|id| !known.iter().any(|(k, _)| k == id)) {
            return Ok(None);
        }
        if !new_tag.is_empty() {
            for id in u.with_db(|c| tag_ids_for(c, std::slice::from_ref(&new_tag)))? {
                if !tag_ids.contains(&id) {
                    tag_ids.push(id);
                }
            }
        }
        let scope = TokenScope {
            access,
            content,
            tags: (!tag_ids.is_empty()).then_some(tag_ids),
        };
        create_token(&sys, &u, &name, scope, now()).map(Some)
    })
    .await;
    match created {
        Ok(Ok(Some(token))) => Ok((display_name, token)),
        Ok(Ok(None)) => Err(bad("Invalid tag").await),
        Ok(Err(e)) => Err(internal(e)),
        Err(r) => Err(r),
    }
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

async fn create_token_route(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(pairs): CsrfForm<Pairs>,
) -> Response {
    match issue_token(&state, peer, &headers, &session, pairs).await {
        Ok((name, token)) => no_store(render(&TokenCreatedPage {
            page: Page::for_session(&session),
            name,
            token,
            public_url: state.cfg.public_url.trim_end_matches('/').to_owned(),
        })),
        Err(r) => r,
    }
}

/// The token an iPhone Shortcut uses: it uploads only, sees metadata only
/// and reaches only documents tagged `inbox`.
async fn ios_setup_route(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<IosSetupForm>,
) -> Response {
    let pairs: Pairs = vec![
        ("name".into(), IOS_TOKEN_NAME.into()),
        ("access".into(), "read_write".into()),
        ("content".into(), "metadata_only".into()),
        ("new_tag".into(), "inbox".into()),
        ("password".into(), form.password),
    ];
    match issue_token(&state, peer, &headers, &session, pairs).await {
        Ok((_, token)) => no_store(render(&IosSetupPage {
            page: Page::for_session(&session),
            shortcut_url: state.cfg.ios_shortcut_url.clone(),
            setup_code: ios_setup_code(&state.cfg.public_url, &token),
        })),
        Err(r) => r,
    }
}

const IOS_TOKEN_NAME: &str = "iPhone Shortcut";

#[derive(Deserialize)]
struct IosSetupForm {
    #[serde(default)]
    password: String,
}

/// `{PM_PUBLIC_URL}|{token}`, what the Shortcut's import question expects.
fn ios_setup_code(public_url: &str, token: &str) -> String {
    format!("{}|{token}", public_url.trim_end_matches('/'))
}

async fn revoke_token_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    let (u, sys, tokens) = (
        session.unlocked.clone(),
        state.sys.clone(),
        state.tokens.clone(),
    );
    let result = blocking(move || -> anyhow::Result<bool> {
        if u.with_db(|c| get_token_meta(c, &id))?.is_none() {
            return Ok(false);
        }
        revoke_token(&sys, &u, &id, &tokens)?;
        Ok(true)
    })
    .await;
    match result {
        Ok(Ok(true)) => redirect(&headers, "/settings?notice=token_revoked"),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => internal(e),
        Err(r) => r,
    }
}

/// Signs out one remembered device. Revoking the one this browser uses also
/// drops its cookie.
async fn revoke_device_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    let (u, sys, id2) = (session.unlocked.clone(), state.sys.clone(), id.clone());
    match blocking(move || crate::devices::revoke_device(&sys, &u, &id2)).await {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => return internal(e),
        Err(r) => return r,
    }
    let mut resp = redirect(&headers, "/settings?notice=device_revoked");
    if session.device_id.as_deref() == Some(id.as_str()) {
        state.sessions.clear_device(&session.id);
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_device_cookie());
    }
    resp
}

/// Signs out every remembered device except the one this session belongs to.
async fn revoke_other_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    let (u, sys, keep) = (
        session.unlocked.clone(),
        state.sys.clone(),
        session.device_id.clone(),
    );
    let result = blocking(move || -> anyhow::Result<()> {
        for d in u.with_db(crate::user_db::list_device_meta)? {
            if keep.as_deref() != Some(d.id.as_str()) {
                crate::devices::revoke_device(&sys, &u, &d.id)?;
            }
        }
        Ok(())
    })
    .await;
    match result {
        Ok(Ok(())) => redirect(&headers, "/settings?notice=devices_revoked"),
        Ok(Err(e)) => internal(e),
        Err(r) => r,
    }
}

/// Disconnects an OAuth app: deletes all its token rows, the grant metadata
/// and its cache entries. Only grants of the current user can be found, and a
/// static token id is not a grant.
async fn revoke_grant_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    let (u, sys, tokens) = (
        session.unlocked.clone(),
        state.sys.clone(),
        state.tokens.clone(),
    );
    let result = blocking(move || -> anyhow::Result<bool> {
        match u.with_db(|c| get_token_meta(c, &id))? {
            Some(m) if m.grant.is_some() => {}
            _ => return Ok(false),
        }
        revoke_grant(&sys, Some(&u), &id, &tokens)?;
        Ok(true)
    })
    .await;
    match result {
        Ok(Ok(true)) => redirect(&headers, "/settings?notice=grant_revoked"),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => internal(e),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// A `Write` that hands its output to a response body in 64 KiB chunks.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<io::Result<Bytes>>,
    buf: Vec<u8>,
}

impl ChannelWriter {
    fn send_buffered(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::take(&mut self.buf));
        self.tx
            .blocking_send(Ok(chunk))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "download was cancelled"))
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= CHUNK {
            self.send_buffered()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffered()
    }
}

#[derive(Deserialize)]
struct ExportForm {
    password: String,
}

/// Streams the export ZIP after the account password was checked (the export
/// holds every document, also those hidden from the web). If it fails half
/// way the body ends with an error, so the browser reports a failed download
/// instead of keeping a cut-off file.
async fn export_zip(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<ExportForm>,
) -> Response {
    let keys = limiter_keys(&state, peer, &headers, &session);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
    match check_password(&state, &session, form.password).await {
        Err(r) => return r,
        Ok(Err(AccountError::InvalidCredentials)) => {
            attempt.failure();
            return failure(
                &state,
                &session,
                StatusCode::UNAUTHORIZED,
                "The password is wrong",
            )
            .await;
        }
        Ok(Err(e)) => return internal(e),
        Ok(Ok(())) => attempt.success(),
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<io::Result<Bytes>>(4);
    let (docs, u): (Arc<_>, Arc<_>) = (state.docs.clone(), session.unlocked.clone());
    tokio::task::spawn_blocking(move || {
        let writer = ChannelWriter {
            tx: tx.clone(),
            buf: Vec::with_capacity(CHUNK),
        };
        let result = export::write_export(&docs, &u, writer).and_then(|mut w| {
            w.flush()?;
            Ok(())
        });
        if let Err(e) = result {
            tracing::error!(error = %e, "export failed");
            let _ = tx.blocking_send(Err(io::Error::other("export failed")));
        }
    });
    let mut resp = Response::new(Body::empty());
    *resp.body_mut() = channel_body(rx);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"personal-media-export.zip\""),
    );
    resp
}
