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

use super::docs::{channel_body, format_date};
use super::ratelimit::{client_ip, ip_key, too_many_requests, user_key};
use super::session::{CsrfForm, CurrentUser, NoFields, Session};
use super::{AppState, Page, kdf_blocking, redirect, render};
use crate::accounts::{AccountError, TotpSetup};
use crate::export;
use crate::tokens::{create_token, revoke_token};
use crate::user_db::{
    Access, Channel, Content, Level, TokenScope, document_overrides, effective_level,
    get_access_defaults, get_token_meta, list_tags, list_token_meta, set_access_defaults,
};
use crate::user_db::{AccessDefaults, TokenMeta};

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
        .route("/settings/tokens/{id}/revoke", post(revoke_token_route))
        .route("/settings/export.zip", get(export_zip))
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
    tags: Vec<TagBox>,
    totp_enabled: bool,
    totp_setup: Option<SetupView>,
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
        "password" => "Password changed. Other sessions were logged out.",
        "totp_on" => "Two-factor authentication is on.",
        "totp_off" => "Two-factor authentication is off.",
        "token_revoked" => "Token revoked.",
        _ => return None,
    })
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

fn channel_rows(defaults: &AccessDefaults) -> Vec<ChannelRow> {
    CHANNELS
        .iter()
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
    docs: &[crate::user_db::Document],
    defaults: &AccessDefaults,
) -> anyhow::Result<Vec<HiddenRow>> {
    let mut rows = Vec::new();
    for d in docs.iter().rev() {
        if effective_level(c, &d.id, Channel::Web, Level::Full)? != Level::Off {
            continue;
        }
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
    let user_id = session.user_id.clone();
    let loaded = blocking(move || -> anyhow::Result<_> {
        let docs = export::all_documents(&u)?;
        let (defaults, hidden, tokens, tags) = u.with_db(|c| -> anyhow::Result<_> {
            let defaults = get_access_defaults(c)?;
            let hidden = hidden_rows(c, &docs, &defaults)?;
            let tags = list_tags(c)?;
            let tokens: Vec<TokenRow> = list_token_meta(c)?
                .iter()
                .map(|t| token_row(t, &tags))
                .collect();
            Ok((defaults, hidden, tokens, tags))
        })?;
        Ok((
            defaults,
            hidden,
            tokens,
            tags,
            accounts.totp_enabled(&user_id),
        ))
    })
    .await;
    let (defaults, hidden, tokens, tags, totp_enabled) = match loaded {
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
        tags: tags
            .into_iter()
            .map(|(id, name)| TagBox { id, name })
            .collect(),
        totp_enabled,
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
    mcp: String,
    semantic_index: String,
}

async fn set_defaults(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<DefaultsForm>,
) -> Response {
    let (Some(web), Some(mcp), Some(sem)) = (
        Level::parse(&form.web),
        Level::parse(&form.mcp),
        Level::parse(&form.semantic_index),
    ) else {
        return failure(
            &state,
            &session,
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid access level",
        )
        .await;
    };
    let defaults = AccessDefaults(
        [
            (Channel::Web, web),
            (Channel::Mcp, mcp),
            (Channel::SemanticIndex, sem),
        ]
        .into(),
    );
    let u = session.unlocked.clone();
    match blocking(move || u.with_db(|c| set_access_defaults(c, &defaults))).await {
        Ok(Ok(())) => redirect(&headers, "/settings?notice=access"),
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
            redirect(&headers, "/settings?notice=password")
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
struct CodeForm {
    code: String,
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
                .set_pending_totp(&session.id, Some(setup.secret_b32.clone()));
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

async fn totp_enable(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<CodeForm>,
) -> Response {
    let keys = limiter_keys(&state, peer, &headers, &session);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
    let Some(secret) = session.pending_totp_secret.clone() else {
        return failure(
            &state,
            &session,
            StatusCode::BAD_REQUEST,
            "Start the setup first",
        )
        .await;
    };
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
            // Keep the same secret on screen so the authenticator stays valid.
            let accounts = state.accounts.clone();
            let username = session.username.clone();
            let setup = blocking(move || accounts.totp_resume(&username, &secret).ok())
                .await
                .ok()
                .flatten();
            settings_response(
                &state,
                &session,
                StatusCode::UNAUTHORIZED,
                View {
                    error: Some("That code is not correct. Try the next one.".to_owned()),
                    setup,
                    ..View::default()
                },
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

async fn totp_disable(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
    CsrfForm(form): CsrfForm<CodeForm>,
) -> Response {
    let keys = limiter_keys(&state, peer, &headers, &session);
    let attempt = match state.limiter.begin(&keys) {
        Ok(a) => a,
        Err(retry) => return too_many_requests(retry),
    };
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

async fn create_token_route(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    CsrfForm(pairs): CsrfForm<Pairs>,
) -> Response {
    let bad = |msg: &'static str| failure(&state, &session, StatusCode::BAD_REQUEST, msg);
    let name = field(&pairs, "name").unwrap_or_default().trim().to_owned();
    if name.is_empty() || name.chars().count() > TOKEN_NAME_MAX_CHARS {
        return bad("The token name is required and at most 100 characters").await;
    }
    let access = match field(&pairs, "access").unwrap_or("read") {
        "read" => Access::Read,
        "read_write" => Access::ReadWrite,
        _ => return bad("Invalid access").await,
    };
    let content = match field(&pairs, "content").unwrap_or("metadata_only") {
        "metadata_only" => Content::MetadataOnly,
        "full_text" => Content::FullText,
        _ => return bad("Invalid content level").await,
    };
    let mut tag_ids: Vec<i64> = Vec::new();
    for (k, v) in &pairs {
        if k == "tags[]" {
            match v.parse::<i64>() {
                Ok(id) if !tag_ids.contains(&id) => tag_ids.push(id),
                Ok(_) => {}
                Err(_) => return bad("Invalid tag").await,
            }
        }
    }

    let (u, sys, display_name) = (session.unlocked.clone(), state.sys.clone(), name.clone());
    let created = blocking(move || -> anyhow::Result<Option<String>> {
        let known = u.with_db(list_tags)?;
        if tag_ids.iter().any(|id| !known.iter().any(|(k, _)| k == id)) {
            return Ok(None);
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
        Ok(Ok(Some(token))) => {
            let mut resp = render(&TokenCreatedPage {
                page: Page::for_session(&session),
                name: display_name,
                token,
                public_url: state.cfg.public_url.trim_end_matches('/').to_owned(),
            });
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Ok(None)) => bad("Invalid tag").await,
        Ok(Err(e)) => internal(e),
        Err(r) => r,
    }
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

/// Streams the export ZIP. If it fails half way the body ends with an error,
/// so the browser reports a failed download instead of keeping a cut-off file.
async fn export_zip(State(state): State<AppState>, CurrentUser(session): CurrentUser) -> Response {
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
