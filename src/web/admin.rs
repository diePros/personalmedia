//! Admin pages: invites and user management (`/admin`).
//!
//! The admin manages accounts but never sees document content: the page shows
//! usernames, roles, dates and the number of bytes stored, nothing else.
//!
//! Disable and delete write the system database first, then drop the user's
//! sessions and cached token unlocks. A login racing with the action is
//! stopped by `auth::finish_login`, which re-reads the user row right before
//! it creates the session (the database write has happened by then, or the
//! session it creates is removed by the cut-off that follows). Token requests
//! must re-check the row the same way.

#![allow(clippy::result_large_err)] // helpers return a ready `Response` as the error

use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use super::docs::format_date;
use super::session::{AdminUser, CsrfForm, NoFields, Session};
use super::{AppState, Page, redirect, render};
use crate::quota::human_bytes;
use crate::system_db::{QuotaSetting, Role};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(page))
        .route("/admin/invites", post(create_invite))
        .route("/admin/invites/{prefix}/revoke", post(revoke_invite))
        .route("/admin/users/{id}/disable", post(disable))
        .route("/admin/users/{id}/enable", post(enable))
        .route("/admin/users/{id}/delete", post(delete))
        .route("/admin/quota", post(set_default_quota))
        .route("/admin/users/{id}/quota", post(set_user_quota))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "admin request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

struct InviteRow {
    prefix: String,
    role: &'static str,
    expires: String,
}

struct UserView {
    id: String,
    username: String,
    role: &'static str,
    created: String,
    disabled: bool,
    storage: String,
    is_self: bool,
    /// "default", "custom" or "unlimited".
    quota_mode: &'static str,
    quota_gib: String,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminPage {
    page: Page,
    notice: Option<&'static str>,
    error: Option<String>,
    new_invite: Option<String>,
    invites: Vec<InviteRow>,
    users: Vec<UserView>,
    default_gib: String,
    default_unlimited: bool,
    default_text: String,
}

fn role_name(r: Role) -> &'static str {
    match r {
        Role::Admin => "admin",
        Role::User => "user",
    }
}

fn notice_text(key: &str) -> Option<&'static str> {
    Some(match key {
        "revoked" => "Invite revoked.",
        "disabled" => "Account disabled and logged out.",
        "enabled" => "Account enabled.",
        "deleted" => "Account and all its data deleted.",
        "quota" => "Storage quota saved.",
        _ => return None,
    })
}

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
/// Largest quota the forms accept: 1 PiB.
const MAX_QUOTA_BYTES: u64 = 1 << 50;

/// Parses a GiB figure (decimal point or comma) into bytes. Empty, negative,
/// non-numeric and over-1-PiB values are rejected.
fn parse_gib(s: &str) -> Option<u64> {
    let gib: f64 = s.trim().replace(',', ".").parse().ok()?;
    if !gib.is_finite() || gib < 0.0 {
        return None;
    }
    let bytes = gib * GIB;
    if bytes > MAX_QUOTA_BYTES as f64 {
        return None;
    }
    Some(bytes as u64)
}

/// The shortest text that parses back to exactly `bytes` (dividing by a power
/// of two is exact), so an unchanged form re-submit changes nothing.
fn gib_text(bytes: u64) -> String {
    format!("{}", bytes as f64 / GIB)
}

fn limit_text(limit: Option<u64>) -> String {
    limit.map_or_else(|| "unlimited".to_owned(), human_bytes)
}

async fn admin_response(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    notice: Option<&'static str>,
    error: Option<String>,
    new_invite: Option<String>,
) -> Response {
    let (sys, me) = (state.sys.clone(), session.user_id.clone());
    let loaded = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let invites: Vec<InviteRow> = sys
            .list_open_invites(now())?
            .into_iter()
            .map(|(prefix, role, exp)| InviteRow {
                prefix,
                role: role_name(role),
                expires: format_date(exp),
            })
            .collect();
        Ok((invites, sys.list_users()?, sys.default_quota()?))
    })
    .await;
    let (invites, rows, default_quota) = match loaded {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return internal(e),
        Err(e) => return internal(e),
    };
    let mut users = Vec::new();
    for u in rows {
        let (mode, limit) = match u.quota {
            QuotaSetting::Default => ("default", default_quota),
            QuotaSetting::Custom(b) => ("custom", Some(b)),
            QuotaSetting::Unlimited => ("unlimited", None),
        };
        let used = state.quotas.usage(&u.id).await;
        users.push(UserView {
            storage: format!("{} / {}", human_bytes(used), limit_text(limit)),
            quota_mode: mode,
            quota_gib: limit.map(gib_text).unwrap_or_default(),
            is_self: u.id == me,
            created: format_date(u.created_at),
            role: role_name(u.role),
            disabled: u.disabled,
            username: u.username,
            id: u.id,
        });
    }
    let mut resp = render(&AdminPage {
        page: Page::for_session(session),
        notice,
        error,
        new_invite,
        invites,
        users,
        default_gib: default_quota.map(gib_text).unwrap_or_default(),
        default_unlimited: default_quota.is_none(),
        default_text: limit_text(default_quota),
    });
    if resp.status() == StatusCode::OK {
        *resp.status_mut() = status;
    }
    resp
}

async fn failure(state: &AppState, session: &Session, status: StatusCode, msg: &str) -> Response {
    admin_response(state, session, status, None, Some(msg.to_owned()), None).await
}

#[derive(Deserialize)]
struct PageQuery {
    notice: Option<String>,
}

async fn page(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Query(q): Query<PageQuery>,
) -> Response {
    let notice = q.notice.as_deref().and_then(notice_text);
    admin_response(&state, &session, StatusCode::OK, notice, None, None).await
}

#[derive(Deserialize)]
struct InviteForm {
    role: Option<String>,
}

async fn create_invite(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    CsrfForm(form): CsrfForm<InviteForm>,
) -> Response {
    let role = match form.role.as_deref().unwrap_or("user") {
        "user" => Role::User,
        "admin" => Role::Admin,
        _ => return failure(&state, &session, StatusCode::BAD_REQUEST, "Unknown role.").await,
    };
    let accounts = state.accounts.clone();
    let url = match tokio::task::spawn_blocking(move || accounts.create_invite(role, now())).await {
        Ok(Ok(url)) => url,
        Ok(Err(e)) => return internal(e),
        Err(e) => return internal(e),
    };
    admin_response(&state, &session, StatusCode::OK, None, None, Some(url)).await
}

async fn revoke_invite(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Path(prefix): Path<String>,
    headers: HeaderMap,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    let sys = state.sys.clone();
    match tokio::task::spawn_blocking(move || sys.revoke_invite(&prefix)).await {
        Ok(Ok(())) => redirect(&headers, "/admin?notice=revoked"),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

/// Looks up the target of a user action. `Err` is the response to return.
async fn target(
    state: &AppState,
    session: &Session,
    id: &str,
    verb: &str,
) -> Result<crate::system_db::UserRow, Response> {
    let sys = state.sys.clone();
    let id_owned = id.to_owned();
    let row = tokio::task::spawn_blocking(move || sys.user_by_id(&id_owned))
        .await
        .map_err(internal)?
        .map_err(internal)?;
    let Some(row) = row else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    if row.id == session.user_id {
        let msg = format!("You cannot {verb} your own account.");
        return Err(failure(state, session, StatusCode::BAD_REQUEST, &msg).await);
    }
    Ok(row)
}

/// What follows a database change that must cut the user off immediately.
fn cut_off(state: &AppState, id: &str) {
    state.sessions.remove_user(id);
    state.tokens.evict_user(id);
}

async fn set_disabled(
    state: AppState,
    session: Session,
    id: String,
    headers: HeaderMap,
    disabled: bool,
) -> Response {
    let verb = if disabled { "disable" } else { "enable" };
    let row = match target(&state, &session, &id, verb).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let accounts = state.accounts.clone();
    let uid = row.id.clone();
    match tokio::task::spawn_blocking(move || accounts.set_disabled(&uid, disabled)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return internal(e),
        Err(e) => return internal(e),
    }
    if disabled {
        cut_off(&state, &row.id);
        redirect(&headers, "/admin?notice=disabled")
    } else {
        redirect(&headers, "/admin?notice=enabled")
    }
}

async fn disable(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    set_disabled(state, session, id, headers, true).await
}

async fn enable(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    set_disabled(state, session, id, headers, false).await
}

#[derive(Deserialize)]
struct DeleteForm {
    confirm_username: Option<String>,
}

async fn delete(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<DeleteForm>,
) -> Response {
    let row = match target(&state, &session, &id, "delete").await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if form.confirm_username.as_deref() != Some(row.username.as_str()) {
        let msg = "Type the username exactly to confirm deletion.";
        return failure(&state, &session, StatusCode::BAD_REQUEST, msg).await;
    }
    let accounts = state.accounts.clone();
    let uid = row.id.clone();
    match tokio::task::spawn_blocking(move || accounts.delete_user(&uid)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return internal(e),
        Err(e) => return internal(e),
    }
    cut_off(&state, &row.id);
    state.quotas.forget(&row.id);
    redirect(&headers, "/admin?notice=deleted")
}

#[derive(Deserialize)]
struct DefaultQuotaForm {
    gib: Option<String>,
    unlimited: Option<String>,
}

const BAD_QUOTA: &str = "Enter a size in GiB (for example 1.5) between 0 and 1048576 (1 PiB).";

async fn set_default_quota(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<DefaultQuotaForm>,
) -> Response {
    let quota = if form.unlimited.is_some() {
        None
    } else {
        match form.gib.as_deref().and_then(parse_gib) {
            Some(b) => Some(b),
            None => return failure(&state, &session, StatusCode::BAD_REQUEST, BAD_QUOTA).await,
        }
    };
    let sys = state.sys.clone();
    match tokio::task::spawn_blocking(move || sys.set_default_quota(quota)).await {
        Ok(Ok(())) => redirect(&headers, "/admin?notice=quota"),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct UserQuotaForm {
    mode: String,
    gib: Option<String>,
}

async fn set_user_quota(
    State(state): State<AppState>,
    AdminUser(session): AdminUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<UserQuotaForm>,
) -> Response {
    let setting = match form.mode.as_str() {
        "default" => QuotaSetting::Default,
        "unlimited" => QuotaSetting::Unlimited,
        "custom" => match form.gib.as_deref().and_then(parse_gib) {
            Some(b) => QuotaSetting::Custom(b),
            None => return failure(&state, &session, StatusCode::BAD_REQUEST, BAD_QUOTA).await,
        },
        _ => {
            return failure(
                &state,
                &session,
                StatusCode::BAD_REQUEST,
                "Unknown quota mode.",
            )
            .await;
        }
    };
    let sys = state.sys.clone();
    let uid = id.clone();
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        if sys.user_by_id(&uid)?.is_none() {
            return Ok(false);
        }
        sys.set_user_quota(&uid, setting)?;
        Ok(true)
    })
    .await;
    match res {
        Ok(Ok(true)) => redirect(&headers, "/admin?notice=quota"),
        Ok(Ok(false)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e),
    }
}

#[cfg(test)]
mod tests {
    use super::{human_bytes, parse_gib};

    #[test]
    fn gib_text_round_trips_exactly() {
        use super::gib_text;
        for b in [
            0u64,
            1,
            40 << 20,
            (5 << 28) + 12_345,
            10 << 30,
            1 << 50,
            1_234_567_891,
        ] {
            assert_eq!(parse_gib(&gib_text(b)), Some(b), "{b} via {}", gib_text(b));
        }
        assert_eq!(gib_text(40 << 20), "0.0390625");
        assert_eq!(gib_text(10 << 30), "10");
    }

    #[test]
    fn parses_gib_with_decimal_comma() {
        assert_eq!(parse_gib("1,5"), Some(3 << 29));
    }

    #[test]
    fn parses_gib() {
        assert_eq!(parse_gib("1"), Some(1 << 30));
        assert_eq!(parse_gib(" 0.5 "), Some(1 << 29));
        assert_eq!(parse_gib("0"), Some(0));
        assert_eq!(parse_gib("-1"), None);
        assert_eq!(parse_gib("abc"), None);
        assert_eq!(parse_gib("NaN"), None);
        assert_eq!(parse_gib("inf"), None);
        assert_eq!(parse_gib("1048576"), Some(1 << 50));
        assert_eq!(parse_gib("1048576.1"), None);
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
