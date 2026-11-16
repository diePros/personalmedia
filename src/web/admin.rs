//! Admin pages: invites and user management (`/admin`).
//!
//! The admin manages accounts but never sees document content: the page shows
//! usernames, roles, dates and the number of bytes stored, nothing else.
//!
//! Disable and delete write the system database first, then drop the user's
//! sessions and cached token unlocks, so a login or token request racing with
//! the action fails its re-check against the database.

#![allow(clippy::result_large_err)] // helpers return a ready `Response` as the error

use std::path::Path as FsPath;
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
use crate::keyring::user_dir;
use crate::system_db::Role;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(page))
        .route("/admin/invites", post(create_invite))
        .route("/admin/invites/{prefix}/revoke", post(revoke_invite))
        .route("/admin/users/{id}/disable", post(disable))
        .route("/admin/users/{id}/enable", post(enable))
        .route("/admin/users/{id}/delete", post(delete))
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
        _ => return None,
    })
}

/// Sum of the file sizes under `dir`, recursively. Symlinks are not followed.
fn dir_size(dir: &FsPath) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) if m.is_file() => m.len(),
            _ => 0,
        })
        .sum()
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 3] = ["KiB", "MiB", "GiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

async fn admin_response(
    state: &AppState,
    session: &Session,
    status: StatusCode,
    notice: Option<&'static str>,
    error: Option<String>,
    new_invite: Option<String>,
) -> Response {
    let (sys, data_dir, me) = (
        state.sys.clone(),
        state.cfg.data_dir.clone(),
        session.user_id.clone(),
    );
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
        let users: Vec<UserView> = sys
            .list_users()?
            .into_iter()
            .map(|u| UserView {
                storage: human_bytes(dir_size(&user_dir(&data_dir, &u.id))),
                is_self: u.id == me,
                created: format_date(u.created_at),
                role: role_name(u.role),
                disabled: u.disabled,
                username: u.username,
                id: u.id,
            })
            .collect();
        Ok((invites, users))
    })
    .await;
    let (invites, users) = match loaded {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return internal(e),
        Err(e) => return internal(e),
    };
    let mut resp = render(&AdminPage {
        page: Page::for_session(session),
        notice,
        error,
        new_invite,
        invites,
        users,
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
    redirect(&headers, "/admin?notice=deleted")
}

#[cfg(test)]
mod tests {
    use super::human_bytes;

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
