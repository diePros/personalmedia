//! `GET|POST /oauth/authorize`: validation, login detour and the consent page.
//!
//! Validation order matters: until `client_id` exists and `redirect_uri` is
//! one the client registered (and still passes the allow-list) the redirect
//! target is not trusted, so those failures render an error page and never
//! redirect. Later failures go back to the client as `error=...`.
//!
//! The validated request is kept server-side under a random id (a visitor
//! who is not logged in gets it in the `__Host-pm_continue` cookie, the
//! consent form carries it as a hidden field); neither carries any parameter.

use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::{AuthRequest, CodeEntry, REQUEST_TTL, SCOPES, mcp_url, redirect_uri_allowed};
use crate::documents::{DocError, validate_meta};
use crate::tokens::{create_grant, scope_string};
use crate::user_db::tag_ids as tag_ids_for;
use crate::user_db::{Access, Content, GrantInfo, ListFilter, TokenScope, list_tags_visible};
use crate::web::session::{
    CsrfForm, CurrentUser, Session, clear_continue_cookie, continue_cookie, continue_id,
    is_staging_id,
};
use crate::web::{AppState, CspOverride, Page, render};

/// Consent form bodies are small.
pub const BODY_LIMIT: usize = 16 * 1024;

const STATE_MAX: usize = 512;

/// The consent page must let the browser follow the redirect to the client's
/// callback (Chrome checks `form-action` against redirects of a form post), and
/// that host is not known statically, so `form-action` is left out here. Every
/// other directive of the default policy stays.
const CONSENT_CSP: &str = "default-src 'self'; img-src 'self' data:; object-src 'self'; \
                           frame-ancestors 'none'; base-uri 'none'";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[derive(Template)]
#[template(path = "oauth_error.html")]
struct ErrorPage {
    page: Page,
    message: String,
}

fn error_page(message: &str) -> Response {
    let mut resp = render(&ErrorPage {
        page: Page::anonymous(),
        message: message.to_owned(),
    });
    if resp.status() == StatusCode::OK {
        *resp.status_mut() = StatusCode::BAD_REQUEST;
    }
    resp
}

struct TagChoice {
    id: i64,
    name: String,
}

#[derive(Template)]
#[template(path = "oauth_consent.html")]
struct ConsentPage {
    page: Page,
    client_name: String,
    redirect_host: String,
    req_id: String,
    read_write: bool,
    full_text: bool,
    tags: Vec<TagChoice>,
}

/// `host[:port]` of an `http(s)` URL.
fn redirect_host(uri: &str) -> String {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    rest.split(['/', '?']).next().unwrap_or(rest).to_owned()
}

/// Sends the browser to `uri` with `params` added to its query (302).
fn redirect_with(uri: &str, params: &[(&str, &str)]) -> Response {
    let query = serde_urlencoded::to_string(params).unwrap_or_default();
    let sep = if uri.contains('?') { '&' } else { '?' };
    let target = format!("{uri}{sep}{query}");
    match HeaderValue::from_str(&target) {
        Ok(v) => (StatusCode::FOUND, [(header::LOCATION, v)]).into_response(),
        Err(_) => error_page("The redirect address is not valid."),
    }
}

/// An error answered by redirecting to the (already trusted) client.
fn redirect_error(uri: &str, state: Option<&str>, code: &str, description: &str) -> Response {
    let mut params = vec![("error", code), ("error_description", description)];
    if let Some(s) = state {
        params.push(("state", s));
    }
    redirect_with(uri, &params)
}

/// Whether `requested` is acceptable for a client that registered
/// `registered`: an exact match, or for loopback URIs the same host, path and
/// query on any port (RFC 8252 section 7.3).
fn redirect_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    fn loopback_parts(u: &str) -> Option<(&str, &str)> {
        let rest = u.strip_prefix("http://")?;
        let slash = rest.find('/')?;
        let (authority, tail) = rest.split_at(slash);
        let (host, _port) = authority.split_once(':')?;
        (host == "127.0.0.1" || host == "localhost").then_some((host, tail))
    }
    match (loopback_parts(registered), loopback_parts(requested)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[derive(serde::Deserialize, Default)]
struct AuthQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

fn challenge_ok(c: &str) -> bool {
    // BASE64URL(SHA-256) is 43 characters; accept the RFC 7636 range.
    (43..=128).contains(&c.len())
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

pub async fn authorize_get(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    session: Option<axum::Extension<Session>>,
) -> Response {
    let Ok(q) = serde_urlencoded::from_str::<AuthQuery>(uri.query().unwrap_or("")) else {
        return error_page("The authorization request is malformed.");
    };

    // 1. The client must exist.
    let Some(client_id) = q.client_id.clone().filter(|c| !c.is_empty()) else {
        return error_page("The authorization request has no client_id.");
    };
    let sys = state.sys.clone();
    let cid = client_id.clone();
    let client = match tokio::task::spawn_blocking(move || sys.oauth_client(&cid)).await {
        Ok(Ok(Some(c))) => c,
        Ok(Ok(None)) => return error_page("This app is not registered with this server."),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "oauth client lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "oauth client lookup task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 2. The redirect URI must be registered and allowed. Only now may errors
    // be sent back to it.
    let Some(redirect_uri) = q.redirect_uri.clone() else {
        return error_page("The authorization request has no redirect_uri.");
    };
    if !client
        .redirect_uris
        .iter()
        .any(|r| redirect_matches(r, &redirect_uri))
        || !redirect_uri_allowed(&redirect_uri, &state.cfg.oauth_extra_redirect_hosts)
    {
        return error_page("The redirect address is not registered for this app.");
    }
    let st = q.state.as_deref();
    if st.is_some_and(|s| s.len() > STATE_MAX) {
        return redirect_error(&redirect_uri, None, "invalid_request", "state is too long");
    }
    let fail = |code: &str, msg: &str| redirect_error(&redirect_uri, st, code, msg);

    if q.response_type.as_deref() != Some("code") {
        return fail(
            "unsupported_response_type",
            "Only response_type=code is supported",
        );
    }
    let Some(challenge) = q.code_challenge.clone().filter(|c| challenge_ok(c)) else {
        return fail("invalid_request", "A valid S256 code_challenge is required");
    };
    if q.code_challenge_method.as_deref() != Some("S256") {
        return fail("invalid_request", "code_challenge_method must be S256");
    }
    if let Some(res) = &q.resource
        && *res != mcp_url(&state.cfg.public_url)
    {
        return fail(
            "invalid_target",
            "resource is not this server's MCP endpoint",
        );
    }
    let scopes: Vec<String> = q
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
        return fail("invalid_scope", "Unknown scope requested");
    }

    let req = AuthRequest::new(
        client_id,
        client.client_name,
        redirect_uri,
        q.state,
        challenge,
        scopes,
    );
    let id = state.oauth.put_request(req.clone());
    match session {
        Some(axum::Extension(s)) if s.must_confirm_recovery.is_none() => {
            consent_page(&s, &id, &req).await
        }
        _ => {
            // Log in first; the login flow returns to `/oauth/authorize/resume`.
            let mut resp = (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, HeaderValue::from_static("/login"))],
            )
                .into_response();
            resp.headers_mut()
                .append(header::SET_COOKIE, continue_cookie(&id, REQUEST_TTL));
            resp
        }
    }
}

/// `GET /oauth/authorize/resume`: where login (or recovery-key confirmation)
/// lands when an authorize request was waiting; shows the consent page.
pub async fn resume(
    State(state): State<AppState>,
    headers: HeaderMap,
    CurrentUser(session): CurrentUser,
) -> Response {
    let found = continue_id(&headers)
        .filter(|id| is_staging_id(id))
        .and_then(|id| state.oauth.request(id).map(|r| (id.to_owned(), r)));
    let Some((id, req)) = found else {
        let mut resp =
            error_page("This authorization request has expired. Start again from the app.");
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_continue_cookie());
        return resp;
    };
    consent_page(&session, &id, &req).await
}

async fn consent_page(session: &Session, req_id: &str, req: &AuthRequest) -> Response {
    let u = session.unlocked.clone();
    let tags = match tokio::task::spawn_blocking(move || {
        u.with_db(|c| list_tags_visible(c, &ListFilter::default()))
    })
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "listing tags for consent failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "consent task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let has = |s: &str| req.scopes.iter().any(|r| r == s);
    let mut resp = render(&ConsentPage {
        page: Page::for_session(session),
        client_name: req
            .client_name
            .chars()
            .take(super::CLIENT_NAME_MAX_CHARS)
            .collect(),
        redirect_host: redirect_host(&req.redirect_uri),
        req_id: req_id.to_owned(),
        read_write: has("mcp:write"),
        full_text: has("content:full"),
        tags: tags
            .into_iter()
            .map(|(id, name)| TagChoice { id, name })
            .collect(),
    });
    resp.extensions_mut().insert(CspOverride(CONSENT_CSP));
    resp
}

type Pairs = Vec<(String, String)>;

fn field<'a>(pairs: &'a Pairs, name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "oauth consent failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// `POST /oauth/authorize`: the consent decision (session + CSRF protected).
pub async fn authorize_post(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    CsrfForm(pairs): CsrfForm<Pairs>,
) -> Response {
    let gone = || {
        let mut resp =
            error_page("This authorization request has expired. Start again from the app.");
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_continue_cookie());
        resp
    };
    let Some(req_id) = field(&pairs, "req").map(str::to_owned) else {
        return gone();
    };
    let Some(req) = state.oauth.request(&req_id) else {
        return gone();
    };

    let decision = field(&pairs, "decision").unwrap_or_default();
    if decision == "deny" {
        state.oauth.take_request(&req_id);
        let mut resp = redirect_error(
            &req.redirect_uri,
            req.state.as_deref(),
            "access_denied",
            "The user denied the request",
        );
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_continue_cookie());
        return resp;
    }
    if decision != "approve" {
        return error_page("Choose Approve or Deny.");
    }

    let access = match field(&pairs, "access").unwrap_or("read") {
        "read" => Access::Read,
        "read_write" => Access::ReadWrite,
        _ => return error_page("Invalid access."),
    };
    let content = match field(&pairs, "content").unwrap_or("metadata_only") {
        "metadata_only" => Content::MetadataOnly,
        "full_text" => Content::FullText,
        _ => return error_page("Invalid content level."),
    };
    let mut tag_ids: Vec<i64> = Vec::new();
    for (k, v) in &pairs {
        if k == "tags[]" {
            match v.parse::<i64>() {
                Ok(id) if !tag_ids.contains(&id) => tag_ids.push(id),
                Ok(_) => {}
                Err(_) => return error_page("Invalid tag."),
            }
        }
    }
    let new_tag = field(&pairs, "new_tag")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if !new_tag.is_empty() {
        let names = std::slice::from_ref(&new_tag);
        if let Err(DocError::InvalidInput(msg)) = validate_meta(None, None, names) {
            return error_page(msg);
        }
    }

    let (u, sys) = (session.unlocked.clone(), state.sys.clone());
    let grant_req = req.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<CodeEntry>> {
        // The client may have been pruned or removed since the page was shown.
        if sys.oauth_client(&grant_req.client_id)?.is_none() {
            return Ok(None);
        }
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
        let scope_str = scope_string(&scope);
        let now = now();
        let (grant_id, pair) = create_grant(
            &sys,
            &u,
            scope,
            GrantInfo {
                client_id: grant_req.client_id.clone(),
                client_name: grant_req.client_name.clone(),
                redirect_host: redirect_host(&grant_req.redirect_uri),
            },
            now,
        )?;
        sys.touch_oauth_client_grant(&grant_req.client_id, now)?;
        Ok(Some(CodeEntry {
            user_id: u.user_id.clone(),
            grant_id,
            client_id: grant_req.client_id,
            redirect_uri: grant_req.redirect_uri,
            challenge: grant_req.challenge,
            scope: scope_str,
            access: pair.access,
            refresh: pair.refresh,
            created: std::time::Instant::now(),
        }))
    })
    .await;
    let entry = match result {
        Ok(Ok(Some(e))) => e,
        Ok(Ok(None)) => return error_page("Invalid tag or unknown app."),
        Ok(Err(e)) => return internal(e),
        Err(e) => return internal(e),
    };
    state.oauth.take_request(&req_id);
    let code = state.oauth.put_code(entry);
    let mut params = vec![("code", code.as_str())];
    if let Some(s) = req.state.as_deref() {
        params.push(("state", s));
    }
    let mut resp = redirect_with(&req.redirect_uri, &params);
    resp.headers_mut()
        .append(header::SET_COOKIE, clear_continue_cookie());
    resp
}
