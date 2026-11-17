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

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::extract::{ConnectInfo, OriginalUri, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::register::clean_client_name;
use super::{
    AUTHORIZE_PER_IP_PER_HOUR, AuthRequest, CodeEntry, REQUEST_TTL, SCOPES, mcp_url,
    redirect_uri_allowed,
};
use crate::accounts::AccountError;
use crate::documents::{DocError, validate_meta};
use crate::tokens::{create_grant, scope_string};
use crate::user_db::tag_ids as tag_ids_for;
use crate::user_db::{Access, Content, GrantInfo, ListFilter, TokenScope, list_tags_visible};
use crate::web::ratelimit::{client_ip, ip_key, too_many_requests, user_key};
use crate::web::session::{
    CsrfForm, CurrentUser, Session, clear_continue_cookie, continue_cookie, continue_id,
    is_staging_id,
};
use crate::web::{AppState, CspOverride, Page, kdf_blocking, render};

/// Consent form bodies are small.
pub const BODY_LIMIT: usize = 16 * 1024;

const STATE_MAX: usize = 512;

/// The consent page's policy: the default one, except that `form-action` also
/// allows the origin the approval redirects to (Chrome checks `form-action`
/// against the redirect that follows a form post).
fn consent_csp(redirect_uri: &str) -> String {
    let origin: String = redirect_uri
        .splitn(4, '/')
        .take(3)
        .collect::<Vec<_>>()
        .join("/");
    format!(
        "default-src 'self'; img-src 'self' data:; object-src 'self'; \
         frame-ancestors 'none'; base-uri 'none'; form-action 'self' {origin}"
    )
}

/// "less than a minute ago", "5 minutes ago", "3 hours ago", "2 days ago".
fn ago(secs: i64) -> String {
    let plural = |n: i64, unit: &str| format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" });
    match secs.max(0) {
        s if s < 60 => "less than a minute ago".to_owned(),
        s if s < 2 * 3600 => plural(s / 60, "minute"),
        s if s < 2 * 86400 => plural(s / 3600, "hour"),
        s => plural(s / 86400, "day"),
    }
}

/// Plain words for a requested scope.
fn scope_words(scope: &str) -> &'static str {
    match scope {
        "mcp:read" => "read access",
        "mcp:write" => "write access",
        "content:full" => "full text",
        _ => "offline access",
    }
}

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
    /// "registered 5 minutes ago"
    registered: String,
    /// The scopes the app asked for, as words; empty when it asked for none.
    asked: String,
    error: Option<String>,
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
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
    // Unknown scopes are ignored (RFC 6749 section 3.3); the consent decision
    // is what counts.
    let scopes: Vec<String> = scopes
        .into_iter()
        .filter(|s| SCOPES.contains(&s.as_str()))
        .collect();

    // Anyone may park requests here without a session; keep one address from
    // flushing the pending-request map (and a victim's request with it).
    let ip = client_ip(peer, &headers, state.cfg.trusted_proxy);
    if let Err(retry) = state.oauth.hit(
        &format!("authorize:{}", ip_key(ip)),
        AUTHORIZE_PER_IP_PER_HOUR,
    ) {
        return too_many_requests(retry);
    }

    let req = AuthRequest::new(
        client_id,
        clean_client_name(&client.client_name),
        redirect_uri,
        q.state,
        challenge,
        scopes,
        client.created_at,
    );
    let id = state.oauth.put_request(req.clone());
    match session {
        Some(axum::Extension(s)) if s.must_confirm_recovery.is_none() => {
            consent_page(&s, &id, &req, None).await
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
    consent_page(&session, &id, &req, None).await
}

async fn consent_page(
    session: &Session,
    req_id: &str,
    req: &AuthRequest,
    error: Option<&str>,
) -> Response {
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
    let mut resp = render(&ConsentPage {
        page: Page::for_session(session),
        client_name: clean_client_name(&req.client_name),
        redirect_host: redirect_host(&req.redirect_uri),
        req_id: req_id.to_owned(),
        registered: format!("registered {}", ago(now() - req.client_created_at)),
        asked: req
            .scopes
            .iter()
            .map(|s| scope_words(s))
            .collect::<Vec<_>>()
            .join(", "),
        error: error.map(str::to_owned),
        tags: tags
            .into_iter()
            .map(|(id, name)| TagChoice { id, name })
            .collect(),
    });
    if error.is_some() {
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
    }
    resp.extensions_mut()
        .insert(CspOverride(consent_csp(&req.redirect_uri).into()));
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
/// Approving also needs the account password (ruling AG): a grant outlives
/// logout and password changes, like a static token does.
pub async fn authorize_post(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
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
    // Taken up front so a double click cannot mint two grants; put back when
    // the attempt fails and the user may try again.
    let Some(req) = state.oauth.take_request(&req_id) else {
        return gone();
    };
    match decide(&state, peer, &headers, &session, &req_id, &req, &pairs).await {
        Ok(resp) => resp,
        Err(resp) => {
            state.oauth.restore_request(&req_id, req);
            resp
        }
    }
}

/// `Ok` consumes the request, `Err` leaves it pending for another attempt.
#[allow(clippy::result_large_err)] // the error is a ready `Response`
async fn decide(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    session: &Session,
    req_id: &str,
    req: &AuthRequest,
    pairs: &Pairs,
) -> Result<Response, Response> {
    let decision = field(pairs, "decision").unwrap_or_default();
    if decision == "deny" {
        let mut resp = redirect_error(
            &req.redirect_uri,
            req.state.as_deref(),
            "access_denied",
            "The user denied the request",
        );
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_continue_cookie());
        return Ok(resp);
    }
    if decision != "approve" {
        return Err(error_page("Choose Approve or Deny."));
    }

    let access = match field(pairs, "access").unwrap_or("read") {
        "read" => Access::Read,
        "read_write" => Access::ReadWrite,
        _ => return Err(error_page("Invalid access.")),
    };
    let content = match field(pairs, "content").unwrap_or("metadata_only") {
        "metadata_only" => Content::MetadataOnly,
        "full_text" => Content::FullText,
        _ => return Err(error_page("Invalid content level.")),
    };
    let mut tag_ids: Vec<i64> = Vec::new();
    for (k, v) in pairs {
        if k == "tags[]" {
            match v.parse::<i64>() {
                Ok(id) if !tag_ids.contains(&id) => tag_ids.push(id),
                Ok(_) => {}
                Err(_) => return Err(error_page("Invalid tag.")),
            }
        }
    }
    let new_tag = field(pairs, "new_tag")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if !new_tag.is_empty() {
        let names = std::slice::from_ref(&new_tag);
        if let Err(DocError::InvalidInput(msg)) = validate_meta(None, None, names) {
            return Err(error_page(msg));
        }
    }

    // The password, checked under the KDF semaphore and the same limiter keys
    // as the login and static-token routes.
    let ip = client_ip(peer, headers, state.cfg.trusted_proxy);
    let keys = [ip_key(ip), user_key(&session.username)];
    let attempt = state.limiter.begin(&keys).map_err(too_many_requests)?;
    let password = field(pairs, "password").unwrap_or_default().to_owned();
    let accounts = state.accounts.clone();
    let user_id = session.user_id.clone();
    match kdf_blocking(state, move || accounts.verify_password(&user_id, &password)).await {
        Err(r) => return Err(r),
        Ok(Err(AccountError::InvalidCredentials)) => {
            attempt.failure();
            return Err(consent_page(session, req_id, req, Some("The password is wrong.")).await);
        }
        Ok(Err(e)) => return Err(internal(e)),
        Ok(Ok(())) => attempt.success(),
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
        Ok(Ok(None)) => return Err(error_page("Invalid tag or unknown app.")),
        Ok(Err(e)) => return Err(internal(e)),
        Err(e) => return Err(internal(e)),
    };
    let code = state.oauth.put_code(entry);
    let mut params = vec![("code", code.as_str())];
    if let Some(s) = req.state.as_deref() {
        params.push(("state", s));
    }
    let mut resp = redirect_with(&req.redirect_uri, &params);
    resp.headers_mut()
        .append(header::SET_COOKIE, clear_continue_cookie());
    Ok(resp)
}
