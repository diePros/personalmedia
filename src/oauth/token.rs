//! `POST /oauth/token` (authorization code + PKCE, refresh token) and
//! `POST /oauth/revoke` (RFC 7009).
//!
//! Both are called cross-origin by non-browser clients and carry no cookies
//! (see the module docs of `oauth`). Nothing here may log tokens, codes,
//! verifiers or `state`.

use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{CodeEntry, ct_eq, json_response, oauth_error};
use crate::tokens::{ACCESS_TTL_SECS, RefreshError, refresh_grant, revoke_grant, revoke_presented};
use crate::web::AppState;
use crate::web::ratelimit::{client_ip, oauth_client_key, oauth_ip_key, too_many_requests};

/// Token and revocation requests are tiny forms.
pub const BODY_LIMIT: usize = 16 * 1024;

#[derive(Deserialize, Default)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// `BASE64URL(SHA-256(verifier)) == challenge`, compared in constant time.
fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    let verifier_ok = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    let computed = BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()));
    // Both comparisons always run.
    ct_eq(computed.as_bytes(), challenge.as_bytes()) & verifier_ok
}

fn invalid_grant() -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "The grant is invalid, expired or already used",
    )
}

fn server_error() -> Response {
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "Internal error",
    )
}

/// Whether a response counts as a failed guess for the rate limiter.
fn counts_as_failure(resp: &Response) -> bool {
    matches!(
        resp.status(),
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED
    ) && resp.extensions().get::<GuessFailure>().is_some()
}

/// Marker extension: this failure was a wrong credential (code, refresh token,
/// verifier, client), not a malformed request.
#[derive(Clone, Copy)]
struct GuessFailure;

fn guess_failure(mut resp: Response) -> Response {
    resp.extensions_mut().insert(GuessFailure);
    resp
}

pub async fn token(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Content-Type must be application/x-www-form-urlencoded",
        );
    }
    let Ok(form) = serde_urlencoded::from_bytes::<TokenForm>(&body) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The body is not a valid form",
        );
    };
    let client_id = form.client_id.clone().filter(|c| !c.is_empty());
    let known = match &client_id {
        Some(id) => {
            let sys = state.sys.clone();
            let cid = id.clone();
            match tokio::task::spawn_blocking(move || sys.oauth_client(&cid)).await {
                Ok(Ok(c)) => c.is_some(),
                _ => return server_error(),
            }
        }
        None => false,
    };
    // Failures are keyed by the registered client, never by the `/mcp` IP key
    // (ruling AH): anyone can make claude.ai's egress IP send garbage codes.
    // Without a known client the only thing to key on is the address.
    let keys = match (&client_id, known) {
        (Some(id), true) => [oauth_client_key(id)],
        _ => [oauth_ip_key(client_ip(
            peer,
            &headers,
            state.cfg.trusted_proxy,
        ))],
    };
    if let Err(retry) = state.limiter.check(&keys) {
        return too_many_requests(retry);
    }
    let resp = handle_token(&state, form, client_id, known).await;
    if resp.status() == StatusCode::OK {
        state.limiter.clear(&keys);
    } else if counts_as_failure(&resp) {
        state.limiter.record_failure(&keys);
    }
    resp
}

async fn handle_token(
    state: &AppState,
    form: TokenForm,
    client_id: Option<String>,
    known: bool,
) -> Response {
    let Some(client_id) = client_id else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    };
    if !known {
        return guess_failure(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Unknown client",
        ));
    }
    match form.grant_type.as_deref() {
        Some("authorization_code") => code_grant(state, form, client_id).await,
        Some("refresh_token") => refresh(state, form, client_id).await,
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be authorization_code or refresh_token",
        ),
    }
}

/// The plaintext pair is copied into a `serde_json::Value` and the response
/// body (and the form strings that carried a code or refresh token in are not
/// zeroized either). That is inherent to handing a token to the client, as
/// with static-token creation, so the "zeroized" guarantee covers the copies
/// held in `CodeEntry` and `IssuedPair`, not these transient ones.
fn token_response(access: &str, refresh: &str, scope: &str) -> Response {
    json_response(
        StatusCode::OK,
        &json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL_SECS,
            "refresh_token": refresh,
            "scope": scope,
        }),
    )
}

/// Deletes a grant that will not be used (or that a replayed code revokes).
fn revoke_for(state: &AppState, user_id: &str, grant_id: &str) {
    let unlocked = state.keyring.get(user_id);
    if let Err(e) = revoke_grant(&state.sys, unlocked.as_deref(), grant_id, &state.tokens) {
        tracing::error!(error = %e, grant = %grant_id, "could not revoke grant");
    }
}

/// Deletes the grant of a code that will not be exchanged.
fn discard(state: &AppState, entry: &CodeEntry) {
    revoke_for(state, &entry.user_id, &entry.grant_id);
}

async fn code_grant(state: &AppState, form: TokenForm, client_id: String) -> Response {
    let (Some(code), Some(redirect_uri), Some(verifier)) =
        (form.code, form.redirect_uri, form.code_verifier)
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code, redirect_uri and code_verifier are required",
        );
    };
    let st = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        let entry = match st.oauth.take_code(&code) {
            None => {
                // A code that was already exchanged: whatever was issued from
                // it goes (RFC 6749 section 4.1.2).
                if let Some((user_id, grant_id)) = st.oauth.spent_code(&code) {
                    tracing::warn!(grant = %grant_id, "authorization code replay; revoking grant");
                    revoke_for(&st, &user_id, &grant_id);
                }
                return guess_failure(invalid_grant());
            }
            Some(Err(expired)) => {
                discard(&st, &expired);
                return guess_failure(invalid_grant());
            }
            Some(Ok(e)) => e,
        };
        // The code is spent either way. Any mismatch also kills the grant that
        // was pre-minted for it.
        let ok = entry.client_id == client_id
            && entry.redirect_uri == redirect_uri
            && pkce_ok(&verifier, &entry.challenge);
        if !ok {
            discard(&st, &entry);
            return guess_failure(invalid_grant());
        }
        st.oauth
            .note_spent_code(&code, &entry.user_id, &entry.grant_id);
        token_response(&entry.access, &entry.refresh, &entry.scope)
    })
    .await;
    result.unwrap_or_else(|_| server_error())
}

async fn refresh(state: &AppState, form: TokenForm, client_id: String) -> Response {
    let Some(token) = form.refresh_token else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };
    let st = state.clone();
    let result = tokio::task::spawn_blocking(move || refresh_grant(&st, &token, &client_id)).await;
    match result {
        Ok(Ok(r)) => token_response(&r.pair.access, &r.pair.refresh, &r.scope),
        Ok(Err(RefreshError::InvalidGrant)) => guess_failure(invalid_grant()),
        Ok(Err(RefreshError::Internal(e))) => {
            tracing::error!(error = %e, "refresh failed");
            server_error()
        }
        Err(_) => server_error(),
    }
}

#[derive(Deserialize, Default)]
struct RevokeForm {
    token: Option<String>,
}

/// RFC 7009: always `200`, whatever the token.
pub async fn revoke(State(state): State<AppState>, body: Bytes) -> Response {
    if let Ok(RevokeForm { token: Some(t) }) = serde_urlencoded::from_bytes::<RevokeForm>(&body) {
        let st = state.clone();
        let res = tokio::task::spawn_blocking(move || revoke_presented(&st, &t)).await;
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "revocation failed"),
            Err(e) => tracing::error!(error = %e, "revocation task failed"),
        }
    }
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
        ],
        "{}",
    )
        .into_response()
}
