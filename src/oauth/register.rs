//! `POST /oauth/register`: RFC 7591 dynamic client registration for public
//! clients. JSON only.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::{
    CLIENT_NAME_MAX_CHARS, MAX_CLIENTS, dcr_key, json_response, oauth_error, redirect_uri_allowed,
};
use crate::system_db::OauthClient;
use crate::web::AppState;
use crate::web::ratelimit::client_ip;

/// Registration bodies are tiny.
pub const BODY_LIMIT: usize = 16 * 1024;
const MAX_REDIRECT_URIS: usize = 10;

fn bad_metadata(msg: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", msg)
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

fn str_list(v: &Value) -> Option<Vec<&str>> {
    v.as_array()?.iter().map(Value::as_str).collect()
}

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_ip(peer, &headers, state.cfg.trusted_proxy);
    if let Err(retry) = state.oauth.dcr_hit(&dcr_key(ip)) {
        let mut resp = oauth_error(
            StatusCode::TOO_MANY_REQUESTS,
            "slow_down",
            "Too many registrations. Try again later.",
        );
        let secs = retry.as_secs() + u64::from(retry.subsec_nanos() > 0);
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(secs.max(1)));
        return resp;
    }
    if !is_json(&headers) {
        return bad_metadata("Content-Type must be application/json");
    }
    let Ok(Value::Object(req)) = serde_json::from_slice::<Value>(&body) else {
        return bad_metadata("The body must be a JSON object");
    };

    // Every client is registered as a public one. A client asking for a
    // secret-based method still gets a client, and the response says `none`
    // (RFC 7591 section 3.2.1 lets the server override metadata).
    if let Some(m) = req.get("token_endpoint_auth_method")
        && !matches!(
            m.as_str(),
            Some("none" | "client_secret_post" | "client_secret_basic")
        )
    {
        return bad_metadata("Unsupported token_endpoint_auth_method");
    }
    if let Some(g) = req.get("grant_types") {
        let ok = str_list(g).is_some_and(|l| {
            l.iter()
                .all(|g| matches!(*g, "authorization_code" | "refresh_token"))
        });
        if !ok {
            return bad_metadata(
                "grant_types may only contain authorization_code and refresh_token",
            );
        }
    }
    if let Some(r) = req.get("response_types")
        && !str_list(r).is_some_and(|l| l.iter().all(|t| *t == "code"))
    {
        return bad_metadata("response_types may only contain code");
    }

    let uris: Vec<String> = match req.get("redirect_uris").and_then(str_list) {
        Some(l) if !l.is_empty() && l.len() <= MAX_REDIRECT_URIS => {
            l.into_iter().map(str::to_owned).collect()
        }
        _ => return bad_metadata("redirect_uris must be a non-empty array of strings"),
    };
    if !uris
        .iter()
        .all(|u| redirect_uri_allowed(u, &state.cfg.oauth_extra_redirect_hosts))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "A redirect URI is not allowed",
        );
    }

    // Stored raw (HTML-escaped when rendered), capped, without control characters.
    let name: String = match req.get("client_name") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => clean_client_name(s),
        Some(_) => return bad_metadata("client_name must be a string"),
    };
    let name = if name.trim().is_empty() {
        "Unnamed client".to_owned()
    } else {
        name
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut id = [0u8; 16];
    crate::crypto::fill_random(&mut id);
    let client = OauthClient {
        client_id: format!("pmc_{}", hex::encode(id)),
        client_name: name,
        redirect_uris: uris,
        created_at: now,
        last_grant_at: None,
    };
    let sys = state.sys.clone();
    let c = client.clone();
    let stored =
        tokio::task::spawn_blocking(move || sys.insert_oauth_client(&c, MAX_CLIENTS)).await;
    match stored {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => {
            let mut resp = oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "Too many registered clients. Try again later.",
            );
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("3600"));
            return resp;
        }
        _ => {
            tracing::error!("storing an oauth client failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    tracing::info!(client_id = %client.client_id, "oauth client registered");
    json_response(
        StatusCode::CREATED,
        &json!({
            "client_id": client.client_id,
            "client_id_issued_at": now,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }),
    )
}

/// Unicode format characters (category Cf): bidi controls, zero-width
/// characters, joiners, tag characters. In a client name they could reorder
/// or hide text on the consent page.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
        | '\u{08E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}' | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// A client name safe to show: control and format characters removed, cut to
/// [`CLIENT_NAME_MAX_CHARS`]. Applied at registration and again at render.
pub fn clean_client_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && !is_format_char(*c))
        .take(CLIENT_NAME_MAX_CHARS)
        .collect()
}

#[cfg(test)]
mod name_tests {
    use super::clean_client_name;

    #[test]
    fn bidi_and_format_characters_are_stripped() {
        assert_eq!(
            clean_client_name("a\u{202E}b\u{200B}c\u{2066}d\u{2069}e\u{FEFF}\u{0007}f"),
            "abcdef"
        );
    }
}
