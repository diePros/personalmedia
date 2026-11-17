//! Discovery documents: RFC 9728 protected-resource metadata and RFC 8414
//! authorization-server metadata.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use super::{SCOPES, json_response, mcp_url};
use crate::web::AppState;

/// `resource` equals the MCP URL exactly; the issuer is listed first.
pub async fn protected_resource(State(state): State<AppState>) -> Response {
    let base = &state.cfg.public_url;
    json_response(
        StatusCode::OK,
        &json!({
            "resource": mcp_url(base),
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": SCOPES,
        }),
    )
}

pub async fn authorization_server(State(state): State<AppState>) -> Response {
    let base = &state.cfg.public_url;
    json_response(
        StatusCode::OK,
        &json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/oauth/authorize"),
            "token_endpoint": format!("{base}/oauth/token"),
            "registration_endpoint": format!("{base}/oauth/register"),
            "revocation_endpoint": format!("{base}/oauth/revoke"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": SCOPES,
        }),
    )
}
