//! MCP server (Streamable HTTP, stateless, plain JSON responses) at `POST /mcp`.
//!
//! This is a minimal JSON-RPC 2.0 implementation rather than the `rmcp` SDK:
//! the endpoint is stateless (no sessions, no SSE), every request carries its
//! own bearer token, and the token's [`Principal`] must reach the tool code
//! without any shared state. A small hand-written dispatcher keeps that
//! trivially auditable and independent of the SDK's host/origin allow-lists
//! and session management. Supported methods: `initialize`,
//! `notifications/*`, `ping`, `tools/list`, `tools/call`.
//!
//! Scope rules (spec 13/13a) are enforced here for every tool: reads go
//! through `Principal::filter` (channel `Mcp`, cap from the token, tag
//! allow-list); a document the token may not see is reported as not found.
//!
//! Logging: only the tool name and the outcome. Never arguments, queries or
//! document content.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use data_encoding::BASE64;
use futures_util::stream;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::documents::{DocError, OnDuplicate, UploadMeta};
use crate::keyring::Unlocked;
use crate::tokens::{Principal, authenticate};
use crate::user_db::{
    Document, Level, effective_level, get_document, get_document_text, list_documents,
    list_tags_visible, search,
};
use crate::web::AppState;
use crate::web::ratelimit::{client_ip, mcp_ip_key, too_many_requests};

const SERVER_NAME: &str = "personal-media";
const LATEST_PROTOCOL: &str = "2025-06-18";
const SUPPORTED_PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
/// Longest document text returned by `get_document`, in characters.
const TEXT_MAX_CHARS: usize = 100_000;
const BODY_SLACK: usize = 64 * 1024;

pub fn routes(state: &AppState) -> Router<AppState> {
    // base64 inflates by 4/3.
    let limit = (state.cfg.max_upload_bytes as usize).saturating_mul(4) / 3 + BODY_SLACK;
    // Layered on the method router, not the `Router`: a router-level layer
    // would also wrap the fallback and 401 every unknown path.
    Router::new().route(
        "/mcp",
        post(rpc)
            .layer(DefaultBodyLimit::max(limit))
            .layer(middleware::from_fn_with_state(state.clone(), auth_layer)),
    )
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
    )
        .into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    (v.len() > 7 && v[..7].eq_ignore_ascii_case("bearer ")).then(|| v[7..].trim())
}

/// Authenticates the bearer token of a request, rate limited per client IP
/// (`mcp-ip:{ip}`; only a successful authentication settles as success).
/// Every failure is a `401` with an empty body; a locked IP gets `429`.
#[allow(clippy::result_large_err)] // the error is a ready `Response`
pub async fn bearer_principal(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<Principal, Response> {
    let ip = client_ip(peer, headers, state.cfg.trusted_proxy);
    let attempt = state
        .limiter
        .begin(&[mcp_ip_key(ip)])
        .map_err(too_many_requests)?;
    let Some(token) = bearer_token(headers).map(str::to_owned) else {
        attempt.failure();
        return Err(unauthorized());
    };
    let st = state.clone();
    match tokio::task::spawn_blocking(move || authenticate(&st, &token)).await {
        Ok(Ok(p)) => {
            attempt.success();
            Ok(p)
        }
        _ => {
            attempt.failure();
            Err(unauthorized())
        }
    }
}

async fn auth_layer(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    match bearer_principal(&state, peer, req.headers()).await {
        Ok(p) => {
            req.extensions_mut().insert(p);
            next.run(req).await
        }
        Err(resp) => resp,
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (status, axum::Json(body.clone())).into_response()
}

async fn rpc(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    body: Bytes,
) -> Response {
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &rpc_error(Value::Null, -32700, "parse error"),
            );
        }
    };
    let Some(obj) = msg.as_object() else {
        // Batches are not part of protocol 2025-06-18.
        return json_response(
            StatusCode::BAD_REQUEST,
            &rpc_error(Value::Null, -32600, "invalid request"),
        );
    };
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        // A response or garbage from the client: acknowledge and ignore.
        return StatusCode::ACCEPTED.into_response();
    };
    let Some(id) = obj.get("id").cloned() else {
        // Notification (e.g. notifications/initialized).
        return StatusCode::ACCEPTED.into_response();
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    let reply = match method {
        "initialize" => {
            let wanted = params.get("protocolVersion").and_then(Value::as_str);
            let version = wanted
                .filter(|v| SUPPORTED_PROTOCOLS.contains(v))
                .unwrap_or(LATEST_PROTOCOL);
            rpc_result(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
                }),
            )
        }
        "ping" => rpc_result(id, json!({})),
        "tools/list" => rpc_result(id, json!({"tools": tool_definitions()})),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return json_response(StatusCode::OK, &rpc_error(id, -32602, "missing tool name"));
            };
            if !TOOL_NAMES.contains(&name) {
                return json_response(StatusCode::OK, &rpc_error(id, -32602, "unknown tool"));
            }
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let outcome = call_tool(&state, &principal, name, args).await;
            tracing::info!(tool = name, ok = outcome.is_ok(), "mcp tool call");
            rpc_result(id, tool_result(outcome))
        }
        _ => rpc_error(id, -32601, "method not found"),
    };
    json_response(StatusCode::OK, &reply)
}

fn tool_result(outcome: Result<Value, String>) -> Value {
    let (text, is_error) = match outcome {
        Ok(v) => (v.to_string(), false),
        Err(msg) => (msg, true),
    };
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const TOOL_NAMES: &[&str] = &[
    "search_documents",
    "list_documents",
    "get_document",
    "list_tags",
    "upload_document",
    "update_document",
];

fn tool_definitions() -> Value {
    let tags = json!({"type": "array", "items": {"type": "string"}});
    let date = json!({"type": "string", "description": "YYYY-MM-DD"});
    json!([
        {
            "name": "search_documents",
            "description": "Full-text search over the documents this token may see.",
            "inputSchema": {"type": "object", "properties": {
                "query": {"type": "string"},
                "tags": tags, "date_from": date, "date_to": date,
                "limit": {"type": "integer", "minimum": 1, "maximum": 50}
            }, "required": ["query"]}
        },
        {
            "name": "list_documents",
            "description": "List documents, newest first.",
            "inputSchema": {"type": "object", "properties": {
                "tags": tags, "date_from": date, "date_to": date,
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "offset": {"type": "integer", "minimum": 0}
            }}
        },
        {
            "name": "get_document",
            "description": "Metadata of one document, plus its extracted text when the token allows full text.",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}
        },
        {
            "name": "list_tags",
            "description": "Tags of the documents this token may see.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "upload_document",
            "description": "Store a new document (read_write tokens only).",
            "inputSchema": {"type": "object", "properties": {
                "filename": {"type": "string"},
                "content_base64": {"type": "string"},
                "title": {"type": "string"},
                "tags": tags, "date": date
            }, "required": ["filename", "content_base64"]}
        },
        {
            "name": "update_document",
            "description": "Change title, tags or date of a document (read_write tokens only).",
            "inputSchema": {"type": "object", "properties": {
                "id": {"type": "string"},
                "title": {"type": "string"},
                "tags": tags,
                "date": {"type": "string", "description": "YYYY-MM-DD; empty string clears the date"}
            }, "required": ["id"]}
        }
    ])
}

#[derive(Deserialize)]
struct SearchArgs {
    query: String,
    #[serde(default)]
    tags: Vec<String>,
    date_from: Option<String>,
    date_to: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize, Default)]
struct ListArgs {
    #[serde(default)]
    tags: Vec<String>,
    date_from: Option<String>,
    date_to: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Deserialize)]
struct IdArgs {
    id: String,
}

#[derive(Deserialize)]
struct UploadArgs {
    filename: String,
    content_base64: String,
    title: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    date: Option<String>,
}

#[derive(Deserialize)]
struct UpdateArgs {
    id: String,
    title: Option<String>,
    tags: Option<Vec<String>>,
    date: Option<String>,
}

fn parse<T: serde::de::DeserializeOwned>(args: Value) -> Result<T, String> {
    serde_json::from_value(args).map_err(|_| "invalid arguments".to_owned())
}

fn internal(e: impl std::fmt::Display) -> String {
    tracing::error!(error = %e, "mcp tool failed");
    "internal error".to_owned()
}

const READ_ONLY: &str = "token is read-only";
const NOT_FOUND: &str = "document not found";

/// Runs index DB work off the async threads.
async fn blocking<T: Send + 'static>(
    u: &Arc<Unlocked>,
    f: impl FnOnce(&Connection) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, String> {
    let u = u.clone();
    tokio::task::spawn_blocking(move || u.with_db(f))
        .await
        .map_err(internal)?
        .map_err(internal)
}

async fn call_tool(
    state: &AppState,
    p: &Principal,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    match name {
        "search_documents" => search_documents(p, parse(args)?).await,
        "list_documents" => list_docs(p, parse(args)?).await,
        "get_document" => get_doc(p, parse(args)?).await,
        "list_tags" => list_tag_names(p).await,
        "upload_document" => {
            if !p.can_write() {
                return Err(READ_ONLY.into());
            }
            upload_document(state, p, parse(args)?).await
        }
        "update_document" => {
            if !p.can_write() {
                return Err(READ_ONLY.into());
            }
            update_document(state, p, parse(args)?).await
        }
        _ => Err("unknown tool".into()),
    }
}

fn doc_json(d: &Document) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("id".into(), json!(d.id));
    m.insert("title".into(), json!(d.title));
    m.insert("document_date".into(), json!(d.document_date));
    m.insert("tags".into(), json!(d.tags));
    m.insert("filename".into(), json!(d.original_filename));
    m
}

fn clean(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

async fn search_documents(p: &Principal, a: SearchArgs) -> Result<Value, String> {
    if a.query.trim().is_empty() {
        return Err("query must not be empty".into());
    }
    let mut f = p.filter();
    f.tags_all = a.tags;
    f.date_from = clean(a.date_from);
    f.date_to = clean(a.date_to);
    f.limit = a.limit.unwrap_or(20).clamp(1, 50);
    let query = a.query;
    let hits = blocking(&p.unlocked, move |c| search(c, &query, &f)).await?;
    let out: Vec<Value> = hits
        .into_iter()
        .map(|h| {
            let mut m = doc_json(&h.doc);
            // Snippets are content: only for documents readable at Full.
            if h.level == Level::Full
                && let Some(s) = h.snippet
            {
                m.insert("snippet".into(), json!(s.replace(['\u{2}', '\u{3}'], "")));
            }
            Value::Object(m)
        })
        .collect();
    Ok(Value::Array(out))
}

async fn list_docs(p: &Principal, a: ListArgs) -> Result<Value, String> {
    let mut f = p.filter();
    f.tags_all = a.tags;
    f.date_from = clean(a.date_from);
    f.date_to = clean(a.date_to);
    f.limit = a.limit.unwrap_or(50).clamp(1, 100);
    f.offset = a.offset.unwrap_or(0);
    let docs = blocking(&p.unlocked, move |c| list_documents(c, &f)).await?;
    Ok(Value::Array(
        docs.iter().map(|d| Value::Object(doc_json(d))).collect(),
    ))
}

/// The document and its effective level, if this token may see it at all.
fn visible_doc(
    c: &Connection,
    p: &Principal,
    id: &str,
) -> anyhow::Result<Option<(Document, Level)>> {
    let Some(doc) = get_document(c, id)? else {
        return Ok(None);
    };
    let level = effective_level(c, id, crate::user_db::Channel::Mcp, p.cap())?;
    if level == Level::Off {
        return Ok(None);
    }
    if let Some(allowed) = p.allowed_tag_names(c)?
        && !doc.tags.iter().any(|t| allowed.contains(t))
    {
        return Ok(None);
    }
    Ok(Some((doc, level)))
}

async fn get_doc(p: &Principal, a: IdArgs) -> Result<Value, String> {
    let p2 = p.clone();
    let found = blocking(&p.unlocked, move |c| {
        let Some((doc, level)) = visible_doc(c, &p2, &a.id)? else {
            return Ok(None);
        };
        let text = if level == Level::Full {
            get_document_text(c, &doc.id)?
        } else {
            None
        };
        Ok(Some((doc, text)))
    })
    .await?;
    let Some((doc, text)) = found else {
        return Err(NOT_FOUND.into());
    };
    let mut m = doc_json(&doc);
    m.insert("mime".into(), json!(doc.mime));
    m.insert("size".into(), json!(doc.size));
    m.insert("text_status".into(), json!(doc.text_status.as_str()));
    if let Some(text) = text {
        let truncated = text.chars().count() > TEXT_MAX_CHARS;
        let text: String = text.chars().take(TEXT_MAX_CHARS).collect();
        m.insert("text".into(), json!(text));
        m.insert("truncated".into(), json!(truncated));
    }
    Ok(Value::Object(m))
}

async fn list_tag_names(p: &Principal) -> Result<Value, String> {
    let f = p.filter();
    let tags = blocking(&p.unlocked, move |c| list_tags_visible(c, &f)).await?;
    Ok(Value::Array(
        tags.into_iter().map(|(_, n)| Value::String(n)).collect(),
    ))
}

async fn upload_document(state: &AppState, p: &Principal, a: UploadArgs) -> Result<Value, String> {
    let max = state.cfg.max_upload_bytes;
    // Reject oversized input before decoding it.
    if a.content_base64.len() as u64 > max.saturating_mul(4) / 3 + 8 {
        return Err("upload too large".into());
    }
    let bytes = BASE64
        .decode(a.content_base64.trim().as_bytes())
        .map_err(|_| "content_base64 is not valid base64".to_owned())?;
    if bytes.len() as u64 > max {
        return Err("upload too large".into());
    }
    let filename = a.filename.trim().to_owned();
    if filename.is_empty() {
        return Err("filename must not be empty".into());
    }
    let (p2, tags) = (p.clone(), a.tags);
    let tags = blocking(&p.unlocked, move |c| p2.tags_for_upload(c, tags))
        .await
        .map_err(|_| "token has no usable tag".to_owned())?;
    let meta = UploadMeta {
        filename,
        mime: None,
        title: clean(a.title),
        tags,
        document_date: clean(a.date),
    };
    let filter = p.filter();
    let body = stream::once(std::future::ready(Ok::<_, anyhow::Error>(Bytes::from(
        bytes,
    ))));
    match state
        .docs
        .store(
            &p.unlocked,
            meta,
            Box::pin(body),
            OnDuplicate::Skip,
            Some(&filter),
            now(),
        )
        .await
    {
        Ok(outcome) => serde_json::to_value(outcome).map_err(internal),
        Err(e) => Err(doc_err(e)),
    }
}

fn doc_err(e: DocError) -> String {
    match e {
        DocError::TooLarge => "upload too large".into(),
        DocError::NotFound => NOT_FOUND.into(),
        DocError::InvalidDate => "invalid date (use YYYY-MM-DD)".into(),
        DocError::Internal(e) => internal(e),
    }
}

async fn update_document(state: &AppState, p: &Principal, a: UpdateArgs) -> Result<Value, String> {
    let (p2, id) = (p.clone(), a.id.clone());
    let new_tags = a.tags.clone();
    // Visibility and the tag rule are checked against the same snapshot.
    let verdict = blocking(&p.unlocked, move |c| {
        if visible_doc(c, &p2, &id)?.is_none() {
            return Ok(Err(NOT_FOUND.to_owned()));
        }
        if let (Some(tags), Some(allowed)) = (&new_tags, p2.allowed_tag_names(c)?)
            && !tags.iter().any(|t| allowed.iter().any(|x| x == t.trim()))
        {
            return Ok(Err("tags must include an allowed tag".to_owned()));
        }
        Ok(Ok(()))
    })
    .await?;
    verdict?;
    let date = a
        .date
        .as_deref()
        .map(str::trim)
        .map(|d| (!d.is_empty()).then_some(d));
    state
        .docs
        .update(
            &p.unlocked,
            &a.id,
            a.title.as_deref(),
            date,
            a.tags.as_deref(),
            now(),
        )
        .map_err(doc_err)?;
    Ok(json!({"id": a.id, "updated": true}))
}
