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
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::documents::{DocError, OnDuplicate, UploadMeta, validate_meta};
use crate::keyring::Unlocked;
use crate::tokens::{Principal, authenticate, parse_bearer};
use crate::user_db::{
    Document, Level, effective_level, get_document, get_document_text, list_documents,
    list_tags_visible, search, update_document_meta,
};
use crate::web::AppState;
use crate::web::ratelimit::{client_ip, mcp_ip_key, too_many_requests};

const SERVER_NAME: &str = "personal-media";
const LATEST_PROTOCOL: &str = "2025-11-25";
/// Newest first. `2025-03-26` is left out on purpose: it requires servers to
/// accept JSON-RPC batches, which this endpoint does not.
const SUPPORTED_PROTOCOLS: &[&str] = &["2025-11-25", "2025-06-18", "2024-11-05"];
/// Longest document text returned by `get_document`, in characters.
const TEXT_MAX_CHARS: usize = 100_000;
/// Room for the JSON envelope and the other fields around the base64 payload.
const BODY_SLACK: usize = 1024 * 1024;

pub fn routes(state: &AppState) -> Router<AppState> {
    // base64 inflates by 4/3: ceil(max * 4 / 3) + 1 MiB.
    let limit = (state.cfg.max_upload_bytes as usize)
        .saturating_mul(4)
        .div_ceil(3)
        .saturating_add(BODY_SLACK);
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
/// (`mcp-ip:{ip}`). Only failures of a well-formed `pm_` token count (a
/// missing or malformed header says nothing about guessing), nothing is
/// reserved while a request is in flight, and a successful authentication
/// clears the address's failures. Every failure is a `401` with an empty
/// body; a locked IP gets `429`.
#[allow(clippy::result_large_err)] // the error is a ready `Response`
pub async fn bearer_principal(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<Principal, Response> {
    let ip = client_ip(peer, headers, state.cfg.trusted_proxy);
    let keys = [mcp_ip_key(ip)];
    state.limiter.check(&keys).map_err(too_many_requests)?;
    let Some(token) = bearer_token(headers).map(str::to_owned) else {
        return Err(unauthorized());
    };
    let well_formed = parse_bearer(&token).is_some();
    let st = state.clone();
    match tokio::task::spawn_blocking(move || authenticate(&st, &token)).await {
        Ok(Ok(p)) => {
            state.limiter.clear(&keys);
            Ok(p)
        }
        _ => {
            if well_formed {
                state.limiter.record_failure(&keys);
            }
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

/// The JSON-RPC envelope. `params` stays raw so that tool arguments are not
/// materialised (or deserialised) until the call has been authorised.
#[derive(Deserialize)]
struct Envelope<'a> {
    method: Option<String>,
    #[serde(default, deserialize_with = "present")]
    id: Option<Value>,
    #[serde(borrow, default)]
    params: Option<&'a RawValue>,
}

/// `Some(value)` whenever the key exists, even when it is `null`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

#[derive(Deserialize)]
struct InitParams {
    #[serde(rename = "protocolVersion")]
    protocol_version: Option<String>,
}

#[derive(Deserialize)]
struct CallParams<'a> {
    name: Option<String>,
    #[serde(borrow, default)]
    arguments: Option<&'a RawValue>,
}

async fn rpc(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    body: Bytes,
) -> Response {
    let env: Envelope = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return match serde_json::from_slice::<Value>(&body) {
                // An object that is not a usable envelope: ignore it.
                Ok(Value::Object(_)) => StatusCode::ACCEPTED.into_response(),
                // Batches are not supported (see SUPPORTED_PROTOCOLS).
                Ok(_) => json_response(
                    StatusCode::BAD_REQUEST,
                    &rpc_error(Value::Null, -32600, "invalid request"),
                ),
                Err(_) => json_response(
                    StatusCode::BAD_REQUEST,
                    &rpc_error(Value::Null, -32700, "parse error"),
                ),
            };
        }
    };
    let Some(method) = env.method.as_deref() else {
        // A response or garbage from the client: acknowledge and ignore.
        return StatusCode::ACCEPTED.into_response();
    };
    let Some(id) = env.id else {
        // Notification (e.g. notifications/initialized).
        return StatusCode::ACCEPTED.into_response();
    };
    let reply = match method {
        "initialize" => {
            let wanted = env
                .params
                .and_then(|p| serde_json::from_str::<InitParams>(p.get()).ok())
                .and_then(|p| p.protocol_version);
            let version = wanted
                .as_deref()
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
        "tools/list" => rpc_result(
            id,
            json!({"tools": tool_definitions(principal.can_write(), principal.cap() == Level::Full)}),
        ),
        "tools/call" => {
            let params = env
                .params
                .and_then(|p| serde_json::from_str::<CallParams>(p.get()).ok());
            let Some(name) = params.as_ref().and_then(|p| p.name.as_deref()) else {
                return json_response(StatusCode::OK, &rpc_error(id, -32602, "missing tool name"));
            };
            if !TOOL_NAMES.contains(&name) {
                return json_response(StatusCode::OK, &rpc_error(id, -32602, "unknown tool"));
            }
            // Write tools are refused for read-only tokens before the
            // arguments are looked at.
            let outcome = if WRITE_TOOLS.contains(&name) && !principal.can_write() {
                Err(ToolError::Tool(READ_ONLY.into()))
            } else {
                let args = params.as_ref().and_then(|p| p.arguments);
                call_tool(&state, &principal, name, args).await
            };
            tracing::info!(tool = name, ok = outcome.is_ok(), "mcp tool call");
            match outcome {
                Err(ToolError::Params(msg)) => rpc_error(id, -32602, msg),
                other => rpc_result(
                    id,
                    tool_result(other.map_err(|e| match e {
                        ToolError::Tool(m) => m,
                        ToolError::Params(m) => m.to_owned(),
                    })),
                ),
            }
        }
        _ => rpc_error(id, -32601, "method not found"),
    };
    json_response(StatusCode::OK, &reply)
}

/// A failed tool call: either a tool-level error (`isError`) or a JSON-RPC
/// invalid-params error.
enum ToolError {
    Tool(String),
    Params(&'static str),
}

impl From<String> for ToolError {
    fn from(m: String) -> Self {
        ToolError::Tool(m)
    }
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

const WRITE_TOOLS: &[&str] = &["upload_document", "update_document"];

const TOOL_NAMES: &[&str] = &[
    "search_documents",
    "list_documents",
    "get_document",
    "list_tags",
    "upload_document",
    "update_document",
    "semantic_search",
];

/// The tool list; write tools only for tokens that may write, semantic search
/// only for full-text tokens.
fn tool_definitions(can_write: bool, full_text: bool) -> Value {
    let tags = json!({"type": "array", "items": {"type": "string"}});
    let date = json!({"type": "string", "description": "YYYY-MM-DD"});
    let all = json!([
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
            "name": "semantic_search",
            "description": "Meaning-based search over document passages (full_text tokens only). Returns the best passage per document. An empty result can also mean that the semantic index is still being built or that the matching documents are not indexed.",
            "inputSchema": {"type": "object", "properties": {
                "query": {"type": "string", "maxLength": 1000},
                "tags": tags, "date_from": date, "date_to": date,
                "limit": {"type": "integer", "minimum": 1, "maximum": 20}
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
    ]);
    let Value::Array(mut all) = all else {
        unreachable!("tool list is an array")
    };
    if !can_write {
        all.retain(|t| !t["name"].as_str().is_some_and(|n| WRITE_TOOLS.contains(&n)));
    }
    if !full_text {
        all.retain(|t| t["name"] != "semantic_search");
    }
    Value::Array(all)
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

fn parse<T: serde::de::DeserializeOwned>(args: Option<&RawValue>) -> Result<T, String> {
    serde_json::from_str(args.map_or("{}", RawValue::get))
        .map_err(|_| "invalid arguments".to_owned())
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
    args: Option<&RawValue>,
) -> Result<Value, ToolError> {
    match name {
        "search_documents" => Ok(search_documents(p, parse(args)?).await?),
        "list_documents" => Ok(list_docs(p, parse(args)?).await?),
        "get_document" => Ok(get_doc(p, parse(args)?).await?),
        "list_tags" => Ok(list_tag_names(p).await?),
        "semantic_search" => semantic_search(state, p, parse(args)?).await,
        "upload_document" => upload_document(state, p, parse(args)?).await,
        "update_document" => update_document(p, parse(args)?).await,
        _ => Err(ToolError::Tool("unknown tool".into())),
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

/// Drop tag names outside the token's allow-list from `docs` (no-op for an
/// unrestricted token).
fn restrict_tags(p: &Principal, c: &Connection, docs: &mut [Document]) -> anyhow::Result<()> {
    if let Some(allowed) = p.allowed_tag_names(c)? {
        for d in docs {
            d.tags.retain(|t| allowed.contains(t));
        }
    }
    Ok(())
}

/// A restricted token filtering on a tag outside its allow-list sees nothing,
/// exactly as if the tag did not exist.
fn tags_filter_allowed(p: &Principal, c: &Connection, tags: &[String]) -> anyhow::Result<bool> {
    Ok(match p.allowed_tag_names(c)? {
        Some(allowed) => tags.iter().all(|t| allowed.contains(t)),
        None => true,
    })
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
    let p2 = p.clone();
    let hits = blocking(&p.unlocked, move |c| {
        if !tags_filter_allowed(&p2, c, &f.tags_all)? {
            return Ok(vec![]);
        }
        let mut hits = search(c, &query, &f)?;
        let mut docs: Vec<Document> = hits.iter().map(|h| h.doc.clone()).collect();
        restrict_tags(&p2, c, &mut docs)?;
        for (h, d) in hits.iter_mut().zip(docs) {
            h.doc = d;
        }
        Ok(hits)
    })
    .await?;
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

/// Longest passage returned by `semantic_search`, in characters.
const PASSAGE_MAX_CHARS: usize = 1200;
const QUERY_MAX_CHARS: usize = 1000;
const NO_INDEX: &str = "semantic index not available yet";

#[derive(Deserialize)]
struct SemanticArgs {
    query: String,
    #[serde(default)]
    tags: Vec<String>,
    date_from: Option<String>,
    date_to: Option<String>,
    limit: Option<u32>,
}

async fn semantic_search(
    state: &AppState,
    p: &Principal,
    a: SemanticArgs,
) -> Result<Value, ToolError> {
    // Metadata-only tokens never reach the vector code.
    if p.cap() != Level::Full {
        return Err(ToolError::Tool("token cannot use semantic search".into()));
    }
    // Tool errors (isError) rather than protocol errors: the model can read
    // them and correct itself.
    if a.query.chars().count() > QUERY_MAX_CHARS {
        return Err(ToolError::Tool(format!(
            "query too long (at most {QUERY_MAX_CHARS} characters)"
        )));
    }
    if a.query.trim().is_empty() {
        return Err(ToolError::Tool("query must not be empty".into()));
    }
    // Never download the model on a query.
    let engine = state.engine.clone();
    let probe = engine.clone();
    match tokio::task::spawn_blocking(move || probe.is_available()).await {
        Ok(true) => {}
        Ok(false) => return Err(ToolError::Tool(NO_INDEX.into())),
        Err(e) => return Err(ToolError::Tool(internal(e))),
    }
    let mut f = p.filter();
    f.tags_all = a.tags;
    f.date_from = clean(a.date_from);
    f.date_to = clean(a.date_to);
    let limit = a.limit.unwrap_or(8).clamp(1, 20) as usize;
    // Nothing visible (or a filter on a foreign tag): answer without loading
    // the model. This reveals nothing the caller cannot see anyway.
    let (p1, f1) = (p.clone(), f.clone());
    let any = blocking(&p.unlocked, move |c| {
        Ok(tags_filter_allowed(&p1, c, &f1.tags_all)?
            && crate::user_db::vectors::has_candidates(c, &f1)?)
    })
    .await
    .map_err(ToolError::Tool)?;
    if !any {
        return Ok(Value::Array(vec![]));
    }
    let query = a.query;
    let qv = match tokio::task::spawn_blocking(move || engine.embed_query(&query)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "semantic query embedding failed");
            return Err(ToolError::Tool(NO_INDEX.into()));
        }
        Err(e) => return Err(ToolError::Tool(internal(e))),
    };
    let p2 = p.clone();
    let hits = blocking(&p.unlocked, move |c| {
        if !tags_filter_allowed(&p2, c, &f.tags_all)? {
            return Ok(vec![]);
        }
        let hits = crate::user_db::vectors::search(c, &qv, &f, limit)?;
        let mut out = Vec::with_capacity(hits.len());
        for (doc, score, chunk) in hits {
            let text = get_document_text(c, &doc.id)?.unwrap_or_default();
            let mut docs = [doc];
            restrict_tags(&p2, c, &mut docs)?;
            let [doc] = docs;
            out.push((
                doc,
                score,
                crate::user_db::vectors::passage(&text, chunk.start, chunk.end, PASSAGE_MAX_CHARS),
            ));
        }
        Ok(out)
    })
    .await
    .map_err(ToolError::Tool)?;
    Ok(Value::Array(
        hits.into_iter()
            .map(|(doc, score, passage)| {
                let mut m = doc_json(&doc);
                m.insert(
                    "score".into(),
                    json!((f64::from(score) * 1000.0).round() / 1000.0),
                );
                m.insert("passage".into(), json!(passage));
                Value::Object(m)
            })
            .collect(),
    ))
}

async fn list_docs(p: &Principal, a: ListArgs) -> Result<Value, String> {
    let mut f = p.filter();
    f.tags_all = a.tags;
    f.date_from = clean(a.date_from);
    f.date_to = clean(a.date_to);
    f.limit = a.limit.unwrap_or(50).clamp(1, 100);
    f.offset = a.offset.unwrap_or(0);
    let p2 = p.clone();
    let docs = blocking(&p.unlocked, move |c| {
        if !tags_filter_allowed(&p2, c, &f.tags_all)? {
            return Ok(vec![]);
        }
        let mut docs = list_documents(c, &f)?;
        restrict_tags(&p2, c, &mut docs)?;
        Ok(docs)
    })
    .await?;
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
        let Some((mut doc, level)) = visible_doc(c, &p2, &a.id)? else {
            return Ok(None);
        };
        restrict_tags(&p2, c, std::slice::from_mut(&mut doc))?;
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

async fn upload_document(
    state: &AppState,
    p: &Principal,
    a: UploadArgs,
) -> Result<Value, ToolError> {
    let max = state.cfg.max_upload_bytes;
    // Reject oversized input before decoding it.
    if a.content_base64.len() as u64 > max.saturating_mul(4) / 3 + 8 {
        return Err("upload too large".to_owned().into());
    }
    let filename = a.filename.trim().to_owned();
    if filename.is_empty() {
        return Err("filename must not be empty".to_owned().into());
    }
    validate_meta(a.title.as_deref(), Some(&filename), &a.tags).map_err(invalid_input)?;
    // At most a couple of uploads hold the base64 text and the decoded bytes
    // in memory at once.
    let _permit = state.mcp_write_permits.acquire().await.map_err(internal)?;
    let bytes = BASE64
        .decode(a.content_base64.trim().as_bytes())
        .map_err(|_| "content_base64 is not valid base64".to_owned())?;
    drop(a.content_base64);
    if bytes.len() as u64 > max {
        return Err("upload too large".to_owned().into());
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
    let size = bytes.len() as u64;
    let body = stream::once(std::future::ready(Ok::<_, anyhow::Error>(Bytes::from(
        bytes,
    ))));
    match state
        .docs
        .store_sized(
            &p.unlocked,
            meta,
            Box::pin(body),
            OnDuplicate::Skip,
            Some(&filter),
            now(),
            Some(size),
        )
        .await
    {
        Ok(outcome) => serde_json::to_value(outcome).map_err(|e| ToolError::Tool(internal(e))),
        Err(e) => Err(doc_err(e)),
    }
}

fn invalid_input(e: DocError) -> ToolError {
    match e {
        DocError::InvalidInput(msg) => ToolError::Params(msg),
        other => doc_err(other),
    }
}

fn doc_err(e: DocError) -> ToolError {
    ToolError::Tool(match e {
        DocError::TooLarge => "upload too large".into(),
        e @ DocError::QuotaExceeded { .. } => e.to_string(),
        DocError::NotFound => NOT_FOUND.into(),
        DocError::InvalidDate => "invalid date (use YYYY-MM-DD)".into(),
        DocError::InvalidInput(msg) => return ToolError::Params(msg),
        DocError::Internal(e) => internal(e),
    })
}

async fn update_document(p: &Principal, a: UpdateArgs) -> Result<Value, ToolError> {
    let p2 = p.clone();
    let id = a.id.clone();
    let date = a.date.map(|d| d.trim().to_owned());
    // Visibility, the tag rule and the write happen on one connection lock,
    // inside one blocking task.
    let verdict = blocking(&p.unlocked, move |c| {
        let Some((doc, _)) = visible_doc(c, &p2, &id)? else {
            return Ok(Err(ToolError::Tool(NOT_FOUND.to_owned())));
        };
        if let Err(e) = validate_meta(a.title.as_deref(), None, a.tags.as_deref().unwrap_or(&[])) {
            return Ok(Err(invalid_input(e)));
        }
        let mut tags = a.tags;
        if let (Some(tags), Some(allowed)) = (tags.as_mut(), p2.allowed_tag_names(c)?) {
            if !tags.iter().any(|t| allowed.iter().any(|x| x == t.trim())) {
                return Ok(Err(ToolError::Tool(
                    "tags must include an allowed tag".to_owned(),
                )));
            }
            // Tags the token cannot see stay on the document.
            for hidden in doc.tags.iter().filter(|t| !allowed.contains(t)) {
                if !tags.iter().any(|t| t.trim() == hidden) {
                    tags.push(hidden.clone());
                }
            }
        }
        let date = date.as_deref().map(|d| (!d.is_empty()).then_some(d));
        if let Some(Some(d)) = date
            && let Err(e) = crate::documents::validate_date(d)
        {
            return Ok(Err(doc_err(e)));
        }
        update_document_meta(c, &id, a.title.as_deref(), date, tags.as_deref(), now())?;
        Ok(Ok(()))
    })
    .await
    .map_err(ToolError::Tool)?;
    verdict?;
    Ok(json!({"id": a.id, "updated": true}))
}
