//! Documents UI and upload API: list/search, upload, detail, raw/download,
//! edit, delete, retry extraction and the per-document access switchboard.
//!
//! Switchboard rule (Ruling G): every web read goes through
//! [`web_filter`] (`channel = Web`, `cap = Full`). A document whose effective
//! web level is `Off` is hidden: absent from list and search, and its detail,
//! raw and download pages are 404. At `Metadata` only the metadata and the
//! switchboard form are shown. Edit, delete and retry work at `Metadata` too
//! (they reveal no content); preview, raw and download need `Full`.
//! `POST /documents/{id}/access` is exempt so the owner can always change it.

#![allow(clippy::result_large_err)] // helpers return a ready `Response` as the error

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::Router;
use axum::body::Body;
use axum::extract::{
    ConnectInfo, DefaultBodyLimit, FromRequest, FromRequestParts, Multipart, Path, Query, Request,
    State,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use serde::Deserialize;

use super::session::{AuthRejection, CsrfForm, CurrentUser, NoFields};
use super::{AppState, CspOverride, Page, is_htmx, render};
use crate::documents::{DocError, OnDuplicate, UploadMeta, validate_meta};
use crate::keyring::Unlocked;
use crate::user_db::documents::get_document_text;
use crate::user_db::vectors::embed_status_words;
use crate::user_db::vectors::{has_candidates, passage, search as vectors_search};
use crate::user_db::{
    AccessFilter, Channel, Document, Level, ListFilter, TextStatus, document_overrides,
    effective_level, get_access_defaults, get_document, list_documents, list_tags_visible, search,
    set_document_access,
};

const PAGE_SIZE: u32 = 50;
const CHUNK: usize = 64 * 1024;
/// Slack on top of `max_upload_bytes` for the multipart framing and text fields.
const BODY_SLACK: usize = 1024 * 1024;

/// MIME types served inline by `/raw`. Everything else (HTML, SVG, ...) is
/// only ever offered as a download.
const INLINE_MIMES: &[&str] = &[
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
];

/// CSP for `/raw`. `style-src 'unsafe-inline'` is needed by the browsers'
/// built-in PDF viewers; `object-src 'self'` and `frame-ancestors 'self'`
/// let our own page embed the response.
const RAW_CSP: &str = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; \
                       object-src 'self'; frame-ancestors 'self'";

pub fn routes(state: &AppState) -> Router<AppState> {
    let limit = state.cfg.max_upload_bytes as usize + BODY_SLACK;
    Router::new()
        .route("/documents", get(list_page))
        .route("/documents/{id}", get(detail_page).post(edit))
        .route("/documents/{id}/raw", get(raw))
        .route("/documents/{id}/download", get(download))
        .route("/documents/{id}/delete", post(delete))
        .route("/documents/{id}/retry", post(retry))
        .route("/documents/{id}/access", post(set_access))
        .route(
            "/api/upload",
            post(upload).layer(DefaultBodyLimit::max(limit)),
        )
}

pub(super) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The owner's web view: switchboard channel `Web`, capped at `Full`.
pub fn web_filter() -> ListFilter {
    ListFilter {
        access: Some(AccessFilter {
            channel: Channel::Web,
            cap: Level::Full,
        }),
        ..ListFilter::default()
    }
}

fn web_level(conn: &rusqlite::Connection, id: &str) -> anyhow::Result<Level> {
    effective_level(conn, id, Channel::Web, Level::Full)
}

fn err(status: StatusCode, msg: &'static str) -> Response {
    (status, msg).into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "documents request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn doc_error(e: DocError) -> Response {
    match e {
        DocError::TooLarge => json_error(StatusCode::PAYLOAD_TOO_LARGE, "upload too large"),
        e @ DocError::QuotaExceeded { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            axum::Json(serde_json::json!({
                "status": "quota_exceeded",
                "message": e.to_string(),
            })),
        )
            .into_response(),
        DocError::NotFound => StatusCode::NOT_FOUND.into_response(),
        DocError::InvalidDate => json_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid date"),
        DocError::InvalidInput(msg) => json_error(StatusCode::UNPROCESSABLE_ENTITY, msg),
        DocError::Internal(e) => internal(e),
    }
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

/// Runs index DB work off the async threads.
async fn db<T: Send + 'static>(
    u: &Arc<Unlocked>,
    f: impl FnOnce(&rusqlite::Connection) -> T + Send + 'static,
) -> Result<T, Response> {
    let u = u.clone();
    tokio::task::spawn_blocking(move || u.with_db(f))
        .await
        .map_err(internal)
}

/// The document if it exists and its web level is at least `min`; the level too.
/// `None` is a 404 for the caller (missing, hidden or not high enough).
async fn visible(
    u: &Arc<Unlocked>,
    id: &str,
    min: Level,
) -> Result<Option<(Document, Level)>, Response> {
    let id = id.to_owned();
    let found = db(u, move |c| -> anyhow::Result<Option<(Document, Level)>> {
        let Some(doc) = get_document(c, &id)? else {
            return Ok(None);
        };
        let level = web_level(c, &id)?;
        Ok((level >= min && level > Level::Off).then_some((doc, level)))
    })
    .await?
    .map_err(internal)?;
    Ok(found)
}

fn redirect_to(headers: &HeaderMap, to: &str) -> Response {
    let Ok(to) = HeaderValue::from_str(to) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if is_htmx(headers) {
        (StatusCode::OK, [("hx-redirect", to)]).into_response()
    } else {
        (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response()
    }
}

// ---------------------------------------------------------------------------
// Content-Disposition
// ---------------------------------------------------------------------------

const FALLBACK_MAX: usize = 150;

/// ASCII-only stand-in for a file name: non-ASCII, control characters, `"`,
/// `\` and `/` become `_`; at most 150 characters, keeping the extension.
fn ascii_fallback(filename: &str) -> String {
    let mut s: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() && !matches!(c, '"' | '\\' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.len() > FALLBACK_MAX {
        let ext_len = s
            .rfind('.')
            .map(|i| s.len() - i)
            .filter(|n| *n <= 20)
            .unwrap_or(0);
        let ext = s[s.len() - ext_len..].to_owned();
        s.truncate(FALLBACK_MAX - ext_len);
        s.push_str(&ext);
    }
    if s.is_empty() {
        s.push_str("download");
    }
    s
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `kind` (`attachment` or `inline`) with a quoted ASCII `filename` and an
/// RFC 8187 `filename*` carrying the real name. Never contains CR or LF.
pub fn content_disposition(kind: &str, filename: &str) -> HeaderValue {
    let value = format!(
        "{kind}; filename=\"{}\"; filename*=UTF-8''{}",
        ascii_fallback(filename),
        percent_encode(filename)
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

pub(super) fn parse_tags(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Longest text field accepted before the file. Text fields are buffered in
/// memory, so they are capped far below the upload limit.
pub(super) const TEXT_FIELD_MAX: usize = 8 * 1024;

pub(super) async fn read_text_field(
    mut field: axum::extract::multipart::Field<'_>,
) -> Result<String, Response> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > TEXT_FIELD_MAX {
                    return Err(json_error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "form field too large",
                    ));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "malformed multipart body",
                ));
            }
        }
    }
    String::from_utf8(buf)
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "malformed multipart body"))
}

async fn upload(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let user = CurrentUser::from_request_parts(&mut parts, &state).await;
    let has_bearer = parts.headers.contains_key(header::AUTHORIZATION);
    // Auth runs before the body is looked at.
    let (unlocked, principal) = match user {
        Ok(CurrentUser(session)) => (session.unlocked.clone(), None),
        Err(AuthRejection::Login { .. }) if has_bearer => {
            match crate::mcp::bearer_principal(&state, peer, &parts.headers).await {
                Ok(p) => (p.unlocked.clone(), Some(p)),
                Err(resp) => return resp,
            }
        }
        Err(e) => return e.into_response(),
    };
    // The request length bounds the file; it is what the quota reserves.
    let size_hint = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    // Answer a quota refusal before the body is read: a browser that is still
    // sending gets the message instead of a connection reset.
    if let Some(n) = size_hint
        && let Err(e) = state.quotas.check_room(&unlocked.user_id, n).await
    {
        return doc_error(DocError::QuotaExceeded {
            used: e.used,
            limit: e.limit,
        });
    }
    let multipart = match Multipart::from_request(Request::from_parts(parts, body), &state).await {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    match principal {
        None => handle_upload(&state, unlocked, multipart, size_hint).await,
        Some(p) => {
            if !p.can_write() {
                return json_error(StatusCode::FORBIDDEN, "token is read-only");
            }
            handle_upload_inner(&state, unlocked, multipart, Some(&p), size_hint).await
        }
    }
}

/// Stores one uploaded file for `unlocked` and answers with the JSON
/// `StoreOutcome` (`stored` or `duplicate`); `TooLarge` is 413, `InvalidDate`
/// 422. The caller authenticates; this does no auth or CSRF checks.
///
/// The text fields `title`, `tags`, `date` and `on_duplicate` must come
/// **before** the `file` field: the file is streamed into the encrypted
/// store without buffering, so everything after it is never read. A request
/// without a `file` field is a 400.
pub async fn handle_upload(
    state: &AppState,
    unlocked: Arc<Unlocked>,
    multipart: Multipart,
    size_hint: Option<u64>,
) -> Response {
    handle_upload_inner(state, unlocked, multipart, None, size_hint).await
}

/// With a `principal` (bearer upload): duplicate detection only sees what the
/// token may see, and the tags are forced to include an allowed one.
async fn handle_upload_inner(
    state: &AppState,
    unlocked: Arc<Unlocked>,
    mut multipart: Multipart,
    principal: Option<&crate::tokens::Principal>,
    size_hint: Option<u64>,
) -> Response {
    let (mut title, mut tags, mut date, mut on_dup) = (None, Vec::new(), None, OnDuplicate::Skip);
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => return json_error(StatusCode::BAD_REQUEST, "missing file field"),
            Err(_) => return json_error(StatusCode::BAD_REQUEST, "malformed multipart body"),
        };
        let name = field.name().unwrap_or_default().to_owned();
        if name == "file" {
            let filename = field
                .file_name()
                .filter(|f| !f.is_empty())
                .unwrap_or("upload")
                .to_owned();
            if let Err(e) = validate_meta(title.as_deref(), Some(&filename), &tags) {
                return doc_error(e);
            }
            let tags = match principal {
                Some(p) => {
                    let (p, given) = (p.clone(), std::mem::take(&mut tags));
                    match db(&unlocked, move |c| p.tags_for_upload(c, given)).await {
                        Ok(Ok(t)) => t,
                        Ok(Err(_)) => {
                            return json_error(StatusCode::FORBIDDEN, "token has no usable tag");
                        }
                        Err(r) => return r,
                    }
                }
                None => std::mem::take(&mut tags),
            };
            let meta = UploadMeta {
                filename,
                mime: field.content_type().map(str::to_owned),
                title: title.take(),
                tags,
                document_date: date.take(),
            };
            let filter = principal.map_or_else(web_filter, |p| p.filter());
            // A body error while the file streams in means the client went away.
            let client_gone = Arc::new(AtomicBool::new(false));
            let flag = client_gone.clone();
            let body =
                field.map(move |chunk| chunk.inspect_err(|_| flag.store(true, Ordering::Relaxed)));
            return match state
                .docs
                .store_sized(
                    &unlocked,
                    meta,
                    Box::pin(body),
                    on_dup,
                    Some(&filter),
                    now(),
                    size_hint,
                )
                .await
            {
                Ok(outcome) => axum::Json(outcome).into_response(),
                Err(DocError::Internal(_)) if client_gone.load(Ordering::Relaxed) => {
                    tracing::info!("upload aborted by the client");
                    json_error(StatusCode::BAD_REQUEST, "upload aborted")
                }
                Err(e) => doc_error(e),
            };
        }
        let value = match read_text_field(field).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        match name.as_str() {
            "title" => title = Some(value).filter(|v| !v.trim().is_empty()),
            "tags" => tags = parse_tags(&value),
            "date" => date = Some(value.trim().to_owned()).filter(|v| !v.is_empty()),
            "on_duplicate" => {
                on_dup = match value.as_str() {
                    "skip" | "" => OnDuplicate::Skip,
                    "keep" => OnDuplicate::Keep,
                    _ => return json_error(StatusCode::BAD_REQUEST, "bad on_duplicate"),
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// List and search
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct ListQuery {
    q: Option<String>,
    tag: Option<String>,
    from: Option<String>,
    to: Option<String>,
    page: Option<String>,
    /// `words` (default) or `meaning`.
    mode: Option<String>,
}

fn non_empty(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// HTML-escape first, then turn the FTS markers into `<mark>`. The result is
/// safe to render with `|safe`.
fn snippet_html(s: &str) -> String {
    escape_html(s)
        .replace('\u{2}', "<mark>")
        .replace('\u{3}', "</mark>")
}

pub(super) fn format_date(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts)
        .map(|d| d.date().to_string())
        .unwrap_or_default()
}

pub(super) fn human_size(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

struct Row {
    id: String,
    title: String,
    date: Option<String>,
    tags: Vec<String>,
    /// Already HTML-escaped, with `<mark>` tags.
    snippet: Option<String>,
    metadata_only: bool,
    /// Search by meaning only: the relative match, 0-100.
    match_pct: Option<u32>,
}

struct ResultsView {
    /// Replaces the list (search by meaning: model missing, nothing indexed).
    notice: Option<&'static str>,
    rows: Vec<Row>,
    searching: bool,
    page_no: u32,
    prev_url: Option<String>,
    next_url: Option<String>,
}

#[derive(Template)]
#[template(path = "_results.html")]
struct ResultsPartial {
    results: ResultsView,
}

#[derive(Template)]
#[template(path = "documents.html")]
struct DocumentsPage {
    page: Page,
    results: ResultsView,
    tags: Vec<String>,
    q: String,
    tag: String,
    from: String,
    to: String,
    meaning: bool,
}

const MEANING_NO_MODEL: &str = "Search by meaning isn't available yet. Turn on the semantic index in Settings → Access defaults (or per document); the model downloads on first indexing.";
const MEANING_NO_INDEX: &str = "No documents are indexed for meaning search yet.";
const MEANING_NO_MATCH: &str = "No matches for these filters.";
const MEANING_BUSY: &str = "A search by meaning is already running. Try again in a moment.";
/// Documents shown for a meaning query (no paging: every document has a score).
const MEANING_LIMIT: usize = 20;
/// Longest query embedded, in characters (as for the MCP tool).
const MEANING_QUERY_MAX: usize = 1000;
/// Longest passage shown, in characters.
const MEANING_PASSAGE_MAX: usize = 300;

/// A cosine score as a percentage. e5 scores are compressed (roughly
/// 0.75-0.92 for related text), so this is only a relative indicator of how
/// well results rank against each other, not a probability. Not rescaled.
fn match_pct(score: f32) -> u32 {
    (score * 100.0).round().clamp(0.0, 100.0) as u32
}

fn page_url(q: &ListQuery, page: u32) -> String {
    let mut pairs: Vec<(&str, String)> = Vec::new();
    for (k, v) in [
        ("q", &q.q),
        ("tag", &q.tag),
        ("from", &q.from),
        ("to", &q.to),
    ] {
        if let Some(v) = non_empty(v) {
            pairs.push((k, v));
        }
    }
    pairs.push(("page", page.to_string()));
    format!(
        "/documents?{}",
        serde_urlencoded::to_string(&pairs).unwrap_or_default()
    )
}

/// Search by meaning: the results (or a notice) for `text`, never paged.
async fn meaning_results(
    state: &AppState,
    session: &super::session::Session,
    mut filter: ListFilter,
    text: String,
) -> Result<ResultsView, Response> {
    let mut results = ResultsView {
        notice: None,
        rows: vec![],
        searching: true,
        page_no: 1,
        prev_url: None,
        next_url: None,
    };
    // Never download the model on a query.
    let engine = state.engine.clone();
    let probe = engine.clone();
    let available = tokio::task::spawn_blocking(move || probe.is_available())
        .await
        .map_err(internal)?;
    if !available {
        results.notice = Some(MEANING_NO_MODEL);
        return Ok(results);
    }
    filter.limit = 0;
    filter.offset = 0;
    // With a tag or date filter, "nothing indexed" would mislead.
    let filtered =
        !filter.tags_all.is_empty() || filter.date_from.is_some() || filter.date_to.is_some();
    // Nothing visible: answer without loading the model.
    let f1 = filter.clone();
    let any = db(&session.unlocked, move |c| has_candidates(c, &f1))
        .await?
        .map_err(internal)?;
    if !any {
        results.notice = Some(if filtered {
            MEANING_NO_MATCH
        } else {
            MEANING_NO_INDEX
        });
        return Ok(results);
    }
    let text: String = text.chars().take(MEANING_QUERY_MAX).collect();
    let qv = match tokio::task::spawn_blocking(move || engine.embed_query(&text))
        .await
        .map_err(internal)?
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "semantic query embedding failed");
            results.notice = Some(MEANING_NO_MODEL);
            return Ok(results);
        }
    };
    let rows = db(&session.unlocked, move |c| -> anyhow::Result<Vec<Row>> {
        let hits = vectors_search(c, &qv, &filter, MEANING_LIMIT)?;
        let mut rows = Vec::with_capacity(hits.len());
        for (doc, score, chunk) in hits {
            let text = get_document_text(c, &doc.id)?.unwrap_or_default();
            rows.push(Row {
                snippet: Some(escape_html(&passage(
                    &text,
                    chunk.start,
                    chunk.end,
                    MEANING_PASSAGE_MAX,
                ))),
                match_pct: Some(match_pct(score)),
                ..row_of(doc)
            });
        }
        Ok(rows)
    })
    .await?
    .map_err(internal)?;
    if rows.is_empty() {
        // Every document with vectors scores; none means nothing is indexed.
        results.notice = Some(if filtered {
            MEANING_NO_MATCH
        } else {
            MEANING_NO_INDEX
        });
    }
    results.rows = rows;
    Ok(results)
}

async fn list_page(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let page_no = query
        .page
        .as_deref()
        .and_then(|p| p.trim().parse::<u32>().ok())
        .filter(|p| *p >= 1)
        .unwrap_or(1)
        .min(100_000);
    let q = non_empty(&query.q);
    let mut filter = web_filter();
    filter.tags_all = non_empty(&query.tag).into_iter().collect();
    filter.date_from = non_empty(&query.from);
    filter.date_to = non_empty(&query.to);
    filter.limit = PAGE_SIZE + 1; // one extra row tells whether there is a next page
    filter.offset = (page_no - 1) * PAGE_SIZE;

    let tag_filter = web_filter();
    let meaning = q.is_some() && query.mode.as_deref() == Some("meaning");
    let mut meaning_view: Option<ResultsView> = None;
    if meaning {
        // One meaning query per session at a time.
        let Some(_slot) = state.sessions.try_begin_meaning(&session.id) else {
            let results = ResultsView {
                notice: Some(MEANING_BUSY),
                rows: vec![],
                searching: true,
                page_no: 1,
                prev_url: None,
                next_url: None,
            };
            let mut resp = render(&ResultsPartial { results });
            *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            return resp;
        };
        match meaning_results(
            &state,
            &session,
            filter.clone(),
            q.clone().unwrap_or_default(),
        )
        .await
        {
            Ok(v) => meaning_view = Some(v),
            Err(r) => return r,
        }
    }
    let search_text = if meaning { None } else { q.clone() };
    let loaded = db(&session.unlocked, move |c| {
        let rows: anyhow::Result<Vec<Row>> = match &search_text {
            Some(text) => search(c, text, &filter).map(|hits| {
                hits.into_iter()
                    .map(|h| Row {
                        metadata_only: h.level < Level::Full,
                        snippet: h.snippet.as_deref().map(snippet_html),
                        ..row_of(h.doc)
                    })
                    .collect()
            }),
            None if meaning => Ok(vec![]),
            None => list_documents(c, &filter).map(|d| d.into_iter().map(row_of).collect()),
        };
        let tags = list_tags_visible(c, &tag_filter);
        rows.and_then(|r| tags.map(|t| (r, t)))
    })
    .await;
    let (mut rows, tags) = match loaded {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return internal(e),
        Err(r) => return r,
    };
    let has_next = rows.len() > PAGE_SIZE as usize;
    rows.truncate(PAGE_SIZE as usize);
    let results = meaning_view.unwrap_or_else(|| ResultsView {
        notice: None,
        rows,
        searching: q.is_some(),
        page_no,
        prev_url: (page_no > 1).then(|| page_url(&query, page_no - 1)),
        next_url: has_next.then(|| page_url(&query, page_no + 1)),
    });
    let mut resp = if is_htmx(&headers) {
        render(&ResultsPartial { results })
    } else {
        render(&DocumentsPage {
            page: Page::for_session(&session),
            results,
            tags: tags.into_iter().map(|(_, n)| n).collect(),
            q: q.unwrap_or_default(),
            tag: non_empty(&query.tag).unwrap_or_default(),
            from: non_empty(&query.from).unwrap_or_default(),
            to: non_empty(&query.to).unwrap_or_default(),
            meaning: query.mode.as_deref() == Some("meaning"),
        })
    };
    resp.headers_mut()
        .insert(header::VARY, HeaderValue::from_static("HX-Request"));
    resp
}

fn row_of(d: Document) -> Row {
    Row {
        id: d.id,
        title: d.title,
        date: d.document_date,
        tags: d.tags,
        snippet: None,
        metadata_only: false,
        match_pct: None,
    }
}

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

struct Opt {
    value: &'static str,
    label: String,
    selected: bool,
}

struct SwitchRow {
    name: &'static str,
    label: &'static str,
    options: Vec<Opt>,
}

#[derive(Template)]
#[template(path = "document.html")]
struct DetailPage {
    page: Page,
    id: String,
    title: String,
    filename: String,
    mime: String,
    size: String,
    date: String,
    tags_csv: String,
    tags: Vec<String>,
    created: String,
    status: &'static str,
    can_retry: bool,
    /// Web level is `Full`: preview and download are shown. The edit and
    /// access forms do not depend on it.
    full: bool,
    preview_pdf: bool,
    preview_image: bool,
    switches: Vec<SwitchRow>,
    embed_status: &'static str,
}

fn mime_essence(mime: &str) -> String {
    mime.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn status_words(s: TextStatus) -> &'static str {
    match s {
        TextStatus::Pending => "Text extraction is in progress",
        TextStatus::Done => "Text extracted",
        TextStatus::Failed => "Text extraction failed",
        TextStatus::Unsupported => "Text extraction is not available for this file type",
    }
}

const CHANNELS: [(Channel, &str); 3] = [
    (Channel::Web, "Web"),
    (Channel::Mcp, "MCP (AI assistants)"),
    (Channel::SemanticIndex, "Semantic index"),
];

fn switch_rows(c: &rusqlite::Connection, id: &str) -> anyhow::Result<Vec<SwitchRow>> {
    let defaults = get_access_defaults(c)?;
    let overrides = document_overrides(c, id)?;
    Ok(CHANNELS
        .iter()
        .map(|(ch, label)| {
            let current = overrides.get(ch).copied();
            let mut options = vec![Opt {
                value: "default",
                label: format!("default ({})", defaults.level(*ch).as_str()),
                selected: current.is_none(),
            }];
            for l in [Level::Off, Level::Metadata, Level::Full] {
                options.push(Opt {
                    value: l.as_str(),
                    label: l.as_str().to_owned(),
                    selected: current == Some(l),
                });
            }
            SwitchRow {
                name: ch.as_str(),
                label,
                options,
            }
        })
        .collect())
}

async fn detail_page(CurrentUser(session): CurrentUser, Path(id): Path<String>) -> Response {
    let (doc, level) = match visible(&session.unlocked, &id, Level::Metadata).await {
        Ok(Some(v)) => v,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(r) => return r,
    };
    let doc_id = doc.id.clone();
    let (switches, embed_status) = match db(&session.unlocked, move |c| {
        Ok::<_, anyhow::Error>((switch_rows(c, &doc_id)?, embed_status_words(c, &doc_id)?))
    })
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return internal(e),
        Err(r) => return r,
    };
    let full = level == Level::Full;
    let essence = mime_essence(&doc.mime);
    render(&DetailPage {
        page: Page::for_session(&session),
        title: doc.title,
        filename: doc.original_filename,
        size: human_size(doc.size),
        date: doc.document_date.unwrap_or_default(),
        tags_csv: doc.tags.join(", "),
        tags: doc.tags,
        created: format_date(doc.created_at),
        status: status_words(doc.text_status),
        can_retry: doc.text_status == TextStatus::Failed,
        preview_pdf: full && essence == "application/pdf",
        preview_image: full
            && essence != "application/pdf"
            && INLINE_MIMES.contains(&essence.as_str()),
        mime: doc.mime,
        id: doc.id,
        full,
        switches,
        embed_status,
    })
}

// ---------------------------------------------------------------------------
// Raw and download
// ---------------------------------------------------------------------------

/// Streams the decrypted blob: a blocking task reads 64 KiB chunks into a
/// small bounded channel, so memory stays flat for big files.
fn stream_body(mut reader: impl std::io::Read + Send + 'static) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(4);
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .blocking_send(Ok(Bytes::copy_from_slice(&buf[..n])))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            }
        }
    });
    channel_body(rx)
}

/// A response body fed by a bounded channel (the other end is a blocking task).
pub(super) fn channel_body(rx: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>) -> Body {
    Body::from_stream(stream::unfold(rx, |mut rx| async {
        rx.recv().await.map(|item| (item, rx))
    }))
}

async fn open_blob(
    state: &AppState,
    u: &Arc<Unlocked>,
    id: &str,
) -> Result<(Document, Body), Response> {
    let (docs, u, id) = (state.docs.clone(), u.clone(), id.to_owned());
    let (doc, reader) = tokio::task::spawn_blocking(move || docs.open_plaintext(&u, &id))
        .await
        .map_err(internal)?
        .map_err(doc_error)?;
    let body = stream_body(reader);
    Ok((doc, body))
}

fn blob_response(
    doc: &Document,
    body: Body,
    content_type: HeaderValue,
    disposition: HeaderValue,
) -> Response {
    let mut resp = Response::new(body);
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, content_type);
    h.insert(header::CONTENT_DISPOSITION, disposition);
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(doc.size));
    resp
}

async fn raw(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
) -> Response {
    let (doc, _) = match visible(&session.unlocked, &id, Level::Full).await {
        Ok(Some(v)) => v,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(r) => return r,
    };
    let essence = mime_essence(&doc.mime);
    if !INLINE_MIMES.contains(&essence.as_str()) {
        return redirect_to(
            &HeaderMap::new(),
            &format!("/documents/{}/download", doc.id),
        );
    }
    let (doc, body) = match open_blob(&state, &session.unlocked, &id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(content_type) = HeaderValue::from_str(&essence) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut resp = blob_response(
        &doc,
        body,
        content_type,
        content_disposition("inline", &doc.original_filename),
    );
    resp.headers_mut().insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
    resp.extensions_mut().insert(CspOverride(RAW_CSP));
    resp
}

async fn download(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
) -> Response {
    match visible(&session.unlocked, &id, Level::Full).await {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(r) => return r,
    }
    let (doc, body) = match open_blob(&state, &session.unlocked, &id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    blob_response(
        &doc,
        body,
        HeaderValue::from_static("application/octet-stream"),
        content_disposition("attachment", &doc.original_filename),
    )
}

// ---------------------------------------------------------------------------
// Edit, delete, retry, access
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EditForm {
    #[serde(default)]
    title: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    tags: String,
}

async fn edit(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<EditForm>,
) -> Response {
    match visible(&session.unlocked, &id, Level::Metadata).await {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(r) => return r,
    }
    let title = form.title.trim().to_owned();
    let date = form.date.trim().to_owned();
    let tags = parse_tags(&form.tags);
    let (docs, u, doc_id) = (state.docs.clone(), session.unlocked.clone(), id.clone());
    let result = tokio::task::spawn_blocking(move || {
        docs.update(
            &u,
            &doc_id,
            (!title.is_empty()).then_some(title.as_str()),
            Some((!date.is_empty()).then_some(date.as_str())),
            Some(&tags),
            now(),
        )
    })
    .await;
    match result {
        Ok(Ok(())) => redirect_to(&headers, &format!("/documents/{id}")),
        Ok(Err(DocError::InvalidDate)) => err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid date"),
        Ok(Err(e)) => doc_error(e),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct DeleteForm {
    confirm: Option<String>,
}

async fn delete(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<DeleteForm>,
) -> Response {
    match visible(&session.unlocked, &id, Level::Metadata).await {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(r) => return r,
    }
    if form.confirm.as_deref() != Some("on") {
        return err(
            StatusCode::BAD_REQUEST,
            "Tick the confirmation box to delete this document",
        );
    }
    let (docs, u) = (state.docs.clone(), session.unlocked.clone());
    match tokio::task::spawn_blocking(move || docs.delete(&u, &id)).await {
        Ok(Ok(())) => redirect_to(&headers, "/documents"),
        Ok(Err(e)) => doc_error(e),
        Err(e) => internal(e),
    }
}

async fn retry(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    let doc = match visible(&session.unlocked, &id, Level::Metadata).await {
        Ok(Some((d, _))) => d,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(r) => return r,
    };
    if doc.text_status != TextStatus::Failed {
        return err(StatusCode::CONFLICT, "Extraction has not failed");
    }
    let (docs, u, doc_id) = (state.docs.clone(), session.unlocked.clone(), id.clone());
    match tokio::task::spawn_blocking(move || docs.retry_extraction(&u, &doc_id)).await {
        Ok(Ok(())) => redirect_to(&headers, &format!("/documents/{id}")),
        Ok(Err(e)) => doc_error(e),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct AccessForm {
    web: String,
    mcp: String,
    semantic_index: String,
}

fn parse_override(s: &str) -> Option<Option<Level>> {
    match s {
        "default" => Some(None),
        "off" => Some(Some(Level::Off)),
        "metadata" => Some(Some(Level::Metadata)),
        "full" => Some(Some(Level::Full)),
        _ => None,
    }
}

/// Exempt from the web-visibility check: the owner can always change access,
/// including un-hiding a document.
async fn set_access(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    CsrfForm(form): CsrfForm<AccessForm>,
) -> Response {
    let (Some(web), Some(mcp), Some(sem)) = (
        parse_override(&form.web),
        parse_override(&form.mcp),
        parse_override(&form.semantic_index),
    ) else {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid access level");
    };
    let doc_id = id.clone();
    let result = db(
        &session.unlocked,
        move |c| -> anyhow::Result<Option<Level>> {
            if get_document(c, &doc_id)?.is_none() {
                return Ok(None);
            }
            // All three overrides change together or not at all.
            let tx = c.unchecked_transaction()?;
            set_document_access(&tx, &doc_id, Channel::Web, web)?;
            set_document_access(&tx, &doc_id, Channel::Mcp, mcp)?;
            set_document_access(&tx, &doc_id, Channel::SemanticIndex, sem)?;
            tx.commit()?;
            Ok(Some(web_level(c, &doc_id)?))
        },
    )
    .await;
    if matches!(result, Ok(Ok(Some(_)))) {
        // Lowering already deleted vectors inside set_document_access.
        let (queue, u, doc) = (state.queue.clone(), session.unlocked.clone(), id.clone());
        let _ = tokio::task::spawn_blocking(move || queue.enqueue_embed_if_needed(&u, &doc)).await;
    }
    match result {
        Ok(Ok(Some(Level::Off))) => redirect_to(&headers, "/documents"),
        Ok(Ok(Some(_))) => redirect_to(&headers, &format!("/documents/{id}")),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => internal(e),
        Err(r) => r,
    }
}

#[cfg(test)]
mod meaning_tests {
    use super::*;

    #[test]
    fn passage_cut_on_char_boundary_with_ellipsis() {
        let text = "ä".repeat(400);
        let p = passage(&text, 0, 400, MEANING_PASSAGE_MAX);
        assert_eq!(p.chars().count(), MEANING_PASSAGE_MAX);
        assert!(p.ends_with('…'));
        // Exactly at the cap is not cut.
        let exact = passage(&text, 0, MEANING_PASSAGE_MAX, MEANING_PASSAGE_MAX);
        assert_eq!(exact.chars().count(), MEANING_PASSAGE_MAX);
        assert!(!exact.ends_with('…'));
        assert_eq!(passage("abcdef", 1, 3, MEANING_PASSAGE_MAX), "bc");
    }

    #[test]
    fn match_percentage_rounds_and_clamps() {
        assert_eq!(match_pct(0.846), 85);
        assert_eq!(match_pct(-0.2), 0);
        assert_eq!(match_pct(1.0001), 100);
    }
}
