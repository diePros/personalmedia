//! The Scan screen and `POST /api/scan`: camera photos (JPEG, prepared by
//! `static/scan.js`) become one multi-page PDF that goes through the normal
//! encrypted store.
//!
//! Page images stay in memory (`Zeroizing` buffers) until the PDF is built and
//! handed to [`crate::documents::Documents::store_sized`] as a one-chunk
//! stream; nothing is written to disk unencrypted.

use askama::Template;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use futures_util::stream;
use zeroize::Zeroizing;

use super::docs::{db, doc_error, json_error, now, parse_tags, read_text_field, web_filter};
use super::session::{AuthRejection, CurrentUser};
use super::{AppState, CSP, CspOverride, Page, render};
use crate::documents::{DocError, OnDuplicate, UploadMeta, validate_meta};
use crate::pdf::jpegs_to_pdf;
use crate::user_db::documents::list_documents;

/// Most pages in one scan.
pub const MAX_PAGES: usize = 50;
/// Largest page after the client's JPEG preparation.
pub const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
/// Slack on top of `max_upload_bytes` for multipart framing and text fields.
const BODY_SLACK: usize = 1024 * 1024;
/// Tag chips offered besides `inbox`.
const RECENT_TAGS: usize = 8;
/// First buffer size for a page; grows by doubling.
const PAGE_START_CAP: usize = 256 * 1024;

pub fn routes(state: &AppState) -> Router<AppState> {
    let limit = state.cfg.max_upload_bytes as usize + BODY_SLACK;
    Router::new().route("/scan", get(scan_page)).route(
        "/api/scan",
        post(scan_upload).layer(DefaultBodyLimit::max(limit)),
    )
}

#[derive(Template)]
#[template(path = "scan.html")]
struct ScanPage {
    page: Page,
    /// The 8 most recently used tags, newest first, without `inbox`.
    tags: Vec<String>,
}

async fn scan_page(user: Result<CurrentUser, AuthRejection>) -> Response {
    let CurrentUser(session) = match user {
        Ok(u) => u,
        // Back to the scanner after logging in.
        Err(AuthRejection::Login { .. }) => {
            return axum::response::Redirect::to("/login?next=scan").into_response();
        }
        Err(e) => return e.into_response(),
    };
    let tags = match db(&session.unlocked, |c| {
        list_documents(
            c,
            &crate::user_db::documents::ListFilter {
                limit: 100,
                ..web_filter()
            },
        )
    })
    .await
    {
        Ok(Ok(docs)) => recent_tags(docs.iter().map(|d| d.tags.as_slice())),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "could not list recent tags for the scan page");
            Vec::new()
        }
        Err(resp) => return resp,
    };
    let mut resp = render(&ScanPage {
        page: Page::for_session(&session),
        tags,
    });
    // The page thumbnails are blob: URLs (in-memory photos).
    resp.extensions_mut()
        .insert(CspOverride(CSP.replace("data:", "data: blob:").into()));
    resp
}

/// Distinct tags in order of first appearance (documents newest first),
/// without `inbox` (always offered), at most [`RECENT_TAGS`].
fn recent_tags<'a>(docs: impl Iterator<Item = &'a [String]>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tags in docs {
        for t in tags {
            if t != "inbox" && !out.contains(t) {
                out.push(t.clone());
                if out.len() == RECENT_TAGS {
                    return out;
                }
            }
        }
    }
    out
}

/// Appends to a zeroizing buffer; a full buffer is replaced by a bigger one
/// and the old one is wiped, so no plaintext copy is left on the heap.
fn push(buf: &mut Zeroizing<Vec<u8>>, chunk: &[u8]) {
    if buf.len() + chunk.len() > buf.capacity() {
        let cap = (buf.capacity() * 2).max(buf.len() + chunk.len());
        let mut bigger = Zeroizing::new(Vec::with_capacity(cap));
        bigger.extend_from_slice(buf);
        *buf = bigger;
    }
    buf.extend_from_slice(chunk);
}

/// `Scan YYYY-MM-DD HH-MM` (UTC), the default title and the file name stem.
fn stamp(ts: i64) -> String {
    let d =
        time::OffsetDateTime::from_unix_timestamp(ts).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "Scan {:04}-{:02}-{:02} {:02}-{:02}",
        d.year(),
        u8::from(d.month()),
        d.day(),
        d.hour(),
        d.minute()
    )
}

/// Session + CSRF header (checked by the session layer), like `/api/upload`.
/// Text fields `title`, `tags` and `date`, then the `page` fields in order.
async fn scan_upload(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let unlocked = session.unlocked.clone();
    let size_hint = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    // Answer a quota refusal before the body is read.
    if let Some(n) = size_hint
        && let Err(e) = state.quotas.check_room(&unlocked.user_id, n).await
    {
        return doc_error(DocError::QuotaExceeded {
            used: e.used,
            limit: e.limit,
        });
    }

    let max_total = state.cfg.max_upload_bytes as usize;
    let (mut title, mut tags, mut date) = (None, Vec::new(), None);
    let mut pages: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut total = 0usize;
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => return json_error(StatusCode::BAD_REQUEST, "malformed multipart body"),
        };
        let name = field.name().unwrap_or_default().to_owned();
        if name != "page" {
            let value = match read_text_field(field).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            match name.as_str() {
                "title" => title = Some(value.trim().to_owned()).filter(|v| !v.is_empty()),
                "tags" => tags = parse_tags(&value),
                "date" => date = Some(value.trim().to_owned()).filter(|v| !v.is_empty()),
                _ => {}
            }
            continue;
        }
        if pages.len() == MAX_PAGES {
            return json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "too many pages (max 50 in one scan)",
            );
        }
        let n = pages.len() + 1;
        let mut buf = Zeroizing::new(Vec::with_capacity(PAGE_START_CAP));
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    if buf.len() + chunk.len() > MAX_PAGE_BYTES {
                        return json_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            &format!("page {n} is too large (max 8 MiB)"),
                        );
                    }
                    if total + chunk.len() > max_total {
                        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "upload too large");
                    }
                    total += chunk.len();
                    push(&mut buf, &chunk);
                }
                Ok(None) => break,
                Err(_) => {
                    return json_error(StatusCode::BAD_REQUEST, "malformed multipart body");
                }
            }
        }
        pages.push(buf);
    }

    if pages.is_empty() {
        return json_error(StatusCode::UNPROCESSABLE_ENTITY, "no pages");
    }
    let ts = now();
    let default_title = stamp(ts);
    if let Err(e) = validate_meta(title.as_deref(), Some(&default_title), &tags) {
        return doc_error(e);
    }
    // Building the PDF copies every page once; keep it off the async threads.
    let built = tokio::task::spawn_blocking(move || {
        let refs: Vec<&[u8]> = pages.iter().map(|p| p.as_slice()).collect();
        jpegs_to_pdf(&refs)
    })
    .await;
    let pdf = match built {
        Ok(Ok(pdf)) => pdf,
        Ok(Err(e)) => return json_error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
        Err(e) => {
            tracing::error!(error = %e, "PDF build task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let size = pdf.len() as u64;
    let meta = UploadMeta {
        filename: format!("{default_title}.pdf"),
        mime: Some("application/pdf".into()),
        title: Some(title.unwrap_or(default_title)),
        tags,
        document_date: date,
    };
    let body = stream::once(async move { Ok::<_, anyhow::Error>(Bytes::from(pdf)) });
    match state
        .docs
        .store_sized(
            &unlocked,
            meta,
            Box::pin(body),
            OnDuplicate::Keep,
            Some(&web_filter()),
            ts,
            Some(size),
        )
        .await
    {
        Ok(outcome) => axum::Json(outcome).into_response(),
        Err(e) => doc_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_format() {
        assert_eq!(stamp(1794918480), "Scan 2026-11-17 12-28");
    }

    #[test]
    fn recent_tags_dedupe_skip_inbox_and_cap() {
        let docs: Vec<Vec<String>> = vec![
            vec!["a".into(), "inbox".into()],
            vec!["b".into(), "a".into()],
            (0..20).map(|i| format!("t{i}")).collect(),
        ];
        let got = recent_tags(docs.iter().map(|d| d.as_slice()));
        assert_eq!(got.len(), RECENT_TAGS);
        assert_eq!(&got[..3], ["a", "b", "t0"]);
        assert!(!got.contains(&"inbox".to_owned()));
    }

    #[test]
    fn push_grows_and_keeps_content() {
        let mut b = Zeroizing::new(Vec::with_capacity(4));
        push(&mut b, b"abc");
        push(&mut b, b"defghij");
        assert_eq!(b.as_slice(), b"abcdefghij");
    }
}
