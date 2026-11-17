//! The Scan screen and `POST /api/scan`: camera photos (JPEG, prepared by
//! `static/scan.js`) become one multi-page PDF that goes through the normal
//! encrypted store.
//!
//! Page images stay in memory (`Zeroizing` buffers) until the PDF is built and
//! handed to [`crate::documents::Documents::store_reserved`] as a chunked
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

use super::docs::{
    db, doc_error, json_error, multipart_error, now, parse_tags, read_text_field, web_filter,
};
use super::session::{AuthRejection, CurrentUser};
use super::{AppState, CSP, CspOverride, Page, render};
use crate::documents::{DocError, OnDuplicate, UploadMeta, validate_meta};
use crate::pdf::jpegs_to_pdf;
use crate::quota::{UPLOAD_OVERHEAD, upload_reservation};
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
/// Piece size when the PDF is handed to the store.
const STORE_CHUNK: usize = 64 * 1024;

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

/// `Scan YYYY-MM-DD HH-MM`, the default title and the file name stem, in the
/// browser's time zone (`tz_offset`: minutes east of UTC; UTC without it).
fn stamp(ts: i64, tz_offset: i32) -> String {
    let d = time::OffsetDateTime::from_unix_timestamp(ts + i64::from(tz_offset) * 60)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
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
/// Text fields `title`, `tags`, `date`, `notes` and `tz_offset`, then the `page` fields in order.
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
    // One scan at a time: the pages and the PDF live in memory.
    let Ok(_permit) = state.scan_permits.try_acquire() else {
        let mut resp = json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Another scan is being saved \u{2014} try again in a moment",
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, header::HeaderValue::from_static("5"));
        return resp;
    };
    // Reserve the quota from Content-Length before the body is read, so a
    // refusal comes first and parallel uploads cannot jointly exceed it.
    let reservation = match state
        .quotas
        .reserve(
            &unlocked.user_id,
            size_hint.map_or(UPLOAD_OVERHEAD, upload_reservation),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return doc_error(DocError::QuotaExceeded {
                used: e.used,
                limit: e.limit,
            });
        }
    };

    let max_total = state.cfg.max_upload_bytes as usize;
    let (mut title, mut tags, mut date) = (None, Vec::new(), None);
    let mut notes = String::new();
    let mut tz_offset = 0i32;
    let mut pages: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut total = 0usize;
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return multipart_error(&e),
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
                "notes" => notes = value.trim().to_owned(),
                // Minutes east of UTC; anything implausible means UTC.
                "tz_offset" => {
                    tz_offset = value
                        .trim()
                        .parse::<i32>()
                        .ok()
                        .filter(|m| (-14 * 60..=14 * 60).contains(m))
                        .unwrap_or(0);
                }
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
                Err(e) => return multipart_error(&e),
            }
        }
        pages.push(buf);
    }

    if pages.is_empty() {
        return json_error(StatusCode::UNPROCESSABLE_ENTITY, "no pages");
    }
    let ts = now();
    let default_title = stamp(ts, tz_offset);
    if let Err(e) = validate_meta(title.as_deref(), Some(&default_title), &tags) {
        return doc_error(e);
    }
    if notes.chars().count() > crate::user_db::NOTES_MAX_CHARS {
        return json_error(StatusCode::UNPROCESSABLE_ENTITY, "notes too long");
    }
    // Building the PDF copies every page once; keep it off the async threads.
    let built = tokio::task::spawn_blocking(move || {
        let refs: Vec<&[u8]> = pages.iter().map(|p| p.as_slice()).collect();
        jpegs_to_pdf(&refs)
    })
    .await;
    let pdf = match built {
        Ok(Ok(pdf)) => Zeroizing::new(pdf),
        Ok(Err(e)) => return json_error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
        Err(e) => {
            tracing::error!(error = %e, "PDF build task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let meta = UploadMeta {
        filename: format!("{default_title}.pdf"),
        mime: Some("application/pdf".into()),
        title: Some(title.unwrap_or(default_title)),
        tags,
        document_date: date,
        date_source: None,
    };
    // Small copies out of the wiped buffer, made one at a time.
    let body = Box::pin(stream::unfold((pdf, 0usize), |(pdf, at)| async move {
        if at >= pdf.len() {
            return None;
        }
        let end = (at + STORE_CHUNK).min(pdf.len());
        let chunk = Bytes::copy_from_slice(&pdf[at..end]);
        Some((Ok::<_, anyhow::Error>(chunk), (pdf, end)))
    }));
    match state
        .docs
        .store_reserved(
            &unlocked,
            meta,
            body,
            OnDuplicate::Keep,
            Some(&web_filter()),
            ts,
            reservation,
        )
        .await
    {
        Ok(outcome) => {
            let mut notes_saved = true;
            if !notes.is_empty()
                && let crate::documents::StoreOutcome::Stored { id } = &outcome
            {
                let (docs, u, id) = (state.docs.clone(), unlocked.clone(), id.clone());
                let saved =
                    tokio::task::spawn_blocking(move || docs.set_notes(&u, &id, &notes, ts)).await;
                if !matches!(saved, Ok(Ok(()))) {
                    tracing::warn!("could not save the notes of a scan");
                    notes_saved = false;
                }
            }
            let mut body = serde_json::to_value(&outcome).unwrap_or_default();
            if !notes_saved && let Some(o) = body.as_object_mut() {
                o.insert(
                    "warning".into(),
                    "Saved, but the notes could not be saved. Add them on the document page."
                        .into(),
                );
            }
            axum::Json(body).into_response()
        }
        Err(e) => doc_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_format() {
        assert_eq!(stamp(1794918480, 0), "Scan 2026-11-17 12-28");
        assert_eq!(stamp(1794918480, 120), "Scan 2026-11-17 14-28");
        assert_eq!(stamp(1794918480, -330), "Scan 2026-11-17 06-58");
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
