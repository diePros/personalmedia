//! PWA entry points served from the site root: the web app manifest, the
//! app-shell service worker (see `static/sw.js`) and the share target.
//!
//! # Share target
//!
//! `POST /share` receives the OS share sheet's multipart body and only
//! *stages* the files in server memory ([`SharedStaging`]): never on disk,
//! nothing is stored in the vault. The user then reviews them on
//! `GET /share/{id}` and saves with `POST /share/{id}`, a normal
//! CSRF-protected form. So the one route exempt from the origin guard and the
//! CSRF header check (`POST /share`, exact path) cannot add anything to a vault.
//!
//! The share is a top-level cross-site POST navigation. Whether the browser
//! sends the `SameSite=Strict` session cookie with it is not guaranteed
//! (Chrome often treats an installed-PWA share as same-site; this is to be
//! confirmed on a real Android phone). The flow works either way: with a
//! session the staged share is bound to that user and the redirect goes to the
//! review page; without one the staging id travels in the `__Host-pm_continue`
//! cookie (`SameSite=Lax`) through login, which then redirects to the review
//! page. `__Host-pm_session` stays `Strict` for now; relaxing it to `Lax`
//! would be the fallback if the phone test shows the continue cookie is not
//! enough.
//!
//! Staged shares are bound to one user: the one who staged them while logged
//! in, else the first logged-in user to open the review page.

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::stream;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::docs::{human_size, now, parse_tags, read_text_field, web_filter};
use super::session::{
    CsrfForm, CurrentUser, MAX_SHARED_FILES, NoFields, Session, StagedFile, clear_continue_cookie,
    continue_cookie, continue_id, is_staging_id,
};
use super::{ASSET_VERSION, AppState, Page, redirect, render};
use crate::documents::{DocError, OnDuplicate, StoreOutcome, UploadMeta, validate_meta};

/// Where the manifest's `share_target` posts to.
pub const SHARE_PATH: &str = "/share";
/// Slack on top of `max_upload_bytes` for multipart framing and text fields.
const BODY_SLACK: usize = 1024 * 1024;
const FILENAME_MAX_CHARS: usize = 255;
const CHUNK: usize = 64 * 1024;

/// Colors match `static/app.css`: `--accent` (light) and `--bg` (light).
const MANIFEST: &str = r##"{
  "name": "Personal Media",
  "short_name": "Media",
  "start_url": "/documents",
  "scope": "/",
  "display": "standalone",
  "theme_color": "#1d4ed8",
  "background_color": "#fafaf9",
  "icons": [
    {"src": "/static/icons/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
    {"src": "/static/icons/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
    {"src": "/static/icons/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}
  ],
  "share_target": {
    "action": "/share",
    "method": "POST",
    "enctype": "multipart/form-data",
    "params": {
      "title": "title",
      "text": "text",
      "files": [{"name": "files", "accept": ["application/pdf", "image/*", "text/plain"]}]
    }
  }
}
"##;

/// `static/sw.js` with the `__ASSET_VERSION__` placeholder in its cache name.
pub const SW_TEMPLATE: &str = include_str!("../../static/sw.js");

pub fn routes(state: &AppState) -> Router<AppState> {
    let limit = state.cfg.max_upload_bytes as usize + BODY_SLACK;
    Router::new()
        .route("/manifest.webmanifest", get(manifest))
        .route("/sw.js", get(service_worker))
        .route(
            SHARE_PATH,
            post(stage_share).layer(DefaultBodyLimit::max(limit)),
        )
        .route("/share/{id}", get(review_page).post(save_share))
        .route("/share/{id}/discard", post(discard_share))
}

async fn manifest() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/manifest+json"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        MANIFEST,
    )
        .into_response()
}

/// `no-cache` so browsers revalidate on every update check; the scope header
/// is belt and braces (the worker already lives at `/`).
async fn service_worker() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            (
                header::HeaderName::from_static("service-worker-allowed"),
                "/",
            ),
        ],
        SW_TEMPLATE.replace("__ASSET_VERSION__", &ASSET_VERSION),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Share target
// ---------------------------------------------------------------------------

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// `POST /share`, called by the OS. No CSRF token and no origin check (see the
/// module docs): it only stages the files in memory.
async fn stage_share(State(state): State<AppState>, req: Request) -> Response {
    // A session that still has to confirm its recovery key counts as none.
    let session = req
        .extensions()
        .get::<Session>()
        .filter(|s| s.must_confirm_recovery.is_none())
        .cloned();
    let mut multipart = match Multipart::from_request(req, &state).await {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let cap = state.shared.entry_max();
    let (mut files, mut title, mut total) = (Vec::new(), None, 0usize);
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return e.into_response(),
        };
        let Some(filename) = field.file_name().map(str::to_owned) else {
            if field.name() == Some("title") {
                let value = match read_text_field(field).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
                title = Some(truncate_chars(value.trim(), 300)).filter(|t| !t.is_empty());
            }
            // `text` and anything else is not used.
            continue;
        };
        let mime = field.content_type().map(str::to_owned);
        let mut bytes = Zeroizing::new(Vec::new());
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    total += chunk.len();
                    if total > cap {
                        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => return e.into_response(),
            }
        }
        if bytes.is_empty() {
            continue;
        }
        if files.len() == MAX_SHARED_FILES {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
        files.push(StagedFile {
            filename: truncate_chars(filename.trim(), FILENAME_MAX_CHARS),
            mime,
            bytes,
        });
    }
    if files.is_empty() {
        return (StatusCode::BAD_REQUEST, "nothing to share").into_response();
    }
    let user_id = session.map(|s| s.user_id);
    let logged_in = user_id.is_some();
    let Ok(id) = state.shared.stage(user_id, files, title) else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let to = if logged_in {
        format!("/share/{id}")
    } else {
        "/login".to_owned()
    };
    let mut resp = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_str(&to).expect("ascii"))],
    )
        .into_response();
    if !logged_in {
        resp.headers_mut()
            .append(header::SET_COOKIE, continue_cookie(&id, state.shared.ttl()));
    }
    resp
}

struct FileRow {
    name: String,
    size: String,
}

#[derive(Template)]
#[template(path = "share_review.html")]
struct ReviewPage {
    page: Page,
    id: String,
    files: Vec<FileRow>,
    title: String,
    tags: String,
    error: Option<String>,
}

fn review_response(
    session: &Session,
    id: &str,
    state: &AppState,
    title: Option<String>,
    tags: String,
    error: Option<&str>,
) -> Option<Response> {
    let view = state.shared.view(id, &session.user_id)?;
    let page = ReviewPage {
        page: Page::for_session(session),
        id: id.to_owned(),
        files: view
            .files
            .into_iter()
            .map(|(name, size)| FileRow {
                name,
                size: human_size(size as u64),
            })
            .collect(),
        title: title.or(view.title).unwrap_or_default(),
        tags,
        error: error.map(str::to_owned),
    };
    let mut resp = render(&page);
    if error.is_some() {
        *resp.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
    }
    Some(resp)
}

async fn review_page(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !is_staging_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(mut resp) = review_response(&session, &id, &state, None, String::new(), None) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if continue_id(&headers).is_some() {
        resp.headers_mut()
            .append(header::SET_COOKIE, clear_continue_cookie());
    }
    resp
}

#[derive(Deserialize)]
struct SaveForm {
    #[serde(default)]
    title: String,
    #[serde(default)]
    tags: String,
}

enum Saved {
    Stored(String),
    Duplicate {
        existing_id: String,
        existing_title: String,
    },
    Failed,
}

struct ResultRow {
    name: String,
    link: Option<String>,
    note: String,
}

#[derive(Template)]
#[template(path = "share_result.html")]
struct ResultPage {
    page: Page,
    rows: Vec<ResultRow>,
}

async fn save_share(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    CsrfForm(form): CsrfForm<SaveForm>,
) -> Response {
    if !is_staging_id(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let title = Some(form.title.trim().to_owned()).filter(|t| !t.is_empty());
    let tags = parse_tags(&form.tags);
    // Same caps as /api/upload, checked before the share is taken so a typo
    // does not cost the user the staged files.
    if let Err(e) = validate_meta(title.as_deref(), None, &tags) {
        let msg = match e {
            DocError::InvalidInput(m) => m,
            _ => "invalid title or tags",
        };
        return match review_response(&session, &id, &state, title, form.tags, Some(msg)) {
            Some(resp) => resp,
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let Some(staged) = state.shared.take(&id, &session.user_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let filter = web_filter();
    let mut outcomes = Vec::new();
    for file in &staged.files {
        let meta = UploadMeta {
            filename: file.filename.clone(),
            mime: file.mime.clone(),
            title: title.clone(),
            tags: tags.clone(),
            document_date: None,
        };
        // The bytes are handed over in chunks so no second full copy is made.
        let body = stream::iter(
            file.bytes
                .chunks(CHUNK)
                .map(|c| Ok::<_, anyhow::Error>(Bytes::copy_from_slice(c))),
        );
        let outcome = state
            .docs
            .store(
                &session.unlocked,
                meta,
                body,
                OnDuplicate::Skip,
                Some(&filter),
                now(),
            )
            .await;
        outcomes.push(match outcome {
            Ok(StoreOutcome::Stored { id }) => Saved::Stored(id),
            Ok(StoreOutcome::Duplicate {
                existing_id,
                existing_title,
            }) => Saved::Duplicate {
                existing_id,
                existing_title,
            },
            Err(e) => {
                if let DocError::Internal(e) = &e {
                    tracing::error!(error = %e, "saving a shared file failed");
                }
                Saved::Failed
            }
        });
    }
    if outcomes.iter().all(|o| matches!(o, Saved::Stored(_))) {
        return redirect(&headers, "/documents");
    }
    let rows = staged
        .files
        .iter()
        .zip(outcomes)
        .map(|(file, outcome)| match outcome {
            Saved::Stored(id) => ResultRow {
                name: file.filename.clone(),
                link: Some(format!("/documents/{id}")),
                note: "Saved".to_owned(),
            },
            Saved::Duplicate {
                existing_id,
                existing_title,
            } => ResultRow {
                name: file.filename.clone(),
                link: Some(format!("/documents/{existing_id}")),
                note: format!("Not saved: already in your vault as \"{existing_title}\""),
            },
            Saved::Failed => ResultRow {
                name: file.filename.clone(),
                link: None,
                note: "Not saved: something went wrong, try sharing it again".to_owned(),
            },
        })
        .collect();
    render(&ResultPage {
        page: Page::for_session(&session),
        rows,
    })
}

async fn discard_share(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    CsrfForm(_): CsrfForm<NoFields>,
) -> Response {
    if !is_staging_id(&id) || state.shared.take(&id, &session.user_id).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    redirect(&headers, "/documents")
}
