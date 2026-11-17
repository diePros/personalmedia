//! PWA entry points served from the site root: the web app manifest, the
//! app-shell service worker (see `static/sw.js`) and the share target.
//!
//! # Share target
//!
//! `POST /share` receives the OS share sheet's multipart body and only
//! *stages* the files in server memory ([`super::session::SharedStaging`]): never on disk,
//! nothing is stored in the vault. The user then reviews them on
//! `GET /share/{id}` and saves with `POST /share/{id}`, a normal
//! CSRF-protected form. So the one route exempt from the origin guard and the
//! CSRF header check (`POST /share`, exact path) cannot add anything to a vault.
//!
//! The share is a top-level cross-site POST navigation. Whether the browser
//! sends the `SameSite=Strict` session cookie with it is not guaranteed
//! (Chrome often treats an installed-PWA share as same-site; this is to be
//! confirmed on a real Android phone, a manual owner check). The flow works
//! either way. With a session the staged share is bound to that user and the
//! redirect goes to the review page. Without one the share goes through login:
//! the staging id travels in the `__Host-pm_continue` cookie
//! (`SameSite=Lax`), and login (or `GET /login` for a browser that is already
//! logged in) redirects to the review page. `__Host-pm_session` stays
//! `Strict`: a `Lax` cookie would not be sent on a cross-site POST either, so
//! relaxing it cannot help and would only expose the app to cross-site GETs.
//!
//! # Who may claim a share
//!
//! A share staged with a session belongs to that user at once. One staged
//! without a session is claimed only by a request that carries its
//! `__Host-pm_continue` cookie (proof that this browser sent it); anyone else
//! gets 404. Its review page warns that the sender is unproven and does not
//! prefill the title. Memory is budgeted while the body streams in, see
//! [`super::session::SharedStaging`].

use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Multipart, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::stream;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::LazyLock;
use zeroize::Zeroizing;

use super::docs::{human_size, now, parse_tags, read_text_field, web_filter};
use super::ratelimit::{client_ip, ip_key, too_many_requests};
use super::session::{
    CsrfForm, CurrentUser, MAX_SHARED_FILES, NoFields, Owner, Refused, Session, StagedFile,
    clear_continue_cookie, continue_cookie, continue_id, is_staging_id,
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
pub const MANIFEST: &str = r##"{
  "name": "Personal Media System",
  "short_name": "PMS",
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

/// Strong `ETag` of the manifest bytes.
static MANIFEST_ETAG: LazyLock<String> =
    LazyLock::new(|| format!("\"{}\"", hex::encode(&Sha256::digest(MANIFEST)[..16])));

/// `no-cache` + strong `ETag`, like the static files: a change to the share
/// target or the icons reaches browsers on their next update check.
async fn manifest(headers: HeaderMap) -> Response {
    let etag = MANIFEST_ETAG.as_str();
    if super::etag_matches(&headers, etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [(header::ETAG, etag), (header::CACHE_CONTROL, "no-cache")],
        )
            .into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "application/manifest+json"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::ETAG, etag),
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

#[derive(Template)]
#[template(path = "share_text_only.html")]
struct TextOnlyPage {
    page: Page,
}

/// `POST /share`, called by the OS. No CSRF token and no origin check (see the
/// module docs): it only stages the files in memory, within the budget of
/// [`super::session::SharedStaging`] and at most [`SHARE_PERMITS`](super::SHARE_PERMITS)
/// bodies at a time.
async fn stage_share(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let Ok(_permit) = state.share_permits.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "5")],
            "busy, try again",
        )
            .into_response();
    };
    // A session that still has to confirm its recovery key counts as none.
    let session = req
        .extensions()
        .get::<Session>()
        .filter(|s| s.must_confirm_recovery.is_none())
        .cloned();
    let owner = match &session {
        Some(s) => Owner::User(s.user_id.clone()),
        None => Owner::Anon(ip_key(client_ip(
            peer,
            req.headers(),
            state.cfg.trusted_proxy,
        ))),
    };
    let mut reservation = match state.shared.begin(owner) {
        Ok(r) => r,
        Err(Refused::AnonBusy) => return too_many_requests(state.shared.ttl()),
        Err(Refused::OverBudget) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let content_length = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    let mut multipart = match Multipart::from_request(req, &state).await {
        Ok(m) => m,
        Err(e) => return e.into_response(),
    };
    let (mut files, mut title) = (Vec::new(), None);
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
                    // Count first, keep after: over budget stops the read here.
                    if reservation.reserve(chunk.len()).is_err() {
                        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                    }
                    if bytes.capacity() == 0 {
                        // One allocation up front (no regrowth that would
                        // leave unwiped copies behind), never beyond the budget.
                        let hint = content_length
                            .unwrap_or(0)
                            .min(reservation.cap())
                            .saturating_sub(reservation.reserved() - chunk.len());
                        bytes.reserve_exact(hint.max(chunk.len()));
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
        // Typically a link or snippet shared as text.
        let page = match &session {
            Some(s) => Page::for_session(s),
            None => Page::anonymous(),
        };
        let mut resp = render(&TextOnlyPage { page });
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return resp;
    }
    let logged_in = session.is_some();
    let id = reservation.commit(files, title);
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
    /// Staged before any login: show the warning, no prefill.
    anonymous: bool,
}

fn review_response(
    session: &Session,
    id: &str,
    proof: Option<&str>,
    state: &AppState,
    title: Option<String>,
    tags: String,
    error: Option<&str>,
) -> Option<Response> {
    let view = state.shared.view(id, &session.user_id, proof)?;
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
        anonymous: view.anonymous,
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
    let proof = continue_id(&headers);
    let Some(mut resp) = review_response(&session, &id, proof, &state, None, String::new(), None)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if proof.is_some() {
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
    let proof = continue_id(&headers);
    let title = Some(form.title.trim().to_owned()).filter(|t| !t.is_empty());
    let tags = parse_tags(&form.tags);
    // Same caps as /api/upload, checked before the share is taken so a typo
    // does not cost the user the staged files.
    if let Err(e) = validate_meta(title.as_deref(), None, &tags) {
        let msg = match e {
            DocError::InvalidInput(m) => m,
            _ => "invalid title or tags",
        };
        return match review_response(&session, &id, proof, &state, title, form.tags, Some(msg)) {
            Some(resp) => resp,
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let Some(staged) = state.shared.take(&id, &session.user_id, proof) else {
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
                .map(|c| Ok::<_, anyhow::Error>(Bytes::from_owner(Zeroizing::new(c.to_vec())))),
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
    if !is_staging_id(&id)
        || state
            .shared
            .take(&id, &session.user_id, continue_id(&headers))
            .is_none()
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    redirect(&headers, "/documents")
}
