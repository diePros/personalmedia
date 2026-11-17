//! Encrypted document storage: streaming upload, blob I/O and metadata edits.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::anyhow;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::crypto::stream::{DecryptReader, EncryptWriter};
use crate::crypto::{Key32, aad, unwrap_key, wrap_key};
use crate::keyring::{Unlocked, user_dir};
use crate::quota::{QuotaError, Quotas, Reservation, UPLOAD_OVERHEAD, upload_reservation};
use crate::user_db::{
    Document, ListFilter, NewDocument, TextStatus, delete_document, find_by_sha256_visible,
    get_document, insert_document, set_text, update_document_meta,
};

/// Queue for text extraction, implemented by the extraction workers.
pub trait Enqueue: Send + Sync {
    fn enqueue(&self, u: Arc<Unlocked>, doc_id: String);
}

pub struct UploadMeta {
    pub filename: String,
    pub mime: Option<String>,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub document_date: Option<String>,
}

#[derive(Clone, Copy)]
pub enum OnDuplicate {
    Skip,
    Keep,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StoreOutcome {
    Stored {
        id: String,
    },
    Duplicate {
        existing_id: String,
        existing_title: String,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum DocError {
    #[error("upload too large")]
    TooLarge,
    /// The user's storage quota is used up.
    #[error("Storage quota reached ({} of {} used)", crate::quota::human_bytes(*used), crate::quota::human_bytes(*limit))]
    QuotaExceeded { used: u64, limit: u64 },
    #[error("not found")]
    NotFound,
    #[error("invalid date")]
    InvalidDate,
    /// A text field is over its length cap (see [`validate_meta`]).
    #[error("{0}")]
    InvalidInput(&'static str),
    #[error("internal error: {0}")]
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for DocError {
    fn from(e: anyhow::Error) -> Self {
        DocError::Internal(e)
    }
}

impl From<QuotaError> for DocError {
    fn from(e: QuotaError) -> Self {
        DocError::QuotaExceeded {
            used: e.used,
            limit: e.limit,
        }
    }
}

impl From<io::Error> for DocError {
    fn from(e: io::Error) -> Self {
        DocError::Internal(e.into())
    }
}

pub fn blob_path(data_dir: &Path, user_id: &str, doc_id: &str) -> PathBuf {
    user_dir(data_dir, user_id).join("blobs").join(doc_id)
}

/// Deletes a file on drop unless disarmed.
struct FileGuard(Option<PathBuf>);

impl FileGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for FileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}

/// Caps on user-supplied metadata, shared by the web and MCP paths.
pub const TITLE_MAX_CHARS: usize = 300;
pub const FILENAME_MAX_CHARS: usize = 255;
pub const TAGS_MAX: usize = 50;
pub const TAG_MAX_CHARS: usize = 64;

/// Title <= 300 chars, filename <= 255, at most 50 tags of <= 64 chars each
/// (after trimming; empty tags do not count).
pub fn validate_meta(
    title: Option<&str>,
    filename: Option<&str>,
    tags: &[String],
) -> Result<(), DocError> {
    if title.is_some_and(|t| t.trim().chars().count() > TITLE_MAX_CHARS) {
        return Err(DocError::InvalidInput(
            "title too long (max 300 characters)",
        ));
    }
    if filename.is_some_and(|f| f.trim().chars().count() > FILENAME_MAX_CHARS) {
        return Err(DocError::InvalidInput(
            "filename too long (max 255 characters)",
        ));
    }
    let mut count = 0;
    for t in tags.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        count += 1;
        if count > TAGS_MAX {
            return Err(DocError::InvalidInput("too many tags (max 50)"));
        }
        if t.chars().count() > TAG_MAX_CHARS {
            return Err(DocError::InvalidInput("tag too long (max 64 characters)"));
        }
    }
    Ok(())
}

pub(crate) fn validate_date(s: &str) -> Result<(), DocError> {
    let b = s.as_bytes();
    let shape = b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
    if !shape {
        return Err(DocError::InvalidDate);
    }
    let y: i32 = s[0..4].parse().map_err(|_| DocError::InvalidDate)?;
    let m: u8 = s[5..7].parse().map_err(|_| DocError::InvalidDate)?;
    let d: u8 = s[8..10].parse().map_err(|_| DocError::InvalidDate)?;
    let month = time::Month::try_from(m).map_err(|_| DocError::InvalidDate)?;
    time::Date::from_calendar_date(y, month, d).map_err(|_| DocError::InvalidDate)?;
    Ok(())
}

fn resolve_mime(given: Option<&str>, filename: &str) -> String {
    match given.map(str::trim) {
        Some(m) if !m.is_empty() && m != "application/octet-stream" => m.to_string(),
        _ => mime_guess::from_path(filename)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_string(),
    }
}

fn extractable(mime: &str) -> bool {
    matches!(
        mime,
        "application/pdf"
            | "image/png"
            | "image/jpeg"
            | "image/tiff"
            | "image/webp"
            | "text/plain"
            | "text/markdown"
    )
}

fn default_title(filename: &str) -> String {
    let stem = Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if stem.is_empty() {
        filename.to_string()
    } else {
        stem.to_string()
    }
}

pub struct Documents {
    data_dir: PathBuf,
    max_upload_bytes: u64,
    queue: Arc<dyn Enqueue>,
    quotas: Arc<Quotas>,
}

type Chunk = Result<Bytes, anyhow::Error>;

impl Documents {
    pub fn new(
        data_dir: PathBuf,
        max_upload_bytes: u64,
        queue: Arc<dyn Enqueue>,
        quotas: Arc<Quotas>,
    ) -> Documents {
        Documents {
            data_dir,
            max_upload_bytes,
            queue,
            quotas,
        }
    }

    /// Store an upload. Duplicate detection (for `OnDuplicate::Skip`) only
    /// considers documents visible under `visibility` (`None` = all documents,
    /// for the owner's web upload); a duplicate the caller cannot see is
    /// treated as `Keep`, so a hidden document's id and title never leak.
    pub async fn store<S, E>(
        &self,
        u: &Arc<Unlocked>,
        meta: UploadMeta,
        body: S,
        on_dup: OnDuplicate,
        visibility: Option<&ListFilter>,
        now: i64,
    ) -> Result<StoreOutcome, DocError>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: Into<anyhow::Error>,
    {
        self.store_sized(u, meta, body, on_dup, visibility, now, None)
            .await
    }

    /// [`Documents::store`] with the expected size of the upload. The quota
    /// is reserved for the whole hinted size (plus the ciphertext overhead)
    /// before anything is written, so parallel uploads that do not fit
    /// together fail early instead of starving each other. Without a hint the
    /// reservation grows chunk by chunk. The hint is an upper bound for
    /// reserving (the request length of a multipart upload is fine); the real
    /// size is what gets committed.
    ///
    /// Known limit: a duplicate is only recognised after the stream was
    /// hashed, so a user at their limit who re-sends a file that is already
    /// stored is told the quota is reached, not that it is a duplicate.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_sized<S, E>(
        &self,
        u: &Arc<Unlocked>,
        meta: UploadMeta,
        mut body: S,
        on_dup: OnDuplicate,
        visibility: Option<&ListFilter>,
        now: i64,
        size_hint: Option<u64>,
    ) -> Result<StoreOutcome, DocError>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: Into<anyhow::Error>,
    {
        if let Some(d) = &meta.document_date {
            validate_date(d)?;
        }
        // Reserve before anything touches the disk; the writer grows it only
        // past the hint (or per chunk without one).
        let initial = size_hint.map_or(UPLOAD_OVERHEAD, upload_reservation);
        let reservation = self.quotas.reserve(&u.user_id, initial).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let final_path = blob_path(&self.data_dir, &u.user_id, &id);
        let part_path = final_path.with_file_name(format!("{id}.part"));
        let mut part_guard = FileGuard(Some(part_path.clone()));

        let dek = Key32::random();
        let blob_aad = aad::blob(&u.user_id, &id);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Chunk>(8);
        let max = self.max_upload_bytes;
        let worker_dek = Key32::from_bytes(*dek.as_bytes());
        let worker_path = part_path.clone();
        let worker = tokio::task::spawn_blocking(
            move || -> Result<([u8; 32], u64, Reservation), DocError> {
                let mut reservation = reservation;
                let file = File::create(&worker_path)?;
                let mut w =
                    EncryptWriter::new(io::BufWriter::new(file), &worker_dek, blob_aad.as_bytes())?;
                let mut hasher = Sha256::new();
                let mut size: u64 = 0;
                while let Some(chunk) = rx.blocking_recv() {
                    let chunk = chunk.map_err(DocError::Internal)?;
                    size += chunk.len() as u64;
                    if size > max {
                        return Err(DocError::TooLarge);
                    }
                    reservation.ensure(upload_reservation(size))?;
                    hasher.update(&chunk);
                    w.write_all(&chunk)?;
                }
                let mut bw = w.finish()?;
                bw.flush()?;
                bw.get_ref().sync_all()?;
                Ok((hasher.finalize().into(), size, reservation))
            },
        );

        while let Some(item) = body.next().await {
            let item = item.map_err(Into::into);
            let failed = item.is_err();
            if tx.send(item).await.is_err() || failed {
                break;
            }
        }
        drop(tx);
        let (sha, size, reservation) = worker
            .await
            .map_err(|e| DocError::Internal(anyhow!("upload task failed: {e}")))??;

        if matches!(on_dup, OnDuplicate::Skip)
            && let Some(existing) = u
                .with_db(|c| {
                    find_by_sha256_visible(c, &sha, visibility.unwrap_or(&ListFilter::default()))
                })
                .map_err(DocError::Internal)?
        {
            return Ok(StoreOutcome::Duplicate {
                existing_id: existing.id,
                existing_title: existing.title,
            });
        }

        let mime = resolve_mime(meta.mime.as_deref(), &meta.filename);
        let eligible = extractable(&mime);
        let title = meta
            .title
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| default_title(&meta.filename));
        let new = NewDocument {
            id: id.clone(),
            wrapped_dek: wrap_key(u.umk(), &dek, aad::dek(&u.user_id, &id).as_bytes()),
            original_filename: meta.filename,
            title,
            mime,
            size,
            sha256: sha,
            document_date: meta.document_date,
            tags: meta.tags,
            created_at: now,
        };

        fs::rename(&part_path, &final_path)?;
        part_guard.disarm();
        let stored_bytes = fs::metadata(&final_path).map_or(size, |m| m.len());
        let mut final_guard = FileGuard(Some(final_path));
        u.with_db(|c| {
            insert_document(c, &new)?;
            if !eligible {
                set_text(c, &id, TextStatus::Unsupported, None, None, now)?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .map_err(DocError::Internal)?;
        final_guard.disarm();
        reservation.commit(stored_bytes);

        if eligible {
            self.queue.enqueue(u.clone(), id.clone());
        }
        Ok(StoreOutcome::Stored { id })
    }

    fn load(&self, u: &Unlocked, id: &str) -> Result<(Document, Key32, PathBuf), DocError> {
        let doc = u
            .with_db(|c| get_document(c, id))
            .map_err(DocError::Internal)?
            .ok_or(DocError::NotFound)?;
        let dek = unwrap_key(
            u.umk(),
            &doc.wrapped_dek,
            aad::dek(&u.user_id, id).as_bytes(),
        )
        .map_err(|e| DocError::Internal(anyhow!("unwrap dek: {e}")))?;
        Ok((doc, dek, blob_path(&self.data_dir, &u.user_id, id)))
    }

    pub fn open_plaintext(
        &self,
        u: &Unlocked,
        id: &str,
    ) -> Result<(Document, DecryptReader<File>), DocError> {
        let (doc, dek, path) = self.load(u, id)?;
        let file = File::open(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => DocError::NotFound,
            _ => e.into(),
        })?;
        let r = DecryptReader::new(file, &dek, aad::blob(&u.user_id, id).as_bytes())?;
        Ok((doc, r))
    }

    pub fn decrypt_to_path(
        &self,
        u: &Unlocked,
        id: &str,
        dest: &Path,
    ) -> Result<Document, DocError> {
        let (doc, mut r) = self.open_plaintext(u, id)?;
        let mut out = File::create(dest)?;
        io::copy(&mut r, &mut out)?;
        out.flush()?;
        Ok(doc)
    }

    pub fn delete(&self, u: &Unlocked, id: &str) -> Result<(), DocError> {
        u.with_db(|c| get_document(c, id))
            .map_err(DocError::Internal)?
            .ok_or(DocError::NotFound)?;
        let path = blob_path(&self.data_dir, &u.user_id, id);
        let blob_len = fs::metadata(&path).map_or(0, |m| m.len());
        match fs::remove_file(&path) {
            Ok(()) => self.quotas.on_delete(&u.user_id, blob_len),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        u.with_db(|c| delete_document(c, id))
            .map_err(DocError::Internal)
    }

    pub fn update(
        &self,
        u: &Unlocked,
        id: &str,
        title: Option<&str>,
        date: Option<Option<&str>>,
        tags: Option<&[String]>,
        now: i64,
    ) -> Result<(), DocError> {
        if let Some(Some(d)) = date {
            validate_date(d)?;
        }
        validate_meta(title, None, tags.unwrap_or_default())?;
        u.with_db(|c| get_document(c, id))
            .map_err(DocError::Internal)?
            .ok_or(DocError::NotFound)?;
        u.with_db(|c| update_document_meta(c, id, title, date, tags, now))
            .map_err(DocError::Internal)
    }

    /// Replace the notes of a document (at most [`NOTES_MAX_CHARS`] characters).
    pub fn set_notes(&self, u: &Unlocked, id: &str, notes: &str, now: i64) -> Result<(), DocError> {
        if notes.chars().count() > crate::user_db::NOTES_MAX_CHARS {
            return Err(DocError::InvalidInput("notes too long"));
        }
        u.with_db(|c| get_document(c, id))
            .map_err(DocError::Internal)?
            .ok_or(DocError::NotFound)?;
        u.with_db(|c| crate::user_db::set_notes(c, id, notes, now))
            .map_err(DocError::Internal)
    }

    pub fn retry_extraction(&self, u: &Arc<Unlocked>, id: &str) -> Result<(), DocError> {
        u.with_db(|c| get_document(c, id))
            .map_err(DocError::Internal)?
            .ok_or(DocError::NotFound)?;
        u.with_db(|c| set_text(c, id, TextStatus::Pending, None, None, now_secs()))
            .map_err(DocError::Internal)?;
        self.queue.enqueue(u.clone(), id.to_string());
        Ok(())
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
