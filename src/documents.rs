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
    #[error("not found")]
    NotFound,
    #[error("invalid date")]
    InvalidDate,
    #[error("internal error: {0}")]
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for DocError {
    fn from(e: anyhow::Error) -> Self {
        DocError::Internal(e)
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

fn validate_date(s: &str) -> Result<(), DocError> {
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
}

type Chunk = Result<Bytes, anyhow::Error>;

impl Documents {
    pub fn new(data_dir: PathBuf, max_upload_bytes: u64, queue: Arc<dyn Enqueue>) -> Documents {
        Documents {
            data_dir,
            max_upload_bytes,
            queue,
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
        mut body: S,
        on_dup: OnDuplicate,
        visibility: Option<&ListFilter>,
        now: i64,
    ) -> Result<StoreOutcome, DocError>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: Into<anyhow::Error>,
    {
        if let Some(d) = &meta.document_date {
            validate_date(d)?;
        }
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
        let worker = tokio::task::spawn_blocking(move || -> Result<([u8; 32], u64), DocError> {
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
                hasher.update(&chunk);
                w.write_all(&chunk)?;
            }
            let mut bw = w.finish()?;
            bw.flush()?;
            bw.get_ref().sync_all()?;
            Ok((hasher.finalize().into(), size))
        });

        while let Some(item) = body.next().await {
            let item = item.map_err(Into::into);
            let failed = item.is_err();
            if tx.send(item).await.is_err() || failed {
                break;
            }
        }
        drop(tx);
        let (sha, size) = worker
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
        match fs::remove_file(blob_path(&self.data_dir, &u.user_id, id)) {
            Ok(()) => {}
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
        u.with_db(|c| get_document(c, id))
            .map_err(DocError::Internal)?
            .ok_or(DocError::NotFound)?;
        u.with_db(|c| update_document_meta(c, id, title, date, tags, now))
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
