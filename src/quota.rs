//! Per-user storage quotas.
//!
//! Usage is the total size of all files under `users/{id}/` (ciphertext blobs
//! and `index.db`), the figure the admin page shows. It is computed lazily by
//! a directory walk and then kept in memory: uploads reserve their bytes
//! before writing (so parallel uploads can never jointly exceed the limit),
//! commit the real size on success and release on failure; deletes subtract
//! at once. An entry is re-walked after [`REFRESH`] while no upload is in
//! flight, which also picks up index growth.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::keyring::user_dir;
use crate::system_db::{QuotaSetting, SystemDb};

/// Extra bytes reserved up front for every upload (stream headers, tags).
pub const UPLOAD_OVERHEAD: u64 = 1024;
/// Plaintext bytes per encrypted chunk and the tag each chunk adds.
const CHUNK_PLAIN: u64 = 65536;
const CHUNK_TAG: u64 = 16;
const REFRESH: Duration = Duration::from_secs(300);

/// Size of the ciphertext for `plain` bytes (one tag per chunk, without the
/// stream header, which [`UPLOAD_OVERHEAD`] covers).
pub fn cipher_len(plain: u64) -> u64 {
    plain.saturating_add(CHUNK_TAG * plain.div_ceil(CHUNK_PLAIN))
}

/// What an upload of `plain` bytes holds on disk, at most.
pub fn upload_reservation(plain: u64) -> u64 {
    cipher_len(plain).saturating_add(UPLOAD_OVERHEAD)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Storage quota reached ({} of {} used)", human_bytes(*used), human_bytes(*limit))]
pub struct QuotaError {
    pub used: u64,
    pub limit: u64,
}

/// "1.5 KiB" style sizes, shared by the admin and settings pages and the
/// quota error text.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 3] = ["KiB", "MiB", "GiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

/// Sum of the file sizes under `dir`, recursively. Symlinks are not followed.
/// Unfinished uploads (`*.part`) count: while an upload runs the walk is not
/// used (its reservation is), and a leftover from a crash stays visible until
/// the startup sweep ([`sweep_stale_parts`]) removes it.
pub fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) if m.is_file() => m.len(),
            _ => 0,
        })
        .sum()
}

/// Size of the user's search index (`index.db` and its WAL/SHM files).
fn index_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("index.db"))
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// Removes the unfinished uploads (`users/*/blobs/*.part`) a crash left
/// behind. Call at startup, before any upload can run; returns how many
/// files were removed.
pub fn sweep_stale_parts(data_dir: &Path) -> usize {
    let Ok(users) = std::fs::read_dir(data_dir.join("users")) else {
        return 0;
    };
    let mut removed = 0;
    for user in users.flatten() {
        let Ok(blobs) = std::fs::read_dir(user.path().join("blobs")) else {
            continue;
        };
        for f in blobs.flatten() {
            let path = f.path();
            if path.extension().is_some_and(|x| x == "part") && std::fs::remove_file(&path).is_ok()
            {
                removed += 1;
            }
        }
    }
    removed
}

struct Entry {
    committed: u64,
    reserved: u64,
    loaded: Instant,
    /// What `committed` includes for the search index, so a commit can add
    /// only its growth.
    index_len: u64,
}

pub struct Quotas {
    sys: Option<Arc<SystemDb>>,
    data_dir: PathBuf,
    entries: Mutex<HashMap<String, Entry>>,
    refresh: Duration,
    /// Bumped by every delete and commit; a directory walk that started
    /// before such a change may have seen the old state and is discarded.
    changes: AtomicU64,
}

impl Quotas {
    pub fn new(sys: Arc<SystemDb>, data_dir: PathBuf) -> Arc<Quotas> {
        Arc::new(Quotas {
            sys: Some(sys),
            data_dir,
            entries: Mutex::default(),
            refresh: REFRESH,
            changes: AtomicU64::new(0),
        })
    }

    /// No limits at all (offline recovery, tests that do not care).
    pub fn unlimited(data_dir: PathBuf) -> Arc<Quotas> {
        Self::unlimited_with_refresh(data_dir, REFRESH)
    }

    /// [`Quotas::unlimited`] with a custom re-walk interval (tests).
    #[doc(hidden)]
    pub fn unlimited_with_refresh(data_dir: PathBuf, refresh: Duration) -> Arc<Quotas> {
        Arc::new(Quotas {
            sys: None,
            data_dir,
            entries: Mutex::default(),
            refresh,
            changes: AtomicU64::new(0),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The user's effective limit in bytes; `None` is unlimited.
    pub fn limit_for(&self, user_id: &str) -> Option<u64> {
        let sys = self.sys.as_ref()?;
        let default = || match sys.default_quota() {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "reading the default quota failed");
                Some(crate::system_db::DEFAULT_QUOTA_BYTES)
            }
        };
        match sys.user_by_id(user_id) {
            Ok(Some(row)) => match row.quota {
                QuotaSetting::Default => default(),
                QuotaSetting::Custom(b) => Some(b),
                QuotaSetting::Unlimited => None,
            },
            Ok(None) => default(),
            Err(e) => {
                tracing::error!(error = %e, "reading a user quota failed");
                default()
            }
        }
    }

    /// [`Quotas::limit_for`] without blocking the async worker thread.
    pub async fn limit_for_async(self: &Arc<Self>, user_id: &str) -> Option<u64> {
        self.sys.as_ref()?;
        let (q, id) = (self.clone(), user_id.to_owned());
        tokio::task::spawn_blocking(move || q.limit_for(&id))
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "quota limit lookup failed");
                Some(crate::system_db::DEFAULT_QUOTA_BYTES)
            })
    }

    fn is_fresh(&self, user_id: &str) -> bool {
        self.lock()
            .get(user_id)
            .is_some_and(|e| e.reserved > 0 || e.loaded.elapsed() < self.refresh)
    }

    async fn ensure_loaded(&self, user_id: &str) {
        let dir = user_dir(&self.data_dir, user_id);
        self.load_with(user_id, move || dir_size(&dir)).await;
    }

    /// Refreshes the cached figure with `walk` when it is missing or stale.
    /// A walk that raced a delete or a commit is thrown away and repeated
    /// (a few times), so it cannot overwrite the newer state.
    #[doc(hidden)]
    pub async fn load_with<W>(&self, user_id: &str, walk: W)
    where
        W: Fn() -> u64 + Clone + Send + 'static,
    {
        const ATTEMPTS: usize = 3;
        for attempt in 0..ATTEMPTS {
            if self.is_fresh(user_id) {
                return;
            }
            let before = self.changes.load(Ordering::SeqCst);
            let w = walk.clone();
            let size = tokio::task::spawn_blocking(w).await.unwrap_or(0);
            let index_len = index_size(&user_dir(&self.data_dir, user_id));
            let mut map = self.lock();
            if self.changes.load(Ordering::SeqCst) != before && attempt + 1 < ATTEMPTS {
                continue;
            }
            match map.get_mut(user_id) {
                Some(e) if e.reserved > 0 || e.loaded.elapsed() < self.refresh => {}
                Some(e) => {
                    e.committed = size;
                    e.index_len = index_len;
                    e.loaded = Instant::now();
                }
                None => {
                    map.insert(
                        user_id.to_owned(),
                        Entry {
                            committed: size,
                            reserved: 0,
                            loaded: Instant::now(),
                            index_len,
                        },
                    );
                }
            }
            return;
        }
    }

    /// Bytes used by the user, including uploads in flight.
    pub async fn usage(&self, user_id: &str) -> u64 {
        self.ensure_loaded(user_id).await;
        self.lock()
            .get(user_id)
            .map_or(0, |e| e.committed + e.reserved)
    }

    /// Reserve `bytes` for an upload. Release by dropping the reservation or
    /// settle it with [`Reservation::commit`].
    pub async fn reserve(
        self: &Arc<Self>,
        user_id: &str,
        bytes: u64,
    ) -> Result<Reservation, QuotaError> {
        self.ensure_loaded(user_id).await;
        let mut r = Reservation {
            q: self.clone(),
            user_id: user_id.to_owned(),
            limit: self.limit_for_async(user_id).await,
            held: 0,
            done: false,
        };
        r.grow(bytes)?;
        Ok(r)
    }

    /// Fail at once when `bytes` cannot fit into what is left of the user's
    /// quota (an early check, nothing is reserved).
    pub async fn check_room(self: &Arc<Self>, user_id: &str, bytes: u64) -> Result<(), QuotaError> {
        let Some(limit) = self.limit_for_async(user_id).await else {
            return Ok(());
        };
        let used = self.usage(user_id).await;
        if used.saturating_add(bytes) > limit {
            return Err(QuotaError { used, limit });
        }
        Ok(())
    }

    /// A document of `bytes` (its blob size on disk) was deleted.
    pub fn on_delete(&self, user_id: &str, bytes: u64) {
        self.changes.fetch_add(1, Ordering::SeqCst);
        if let Some(e) = self.lock().get_mut(user_id) {
            e.committed = e.committed.saturating_sub(bytes);
        }
    }

    /// Drop the cached figure (the user was deleted).
    pub fn forget(&self, user_id: &str) {
        self.lock().remove(user_id);
    }
}

/// Bytes held for one upload in flight.
pub struct Reservation {
    q: Arc<Quotas>,
    user_id: String,
    limit: Option<u64>,
    held: u64,
    done: bool,
}

impl Reservation {
    /// Make sure at least `total` bytes are held in all; grows by the
    /// difference (and never shrinks).
    pub fn ensure(&mut self, total: u64) -> Result<(), QuotaError> {
        match total.checked_sub(self.held) {
            Some(more) if more > 0 => self.grow(more),
            _ => Ok(()),
        }
    }

    /// Hold `n` more bytes; fails (holding nothing more) when that would
    /// push the user over the limit.
    pub fn grow(&mut self, n: u64) -> Result<(), QuotaError> {
        let mut map = self.q.lock();
        let e = map.entry(self.user_id.clone()).or_insert_with(|| Entry {
            committed: 0,
            reserved: 0,
            loaded: Instant::now(),
            index_len: 0,
        });
        if let Some(limit) = self.limit {
            let total = e.committed + e.reserved;
            if total.saturating_add(n) > limit {
                return Err(QuotaError {
                    used: total.saturating_sub(self.held),
                    limit,
                });
            }
        }
        e.reserved += n;
        self.held += n;
        Ok(())
    }

    /// The upload succeeded: trade the reservation for the real size.
    /// The search index grew (or shrank) meanwhile; that change is counted
    /// too, so index growth does not wait for the next re-walk.
    pub fn commit(mut self, final_bytes: u64) {
        self.done = true;
        let index_now = index_size(&user_dir(&self.q.data_dir, &self.user_id));
        self.q.changes.fetch_add(1, Ordering::SeqCst);
        if let Some(e) = self.q.lock().get_mut(&self.user_id) {
            e.reserved = e.reserved.saturating_sub(self.held);
            e.committed = (e.committed + final_bytes + index_now).saturating_sub(e.index_len);
            e.index_len = index_now;
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.done
            && let Some(e) = self.q.lock().get_mut(&self.user_id)
        {
            e.reserved = e.reserved.saturating_sub(self.held);
        }
    }
}
