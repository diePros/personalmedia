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
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::keyring::user_dir;
use crate::system_db::{QuotaSetting, SystemDb};

/// Extra bytes reserved up front for every upload (stream headers, tags).
pub const UPLOAD_OVERHEAD: u64 = 1024;
const REFRESH: Duration = Duration::from_secs(300);

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

/// Sum of the file sizes under `dir`, recursively. Symlinks are not followed
/// and unfinished uploads (`*.part`) are not counted: they are covered by
/// their reservation.
pub fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) if m.is_file() && e.path().extension().is_none_or(|x| x != "part") => m.len(),
            _ => 0,
        })
        .sum()
}

struct Entry {
    committed: u64,
    reserved: u64,
    loaded: Instant,
}

pub struct Quotas {
    sys: Option<Arc<SystemDb>>,
    data_dir: PathBuf,
    entries: Mutex<HashMap<String, Entry>>,
}

impl Quotas {
    pub fn new(sys: Arc<SystemDb>, data_dir: PathBuf) -> Arc<Quotas> {
        Arc::new(Quotas {
            sys: Some(sys),
            data_dir,
            entries: Mutex::default(),
        })
    }

    /// No limits at all (offline recovery, tests that do not care).
    pub fn unlimited(data_dir: PathBuf) -> Arc<Quotas> {
        Arc::new(Quotas {
            sys: None,
            data_dir,
            entries: Mutex::default(),
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

    fn is_fresh(&self, user_id: &str) -> bool {
        self.lock()
            .get(user_id)
            .is_some_and(|e| e.reserved > 0 || e.loaded.elapsed() < REFRESH)
    }

    async fn ensure_loaded(&self, user_id: &str) {
        if self.is_fresh(user_id) {
            return;
        }
        let dir = user_dir(&self.data_dir, user_id);
        let size = tokio::task::spawn_blocking(move || dir_size(&dir))
            .await
            .unwrap_or(0);
        let mut map = self.lock();
        match map.get_mut(user_id) {
            Some(e) if e.reserved > 0 || e.loaded.elapsed() < REFRESH => {}
            Some(e) => {
                e.committed = size;
                e.loaded = Instant::now();
            }
            None => {
                map.insert(
                    user_id.to_owned(),
                    Entry {
                        committed: size,
                        reserved: 0,
                        loaded: Instant::now(),
                    },
                );
            }
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
            limit: self.limit_for(user_id),
            held: 0,
            done: false,
        };
        r.grow(bytes)?;
        Ok(r)
    }

    /// A document of `bytes` (its blob size on disk) was deleted.
    pub fn on_delete(&self, user_id: &str, bytes: u64) {
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
    /// Hold `n` more bytes; fails (holding nothing more) when that would
    /// push the user over the limit.
    pub fn grow(&mut self, n: u64) -> Result<(), QuotaError> {
        let mut map = self.q.lock();
        let e = map.entry(self.user_id.clone()).or_insert_with(|| Entry {
            committed: 0,
            reserved: 0,
            loaded: Instant::now(),
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
    pub fn commit(mut self, final_bytes: u64) {
        self.done = true;
        if let Some(e) = self.q.lock().get_mut(&self.user_id) {
            e.reserved = e.reserved.saturating_sub(self.held);
            e.committed += final_bytes;
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
