//! In-memory keyring: `user_id -> unlocked state {UMK, open index DB}`.
//!
//! The keyring itself only holds `Weak` references. Sessions, MCP requests and
//! processing jobs hold the `Arc<Unlocked>`; when the last one is dropped the
//! UMK is zeroized and the index DB connection is closed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use anyhow::Context;
use rusqlite::Connection;

use crate::crypto::{Key32, aad, unwrap_key};
use crate::user_db::open_user_db;

/// Notified once for every fresh unlock (not when an existing unlock is reused).
pub trait OnUnlock: Send + Sync {
    fn unlocked(&self, u: &Arc<Unlocked>);
}

/// A user's unlocked state. Dropping it zeroizes the UMK and closes the index DB.
pub struct Unlocked {
    pub user_id: String,
    umk: Key32,
    db: Mutex<Connection>,
}

impl Unlocked {
    /// Unwrap the index key with `umk` and open the user's index DB, without
    /// registering anywhere (the offline recovery CLI has no keyring).
    pub fn open(
        data_dir: &Path,
        user_id: &str,
        umk: Key32,
        index_key_wrapped: &[u8],
    ) -> anyhow::Result<Unlocked> {
        let index_key = unwrap_key(&umk, index_key_wrapped, aad::index_key(user_id).as_bytes())
            .context("unwrapping index key")?;
        let conn = open_user_db(&index_db_path(data_dir, user_id), &index_key)?;
        Ok(Unlocked {
            user_id: user_id.to_string(),
            umk,
            db: Mutex::new(conn),
        })
    }

    pub fn umk(&self) -> &Key32 {
        &self.umk
    }

    /// Run `f` with exclusive access to the user's index DB connection.
    pub fn with_db<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        // A poisoned lock only means another thread panicked; the connection is still valid.
        let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
        f(&conn)
    }
}

impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlocked")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

pub struct Keyring {
    data_dir: PathBuf,
    on_unlock: Arc<dyn OnUnlock>,
    map: Mutex<HashMap<String, Weak<Unlocked>>>,
}

pub fn user_dir(data_dir: &Path, user_id: &str) -> PathBuf {
    data_dir.join("users").join(user_id)
}

pub fn index_db_path(data_dir: &Path, user_id: &str) -> PathBuf {
    user_dir(data_dir, user_id).join("index.db")
}

impl Keyring {
    pub fn new(data_dir: PathBuf, on_unlock: Arc<dyn OnUnlock>) -> Keyring {
        Keyring {
            data_dir,
            on_unlock,
            map: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Weak<Unlocked>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Return the live unlocked state for `user_id`, or create it by unwrapping
    /// the index key with `umk` and opening the user's index DB.
    pub fn unlock(
        &self,
        user_id: &str,
        umk: Key32,
        index_key_wrapped: &[u8],
    ) -> anyhow::Result<Arc<Unlocked>> {
        let fresh = {
            // The lock is held across check -> open -> insert so two concurrent
            // unlocks of one user can never produce two `Unlocked`.
            let mut map = self.lock();
            if let Some(live) = map.get(user_id).and_then(Weak::upgrade) {
                return Ok(live);
            }
            map.retain(|_, w| w.strong_count() > 0);

            let fresh = Arc::new(Unlocked::open(
                &self.data_dir,
                user_id,
                umk,
                index_key_wrapped,
            )?);
            map.insert(user_id.to_string(), Arc::downgrade(&fresh));
            fresh
        };
        self.on_unlock.unlocked(&fresh);
        Ok(fresh)
    }

    pub fn get(&self, user_id: &str) -> Option<Arc<Unlocked>> {
        self.lock().get(user_id).and_then(Weak::upgrade)
    }
}
