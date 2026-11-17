//! System database: plaintext SQLite holding only account/auth plumbing.
//! It never holds user content; the only user-identifying datum is the username.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

use crate::crypto::Argon2Params;

pub const SYSTEM_DB_FILE: &str = "system.db";

#[derive(Debug, thiserror::Error)]
pub enum SysError {
    #[error("username already taken")]
    UsernameTaken,
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InviteError {
    #[error("invite not found")]
    NotFound,
    #[error("invite expired")]
    Expired,
    #[error("invite already used")]
    Used,
    #[error("database error")]
    Internal,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
        }
    }

    fn parse(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "user" => Some(Role::User),
            _ => None,
        }
    }
}

/// The default quota the v2 migration seeds: 10 GiB.
pub const DEFAULT_QUOTA_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const DEFAULT_QUOTA_KEY: &str = "default_quota_bytes";

/// A user's storage quota: the admin default, their own number or no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaSetting {
    Default,
    Custom(u64),
    Unlimited,
}

#[derive(Clone, Debug)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub disabled: bool,
    pub created_at: i64,
    pub salt: [u8; 16],
    pub argon2: Argon2Params,
    pub umk_by_password: Vec<u8>,
    pub umk_by_recovery: Vec<u8>,
    pub index_key_wrapped: Vec<u8>,
    pub totp_sealed: Option<Vec<u8>>,
    /// The newest recovery key, sealed under the UMK, until the user confirms
    /// having saved it.
    pub pending_recovery_sealed: Option<Vec<u8>>,
    pub quota: QuotaSetting,
}

pub struct SystemDb {
    conn: Mutex<Connection>,
    /// Column list for user reads; a v1 database opened read-only has no
    /// quota columns, so constants stand in for them.
    cols: &'static str,
}

#[doc(hidden)]
pub const SCHEMA_V1: &str = "
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin','user')),
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    salt BLOB NOT NULL,
    argon2_m INTEGER NOT NULL,
    argon2_t INTEGER NOT NULL,
    argon2_p INTEGER NOT NULL,
    umk_by_password BLOB NOT NULL,
    umk_by_recovery BLOB NOT NULL,
    index_key_wrapped BLOB NOT NULL,
    totp_sealed BLOB,
    pending_recovery_sealed BLOB
);
CREATE TABLE invites (
    token_hash BLOB PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('admin','user')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE TABLE tokens (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    umk_wrapped BLOB NOT NULL
);
CREATE INDEX tokens_user ON tokens(user_id);
";

const MIGRATION_V2: &str = "
CREATE TABLE system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO system_settings (key, value) VALUES ('default_quota_bytes', '10737418240');
ALTER TABLE users ADD COLUMN quota_mode TEXT NOT NULL DEFAULT 'default'
    CHECK (quota_mode IN ('default','custom','unlimited'));
ALTER TABLE users ADD COLUMN quota_bytes INTEGER;
PRAGMA user_version = 2;
";

const USER_COLS: &str = "id, username, role, disabled, created_at, salt, argon2_m, argon2_t, \
     argon2_p, umk_by_password, umk_by_recovery, index_key_wrapped, totp_sealed, \
     pending_recovery_sealed, quota_mode, quota_bytes";
/// Same shape as [`USER_COLS`] for a database without the quota columns.
const USER_COLS_NO_QUOTA: &str = "id, username, role, disabled, created_at, salt, argon2_m, \
     argon2_t, argon2_p, umk_by_password, umk_by_recovery, index_key_wrapped, totp_sealed, \
     pending_recovery_sealed, 'default', NULL";

fn bad_col(i: usize, what: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        i,
        rusqlite::types::Type::Blob,
        what.to_string().into(),
    )
}

fn row_to_user(r: &rusqlite::Row<'_>) -> rusqlite::Result<UserRow> {
    let role: String = r.get(2)?;
    let salt: Vec<u8> = r.get(5)?;
    Ok(UserRow {
        id: r.get(0)?,
        username: r.get(1)?,
        role: Role::parse(&role).ok_or_else(|| bad_col(2, "invalid role"))?,
        disabled: r.get::<_, i64>(3)? != 0,
        created_at: r.get(4)?,
        salt: salt
            .try_into()
            .map_err(|_| bad_col(5, "salt must be 16 bytes"))?,
        argon2: Argon2Params {
            m_kib: r.get(6)?,
            t: r.get(7)?,
            p: r.get(8)?,
        },
        umk_by_password: r.get(9)?,
        umk_by_recovery: r.get(10)?,
        index_key_wrapped: r.get(11)?,
        totp_sealed: r.get(12)?,
        pending_recovery_sealed: r.get(13)?,
        quota: {
            let mode: String = r.get(14)?;
            let bytes: Option<i64> = r.get(15)?;
            match (mode.as_str(), bytes) {
                ("default", _) => QuotaSetting::Default,
                ("unlimited", _) => QuotaSetting::Unlimited,
                ("custom", Some(b)) if b >= 0 => QuotaSetting::Custom(b as u64),
                _ => return Err(bad_col(14, "invalid quota")),
            }
        },
    })
}

impl SystemDb {
    /// Open (creating if needed) the plain, unencrypted system database.
    pub fn open(path: &Path) -> anyhow::Result<SystemDb> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version < 1 {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(SCHEMA_V1)?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
        }
        if version < 2 {
            // Re-checked inside the write transaction so two openers cannot
            // both apply the migration.
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            let res = (|| -> anyhow::Result<()> {
                let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
                if v < 2 {
                    conn.execute_batch(MIGRATION_V2)?;
                }
                Ok(())
            })();
            match res {
                Ok(()) => conn.execute_batch("COMMIT;")?,
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    return Err(e.context("migrating system db to v2"));
                }
            }
        }
        Ok(SystemDb {
            conn: Mutex::new(conn),
            cols: USER_COLS,
        })
    }

    /// Open an existing system database read-only (no schema creation, no WAL
    /// pragma, nothing written). For offline recovery from a backup.
    pub fn open_readonly(path: &Path) -> anyhow::Result<SystemDb> {
        let conn = crate::user_db::open_readonly_with(path, |c| {
            let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
            c.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
                r.get::<_, i64>(0)
            })?;
            anyhow::ensure!(version >= 1, "not a system database");
            Ok(())
        })?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        Ok(SystemDb {
            conn: Mutex::new(conn),
            cols: if version >= 2 {
                USER_COLS
            } else {
                USER_COLS_NO_QUOTA
            },
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned lock only means another thread panicked; the connection is still valid.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Inserts a user, quota setting included.
    pub fn insert_user(&self, u: &UserRow) -> Result<(), SysError> {
        let (mode, bytes) = match u.quota {
            QuotaSetting::Default => ("default", None),
            QuotaSetting::Custom(b) => ("custom", Some(i64::try_from(b).unwrap_or(i64::MAX))),
            QuotaSetting::Unlimited => ("unlimited", None),
        };
        let res = self.lock().execute(
            &format!("INSERT INTO users ({USER_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"),
            params![
                u.id,
                u.username,
                u.role.as_str(),
                u.disabled as i64,
                u.created_at,
                u.salt.as_slice(),
                u.argon2.m_kib,
                u.argon2.t,
                u.argon2.p,
                u.umk_by_password,
                u.umk_by_recovery,
                u.index_key_wrapped,
                u.totp_sealed,
                u.pending_recovery_sealed,
                mode,
                bytes,
            ],
        );
        match res {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation
                    && e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
            {
                Err(SysError::UsernameTaken)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn user_where(&self, col: &str, val: &str) -> anyhow::Result<Option<UserRow>> {
        Ok(self
            .lock()
            .query_row(
                &format!("SELECT {} FROM users WHERE {col} = ?1", self.cols),
                [val],
                row_to_user,
            )
            .optional()?)
    }

    pub fn user_by_name(&self, name: &str) -> anyhow::Result<Option<UserRow>> {
        self.user_where("username", name)
    }

    pub fn user_by_id(&self, id: &str) -> anyhow::Result<Option<UserRow>> {
        self.user_where("id", id)
    }

    pub fn list_users(&self) -> anyhow::Result<Vec<UserRow>> {
        let conn = self.lock();
        let mut st = conn.prepare(&format!(
            "SELECT {} FROM users ORDER BY created_at, username",
            self.cols
        ))?;
        let rows = st.query_map([], row_to_user)?.collect::<Result<_, _>>()?;
        Ok(rows)
    }

    pub fn set_password_wrap(
        &self,
        id: &str,
        salt: [u8; 16],
        argon2: Argon2Params,
        wrapped: &[u8],
    ) -> anyhow::Result<()> {
        self.lock().execute(
            "UPDATE users SET salt=?2, argon2_m=?3, argon2_t=?4, argon2_p=?5, umk_by_password=?6 WHERE id=?1",
            params![id, salt.as_slice(), argon2.m_kib, argon2.t, argon2.p, wrapped],
        )?;
        Ok(())
    }

    pub fn set_recovery_wrap(&self, id: &str, wrapped: &[u8]) -> anyhow::Result<()> {
        self.lock().execute(
            "UPDATE users SET umk_by_recovery=?2 WHERE id=?1",
            params![id, wrapped],
        )?;
        Ok(())
    }

    /// Replace the recovery wrap and the sealed copy of the new key in one statement.
    pub fn replace_recovery(
        &self,
        id: &str,
        wrapped: &[u8],
        pending_sealed: &[u8],
    ) -> anyhow::Result<()> {
        self.lock().execute(
            "UPDATE users SET umk_by_recovery=?2, pending_recovery_sealed=?3 WHERE id=?1",
            params![id, wrapped, pending_sealed],
        )?;
        Ok(())
    }

    /// Clear the pending recovery key once the user confirmed saving it.
    pub fn clear_pending_recovery(&self, id: &str) -> anyhow::Result<()> {
        self.lock().execute(
            "UPDATE users SET pending_recovery_sealed=NULL WHERE id=?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn set_totp(&self, id: &str, sealed: Option<&[u8]>) -> anyhow::Result<()> {
        self.lock().execute(
            "UPDATE users SET totp_sealed=?2 WHERE id=?1",
            params![id, sealed],
        )?;
        Ok(())
    }

    pub fn set_disabled(&self, id: &str, disabled: bool) -> anyhow::Result<()> {
        self.lock().execute(
            "UPDATE users SET disabled=?2 WHERE id=?1",
            params![id, disabled as i64],
        )?;
        Ok(())
    }

    /// The admin-set default quota; `None` is unlimited.
    pub fn default_quota(&self) -> anyhow::Result<Option<u64>> {
        let v: Option<String> = self
            .lock()
            .query_row(
                "SELECT value FROM system_settings WHERE key = ?1",
                [DEFAULT_QUOTA_KEY],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match v.as_deref() {
            None => Some(DEFAULT_QUOTA_BYTES),
            Some("unlimited") => None,
            Some(n) => Some(n.parse()?),
        })
    }

    pub fn set_default_quota(&self, quota: Option<u64>) -> anyhow::Result<()> {
        let value = quota.map_or_else(|| "unlimited".to_owned(), |n| n.to_string());
        self.lock().execute(
            "INSERT INTO system_settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![DEFAULT_QUOTA_KEY, value],
        )?;
        Ok(())
    }

    pub fn set_user_quota(&self, id: &str, q: QuotaSetting) -> anyhow::Result<()> {
        let (mode, bytes) = match q {
            QuotaSetting::Default => ("default", None),
            QuotaSetting::Custom(b) => ("custom", Some(i64::try_from(b)?)),
            QuotaSetting::Unlimited => ("unlimited", None),
        };
        self.lock().execute(
            "UPDATE users SET quota_mode=?2, quota_bytes=?3 WHERE id=?1",
            params![id, mode, bytes],
        )?;
        Ok(())
    }

    /// Delete a user; their tokens go with them via ON DELETE CASCADE.
    pub fn delete_user(&self, id: &str) -> anyhow::Result<()> {
        self.lock().execute("DELETE FROM users WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn create_invite(
        &self,
        token_hash: [u8; 32],
        role: Role,
        created_at: i64,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        self.lock().execute(
            "INSERT INTO invites (token_hash, role, created_at, expires_at) VALUES (?1,?2,?3,?4)",
            params![token_hash.as_slice(), role.as_str(), created_at, expires_at],
        )?;
        Ok(())
    }

    /// Read-only invite check: same errors as [`SystemDb::consume_invite`],
    /// but nothing is marked used.
    pub fn invite_status(&self, token_hash: [u8; 32], now: i64) -> Result<Role, InviteError> {
        let conn = self.lock();
        let row: Option<(String, i64, Option<i64>)> = conn
            .query_row(
                "SELECT role, expires_at, used_at FROM invites WHERE token_hash=?1",
                [token_hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| InviteError::Internal)?;
        let (role, expires_at, used_at) = row.ok_or(InviteError::NotFound)?;
        if used_at.is_some() {
            return Err(InviteError::Used);
        }
        if now > expires_at {
            return Err(InviteError::Expired);
        }
        Role::parse(&role).ok_or(InviteError::Internal)
    }

    /// Atomically validate an invite and mark it used.
    pub fn consume_invite(&self, token_hash: [u8; 32], now: i64) -> Result<Role, InviteError> {
        let mut conn = self.lock();
        let internal = |_: rusqlite::Error| InviteError::Internal;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(internal)?;
        let row: Option<(String, i64, Option<i64>)> = tx
            .query_row(
                "SELECT role, expires_at, used_at FROM invites WHERE token_hash=?1",
                [token_hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(internal)?;
        let (role, expires_at, used_at) = row.ok_or(InviteError::NotFound)?;
        if used_at.is_some() {
            return Err(InviteError::Used);
        }
        if now > expires_at {
            return Err(InviteError::Expired);
        }
        let role = Role::parse(&role).ok_or(InviteError::Internal)?;
        tx.execute(
            "UPDATE invites SET used_at=?2 WHERE token_hash=?1",
            params![token_hash.as_slice(), now],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(role)
    }

    /// Open (unused, unexpired) invites as (first 8 hex chars of hash, role, expires_at).
    pub fn list_open_invites(&self, now: i64) -> anyhow::Result<Vec<(String, Role, i64)>> {
        let conn = self.lock();
        let mut st = conn.prepare(
            "SELECT hex(token_hash), role, expires_at FROM invites \
             WHERE used_at IS NULL AND expires_at >= ?1 ORDER BY created_at, expires_at",
        )?;
        let rows = st.query_map([now], |r| {
            let h: String = r.get(0)?;
            let role: String = r.get(1)?;
            Ok((
                h[..8].to_lowercase(),
                Role::parse(&role).ok_or_else(|| bad_col(1, "invalid role"))?,
                r.get(2)?,
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Delete the open invite whose hash starts with `hash_prefix`. The prefix
    /// must be exactly 8 lowercase hex characters, and the invite is deleted
    /// only when exactly one open invite matches it.
    pub fn revoke_invite(&self, hash_prefix: &str) -> anyhow::Result<()> {
        if hash_prefix.len() != 8
            || !hash_prefix
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Ok(());
        }
        self.lock().execute(
            "DELETE FROM invites WHERE used_at IS NULL AND substr(lower(hex(token_hash)),1,8) = ?1 \
             AND (SELECT count(*) FROM invites WHERE used_at IS NULL \
                  AND substr(lower(hex(token_hash)),1,8) = ?1) = 1",
            [hash_prefix],
        )?;
        Ok(())
    }

    pub fn insert_token(
        &self,
        token_id: &str,
        user_id: &str,
        umk_wrapped: &[u8],
    ) -> anyhow::Result<()> {
        self.lock().execute(
            "INSERT INTO tokens (token_id, user_id, umk_wrapped) VALUES (?1,?2,?3)",
            params![token_id, user_id, umk_wrapped],
        )?;
        Ok(())
    }

    pub fn token(&self, token_id: &str) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT user_id, umk_wrapped FROM tokens WHERE token_id=?1",
                [token_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn delete_token(&self, token_id: &str) -> anyhow::Result<()> {
        self.lock()
            .execute("DELETE FROM tokens WHERE token_id=?1", [token_id])?;
        Ok(())
    }

    pub fn token_ids_for_user(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        let conn = self.lock();
        let mut st =
            conn.prepare("SELECT token_id FROM tokens WHERE user_id=?1 ORDER BY token_id")?;
        let rows = st.query_map([user_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, SystemDb) {
        let d = tempfile::tempdir().unwrap();
        let db = SystemDb::open(&d.path().join(SYSTEM_DB_FILE)).unwrap();
        (d, db)
    }

    fn user(id: &str, name: &str) -> UserRow {
        UserRow {
            id: id.into(),
            username: name.into(),
            role: Role::User,
            disabled: false,
            created_at: 100,
            salt: [7; 16],
            argon2: Argon2Params {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
            umk_by_password: vec![1, 2, 3],
            umk_by_recovery: vec![4, 5],
            index_key_wrapped: vec![6],
            totp_sealed: None,
            pending_recovery_sealed: None,
            quota: QuotaSetting::Default,
        }
    }

    #[test]
    fn insert_user_persists_the_quota() {
        let (_d, db) = db();
        let mut u = user("u1", "alice");
        u.quota = QuotaSetting::Custom(12_345);
        db.insert_user(&u).unwrap();
        assert_eq!(
            db.user_by_id("u1").unwrap().unwrap().quota,
            QuotaSetting::Custom(12_345)
        );
        let mut u = user("u2", "bob");
        u.quota = QuotaSetting::Unlimited;
        db.insert_user(&u).unwrap();
        assert_eq!(
            db.user_by_id("u2").unwrap().unwrap().quota,
            QuotaSetting::Unlimited
        );
    }

    #[test]
    fn user_crud_roundtrip() {
        let (_d, db) = db();
        let u = user("u1", "alice");
        db.insert_user(&u).unwrap();
        let got = db.user_by_name("alice").unwrap().unwrap();
        assert_eq!(got.id, "u1");
        assert_eq!(got.salt, [7; 16]);
        assert_eq!(got.argon2, u.argon2);
        assert_eq!(got.role, Role::User);
        assert_eq!(got.umk_by_password, vec![1, 2, 3]);
        assert!(db.user_by_id("u1").unwrap().is_some());
        assert!(db.user_by_id("nope").unwrap().is_none());
        assert_eq!(db.list_users().unwrap().len(), 1);

        let a2 = Argon2Params {
            m_kib: 2048,
            t: 2,
            p: 1,
        };
        db.set_password_wrap("u1", [9; 16], a2, &[8, 8]).unwrap();
        db.set_recovery_wrap("u1", &[5, 5]).unwrap();
        db.replace_recovery("u1", &[6, 6], &[7]).unwrap();
        let got = db.user_by_id("u1").unwrap().unwrap();
        assert_eq!(got.umk_by_recovery, vec![6, 6]);
        assert_eq!(got.pending_recovery_sealed, Some(vec![7]));
        db.clear_pending_recovery("u1").unwrap();
        assert_eq!(
            db.user_by_id("u1")
                .unwrap()
                .unwrap()
                .pending_recovery_sealed,
            None
        );
        db.set_recovery_wrap("u1", &[5, 5]).unwrap();
        db.set_totp("u1", Some(&[1])).unwrap();
        db.set_disabled("u1", true).unwrap();
        let got = db.user_by_id("u1").unwrap().unwrap();
        assert_eq!(got.salt, [9; 16]);
        assert_eq!(got.argon2, a2);
        assert_eq!(got.umk_by_password, vec![8, 8]);
        assert_eq!(got.umk_by_recovery, vec![5, 5]);
        assert_eq!(got.totp_sealed, Some(vec![1]));
        assert!(got.disabled);
        db.set_totp("u1", None).unwrap();
        assert_eq!(db.user_by_id("u1").unwrap().unwrap().totp_sealed, None);
        db.delete_user("u1").unwrap();
        assert!(db.user_by_id("u1").unwrap().is_none());
    }

    #[test]
    fn duplicate_username_rejected() {
        let (_d, db) = db();
        db.insert_user(&user("u1", "alice")).unwrap();
        let e = db.insert_user(&user("u2", "alice")).unwrap_err();
        assert!(matches!(e, SysError::UsernameTaken));
    }

    #[test]
    fn invite_single_use() {
        let (_d, db) = db();
        let h = [1u8; 32];
        db.create_invite(h, Role::Admin, 0, 100).unwrap();
        assert_eq!(db.list_open_invites(10).unwrap().len(), 1);
        assert_eq!(db.consume_invite(h, 10).unwrap(), Role::Admin);
        assert_eq!(db.consume_invite(h, 11).unwrap_err(), InviteError::Used);
        assert!(db.list_open_invites(10).unwrap().is_empty());
        assert_eq!(
            db.consume_invite([2; 32], 10).unwrap_err(),
            InviteError::NotFound
        );
    }

    #[test]
    fn invite_status_is_read_only() {
        let (_d, db) = db();
        let h = [3; 32];
        db.create_invite(h, Role::User, 0, 100).unwrap();
        assert_eq!(db.invite_status(h, 10).unwrap(), Role::User);
        assert_eq!(db.invite_status(h, 10).unwrap(), Role::User);
        assert_eq!(db.invite_status(h, 101).unwrap_err(), InviteError::Expired);
        assert_eq!(
            db.invite_status([4; 32], 10).unwrap_err(),
            InviteError::NotFound
        );
        db.consume_invite(h, 10).unwrap();
        assert_eq!(db.invite_status(h, 11).unwrap_err(), InviteError::Used);
    }

    #[test]
    fn invite_expiry() {
        let (_d, db) = db();
        let h = [3u8; 32];
        db.create_invite(h, Role::User, 0, 100).unwrap();
        assert_eq!(db.consume_invite(h, 101).unwrap_err(), InviteError::Expired);
        assert!(db.list_open_invites(101).unwrap().is_empty());
    }

    #[test]
    fn revoke_invite_by_prefix() {
        let (_d, db) = db();
        let h = [0xab; 32];
        db.create_invite(h, Role::User, 0, 100).unwrap();
        let open = db.list_open_invites(1).unwrap();
        assert_eq!(open[0].0, "abababab");
        assert_eq!(open[0].2, 100);
        db.revoke_invite("abababab").unwrap();
        assert_eq!(db.consume_invite(h, 1).unwrap_err(), InviteError::NotFound);
    }

    #[test]
    fn revoke_invite_requires_exact_unique_prefix() {
        let (_d, db) = db();
        let mut h1 = [0xab; 32];
        let mut h2 = [0xab; 32];
        h2[31] = 0x01; // same first 8 hex chars as h1
        db.create_invite(h1, Role::User, 0, 100).unwrap();
        db.create_invite(h2, Role::User, 0, 100).unwrap();
        h1[0] = 0xcd;
        db.create_invite(h1, Role::User, 0, 100).unwrap();
        // Short, uppercase, non-hex and ambiguous prefixes delete nothing.
        for p in ["", "ab", "abababa", "ABABABAB", "abababag", "abababab"] {
            db.revoke_invite(p).unwrap();
        }
        assert_eq!(db.list_open_invites(1).unwrap().len(), 3);
        db.revoke_invite("cdababab").unwrap();
        assert_eq!(db.list_open_invites(1).unwrap().len(), 2);
    }

    #[test]
    fn delete_user_removes_tokens() {
        let (_d, db) = db();
        db.insert_user(&user("u1", "alice")).unwrap();
        db.insert_token("t1", "u1", &[1, 2]).unwrap();
        db.insert_token("t2", "u1", &[3]).unwrap();
        assert_eq!(
            db.token("t1").unwrap(),
            Some(("u1".to_string(), vec![1, 2]))
        );
        assert_eq!(db.token_ids_for_user("u1").unwrap().len(), 2);
        db.delete_token("t2").unwrap();
        assert_eq!(db.token_ids_for_user("u1").unwrap(), vec!["t1".to_string()]);
        db.delete_user("u1").unwrap();
        assert!(db.token("t1").unwrap().is_none());
    }

    #[test]
    fn schema_has_no_content_columns() {
        let (_d, db) = db();
        let conn = db.conn.lock().unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(!tables.is_empty());
        for t in tables {
            let cols: Vec<String> = conn
                .prepare(&format!("PRAGMA table_info({t})"))
                .unwrap()
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            for bad in ["filename", "title", "tags", "name", "scope"] {
                assert!(!cols.iter().any(|c| c == bad), "{t} has {bad}");
            }
        }
    }
}
