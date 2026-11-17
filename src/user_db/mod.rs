//! Per-user encrypted index database (SQLCipher): documents, tags, extracted
//! text, FTS5, access switchboard, token metadata and settings.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::crypto::Key32;

pub mod access;
pub mod documents;
pub mod meta;
pub mod vectors;

pub use access::{
    AccessDefaults, AccessFilter, Channel, Level, document_overrides, effective_level,
    get_access_defaults, set_access_defaults, set_document_access,
};
pub use documents::{
    Document, ListFilter, NewDocument, SearchHit, TextStatus, delete_document, find_by_sha256,
    find_by_sha256_visible, get_document, get_document_text, hidden_from, insert_document,
    list_documents, list_tags, list_tags_visible, pending_document_ids, search, set_text, tag_ids,
    update_document_meta,
};
pub use meta::{
    Access, Content, TokenMeta, TokenScope, delete_token_meta, get_setting, get_token_meta,
    insert_token_meta, list_token_meta, set_setting, touch_token,
};

#[doc(hidden)]
pub const SCHEMA_V1: &str = "
CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    wrapped_dek BLOB NOT NULL,
    original_filename TEXT NOT NULL,
    title TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 BLOB NOT NULL,
    document_date TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    text_status TEXT NOT NULL DEFAULT 'pending',
    page_count INTEGER
);
CREATE INDEX documents_sha256 ON documents(sha256);
CREATE INDEX documents_created ON documents(created_at DESC);
CREATE TABLE document_text (
    document_id TEXT PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    content TEXT NOT NULL
);
CREATE VIRTUAL TABLE documents_fts USING fts5(
    doc_id UNINDEXED, title, filename, tags, content,
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TABLE tags (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
CREATE TABLE document_tags (
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (document_id, tag_id)
);
CREATE INDEX document_tags_tag ON document_tags(tag_id);
CREATE TABLE document_access (
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    level TEXT NOT NULL,
    PRIMARY KEY (document_id, channel)
);
CREATE TABLE token_meta (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// v2 (v1.2): encrypted chunk vectors for semantic search.
const MIGRATION_V2: &str = "
CREATE TABLE chunk_vectors (
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    chunk_no INTEGER NOT NULL,
    start INTEGER NOT NULL,
    end INTEGER NOT NULL,
    model TEXT NOT NULL,
    vector BLOB NOT NULL,
    PRIMARY KEY(document_id, chunk_no)
);
ALTER TABLE documents ADD COLUMN embed_status TEXT NOT NULL DEFAULT 'none';
PRAGMA user_version = 2;
";

/// Open (creating if needed) the user's SQLCipher index with a raw key, and migrate.
pub fn open_user_db(path: &Path, key: &Key32) -> Result<Connection> {
    let conn = Connection::open(path).context("opening user db")?;
    let key_hex = Zeroizing::new(hex::encode(key.as_bytes()));
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex.as_str()));
    conn.execute_batch(&pragma)?;
    // Keep temp structures in memory so sorts/merges never spill plaintext to disk.
    conn.execute_batch("PRAGMA temp_store = MEMORY; PRAGMA secure_delete = ON;")?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    // Reading the schema fails here if the key is wrong.
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .context("user db: wrong key or not a database")?;
    if version < 1 {
        conn.execute_batch(&format!(
            "BEGIN; {SCHEMA_V1} PRAGMA user_version = 1; COMMIT;"
        ))?;
    }
    if version < 2 {
        // Re-checked inside the write transaction so a concurrent opener
        // cannot apply the migration twice.
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        let res = (|| -> Result<()> {
            let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if v < 2 {
                conn.execute_batch(MIGRATION_V2)?;
            }
            Ok(())
        })();
        match res {
            Ok(()) => conn.execute_batch("COMMIT;")?,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e.context("migrating user db to v2"));
            }
        }
    }
    Ok(conn)
}

/// Open `path` read-only and run `init` (key pragma, probe query), writing
/// nothing next to it. Without a pending `-wal` file the database is opened
/// `immutable=1` (no locks, no `-shm`/`-wal` created, works on a read-only
/// mount). With a non-empty `-wal` file the normal read-only open is tried
/// first so the log is applied; if that fails (unwritable directory), the
/// log is ignored with a warning on stderr.
pub(crate) fn open_readonly_with(
    path: &Path,
    init: impl Fn(&Connection) -> Result<()>,
) -> Result<Connection> {
    use rusqlite::OpenFlags;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    let immutable = || -> Result<Connection> {
        let mut uri = String::from("file:");
        for b in std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()) {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'/' | b'~' => {
                    uri.push(*b as char)
                }
                _ => uri.push_str(&format!("%{b:02X}")),
            }
        }
        uri.push_str("?immutable=1");
        let c = Connection::open_with_flags(&uri, flags)
            .with_context(|| format!("opening {} read-only", path.display()))?;
        init(&c)?;
        Ok(c)
    };
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    if !std::fs::metadata(&wal).is_ok_and(|m| m.len() > 0) {
        return immutable();
    }
    let plain = Connection::open_with_flags(path, flags)
        .map_err(anyhow::Error::from)
        .and_then(|c| init(&c).map(|()| c));
    match plain {
        Ok(c) => Ok(c),
        Err(_) => {
            eprintln!(
                "warning: {} has a non-empty -wal file that cannot be applied read-only; \
                 recent changes may be missing",
                path.display()
            );
            immutable()
        }
    }
}

/// Open the user's SQLCipher index read-only: no migrations, no writes of any
/// kind, temp structures in memory. For offline recovery from a backup.
pub fn open_user_db_readonly(path: &Path, key: &Key32) -> Result<Connection> {
    open_readonly_with(path, |conn| {
        let key_hex = Zeroizing::new(hex::encode(key.as_bytes()));
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex.as_str()));
        conn.execute_batch(&pragma)?;
        conn.execute_batch("PRAGMA temp_store = MEMORY;")?;
        // Reading the schema fails here if the key is wrong.
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .context("user db: wrong key or not a database")?;
        // user_version alone can succeed on some failures; touch the schema.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .context("user db: wrong key or not a database")?;
        anyhow::ensure!(version >= 1, "user db: not initialised");
        Ok(())
    })
}
