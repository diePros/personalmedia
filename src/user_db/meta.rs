//! Token metadata and per-user settings.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    ReadWrite,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    MetadataOnly,
    FullText,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct TokenScope {
    pub access: Access,
    pub content: Content,
    pub tags: Option<Vec<i64>>,
}

/// Who an OAuth grant was given to. Present on grant metadata only; the
/// metadata `id` of a grant is its `grant_id`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct GrantInfo {
    pub client_id: String,
    pub client_name: String,
    pub redirect_host: String,
}

#[derive(Clone, Debug)]
pub struct TokenMeta {
    pub id: String,
    pub name: String,
    pub scope: TokenScope,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// `Some` for an OAuth grant, `None` for a static `pm_` token.
    pub grant: Option<GrantInfo>,
}

/// What `scope_json` holds: the scope plus, for grants, `grant` (rows written
/// before v1.4 simply lack the field).
#[derive(Serialize, Deserialize)]
struct StoredScope {
    #[serde(flatten)]
    scope: TokenScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant: Option<GrantInfo>,
}

pub fn insert_token_meta(conn: &Connection, t: &TokenMeta) -> Result<()> {
    conn.execute(
        "INSERT INTO token_meta(id, name, scope_json, created_at, last_used_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            t.id,
            t.name,
            serde_json::to_string(&StoredScope {
                scope: t.scope.clone(),
                grant: t.grant.clone(),
            })?,
            t.created_at,
            t.last_used_at
        ],
    )?;
    Ok(())
}

fn row_to_meta(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, String, String, i64, Option<i64>)> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

fn build(raw: (String, String, String, i64, Option<i64>)) -> Result<TokenMeta> {
    let stored: StoredScope = serde_json::from_str(&raw.2)?;
    Ok(TokenMeta {
        id: raw.0,
        name: raw.1,
        scope: stored.scope,
        created_at: raw.3,
        last_used_at: raw.4,
        grant: stored.grant,
    })
}

pub fn list_token_meta(conn: &Connection) -> Result<Vec<TokenMeta>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, scope_json, created_at, last_used_at FROM token_meta
         ORDER BY created_at, id",
    )?;
    let rows = stmt.query_map([], row_to_meta)?;
    rows.map(|r| build(r?)).collect()
}

pub fn get_token_meta(conn: &Connection, id: &str) -> Result<Option<TokenMeta>> {
    let raw = conn
        .query_row(
            "SELECT id, name, scope_json, created_at, last_used_at FROM token_meta WHERE id = ?1",
            [id],
            row_to_meta,
        )
        .optional()?;
    raw.map(build).transpose()
}

pub fn delete_token_meta(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM token_meta WHERE id = ?1", [id])?;
    Ok(())
}

pub fn touch_token(conn: &Connection, id: &str, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE token_meta SET last_used_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    Ok(())
}

pub fn get_setting(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}
