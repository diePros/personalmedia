//! Access switchboard (spec 13a): per-channel defaults plus per-document overrides.

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::meta::{get_setting, set_setting};

const DEFAULTS_KEY: &str = "access_defaults";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Web,
    Mcp,
    SemanticIndex,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Web => "web",
            Channel::Mcp => "mcp",
            Channel::SemanticIndex => "semantic_index",
        }
    }

    fn parse(s: &str) -> Option<Channel> {
        match s {
            "web" => Some(Channel::Web),
            "mcp" => Some(Channel::Mcp),
            "semantic_index" => Some(Channel::SemanticIndex),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Off,
    Metadata,
    Full,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Off => "off",
            Level::Metadata => "metadata",
            Level::Full => "full",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Level> {
        match s {
            "off" => Some(Level::Off),
            "metadata" => Some(Level::Metadata),
            "full" => Some(Level::Full),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDefaults(pub HashMap<Channel, Level>);

impl Default for AccessDefaults {
    fn default() -> Self {
        AccessDefaults(HashMap::from([
            (Channel::Web, Level::Full),
            (Channel::Mcp, Level::Metadata),
            (Channel::SemanticIndex, Level::Off),
        ]))
    }
}

impl AccessDefaults {
    /// A channel missing from the map is `Off`.
    pub fn level(&self, channel: Channel) -> Level {
        self.0.get(&channel).copied().unwrap_or(Level::Off)
    }
}

/// The caller's own limit on a channel (owner web session = Full; MCP = token scope).
#[derive(Clone, Copy)]
pub struct AccessFilter {
    pub channel: Channel,
    pub cap: Level,
}

pub fn get_access_defaults(conn: &Connection) -> Result<AccessDefaults> {
    match get_setting(conn, DEFAULTS_KEY)? {
        Some(json) => Ok(serde_json::from_str(&json)?),
        None => Ok(AccessDefaults::default()),
    }
}

/// Runs `f` inside a savepoint (works with or without an open transaction).
fn atomically(conn: &Connection, f: impl FnOnce() -> Result<()>) -> Result<()> {
    conn.execute_batch("SAVEPOINT access_change;")?;
    match f() {
        Ok(()) => Ok(conn.execute_batch("RELEASE access_change;")?),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO access_change; RELEASE access_change;");
            Err(e)
        }
    }
}

/// Lowering `semantic_index` deletes the affected vectors in the same
/// operation. Raising it only changes the setting: the caller enqueues
/// embedding (`ExtractQueue::enqueue_embeds_needed`).
pub fn set_access_defaults(conn: &Connection, defaults: &AccessDefaults) -> Result<()> {
    atomically(conn, || {
        set_setting(conn, DEFAULTS_KEY, &serde_json::to_string(defaults)?)?;
        super::vectors::enforce_all(conn)
    })
}

/// `None` removes the override (document follows the default again).
/// Lowering `semantic_index` deletes the document's vectors in the same
/// operation; raising it needs the caller to enqueue embedding.
pub fn set_document_access(
    conn: &Connection,
    doc_id: &str,
    channel: Channel,
    level: Option<Level>,
) -> Result<()> {
    atomically(conn, || {
        write_document_access(conn, doc_id, channel, level)?;
        if channel == Channel::SemanticIndex {
            super::vectors::enforce_document(conn, doc_id)?;
        }
        Ok(())
    })
}

fn write_document_access(
    conn: &Connection,
    doc_id: &str,
    channel: Channel,
    level: Option<Level>,
) -> Result<()> {
    match level {
        Some(l) => {
            conn.execute(
                "INSERT INTO document_access(document_id, channel, level) VALUES (?1, ?2, ?3)
                 ON CONFLICT(document_id, channel) DO UPDATE SET level = excluded.level",
                params![doc_id, channel.as_str(), l.as_str()],
            )?;
        }
        None => {
            conn.execute(
                "DELETE FROM document_access WHERE document_id = ?1 AND channel = ?2",
                params![doc_id, channel.as_str()],
            )?;
        }
    }
    Ok(())
}

pub fn document_overrides(conn: &Connection, doc_id: &str) -> Result<HashMap<Channel, Level>> {
    let mut stmt =
        conn.prepare("SELECT channel, level FROM document_access WHERE document_id = ?1")?;
    let rows = stmt.query_map([doc_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (c, l) = row?;
        let c = Channel::parse(&c).ok_or_else(|| anyhow!("unknown channel in db"))?;
        let l = Level::parse(&l).ok_or_else(|| anyhow!("unknown level in db"))?;
        out.insert(c, l);
    }
    Ok(out)
}

/// The level a document without an override starts from on `channel`.
/// Ruling AJ: on the MCP channel the token/app scope governs, so the stored
/// user default is ignored there (treated as `Full` before the cap applies).
pub fn base_default(conn: &Connection, channel: Channel) -> Result<Level> {
    if channel == Channel::Mcp {
        return Ok(Level::Full);
    }
    Ok(get_access_defaults(conn)?.level(channel))
}

/// `min(override.unwrap_or(base_default), cap)`.
pub fn effective_level(
    conn: &Connection,
    doc_id: &str,
    channel: Channel,
    cap: Level,
) -> Result<Level> {
    let over: Option<String> = conn
        .query_row(
            "SELECT level FROM document_access WHERE document_id = ?1 AND channel = ?2",
            params![doc_id, channel.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let base = match over {
        Some(s) => Level::parse(&s).ok_or_else(|| anyhow!("unknown level in db"))?,
        None => base_default(conn, channel)?,
    };
    Ok(base.min(cap))
}
