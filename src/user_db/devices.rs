//! Labels and last use of remembered devices (`device_meta`).

use anyhow::Result;
use rusqlite::{Connection, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMeta {
    pub id: String,
    pub label: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

pub fn insert_device_meta(conn: &Connection, d: &DeviceMeta) -> Result<()> {
    conn.execute(
        "INSERT INTO device_meta(id, label, created_at, last_used_at) VALUES (?1,?2,?3,?4)",
        params![d.id, d.label, d.created_at, d.last_used_at],
    )?;
    Ok(())
}

/// Newest last use first (a never-used device counts from its creation).
pub fn list_device_meta(conn: &Connection) -> Result<Vec<DeviceMeta>> {
    let mut st = conn.prepare(
        "SELECT id, label, created_at, last_used_at FROM device_meta
         ORDER BY COALESCE(last_used_at, created_at) DESC, created_at DESC, id",
    )?;
    let rows = st.query_map([], |r| {
        Ok(DeviceMeta {
            id: r.get(0)?,
            label: r.get(1)?,
            created_at: r.get(2)?,
            last_used_at: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn touch_device_meta(conn: &Connection, id: &str, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE device_meta SET last_used_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    Ok(())
}

pub fn delete_device_meta(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM device_meta WHERE id = ?1", [id])?;
    Ok(())
}

pub fn delete_all_device_meta(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM device_meta", [])?;
    Ok(())
}

/// Removes metadata whose system row no longer exists (expired or revoked
/// while the user was locked). `live_ids` are the user's device token ids.
pub fn prune_device_meta(conn: &Connection, live_ids: &[String]) -> Result<()> {
    for d in list_device_meta(conn)? {
        if !live_ids.contains(&d.id) {
            delete_device_meta(conn, &d.id)?;
        }
    }
    Ok(())
}
