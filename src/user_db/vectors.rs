//! Encrypted chunk vectors (live only in the SQLCipher index DB) and the
//! per-document embedding status.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

use super::access::{Channel, Level, effective_level};
use crate::embed::Chunk;

/// f32 little-endian.
fn vec_to_blob(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// Decode a stored vector (f32 little-endian).
pub fn blob_to_vec(b: &[u8]) -> Vec<f32> {
    b.as_chunks::<4>()
        .0
        .iter()
        .map(|c| f32::from_le_bytes(*c))
        .collect()
}

pub fn set_embed_status(conn: &Connection, doc_id: &str, status: &str) -> Result<()> {
    ensure!(
        matches!(status, "none" | "pending" | "done" | "failed"),
        "bad embed status"
    );
    conn.execute(
        "UPDATE documents SET embed_status = ?2 WHERE id = ?1",
        params![doc_id, status],
    )?;
    Ok(())
}

pub fn get_embed_status(conn: &Connection, doc_id: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT embed_status FROM documents WHERE id = ?1",
            [doc_id],
            |r| r.get(0),
        )
        .optional()?)
}

/// Delete all vectors of a document and reset its status to `none`.
pub fn delete_vectors(conn: &Connection, doc_id: &str) -> Result<()> {
    conn.execute("DELETE FROM chunk_vectors WHERE document_id = ?1", [doc_id])?;
    set_embed_status(conn, doc_id, "none")
}

fn write_vectors(
    conn: &Connection,
    doc_id: &str,
    model: &str,
    items: &[(Chunk, Vec<f32>)],
) -> Result<()> {
    conn.execute("DELETE FROM chunk_vectors WHERE document_id = ?1", [doc_id])?;
    let mut stmt = conn.prepare(
        "INSERT INTO chunk_vectors(document_id, chunk_no, start, end, model, vector)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (no, (chunk, v)) in items.iter().enumerate() {
        stmt.execute(params![
            doc_id,
            no as i64,
            chunk.start as i64,
            chunk.end as i64,
            model,
            vec_to_blob(v)
        ])?;
    }
    drop(stmt);
    set_embed_status(conn, doc_id, "done")
}

/// Replace all vectors of a document in one transaction.
pub fn replace_vectors(
    conn: &Connection,
    doc_id: &str,
    model: &str,
    items: &[(Chunk, Vec<f32>)],
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    write_vectors(&tx, doc_id, model, items)?;
    tx.commit()?;
    Ok(())
}

/// Race guard: inside ONE write transaction, re-check that the document still
/// has the text the vectors were computed from and that its effective
/// `semantic_index` is still `full`. Only then write. Returns whether the
/// vectors were stored; otherwise they are discarded.
pub fn replace_vectors_guarded(
    conn: &Connection,
    doc_id: &str,
    model: &str,
    text: &str,
    items: &[(Chunk, Vec<f32>)],
) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let current: Option<String> = tx
        .query_row(
            "SELECT content FROM document_text WHERE document_id = ?1",
            [doc_id],
            |r| r.get(0),
        )
        .optional()?;
    let ok = current.as_deref() == Some(text)
        && effective_level(&tx, doc_id, Channel::SemanticIndex, Level::Full)? == Level::Full;
    if ok {
        write_vectors(&tx, doc_id, model, items)?;
        tx.commit()?;
    }
    Ok(ok)
}

pub fn vector_count(conn: &Connection, doc_id: &str) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT count(*) FROM chunk_vectors WHERE document_id = ?1",
        [doc_id],
        |r| r.get(0),
    )?)
}

/// One stored chunk vector.
#[derive(Debug, Clone)]
pub struct StoredVector {
    pub chunk_no: usize,
    pub start: usize,
    pub end: usize,
    pub model: String,
    pub vector: Vec<f32>,
}

/// All stored vectors of a document, in chunk order.
pub fn get_vectors(conn: &Connection, doc_id: &str) -> Result<Vec<StoredVector>> {
    let mut stmt = conn.prepare(
        "SELECT chunk_no, start, end, model, vector FROM chunk_vectors
         WHERE document_id = ?1 ORDER BY chunk_no",
    )?;
    let rows = stmt.query_map([doc_id], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (no, s, e, m, b) = row?;
        out.push(StoredVector {
            chunk_no: no as usize,
            start: s as usize,
            end: e as usize,
            model: m,
            vector: blob_to_vec(&b),
        });
    }
    Ok(out)
}

/// Is `doc_id` eligible for, and missing, vectors of `model`? Effective
/// `semantic_index` = full, text done, no vectors for `model`, and not
/// already finished with an empty text.
pub fn needs_embedding(conn: &Connection, doc_id: &str, model: &str) -> Result<bool> {
    let row: Option<(String, String, bool, bool)> = conn
        .query_row(
            "SELECT d.text_status, d.embed_status,
                    EXISTS(SELECT 1 FROM chunk_vectors v WHERE v.document_id = d.id AND v.model = ?2),
                    EXISTS(SELECT 1 FROM chunk_vectors v WHERE v.document_id = d.id)
             FROM documents d WHERE d.id = ?1",
            params![doc_id, model],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((text_status, embed_status, has_model, has_any)) = row else {
        return Ok(false);
    };
    if text_status != "done" || has_model {
        return Ok(false);
    }
    // A document whose text has no chunks was embedded (to nothing) already.
    if embed_status == "done" && !has_any {
        return Ok(false);
    }
    Ok(effective_level(conn, doc_id, Channel::SemanticIndex, Level::Full)? == Level::Full)
}

/// Documents whose effective `semantic_index` is full, whose text is done and
/// that have no vectors for `model` (this also covers a model change).
pub fn docs_needing_embedding(conn: &Connection, model: &str) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT id FROM documents WHERE text_status = 'done' ORDER BY created_at, id")?;
    let ids: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);
    let mut out = Vec::new();
    for id in ids {
        if needs_embedding(conn, &id, model)? {
            out.push(id);
        }
    }
    Ok(out)
}

/// Deletes the vectors of `doc_id` unless its effective `semantic_index` is
/// full. The switchboard writers call this themselves, so lowering the level
/// always removes vectors synchronously.
pub(crate) fn enforce_document(conn: &Connection, doc_id: &str) -> Result<()> {
    if effective_level(conn, doc_id, Channel::SemanticIndex, Level::Full)? != Level::Full {
        let held: bool = conn
            .query_row(
                "SELECT d.embed_status <> 'none'
                     OR EXISTS(SELECT 1 FROM chunk_vectors v WHERE v.document_id = d.id)
                 FROM documents d WHERE d.id = ?1",
                [doc_id],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false);
        if held {
            delete_vectors(conn, doc_id)?;
        }
    }
    Ok(())
}

/// [`enforce_document`] for every document (after a default changed).
pub(crate) fn enforce_all(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT id FROM documents WHERE embed_status <> 'none'
            OR EXISTS(SELECT 1 FROM chunk_vectors v WHERE v.document_id = documents.id)",
    )?;
    let ids: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);
    for id in ids {
        enforce_document(conn, &id)?;
    }
    Ok(())
}
