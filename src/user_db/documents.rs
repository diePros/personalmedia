//! Documents, tags, extracted text, FTS index and search.

use anyhow::{Result, anyhow};
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use serde::Serialize;

use super::access::{AccessFilter, Level, get_access_defaults};

#[derive(Clone, Copy, PartialEq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TextStatus {
    Pending,
    Done,
    Failed,
    Unsupported,
}

impl TextStatus {
    fn as_str(self) -> &'static str {
        match self {
            TextStatus::Pending => "pending",
            TextStatus::Done => "done",
            TextStatus::Failed => "failed",
            TextStatus::Unsupported => "unsupported",
        }
    }

    fn parse(s: &str) -> Option<TextStatus> {
        match s {
            "pending" => Some(TextStatus::Pending),
            "done" => Some(TextStatus::Done),
            "failed" => Some(TextStatus::Failed),
            "unsupported" => Some(TextStatus::Unsupported),
            _ => None,
        }
    }
}

pub struct NewDocument {
    pub id: String,
    pub wrapped_dek: Vec<u8>,
    pub original_filename: String,
    pub title: String,
    pub mime: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub document_date: Option<String>,
    pub tags: Vec<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Document {
    pub id: String,
    #[serde(skip)]
    pub wrapped_dek: Vec<u8>,
    pub original_filename: String,
    pub title: String,
    pub mime: String,
    pub size: u64,
    pub sha256_hex: String,
    pub document_date: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub text_status: TextStatus,
    pub page_count: Option<u32>,
    pub tags: Vec<String>,
}

#[derive(Default, Clone)]
pub struct ListFilter {
    pub tags_all: Vec<String>,
    /// ANY of these tag ids.
    pub tag_allow: Option<Vec<i64>>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    /// `None` = no switchboard restrictions (export/recovery only).
    pub access: Option<AccessFilter>,
    /// 0 means 50.
    pub limit: u32,
    pub offset: u32,
}

impl ListFilter {
    fn limit(&self) -> i64 {
        if self.limit == 0 {
            50
        } else {
            self.limit as i64
        }
    }
}

pub struct SearchHit {
    pub doc: Document,
    pub level: Level,
    pub snippet: Option<String>,
}

const DOC_COLS: &str = "d.id, d.wrapped_dek, d.original_filename, d.title, d.mime, d.size, \
     d.sha256, d.document_date, d.created_at, d.updated_at, d.text_status, d.page_count";

fn map_doc(r: &rusqlite::Row<'_>) -> rusqlite::Result<Document> {
    let sha: Vec<u8> = r.get(6)?;
    let status: String = r.get(10)?;
    let bad = |what: &str| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            what.to_string().into(),
        )
    };
    Ok(Document {
        id: r.get(0)?,
        wrapped_dek: r.get(1)?,
        original_filename: r.get(2)?,
        title: r.get(3)?,
        mime: r.get(4)?,
        size: r.get::<_, i64>(5)? as u64,
        sha256_hex: hex::encode(sha),
        document_date: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
        text_status: TextStatus::parse(&status).ok_or_else(|| bad("bad text_status"))?,
        page_count: r.get::<_, Option<i64>>(11)?.map(|p| p as u32),
        tags: Vec::new(),
    })
}

fn load_tags(conn: &Connection, doc: &mut Document) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "SELECT t.name FROM document_tags dt JOIN tags t ON t.id = dt.tag_id
         WHERE dt.document_id = ?1 ORDER BY t.name",
    )?;
    doc.tags = stmt
        .query_map([&doc.id], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(())
}

fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim();
        if !t.is_empty() && !out.iter().any(|o| o == t) {
            out.push(t.to_string());
        }
    }
    out
}

/// Delete and re-insert the FTS row from current table contents.
fn reindex(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM documents_fts WHERE doc_id = ?1", [id])?;
    conn.execute(
        "INSERT INTO documents_fts(doc_id, title, filename, tags, content)
         SELECT d.id, d.title, d.original_filename,
                COALESCE((SELECT group_concat(name, ' ') FROM
                    (SELECT t.name FROM document_tags dt JOIN tags t ON t.id = dt.tag_id
                     WHERE dt.document_id = d.id ORDER BY t.name)), ''),
                COALESCE((SELECT content FROM document_text WHERE document_id = d.id), '')
         FROM documents d WHERE d.id = ?1",
        [id],
    )?;
    Ok(())
}

pub fn tag_ids(conn: &Connection, names: &[String]) -> Result<Vec<i64>> {
    let mut out = Vec::new();
    for name in normalize_tags(names) {
        conn.execute("INSERT OR IGNORE INTO tags(name) VALUES (?1)", [&name])?;
        out.push(conn.query_row("SELECT id FROM tags WHERE name = ?1", [&name], |r| r.get(0))?);
    }
    Ok(out)
}

pub fn list_tags(conn: &Connection) -> Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare("SELECT id, name FROM tags ORDER BY name")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn set_doc_tags(conn: &Connection, id: &str, tags: &[String]) -> Result<()> {
    conn.execute("DELETE FROM document_tags WHERE document_id = ?1", [id])?;
    for tid in tag_ids(conn, tags)? {
        conn.execute(
            "INSERT OR IGNORE INTO document_tags(document_id, tag_id) VALUES (?1, ?2)",
            params![id, tid],
        )?;
    }
    Ok(())
}

pub fn insert_document(conn: &Connection, d: &NewDocument) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO documents(id, wrapped_dek, original_filename, title, mime, size, sha256,
            document_date, created_at, updated_at, text_status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, 'pending')",
        params![
            d.id,
            d.wrapped_dek,
            d.original_filename,
            d.title,
            d.mime,
            d.size as i64,
            d.sha256.as_slice(),
            d.document_date,
            d.created_at
        ],
    )?;
    set_doc_tags(&tx, &d.id, &d.tags)?;
    reindex(&tx, &d.id)?;
    tx.commit()?;
    Ok(())
}

pub fn get_document(conn: &Connection, id: &str) -> Result<Option<Document>> {
    let doc = conn
        .query_row(
            &format!("SELECT {DOC_COLS} FROM documents d WHERE d.id = ?1"),
            [id],
            map_doc,
        )
        .optional()?;
    finish_one(conn, doc)
}

pub fn find_by_sha256(conn: &Connection, sha: &[u8; 32]) -> Result<Option<Document>> {
    let doc = conn
        .query_row(
            &format!(
                "SELECT {DOC_COLS} FROM documents d WHERE d.sha256 = ?1 ORDER BY d.created_at LIMIT 1"
            ),
            [sha.as_slice()],
            map_doc,
        )
        .optional()?;
    finish_one(conn, doc)
}

fn finish_one(conn: &Connection, doc: Option<Document>) -> Result<Option<Document>> {
    match doc {
        Some(mut d) => {
            load_tags(conn, &mut d)?;
            Ok(Some(d))
        }
        None => Ok(None),
    }
}

/// Append filter conditions (each starting with " AND ") and their params.
fn filter_conditions(f: &ListFilter, sql: &mut String, params: &mut Vec<Value>) {
    for tag in &f.tags_all {
        sql.push_str(
            " AND EXISTS (SELECT 1 FROM document_tags dt JOIN tags t ON t.id = dt.tag_id \
             WHERE dt.document_id = d.id AND t.name = ?)",
        );
        params.push(Value::Text(tag.clone()));
    }
    if let Some(ids) = &f.tag_allow {
        if ids.is_empty() {
            sql.push_str(" AND 1 = 0");
        } else {
            let marks = vec!["?"; ids.len()].join(",");
            sql.push_str(&format!(
                " AND EXISTS (SELECT 1 FROM document_tags dt WHERE dt.document_id = d.id \
                 AND dt.tag_id IN ({marks}))"
            ));
            params.extend(ids.iter().map(|i| Value::Integer(*i)));
        }
    }
    if let Some(from) = &f.date_from {
        sql.push_str(" AND d.document_date >= ?");
        params.push(Value::Text(from.clone()));
    }
    if let Some(to) = &f.date_to {
        sql.push_str(" AND d.document_date <= ?");
        params.push(Value::Text(to.clone()));
    }
}

/// Raw (pre-cap) levels whose effective level is `target` under `cap`.
fn raw_levels_for(target: Level, cap: Level) -> Vec<&'static str> {
    [Level::Metadata, Level::Full]
        .into_iter()
        .filter(|raw| (*raw).min(cap) == target)
        .map(Level::as_str)
        .collect()
}

pub fn list_documents(conn: &Connection, f: &ListFilter) -> Result<Vec<Document>> {
    let mut params: Vec<Value> = Vec::new();
    let mut sql = format!("SELECT {DOC_COLS} FROM documents d");
    if let Some(a) = f.access {
        let default = get_access_defaults(conn)?.level(a.channel);
        sql.push_str(" LEFT JOIN document_access a ON a.document_id = d.id AND a.channel = ?");
        params.push(Value::Text(a.channel.as_str().into()));
        // Effective level is Off when the raw level is off or the cap is off.
        sql.push_str(" WHERE COALESCE(a.level, ?) != 'off'");
        params.push(Value::Text(default.as_str().into()));
        if a.cap == Level::Off {
            sql.push_str(" AND 1 = 0");
        }
    } else {
        sql.push_str(" WHERE 1 = 1");
    }
    filter_conditions(f, &mut sql, &mut params);
    sql.push_str(" ORDER BY d.created_at DESC, d.id LIMIT ? OFFSET ?");
    params.push(Value::Integer(f.limit()));
    params.push(Value::Integer(f.offset as i64));
    let mut stmt = conn.prepare(&sql)?;
    let mut docs: Vec<Document> = stmt
        .query_map(params_from_iter(params), map_doc)?
        .collect::<rusqlite::Result<_>>()?;
    for d in &mut docs {
        load_tags(conn, d)?;
    }
    Ok(docs)
}

pub fn update_document_meta(
    conn: &Connection,
    id: &str,
    title: Option<&str>,
    document_date: Option<Option<&str>>,
    tags: Option<&[String]>,
    now: i64,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    if let Some(t) = title {
        tx.execute(
            "UPDATE documents SET title = ?2 WHERE id = ?1",
            params![id, t],
        )?;
    }
    if let Some(date) = document_date {
        tx.execute(
            "UPDATE documents SET document_date = ?2 WHERE id = ?1",
            params![id, date],
        )?;
    }
    if let Some(tags) = tags {
        set_doc_tags(&tx, id, tags)?;
    }
    tx.execute(
        "UPDATE documents SET updated_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    reindex(&tx, id)?;
    tx.commit()?;
    Ok(())
}

pub fn delete_document(conn: &Connection, id: &str) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM documents_fts WHERE doc_id = ?1", [id])?;
    tx.execute("DELETE FROM documents WHERE id = ?1", [id])?;
    tx.commit()?;
    Ok(())
}

pub fn set_text(
    conn: &Connection,
    id: &str,
    status: TextStatus,
    text: Option<&str>,
    page_count: Option<u32>,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let n = tx.execute(
        "UPDATE documents SET text_status = ?2, page_count = ?3 WHERE id = ?1",
        params![id, status.as_str(), page_count.map(|p| p as i64)],
    )?;
    if n == 0 {
        return Err(anyhow!("document not found"));
    }
    match text {
        Some(t) => {
            tx.execute(
                "INSERT INTO document_text(document_id, content) VALUES (?1, ?2)
                 ON CONFLICT(document_id) DO UPDATE SET content = excluded.content",
                params![id, t],
            )?;
        }
        None => {
            tx.execute("DELETE FROM document_text WHERE document_id = ?1", [id])?;
        }
    }
    reindex(&tx, id)?;
    tx.commit()?;
    Ok(())
}

pub fn pending_document_ids(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT id FROM documents WHERE text_status = 'pending' ORDER BY created_at, id",
    )?;
    Ok(stmt
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?)
}

/// Build an FTS5 expression from user text: every term is a quoted literal, the
/// last one is a prefix match, terms are ANDed. `None` if nothing is left.
fn build_match(text: &str, metadata_only: bool) -> Option<String> {
    let terms: Vec<String> = text
        .split_whitespace()
        .map(|t| t.replace('"', ""))
        .filter(|t| !t.is_empty())
        .collect();
    let last = terms.len().checked_sub(1)?;
    let joined = terms
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if i == last {
                format!("\"{t}\"*")
            } else {
                format!("\"{t}\"")
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(if metadata_only {
        format!("{{title filename tags}} : ({joined})")
    } else {
        joined
    })
}

pub fn search(conn: &Connection, text: &str, f: &ListFilter) -> Result<Vec<SearchHit>> {
    let (Some(full_expr), Some(meta_expr)) = (build_match(text, false), build_match(text, true))
    else {
        return Ok(vec![]);
    };
    // (target level, raw levels to select, expression)
    let mut passes: Vec<(Level, Option<Vec<&'static str>>, String)> = Vec::new();
    match f.access {
        None => passes.push((Level::Full, None, full_expr)),
        Some(a) => {
            let full_raw = raw_levels_for(Level::Full, a.cap);
            if !full_raw.is_empty() {
                passes.push((Level::Full, Some(full_raw), full_expr));
            }
            let meta_raw = raw_levels_for(Level::Metadata, a.cap);
            if !meta_raw.is_empty() {
                passes.push((Level::Metadata, Some(meta_raw), meta_expr));
            }
        }
    }
    let want = f.limit() + f.offset as i64;
    let mut hits: Vec<(f64, SearchHit)> = Vec::new();
    for (level, raw, expr) in passes {
        let mut params: Vec<Value> = Vec::new();
        let snippet_col = if level == Level::Full {
            "snippet(documents_fts, -1, char(2), char(3), '…', 12)"
        } else {
            "NULL"
        };
        let mut sql = format!(
            "SELECT {DOC_COLS}, bm25(documents_fts), {snippet_col} FROM documents_fts \
             JOIN documents d ON d.id = documents_fts.doc_id"
        );
        if let (Some(a), Some(raw)) = (f.access, &raw) {
            let default = get_access_defaults(conn)?.level(a.channel);
            sql.push_str(" LEFT JOIN document_access a ON a.document_id = d.id AND a.channel = ?");
            params.push(Value::Text(a.channel.as_str().into()));
            sql.push_str(" WHERE documents_fts MATCH ?");
            params.push(Value::Text(expr));
            let marks = vec!["?"; raw.len()].join(",");
            sql.push_str(&format!(" AND COALESCE(a.level, ?) IN ({marks})"));
            params.push(Value::Text(default.as_str().into()));
            params.extend(raw.iter().map(|s| Value::Text((*s).into())));
        } else {
            sql.push_str(" WHERE documents_fts MATCH ?");
            params.push(Value::Text(expr));
        }
        filter_conditions(f, &mut sql, &mut params);
        sql.push_str(" ORDER BY bm25(documents_fts), d.id LIMIT ?");
        params.push(Value::Integer(want));
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(params), |r| {
            Ok((
                map_doc(r)?,
                r.get::<_, f64>(12)?,
                r.get::<_, Option<String>>(13)?,
            ))
        })?;
        for row in rows {
            let (doc, rank, snippet) = row?;
            hits.push((
                rank,
                SearchHit {
                    doc,
                    level,
                    snippet,
                },
            ));
        }
    }
    hits.sort_by(|a, b| {
        a.0.total_cmp(&b.0)
            .then_with(|| a.1.doc.id.cmp(&b.1.doc.id))
    });
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<SearchHit> = Vec::new();
    for (_, mut hit) in hits {
        if seen.insert(hit.doc.id.clone()) {
            load_tags(conn, &mut hit.doc)?;
            out.push(hit);
        }
    }
    Ok(out
        .into_iter()
        .skip(f.offset as usize)
        .take(f.limit() as usize)
        .collect())
}
