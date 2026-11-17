//! Documents, tags, extracted text, FTS index and search.

use anyhow::{Result, anyhow};
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use serde::Serialize;

use super::access::{AccessFilter, Channel, Level, base_default};

#[derive(Clone, Copy, PartialEq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TextStatus {
    Pending,
    Done,
    Failed,
    Unsupported,
}

impl TextStatus {
    pub fn as_str(self) -> &'static str {
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

/// Where a document's searchable text came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TextSource {
    /// pdftotext / OCR.
    Ocr,
    /// Written by the user's own AI assistant over MCP (handwriting).
    Transcription,
    /// No text.
    None,
}

impl TextSource {
    pub fn as_str(self) -> &'static str {
        match self {
            TextSource::Ocr => "ocr",
            TextSource::Transcription => "transcription",
            TextSource::None => "none",
        }
    }

    fn parse(s: &str) -> Option<TextSource> {
        match s {
            "ocr" => Some(TextSource::Ocr),
            "transcription" => Some(TextSource::Transcription),
            "none" => Some(TextSource::None),
            _ => None,
        }
    }
}

/// Longest `notes` value, in characters.
pub const NOTES_MAX_CHARS: usize = 2000;

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
    /// User-typed keywords; metadata (searchable at the metadata level).
    pub notes: String,
    pub text_source: TextSource,
    pub tags: Vec<String>,
}

#[derive(Default, Clone)]
pub struct ListFilter {
    pub tags_all: Vec<String>,
    /// ANY of these tag ids.
    pub tag_allow: Option<Vec<i64>>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    /// Only documents tagged `handwritten` whose text is not yet a
    /// transcription (`text_source` is not `transcription`). Needs a v3+ index.
    pub needs_transcription: bool,
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
     d.sha256, d.document_date, d.created_at, d.updated_at, d.text_status, d.page_count, \
     d.notes, d.text_source";

/// [`DOC_COLS`] for an index DB older than v3 (opened read-only for recovery
/// and never migrated): the missing columns read as their defaults.
const DOC_COLS_PRE_V3: &str = "d.id, d.wrapped_dek, d.original_filename, d.title, d.mime, d.size, \
     d.sha256, d.document_date, d.created_at, d.updated_at, d.text_status, d.page_count, \
     '' AS notes, 'ocr' AS text_source";

/// The document column list that matches the schema version of `conn`.
fn doc_cols(conn: &Connection) -> &'static str {
    match conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
        Ok(v) if v < 3 => DOC_COLS_PRE_V3,
        _ => DOC_COLS,
    }
}

/// Index of the first column after the document columns.
const AFTER_DOC_COLS: usize = 14;

fn map_doc(r: &rusqlite::Row<'_>) -> rusqlite::Result<Document> {
    let sha: Vec<u8> = r.get(6)?;
    let status: String = r.get(10)?;
    let source: String = r.get(13)?;
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
        notes: r.get(12)?,
        text_source: TextSource::parse(&source).ok_or_else(|| bad("bad text_source"))?,
        tags: Vec::new(),
    })
}

pub(crate) fn load_tags(conn: &Connection, doc: &mut Document) -> Result<()> {
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
        "INSERT INTO documents_fts(doc_id, title, filename, tags, notes, content)
         SELECT d.id, d.title, d.original_filename,
                COALESCE((SELECT group_concat(name, ' ') FROM
                    (SELECT t.name FROM document_tags dt JOIN tags t ON t.id = dt.tag_id
                     WHERE dt.document_id = d.id ORDER BY t.name)), ''),
                d.notes,
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

/// Tags attached to at least one document visible under `f` (switchboard access
/// and tag allow-list). Ignores `tags_all`, dates and paging. Orphan tags are
/// never returned.
pub fn list_tags_visible(conn: &Connection, f: &ListFilter) -> Result<Vec<(i64, String)>> {
    let mut params: Vec<Value> = Vec::new();
    let mut sql = String::from(
        "SELECT t.id, t.name FROM tags t WHERE t.id IN \
         (SELECT dt2.tag_id FROM documents d JOIN document_tags dt2 ON dt2.document_id = d.id",
    );
    access_clause(conn, f, &mut sql, &mut params)?;
    tag_allow_condition(f, &mut sql, &mut params);
    sql.push(')');
    // A restricted token never learns the names of tags outside its allow-list,
    // even when a visible document carries them.
    if let Some(ids) = &f.tag_allow {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let marks = vec!["?"; ids.len()].join(",");
        sql.push_str(&format!(" AND t.id IN ({marks})"));
        params.extend(ids.iter().map(|i| Value::Integer(*i)));
    }
    sql.push_str(" ORDER BY t.name");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params), |r| Ok((r.get(0)?, r.get(1)?)))?;
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
            &format!("SELECT {} FROM documents d WHERE d.id = ?1", doc_cols(conn)),
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
                "SELECT {} FROM documents d WHERE d.sha256 = ?1 ORDER BY d.created_at LIMIT 1",
                doc_cols(conn)
            ),
            [sha.as_slice()],
            map_doc,
        )
        .optional()?;
    finish_one(conn, doc)
}

/// Like [`find_by_sha256`], but only documents visible under `f` count.
pub fn find_by_sha256_visible(
    conn: &Connection,
    sha: &[u8; 32],
    f: &ListFilter,
) -> Result<Option<Document>> {
    let mut params: Vec<Value> = Vec::new();
    let mut sql = format!("SELECT {} FROM documents d", doc_cols(conn));
    access_clause(conn, f, &mut sql, &mut params)?;
    tag_allow_condition(f, &mut sql, &mut params);
    sql.push_str(" AND d.sha256 = ? ORDER BY d.created_at, d.id LIMIT 1");
    params.push(Value::Blob(sha.to_vec()));
    let doc = conn
        .query_row(&sql, params_from_iter(params), map_doc)
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

/// The token tag allow-list: the document carries ANY of the allowed tag ids.
fn tag_allow_condition(f: &ListFilter, sql: &mut String, params: &mut Vec<Value>) {
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
}

/// Append the switchboard join and the start of the WHERE clause (documents
/// aliased `d`). Always leaves a WHERE clause so callers can append " AND ...".
fn access_clause(
    conn: &Connection,
    f: &ListFilter,
    sql: &mut String,
    params: &mut Vec<Value>,
) -> Result<()> {
    if let Some(a) = f.access {
        let default = base_default(conn, a.channel)?;
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
    Ok(())
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
    tag_allow_condition(f, sql, params);
    if let Some(from) = &f.date_from {
        sql.push_str(" AND d.document_date >= ?");
        params.push(Value::Text(from.clone()));
    }
    if let Some(to) = &f.date_to {
        sql.push_str(" AND d.document_date <= ?");
        params.push(Value::Text(to.clone()));
    }
    if f.needs_transcription {
        sql.push_str(
            " AND d.text_source != 'transcription' AND EXISTS (SELECT 1 FROM document_tags dt \
             JOIN tags t ON t.id = dt.tag_id WHERE dt.document_id = d.id AND t.name = 'handwritten')",
        );
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
    let mut sql = format!("SELECT {} FROM documents d", doc_cols(conn));
    access_clause(conn, f, &mut sql, &mut params)?;
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

/// Documents a semantic search may read vectors of: effective level of the
/// filter's channel (`mcp` or `web`) `Full` under the filter's cap (which must itself be `Full`), effective
/// `semantic_index` `Full`, plus the tag allow-list and date filters. Decided
/// in SQL; no limit. `f.access` must be `Some(Mcp | Web, Full)` or nothing
/// matches. The documents come without tags (the caller loads them for the few it keeps).
pub(crate) fn semantic_candidates(conn: &Connection, f: &ListFilter) -> Result<Vec<Document>> {
    let Some(a) = f.access else {
        return Ok(vec![]);
    };
    // Only the content channels can search by meaning.
    if !matches!(a.channel, Channel::Mcp | Channel::Web) || a.cap != Level::Full {
        return Ok(vec![]);
    }
    let mut params: Vec<Value> = vec![Value::Text(Channel::SemanticIndex.as_str().into())];
    let mut sql = format!(
        "SELECT {} FROM documents d \
         LEFT JOIN document_access s ON s.document_id = d.id AND s.channel = ?",
        doc_cols(conn)
    );
    access_clause(conn, f, &mut sql, &mut params)?;
    sql.push_str(" AND COALESCE(a.level, ?) = 'full'");
    params.push(Value::Text(base_default(conn, a.channel)?.as_str().into()));
    sql.push_str(" AND COALESCE(s.level, ?) = 'full'");
    params.push(Value::Text(
        base_default(conn, Channel::SemanticIndex)?.as_str().into(),
    ));
    filter_conditions(f, &mut sql, &mut params);
    sql.push_str(" ORDER BY d.id");
    let mut stmt = conn.prepare(&sql)?;
    let docs: Vec<Document> = stmt
        .query_map(params_from_iter(params), map_doc)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(docs)
}

/// Documents whose effective level on `channel` is off (the raw level, or the
/// channel default when there is no override), newest first. One query.
pub fn hidden_from(conn: &Connection, channel: Channel) -> Result<Vec<Document>> {
    let default = base_default(conn, channel)?;
    let sql = format!(
        "SELECT {} FROM documents d \
         LEFT JOIN document_access a ON a.document_id = d.id AND a.channel = ?1 \
         WHERE COALESCE(a.level, ?2) = 'off' \
         ORDER BY d.created_at DESC, d.id",
        doc_cols(conn)
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut docs: Vec<Document> = stmt
        .query_map(params![channel.as_str(), default.as_str()], map_doc)?
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
    update_document_meta_notes(conn, id, title, document_date, tags, None, now)
}

/// [`update_document_meta`] plus the notes, all in one transaction.
pub fn update_document_meta_notes(
    conn: &Connection,
    id: &str,
    title: Option<&str>,
    document_date: Option<Option<&str>>,
    tags: Option<&[String]>,
    notes: Option<&str>,
    now: i64,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    if let Some(n) = notes {
        tx.execute(
            "UPDATE documents SET notes = ?2 WHERE id = ?1",
            params![id, n],
        )?;
    }
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
    now: i64,
) -> Result<()> {
    let source = if text.is_some() {
        TextSource::Ocr
    } else {
        TextSource::None
    };
    set_text_from(conn, id, status, text, page_count, source, now)
}

/// Stores a background extraction result, unless the user's AI transcribed
/// the document meanwhile (the check and the write are one transaction, so a
/// transcription can never be overwritten by a late OCR result). `false`
/// means the transcription was kept and nothing changed.
pub fn set_extracted_text(
    conn: &Connection,
    id: &str,
    status: TextStatus,
    text: Option<&str>,
    page_count: Option<u32>,
    now: i64,
) -> Result<bool> {
    let source = if text.is_some() {
        TextSource::Ocr
    } else {
        TextSource::None
    };
    set_text_from_unless_transcribed(conn, id, status, text, page_count, source, now)
}

/// Store handwriting transcribed by the user's AI: `text_source` becomes
/// `transcription`, status `done`; vectors are dropped (the caller
/// re-enqueues embedding) and the FTS row is rebuilt.
pub fn set_transcription(conn: &Connection, id: &str, text: &str, now: i64) -> Result<()> {
    // The page count is a property of the file, not of the text: keep it.
    let pages = get_document(conn, id)?
        .ok_or_else(|| anyhow!("document not found"))?
        .page_count;
    set_text_from(
        conn,
        id,
        TextStatus::Done,
        Some(text),
        pages,
        TextSource::Transcription,
        now,
    )
}

/// Set the free-form notes (metadata, searchable at the metadata level).
pub fn set_notes(conn: &Connection, id: &str, notes: &str, now: i64) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let n = tx.execute(
        "UPDATE documents SET notes = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, notes, now],
    )?;
    if n == 0 {
        return Err(anyhow!("document not found"));
    }
    reindex(&tx, id)?;
    tx.commit()?;
    Ok(())
}

fn set_text_from(
    conn: &Connection,
    id: &str,
    status: TextStatus,
    text: Option<&str>,
    page_count: Option<u32>,
    source: TextSource,
    now: i64,
) -> Result<()> {
    write_text(conn, id, status, text, page_count, source, now, false).map(|_| ())
}

fn set_text_from_unless_transcribed(
    conn: &Connection,
    id: &str,
    status: TextStatus,
    text: Option<&str>,
    page_count: Option<u32>,
    source: TextSource,
    now: i64,
) -> Result<bool> {
    write_text(conn, id, status, text, page_count, source, now, true)
}

#[allow(clippy::too_many_arguments)]
fn write_text(
    conn: &Connection,
    id: &str,
    status: TextStatus,
    text: Option<&str>,
    page_count: Option<u32>,
    source: TextSource,
    now: i64,
    keep_transcription: bool,
) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    if keep_transcription {
        let kept: Option<String> = tx
            .query_row(
                "SELECT text_source FROM documents WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if kept.as_deref() == Some(TextSource::Transcription.as_str()) {
            return Ok(false);
        }
    }
    let n = tx.execute(
        "UPDATE documents SET text_status = ?2, page_count = ?3,
            text_source = ?5, updated_at = ?4 WHERE id = ?1",
        params![
            id,
            status.as_str(),
            page_count.map(|p| p as i64),
            now,
            source.as_str()
        ],
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
    // New text invalidates its vectors; the caller re-enqueues embedding.
    tx.execute("DELETE FROM chunk_vectors WHERE document_id = ?1", [id])?;
    tx.execute(
        "UPDATE documents SET embed_status = 'none' WHERE id = ?1",
        [id],
    )?;
    reindex(&tx, id)?;
    tx.commit()?;
    Ok(true)
}

/// The extracted text of a document, if extraction produced any.
pub fn get_document_text(conn: &Connection, id: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT content FROM document_text WHERE document_id = ?1",
            [id],
            |r| r.get(0),
        )
        .optional()?)
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
///
/// With `hide_tags` the `tags` column is excluded, so a tag-restricted token
/// cannot probe the names of tags it is not allowed to see.
fn build_match(text: &str, metadata_only: bool, hide_tags: bool) -> Option<String> {
    let terms: Vec<String> = text
        .split_whitespace()
        .map(|t| {
            t.chars()
                .filter(|c| *c != '"' && !c.is_control())
                .collect::<String>()
        })
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
    Some(match (metadata_only, hide_tags) {
        (true, false) => format!("{{title filename tags notes}} : ({joined})"),
        (true, true) => format!("{{title filename notes}} : ({joined})"),
        (false, true) => format!("{{title filename notes content}} : ({joined})"),
        (false, false) => joined,
    })
}

pub fn search(conn: &Connection, text: &str, f: &ListFilter) -> Result<Vec<SearchHit>> {
    let hide_tags = f.tag_allow.is_some();
    let (Some(full_expr), Some(meta_expr)) = (
        build_match(text, false, hide_tags),
        build_match(text, true, hide_tags),
    ) else {
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
        // Column 5 is `content`; a restricted token must never get a snippet
        // taken from the `tags` column.
        let snippet_col = match (level == Level::Full, hide_tags) {
            (true, false) => "snippet(documents_fts, -1, char(2), char(3), '…', 12)",
            (true, true) => "snippet(documents_fts, 5, char(2), char(3), '…', 12)",
            (false, _) => "NULL",
        };
        let mut sql = format!(
            "SELECT {}, bm25(documents_fts), {snippet_col} FROM documents_fts \
             JOIN documents d ON d.id = documents_fts.doc_id",
            doc_cols(conn)
        );
        if let (Some(a), Some(raw)) = (f.access, &raw) {
            let default = base_default(conn, a.channel)?;
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
                r.get::<_, f64>(AFTER_DOC_COLS)?,
                r.get::<_, Option<String>>(AFTER_DOC_COLS + 1)?,
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
