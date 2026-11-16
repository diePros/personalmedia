//! ZIP export of all of a user's documents. Used by the web UI (and, in
//! Task 15, by the recovery CLI).
//!
//! The archive holds every document, hidden ones included (it is the owner's
//! own data, so the switchboard does not apply): `metadata.json` first, then
//! `files/{safe name}` for each document. Entries are stored uncompressed and
//! written in streaming mode, so the output can be any `Write`.

use std::collections::HashSet;
use std::io::{self, Write};

use anyhow::Context;
use serde::Serialize;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::documents::Documents;
use crate::keyring::Unlocked;
use crate::user_db::{Document, ListFilter, list_documents};

const NAME_MAX_BYTES: usize = 150;
const PAGE: u32 = 500;

/// A file name that is safe inside a ZIP: UTF-8 is kept, but path separators
/// and control characters are replaced by `_`, and leading `.`, `/` and `\`
/// are dropped, so the result can never escape the extraction directory.
fn safe_name(original: &str) -> String {
    let trimmed = original.trim_start_matches(['.', '/', '\\']);
    let mut s: String = trimmed
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .collect();
    // "a..b" is harmless, but keep "no `..` anywhere" an easy invariant.
    while s.contains("..") {
        s = s.replace("..", ".");
    }
    let s = s.trim();
    if s.is_empty() || s == "." {
        return "document".to_owned();
    }
    truncate_keeping_extension(s, NAME_MAX_BYTES)
}

fn truncate_keeping_extension(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let ext = s.rfind('.').map(|i| &s[i..]).filter(|e| e.len() <= 20);
    let ext = ext.unwrap_or("");
    let mut end = max - ext.len();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let stem_end = s.rfind('.').filter(|_| !ext.is_empty()).unwrap_or(s.len());
    let mut out = s[..end.min(stem_end)].to_owned();
    out.push_str(ext);
    out
}

/// `(document id, zip path)` for every document, in the given order. A name
/// that is already taken gets ` (2)`, ` (3)`, ... before the extension.
/// Collisions are detected case-insensitively, so the archive also extracts
/// cleanly on case-insensitive file systems.
pub fn plan_entries(docs: &[Document]) -> Vec<(String, String)> {
    let mut used: HashSet<String> = HashSet::new();
    docs.iter()
        .map(|d| {
            let name = safe_name(&d.original_filename);
            let (stem, ext) = match name.rfind('.') {
                Some(i) if i > 0 => (&name[..i], &name[i..]),
                _ => (name.as_str(), ""),
            };
            let mut candidate = name.clone();
            let mut n = 1;
            while !used.insert(candidate.to_lowercase()) {
                n += 1;
                candidate = format!("{stem} ({n}){ext}");
            }
            (d.id.clone(), format!("files/{candidate}"))
        })
        .collect()
}

#[derive(Serialize)]
struct MetaEntry<'a> {
    id: &'a str,
    title: &'a str,
    original_filename: &'a str,
    zip_path: &'a str,
    mime: &'a str,
    document_date: Option<&'a str>,
    tags: &'a [String],
    created_at: i64,
}

/// The pretty-printed `metadata.json` for `docs` and their `plan` (as made by
/// [`plan_entries`]). Shared by the ZIP export and the recovery CLI.
pub fn metadata_json(docs: &[Document], plan: &[(String, String)]) -> anyhow::Result<Vec<u8>> {
    let meta: Vec<MetaEntry> = docs
        .iter()
        .zip(plan)
        .map(|(d, (_, path))| MetaEntry {
            id: &d.id,
            title: &d.title,
            original_filename: &d.original_filename,
            zip_path: path,
            mime: &d.mime,
            document_date: d.document_date.as_deref(),
            tags: &d.tags,
            created_at: d.created_at,
        })
        .collect();
    Ok(serde_json::to_vec_pretty(&meta)?)
}

/// Every document of the user, oldest first. Ignores the switchboard.
pub fn all_documents(u: &Unlocked) -> anyhow::Result<Vec<Document>> {
    let mut all = Vec::new();
    let mut offset = 0;
    loop {
        let filter = ListFilter {
            limit: PAGE,
            offset,
            ..ListFilter::default()
        };
        let page = u.with_db(|c| list_documents(c, &filter))?;
        let n = page.len() as u32;
        all.extend(page);
        if n < PAGE {
            break;
        }
        offset += n;
    }
    all.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    Ok(all)
}

/// Write the export ZIP to `out` and return it. Blocking: call it from
/// `spawn_blocking`.
pub fn write_export<W: Write>(docs: &Documents, u: &Unlocked, out: W) -> anyhow::Result<W> {
    let all = all_documents(u)?;
    let plan = plan_entries(&all);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .large_file(true);
    let mut zip = ZipWriter::new_stream(out);

    zip.start_file("metadata.json", options)?;
    zip.write_all(&metadata_json(&all, &plan)?)?;

    for (id, path) in &plan {
        let (_, mut reader) = docs
            .open_plaintext(u, id)
            .map_err(|e| anyhow::anyhow!("opening a document for export: {e}"))?;
        zip.start_file(path.as_str(), options)?;
        io::copy(&mut reader, &mut zip).context("writing document to export")?;
    }
    Ok(zip.finish()?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitized() {
        assert_eq!(safe_name("../a.pdf"), "a.pdf");
        assert_eq!(safe_name("/etc/passwd"), "etc_passwd");
        assert_eq!(safe_name("..\\..\\x.txt"), "x.txt");
        assert_eq!(safe_name("a/b\\c.txt"), "a_b_c.txt");
        assert_eq!(safe_name("a..b.txt"), "a.b.txt");
        assert_eq!(safe_name("Rechnung für März.pdf"), "Rechnung für März.pdf");
        assert_eq!(safe_name("..."), "document");
        assert_eq!(safe_name("a\nb"), "a_b");
    }

    #[test]
    fn long_names_keep_extension_and_char_boundaries() {
        let long = format!("{}.pdf", "ä".repeat(200));
        let n = safe_name(&long);
        assert!(n.len() <= NAME_MAX_BYTES);
        assert!(n.ends_with(".pdf"));
    }
}
