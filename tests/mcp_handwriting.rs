//! Handwriting through the user's own AI: `get_page_image`,
//! `set_transcription`, `set_notes` (Task 32).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, header};
use bytes::Bytes;
use common::*;
use data_encoding::BASE64;
use futures_util::stream;
use personal_media::documents::{OnDuplicate, UploadMeta};
use personal_media::keyring::Unlocked;
use personal_media::tokens::create_token;
use personal_media::user_db::vectors::{replace_vectors, vector_count};
use personal_media::user_db::{
    Access, Channel, Content, Level, TextSource, TextStatus, TokenScope, get_document,
    get_document_text, set_document_access, set_text, tag_ids,
};
use serde_json::{Value, json};

const JPG1: &[u8] = include_bytes!("fixtures/scan1.jpg");
const JPG2: &[u8] = include_bytes!("fixtures/scan2.jpg");

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Fx {
    t: TestApp,
    u: Arc<Unlocked>,
}

impl Fx {
    fn new() -> Fx {
        let t = TestApp::new();
        let c = t.session_for("alice");
        let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
        Fx { t, u }
    }

    fn token(&self, access: Access, content: Content, tags: Option<&[&str]>) -> String {
        let ids = tags.map(|names| {
            let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            self.u.with_db(|c| tag_ids(c, &names)).unwrap()
        });
        let scope = TokenScope {
            access,
            content,
            tags: ids,
        };
        create_token(&self.t.state.sys, &self.u, "claude", scope, now()).unwrap()
    }

    /// Stores `bytes` as `mime` with the MCP level `mcp` and waits until
    /// the background extraction is over (so it cannot overwrite test text).
    async fn doc(&self, name: &str, mime: &str, bytes: &[u8], tags: &[&str], mcp: Level) -> String {
        let meta = UploadMeta {
            filename: name.to_owned(),
            mime: Some(mime.to_owned()),
            title: Some(format!("title of {name}")),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            document_date: None,
        };
        let body = stream::once(std::future::ready(Ok::<_, anyhow::Error>(Bytes::from(
            bytes.to_vec(),
        ))));
        let out = self
            .t
            .state
            .docs
            .store(
                &self.u,
                meta,
                Box::pin(body),
                OnDuplicate::Keep,
                None,
                now(),
            )
            .await
            .unwrap();
        let id = serde_json::to_value(out).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        for _ in 0..2400 {
            let st = self
                .u
                .with_db(|c| get_document(c, &id))
                .unwrap()
                .unwrap()
                .text_status;
            if st != TextStatus::Pending {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        self.u
            .with_db(|c| set_document_access(c, &id, Channel::Mcp, Some(mcp)))
            .unwrap();
        id
    }

    async fn two_page_pdf(&self, mcp: Level) -> String {
        let pdf = personal_media::pdf::jpegs_to_pdf(&[JPG1, JPG2]).unwrap();
        self.doc("hand.pdf", "application/pdf", &pdf, &["handwritten"], mcp)
            .await
    }

    async fn post(&self, token: &str, body: &Value) -> Value {
        let b = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let resp = self
            .t
            .request(b.body(Body::from(body.to_string())).unwrap())
            .await;
        assert_eq!(resp.status().as_u16(), 200);
        serde_json::from_slice(&body_bytes(resp).await).unwrap()
    }

    /// The raw `result` of a `tools/call`.
    async fn raw_call(&self, token: &str, tool: &str, args: Value) -> Value {
        let v = self
            .post(
                token,
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                        "params":{"name":tool,"arguments":args}}),
            )
            .await;
        v["result"].clone()
    }

    /// `(is_error, parsed first text item)`.
    async fn call(&self, token: &str, tool: &str, args: Value) -> (bool, Value) {
        let r = self.raw_call(token, tool, args).await;
        let text = r["content"][0]["text"].as_str().unwrap();
        let parsed = serde_json::from_str(text).unwrap_or(Value::String(text.to_owned()));
        (r["isError"].as_bool().unwrap(), parsed)
    }

    async fn tool_names(&self, token: &str) -> Vec<String> {
        let v = self
            .post(
                token,
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            )
            .await;
        v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    }

    fn tmp_names(&self) -> Vec<std::ffi::OsString> {
        std::fs::read_dir(self.t.state.cfg.data_dir.join("tmp"))
            .map(|d| d.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default()
    }
}

/// Width and height from the first SOF marker of a JPEG.
fn jpeg_size(b: &[u8]) -> (u32, u32) {
    assert_eq!(&b[..2], [0xff, 0xd8], "not a JPEG");
    let mut i = 2;
    while i + 9 < b.len() {
        assert_eq!(b[i], 0xff);
        let m = b[i + 1];
        let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        if (0xc0..=0xcf).contains(&m) && m != 0xc4 && m != 0xc8 && m != 0xcc {
            let h = u16::from_be_bytes([b[i + 5], b[i + 6]]) as u32;
            let w = u16::from_be_bytes([b[i + 7], b[i + 8]]) as u32;
            return (w, h);
        }
        i += 2 + len;
    }
    panic!("no SOF");
}

fn image_of(r: &Value) -> Vec<u8> {
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["content"][0]["type"], "image");
    BASE64
        .decode(r["content"][0]["data"].as_str().unwrap().as_bytes())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn page_image_only_for_full_text_and_full_mcp() {
    let f = Fx::new();
    let full = f.token(Access::Read, Content::FullText, None);
    let meta_tok = f.token(Access::Read, Content::MetadataOnly, None);
    let restricted = f.token(Access::Read, Content::FullText, Some(&["other"]));
    let id = f
        .doc("a.jpg", "image/jpeg", JPG1, &["handwritten"], Level::Full)
        .await;

    // Stored image comes back as stored, with its MIME type.
    let r = f.raw_call(&full, "get_page_image", json!({"id": id})).await;
    assert_eq!(image_of(&r), JPG1);
    assert_eq!(r["content"][0]["mimeType"], "image/jpeg");
    assert_eq!(r["content"][1]["text"], "page 1 of 1");

    // Metadata-only tokens neither see nor may call the tool.
    assert!(
        !f.tool_names(&meta_tok)
            .await
            .contains(&"get_page_image".into())
    );
    assert!(f.tool_names(&full).await.contains(&"get_page_image".into()));
    let (err, msg) = f.call(&meta_tok, "get_page_image", json!({"id": id})).await;
    assert!(err);
    assert_eq!(msg, "token cannot read page images");

    // A tag allow-list that excludes the document: not found.
    let (err, msg) = f
        .call(&restricted, "get_page_image", json!({"id": id}))
        .await;
    assert!(err);
    assert_eq!(msg, "document not found");

    // The document's own override wins over a full_text token.
    f.u.with_db(|c| set_document_access(c, &id, Channel::Mcp, Some(Level::Metadata)))
        .unwrap();
    let (err, msg) = f.call(&full, "get_page_image", json!({"id": id})).await;
    assert!(err);
    assert_eq!(msg, "token cannot read page images");
    f.u.with_db(|c| set_document_access(c, &id, Channel::Mcp, Some(Level::Off)))
        .unwrap();
    let (err, msg) = f.call(&full, "get_page_image", json!({"id": id})).await;
    assert!(err);
    assert_eq!(msg, "document not found");
}

#[tokio::test(flavor = "multi_thread")]
async fn page_image_too_large_image_is_refused() {
    let f = Fx::new();
    let full = f.token(Access::Read, Content::FullText, None);
    let mut big = JPG1.to_vec();
    big.resize(4 * 1024 * 1024 + 1, 0);
    let id = f.doc("big.jpg", "image/jpeg", &big, &[], Level::Full).await;
    let (err, msg) = f.call(&full, "get_page_image", json!({"id": id})).await;
    assert!(err);
    assert_eq!(msg, "page too large for preview");
}

#[tokio::test(flavor = "multi_thread")]
async fn page_image_pdf_page_bounds() {
    let f = Fx::new();
    let full = f.token(Access::Read, Content::FullText, None);
    let id = f.two_page_pdf(Level::Full).await;

    for (page, label) in [
        (None, "page 1 of 2"),
        (Some(1), "page 1 of 2"),
        (Some(2), "page 2 of 2"),
    ] {
        let args = match page {
            Some(p) => json!({"id": id, "page": p}),
            None => json!({"id": id}),
        };
        let r = f.raw_call(&full, "get_page_image", args).await;
        let jpeg = image_of(&r);
        assert_eq!(r["content"][0]["mimeType"], "image/jpeg");
        assert_eq!(r["content"][1]["text"], label);
        let (w, h) = jpeg_size(&jpeg);
        assert!(w.max(h) <= 1568, "{w}x{h}");
        assert!(w.max(h) > 400, "{w}x{h}");
    }
    for page in [0, 3] {
        let (err, msg) = f
            .call(&full, "get_page_image", json!({"id": id, "page": page}))
            .await;
        assert!(err, "page {page}");
        assert!(msg.as_str().unwrap().contains("page"), "{msg}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn page_image_rate_limited() {
    let f = Fx::new();
    let a = f.token(Access::Read, Content::FullText, None);
    let b = f.token(Access::Read, Content::FullText, None);
    let id = f.doc("a.jpg", "image/jpeg", JPG1, &[], Level::Full).await;
    for i in 0..20 {
        let r = f.raw_call(&a, "get_page_image", json!({"id": id})).await;
        assert_eq!(r["isError"], false, "call {i}: {r}");
    }
    let (err, msg) = f.call(&a, "get_page_image", json!({"id": id})).await;
    assert!(err);
    assert_eq!(msg, "rate limit: try again in a minute");
    // Per token: another token is not affected.
    let r = f.raw_call(&b, "get_page_image", json!({"id": id})).await;
    assert_eq!(r["isError"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn page_image_rate_limit_survives_oauth_refresh() {
    let f = Fx::new();
    let id = f.doc("a.jpg", "image/jpeg", JPG1, &[], Level::Full).await;
    let scope = TokenScope {
        access: Access::Read,
        content: Content::FullText,
        tags: None,
    };
    let (_, pair) = personal_media::tokens::create_grant(
        &f.t.state.sys,
        &f.u,
        scope,
        personal_media::user_db::GrantInfo {
            client_id: "cid".into(),
            client_name: "app".into(),
            redirect_host: "claude.ai".into(),
        },
        now(),
    )
    .unwrap();
    for i in 0..20 {
        let r = f
            .raw_call(&pair.access, "get_page_image", json!({"id": id}))
            .await;
        assert_eq!(r["isError"], false, "call {i}: {r}");
    }
    // A refresh mints a new access token id; the window is the grant's.
    let state = f.t.state.clone();
    let refresh = pair.refresh.to_string();
    let fresh = tokio::task::spawn_blocking(move || {
        personal_media::tokens::refresh_grant(&state, &refresh, "cid")
    })
    .await
    .unwrap()
    .unwrap();
    let (err, msg) = f
        .call(&fresh.pair.access, "get_page_image", json!({"id": id}))
        .await;
    assert!(err);
    assert_eq!(msg, "rate limit: try again in a minute");
}

#[tokio::test(flavor = "multi_thread")]
async fn page_image_temp_files_removed() {
    let f = Fx::new();
    let full = f.token(Access::Read, Content::FullText, None);
    let id = f.two_page_pdf(Level::Full).await;
    // Entries may vanish (an OCR job finishing its cleanup), but this
    // tool's calls must not leave any new one behind.
    let before = f.tmp_names();
    let r = f
        .raw_call(&full, "get_page_image", json!({"id": id, "page": 2}))
        .await;
    image_of(&r);
    // An out-of-range request cleans up as well.
    let (err, _) = f
        .call(&full, "get_page_image", json!({"id": id, "page": 9}))
        .await;
    assert!(err);
    let left: Vec<_> = f
        .tmp_names()
        .into_iter()
        .filter(|n| !before.contains(n))
        .collect();
    assert!(left.is_empty(), "scratch dir left behind: {left:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn set_transcription_makes_text_searchable_and_reembeds() {
    let f = Fx::new();
    let rw = f.token(Access::ReadWrite, Content::FullText, None);
    let id = f.two_page_pdf(Level::Full).await;
    f.u.with_db(|c| set_document_access(c, &id, Channel::SemanticIndex, Some(Level::Full)))
        .unwrap();
    f.u.with_db(|c| set_text(c, &id, TextStatus::Done, Some("old text"), Some(2), 1))
        .unwrap();
    f.u.with_db(|c| replace_vectors(c, &id, "some-model", &[]))
        .unwrap();
    f.u.with_db(|c| {
        c.execute(
            "INSERT INTO chunk_vectors(document_id, chunk_no, start, end, model, vector)
             VALUES (?1, 0, 0, 8, 'some-model', x'00')",
            [&id],
        )
    })
    .unwrap();
    assert_eq!(f.u.with_db(|c| vector_count(c, &id)).unwrap(), 1);

    let (err, v) = f
        .call(
            &rw,
            "set_transcription",
            json!({"id": id, "text": "Dear Quokka, see you on Tuesday"}),
        )
        .await;
    assert!(!err, "{v}");

    let (_, hits) = f
        .call(&rw, "search_documents", json!({"query": "quokka"}))
        .await;
    assert_eq!(hits.as_array().unwrap().len(), 1, "{hits}");
    assert!(hits[0]["snippet"].as_str().unwrap().contains("Quokka"));
    let (_, old) = f
        .call(&rw, "search_documents", json!({"query": "old"}))
        .await;
    assert!(old.as_array().unwrap().is_empty());

    let doc = f.u.with_db(|c| get_document(c, &id)).unwrap().unwrap();
    assert_eq!(doc.text_source, TextSource::Transcription);
    assert_eq!(doc.text_status, TextStatus::Done);
    assert_eq!(doc.page_count, Some(2));
    let (_, got) = f.call(&rw, "get_document", json!({"id": id})).await;
    assert_eq!(got["text_source"], "transcription");
    assert_eq!(got["text"], "Dear Quokka, see you on Tuesday");

    // Old vectors are gone and embedding was queued again (without a model
    // the job ends as `failed`, never back at `none`).
    assert_eq!(f.u.with_db(|c| vector_count(c, &id)).unwrap(), 0);
    let status =
        f.u.with_db(|c| personal_media::user_db::vectors::get_embed_status(c, &id))
            .unwrap()
            .unwrap();
    assert_ne!(status, "none");

    // Append adds a blank line and the new text.
    let (err, _) = f
        .call(
            &rw,
            "set_transcription",
            json!({"id": id, "text": "Page two", "mode": "append"}),
        )
        .await;
    assert!(!err);
    let text = f.u.with_db(|c| get_document_text(c, &id)).unwrap().unwrap();
    assert_eq!(text, "Dear Quokka, see you on Tuesday\n\nPage two");
    // Replace is the default.
    f.call(&rw, "set_transcription", json!({"id": id, "text": "Fresh"}))
        .await;
    let text = f.u.with_db(|c| get_document_text(c, &id)).unwrap().unwrap();
    assert_eq!(text, "Fresh");
}

#[tokio::test(flavor = "multi_thread")]
async fn set_transcription_requires_write_and_full() {
    let f = Fx::new();
    let ro = f.token(Access::Read, Content::FullText, None);
    let rw_meta = f.token(Access::ReadWrite, Content::MetadataOnly, None);
    let rw = f.token(Access::ReadWrite, Content::FullText, None);
    let id = f.two_page_pdf(Level::Full).await;
    let args = json!({"id": id, "text": "x"});

    assert!(
        !f.tool_names(&ro)
            .await
            .contains(&"set_transcription".into())
    );
    assert!(
        !f.tool_names(&rw_meta)
            .await
            .contains(&"set_transcription".into())
    );
    assert!(
        f.tool_names(&rw)
            .await
            .contains(&"set_transcription".into())
    );

    let (err, msg) = f.call(&ro, "set_transcription", args.clone()).await;
    assert!(err);
    assert_eq!(msg, "token is read-only");
    let (err, _) = f.call(&rw_meta, "set_transcription", args.clone()).await;
    assert!(err);

    // The document's override beats the token.
    f.u.with_db(|c| set_document_access(c, &id, Channel::Mcp, Some(Level::Metadata)))
        .unwrap();
    let (err, _) = f.call(&rw, "set_transcription", args.clone()).await;
    assert!(err);
    f.u.with_db(|c| set_document_access(c, &id, Channel::Mcp, Some(Level::Off)))
        .unwrap();
    let (err, msg) = f.call(&rw, "set_transcription", args.clone()).await;
    assert!(err);
    assert_eq!(msg, "document not found");

    let doc = f.u.with_db(|c| get_document(c, &id)).unwrap().unwrap();
    assert_ne!(doc.text_source, TextSource::Transcription);

    // Size cap.
    f.u.with_db(|c| set_document_access(c, &id, Channel::Mcp, Some(Level::Full)))
        .unwrap();
    let (err, msg) = f
        .call(
            &rw,
            "set_transcription",
            json!({"id": id, "text": "a".repeat(500_001)}),
        )
        .await;
    assert!(err);
    assert!(msg.as_str().unwrap().contains("too long"));
}

#[tokio::test(flavor = "multi_thread")]
async fn notes_searchable_at_metadata_level() {
    let f = Fx::new();
    let rw = f.token(Access::ReadWrite, Content::FullText, None);
    let meta_tok = f.token(Access::Read, Content::MetadataOnly, None);
    let ro = f.token(Access::Read, Content::FullText, None);
    let restricted = f.token(Access::Read, Content::MetadataOnly, Some(&["handwritten"]));
    let id = f.two_page_pdf(Level::Full).await;

    let (err, msg) = f
        .call(&ro, "set_notes", json!({"id": id, "notes": "x"}))
        .await;
    assert!(err);
    assert_eq!(msg, "token is read-only");
    let (err, msg) = f
        .call(
            &rw,
            "set_notes",
            json!({"id": id, "notes": "a".repeat(2001)}),
        )
        .await;
    assert!(err, "{msg}");

    let (err, v) = f
        .call(
            &rw,
            "set_notes",
            json!({"id": id, "notes": "  grandmother recipe, tiramisu  "}),
        )
        .await;
    assert!(!err, "{v}");

    for tok in [&meta_tok, &restricted, &rw] {
        let (_, hits) = f
            .call(tok, "search_documents", json!({"query": "tiramisu"}))
            .await;
        assert_eq!(hits.as_array().unwrap().len(), 1, "{hits}");
        assert_eq!(hits[0]["notes"], "grandmother recipe, tiramisu");
        assert!(hits[0].get("snippet").is_none() || hits[0]["snippet"].is_null() || tok == &rw);
    }
    let (_, got) = f.call(&meta_tok, "get_document", json!({"id": id})).await;
    assert_eq!(got["notes"], "grandmother recipe, tiramisu");
    assert!(got.get("text").is_none());

    // Hidden documents stay hidden.
    f.u.with_db(|c| set_document_access(c, &id, Channel::Mcp, Some(Level::Off)))
        .unwrap();
    let (err, msg) = f
        .call(&rw, "set_notes", json!({"id": id, "notes": "y"}))
        .await;
    assert!(err);
    assert_eq!(msg, "document not found");
    let (_, hits) = f
        .call(&meta_tok, "search_documents", json!({"query": "tiramisu"}))
        .await;
    assert!(hits.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_documents_needs_transcription_filter() {
    let f = Fx::new();
    let todo = f.two_page_pdf(Level::Full).await;
    let done = f.two_page_pdf(Level::Full).await;
    f.doc(
        "plain.bin",
        "application/octet-stream",
        b"plain",
        &["diary"],
        Level::Full,
    )
    .await;
    let rw = f.token(Access::ReadWrite, Content::FullText, None);
    f.call(
        &rw,
        "set_transcription",
        json!({"id": done, "text": "Done"}),
    )
    .await;

    let (err, v) = f
        .call(&rw, "list_documents", json!({"needs_transcription": true}))
        .await;
    assert!(!err, "{v}");
    let got: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["id"].as_str().unwrap())
        .collect();
    assert_eq!(got, [todo.as_str()]);
    let (_, all) = f.call(&rw, "list_documents", json!({})).await;
    assert_eq!(all.as_array().unwrap().len(), 3);

    // A tag allow-list without `handwritten` still gates everything.
    f.doc(
        "both.bin",
        "application/octet-stream",
        b"both",
        &["diary", "handwritten"],
        Level::Full,
    )
    .await;
    let diary = f.token(Access::Read, Content::FullText, Some(&["diary"]));
    let (_, v) = f
        .call(
            &diary,
            "list_documents",
            json!({"needs_transcription": true}),
        )
        .await;
    assert!(v.as_array().unwrap().is_empty());
    let hw = f.token(Access::Read, Content::FullText, Some(&["handwritten"]));
    let (_, v) = f
        .call(&hw, "list_documents", json!({"needs_transcription": true}))
        .await;
    assert_eq!(v.as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_update_date_sets_ai_source() {
    use personal_media::user_db::DateSource;
    let f = Fx::new();
    let rw = f.token(Access::ReadWrite, Content::FullText, None);
    let id = f
        .doc("d.bin", "application/octet-stream", b"x", &[], Level::Full)
        .await;
    let state = |id: &str| {
        let d = f.u.with_db(|c| get_document(c, id)).unwrap().unwrap();
        (d.document_date, d.date_source)
    };
    assert_eq!(state(&id), (None, None));
    let (err, _) = f
        .call(
            &rw,
            "update_document",
            json!({"id": id, "date": "2024-06-07"}),
        )
        .await;
    assert!(!err);
    assert_eq!(
        state(&id),
        (Some("2024-06-07".into()), Some(DateSource::Ai))
    );
    // A title-only update leaves the source alone.
    let (err, _) = f
        .call(&rw, "update_document", json!({"id": id, "title": "x"}))
        .await;
    assert!(!err);
    assert_eq!(state(&id).1, Some(DateSource::Ai));
    // upload_document with a date is AI-set too.
    let (err, v) = f
        .call(
            &rw,
            "upload_document",
            json!({"filename": "u.dat", "content_base64": BASE64.encode(b"uu"), "date": "2023-01-02"}),
        )
        .await;
    assert!(!err);
    assert_eq!(
        state(v["id"].as_str().unwrap()),
        (Some("2023-01-02".into()), Some(DateSource::Ai))
    );
}
