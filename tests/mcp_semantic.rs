//! `semantic_search` MCP tool. Tests that run the real model need it present
//! (set `PM_TEST_MODELS_DIR`) and print `SKIP` otherwise.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, header};
use bytes::Bytes;
use common::*;
use futures_util::stream;
use personal_media::documents::{OnDuplicate, UploadMeta};
use personal_media::embed::model::{MODEL_FILE, TOKENIZER_FILE};
use personal_media::embed::{Chunk, MODEL};
use personal_media::keyring::Unlocked;
use personal_media::tokens::create_token;
use personal_media::user_db::vectors::replace_vectors;
use personal_media::user_db::{
    Access, Channel, Content, Level, TextStatus, TokenScope, get_document, set_document_access,
    set_text, tag_ids,
};
use serde_json::{Value, json};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn models_dir() -> Option<PathBuf> {
    let root = PathBuf::from(std::env::var("PM_TEST_MODELS_DIR").ok()?).join("models");
    let dir = MODEL.dir(&root);
    (dir.join(MODEL_FILE).exists() && dir.join(TOKENIZER_FILE).exists()).then_some(root)
}

struct Fx {
    t: TestApp,
    u: Arc<Unlocked>,
}

impl Fx {
    /// `None` = the default (empty) models dir, i.e. no model.
    fn new(models: Option<PathBuf>) -> Fx {
        let t = TestApp::with_config(|c| {
            if let Some(m) = models {
                c.models_dir = m;
            }
        });
        let c = t.session_for("alice");
        let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
        Fx { t, u }
    }

    fn token(&self, content: Content, tags: Option<&[&str]>) -> String {
        let ids = tags.map(|names| {
            let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            self.u.with_db(|c| tag_ids(c, &names)).unwrap()
        });
        let scope = TokenScope {
            access: Access::Read,
            content,
            tags: ids,
        };
        create_token(&self.t.state.sys, &self.u, "hermes", scope, now()).unwrap()
    }

    /// Stores a document with text, mcp = full and semantic_index = full,
    /// and (when `index`) real vectors for it.
    async fn doc(
        &self,
        name: &str,
        text: &str,
        tags: &[&str],
        date: Option<&str>,
        mcp: Level,
        sem: Level,
    ) -> String {
        let meta = UploadMeta {
            filename: name.to_owned(),
            mime: Some("application/octet-stream".into()),
            title: Some(format!("title of {name}")),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            document_date: date.map(str::to_owned),
        };
        let body = stream::once(std::future::ready(Ok::<_, anyhow::Error>(Bytes::from(
            format!("bytes of {name}"),
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
        // Let the extraction worker finish first, or it would overwrite the text.
        for _ in 0..200 {
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
        self.u.with_db(|c| {
            set_text(c, &id, TextStatus::Done, Some(text), None, 1).unwrap();
            set_document_access(c, &id, Channel::Mcp, Some(mcp)).unwrap();
            set_document_access(c, &id, Channel::SemanticIndex, Some(sem)).unwrap();
        });
        // Vectors are written regardless of the levels, to prove that search
        // itself (not just the indexer) honours them.
        let engine = self.t.state.engine.clone();
        let text = text.to_owned();
        let vecs = tokio::task::spawn_blocking(move || {
            let chunks = engine.chunk(&text).unwrap();
            let strs: Vec<String> = chunks
                .iter()
                .map(|ch| {
                    text.chars()
                        .skip(ch.start)
                        .take(ch.end - ch.start)
                        .collect()
                })
                .collect();
            let refs: Vec<&str> = strs.iter().map(String::as_str).collect();
            let v = engine.embed_passages(&refs).unwrap();
            chunks.into_iter().zip(v).collect::<Vec<_>>()
        })
        .await
        .unwrap();
        self.u
            .with_db(|c| replace_vectors(c, &id, MODEL.name, &vecs))
            .unwrap();
        id
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

    /// `tools/call`; returns `(is_error, parsed text content)`.
    async fn call(&self, token: &str, args: Value) -> (bool, Value) {
        let v = self
            .post(
                token,
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                        "params":{"name":"semantic_search","arguments":args}}),
            )
            .await;
        let r = &v["result"];
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
}

const F: Level = Level::Full;

#[tokio::test(flavor = "multi_thread")]
async fn semantic_search_finds_cross_language_match() {
    let Some(m) = models_dir() else {
        eprintln!("SKIP semantic_search_finds_cross_language_match: no model");
        return;
    };
    let f = Fx::new(Some(m));
    let cat = f
        .doc(
            "katze.txt",
            "Die Katze schläft den ganzen Tag auf dem warmen Sofa im Wohnzimmer.",
            &[],
            None,
            F,
            F,
        )
        .await;
    f.doc("tax.txt", "The quarterly corporate tax return must be filed with the revenue office before the deadline.", &[], None, F, F).await;
    f.doc(
        "engine.txt",
        "The diesel engine needs an oil change and new spark plugs every year.",
        &[],
        None,
        F,
        F,
    )
    .await;
    let tok = f.token(Content::FullText, None);
    let (err, v) = f
        .call(&tok, json!({"query": "a cat sleeping on the couch"}))
        .await;
    assert!(!err, "{v}");
    let hits = v.as_array().unwrap();
    assert_eq!(hits[0]["id"], cat.as_str(), "{v}");
    assert!(
        hits[0]["passage"].as_str().unwrap().contains("Katze"),
        "{v}"
    );
    let score = hits[0]["score"].as_f64().unwrap();
    assert!((score * 1000.0 - (score * 1000.0).round()).abs() < 1e-6);
    for k in ["title", "document_date", "tags", "filename"] {
        assert!(hits[0].get(k).is_some(), "missing {k}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn semantic_search_ignores_non_full_documents_and_tokens() {
    let Some(m) = models_dir() else {
        eprintln!("SKIP semantic_search_ignores_non_full_documents_and_tokens: no model");
        return;
    };
    let f = Fx::new(Some(m));
    f.doc(
        "a.txt",
        "Der Hund spielt im Garten mit dem Ball.",
        &[],
        None,
        F,
        F,
    )
    .await;
    f.doc(
        "b.txt",
        "Dogs love to play fetch in the park.",
        &[],
        None,
        F,
        F,
    )
    .await;
    f.doc(
        "c.txt",
        "The stock market closed higher on Tuesday.",
        &[],
        None,
        F,
        F,
    )
    .await;
    let tok = f.token(Content::FullText, None);
    let q = json!({"query": "dog playing with a ball"});
    let (e0, base) = f.call(&tok, q.clone()).await;
    assert!(!e0);
    // Perfectly matching documents that must stay invisible.
    let hidden = [
        f.doc(
            "h1.txt",
            "dog playing with a ball",
            &[],
            None,
            Level::Metadata,
            F,
        )
        .await,
        f.doc(
            "h2.txt",
            "dog playing with a ball",
            &[],
            None,
            Level::Off,
            F,
        )
        .await,
        f.doc(
            "h3.txt",
            "dog playing with a ball",
            &[],
            None,
            F,
            Level::Metadata,
        )
        .await,
        f.doc(
            "h4.txt",
            "dog playing with a ball",
            &[],
            None,
            F,
            Level::Off,
        )
        .await,
    ];
    let (e1, after) = f.call(&tok, q.clone()).await;
    assert!(!e1);
    assert_eq!(base, after, "hidden documents changed the result");
    for h in &hidden {
        assert!(!after.to_string().contains(h.as_str()));
    }
    // A metadata-only token cannot use the tool and does not see it listed.
    let meta = f.token(Content::MetadataOnly, None);
    let (err, v) = f.call(&meta, q).await;
    assert!(err);
    assert_eq!(v, json!("token cannot use semantic search"));
    assert!(
        !f.tool_names(&meta)
            .await
            .contains(&"semantic_search".into())
    );
    assert!(f.tool_names(&tok).await.contains(&"semantic_search".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn semantic_search_respects_tag_allow_list_and_dates() {
    let Some(m) = models_dir() else {
        eprintln!("SKIP semantic_search_respects_tag_allow_list_and_dates: no model");
        return;
    };
    let f = Fx::new(Some(m));
    let text = "The cat sat on the mat.";
    let a = f
        .doc(
            "a.txt",
            text,
            &["pets", "secret-tag"],
            Some("2024-01-10"),
            F,
            F,
        )
        .await;
    let b = f
        .doc("b.txt", text, &["work"], Some("2024-06-10"), F, F)
        .await;
    let c = f
        .doc("c.txt", text, &["pets"], Some("2025-01-10"), F, F)
        .await;
    let all = f.token(Content::FullText, None);
    let (_, v) = f.call(&all, json!({"query": "cat on a mat"})).await;
    assert_eq!(v.as_array().unwrap().len(), 3);

    let pets = f.token(Content::FullText, Some(&["pets"]));
    let (err, v) = f.call(&pets, json!({"query": "cat on a mat"})).await;
    assert!(!err);
    let ids: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&a.as_str()) && ids.contains(&c.as_str()) && !ids.contains(&b.as_str()));
    // Foreign tag names never leak.
    assert!(!v.to_string().contains("secret-tag"));
    for h in v.as_array().unwrap() {
        assert_eq!(h["tags"], json!(["pets"]));
    }
    // Filtering on a tag outside the allow-list is the same as an unknown tag.
    let (_, v) = f
        .call(&pets, json!({"query": "cat on a mat", "tags": ["work"]}))
        .await;
    assert_eq!(v, json!([]));
    // Date filters.
    let (_, v) = f
        .call(
            &all,
            json!({"query": "cat on a mat", "date_from": "2024-03-01", "date_to": "2024-12-31"}),
        )
        .await;
    let ids: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![b.as_str()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn semantic_search_limits() {
    let Some(m) = models_dir() else {
        eprintln!("SKIP semantic_search_limits: no model");
        return;
    };
    let f = Fx::new(Some(m));
    for i in 0..22 {
        f.doc(
            &format!("d{i}.txt"),
            &format!("Note number {i} about apples."),
            &[],
            None,
            F,
            F,
        )
        .await;
    }
    let tok = f.token(Content::FullText, None);
    let (_, v) = f.call(&tok, json!({"query": "apples", "limit": 100})).await;
    assert_eq!(v.as_array().unwrap().len(), 20);
    let (_, v) = f.call(&tok, json!({"query": "apples"})).await;
    assert_eq!(v.as_array().unwrap().len(), 8);
    let (_, v) = f.call(&tok, json!({"query": "apples", "limit": 3})).await;
    assert_eq!(v.as_array().unwrap().len(), 3);

    // Query length: 1000 chars is fine, 1001 is invalid params.
    let (err, _) = f.call(&tok, json!({"query": "a".repeat(1000)})).await;
    assert!(!err);
    let r = f
        .post(
            &tok,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                    "params":{"name":"semantic_search","arguments":{"query":"a".repeat(1001)}}}),
        )
        .await;
    assert_eq!(r["error"]["code"], -32602, "{r}");

    // A long chunk is cut to 1200 chars with an ellipsis.
    let long = "word ".repeat(2000);
    let id = f
        .doc("long.txt", "Bananas are yellow fruit.", &[], None, F, F)
        .await;
    f.u.with_db(|c| {
        set_text(c, &id, TextStatus::Done, Some(&long), None, 2).unwrap();
        let v =
            f.t.state
                .engine
                .embed_passages(&["Bananas are yellow fruit."])
                .unwrap();
        replace_vectors(
            c,
            &id,
            MODEL.name,
            &[(
                Chunk {
                    start: 0,
                    end: long.chars().count(),
                },
                v[0].clone(),
            )],
        )
        .unwrap();
    });
    let (_, v) = f.call(&tok, json!({"query": "bananas", "limit": 1})).await;
    assert_eq!(v[0]["id"], id.as_str());
    let p = v[0]["passage"].as_str().unwrap();
    assert!(
        p.chars().count() <= 1200 && p.ends_with('…'),
        "{}",
        p.chars().count()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn semantic_search_without_model_returns_clear_error() {
    // Default models dir is empty: the tool must not download or panic.
    let f = Fx::new(None);
    let tok = f.token(Content::FullText, None);
    let (err, v) = f.call(&tok, json!({"query": "anything"})).await;
    assert!(err);
    assert_eq!(v, json!("semantic index not available yet"));
}
