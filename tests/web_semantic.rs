//! Web search by meaning (`/search?mode=meaning`). Tests that run the real model need it present
//! (set `PM_TEST_MODELS_DIR`) and print `SKIP` otherwise.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use common::*;
use futures_util::stream;
use personal_media::documents::{OnDuplicate, UploadMeta};
use personal_media::embed::MODEL;
use personal_media::embed::model::{MODEL_FILE, TOKENIZER_FILE};
use personal_media::keyring::Unlocked;
use personal_media::user_db::vectors::replace_vectors;
use personal_media::user_db::{
    Channel, Level, TextStatus, get_document, set_document_access, set_text,
};

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
    c: Client,
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
        Fx { t, c, u }
    }

    /// Stores a document with text, mcp = full and semantic_index = full,
    /// and (when `index`) real vectors for it.
    async fn doc(
        &self,
        name: &str,
        text: &str,
        tags: &[&str],
        date: Option<&str>,
        web: Level,
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
        // (No fixed short deadline: a slow runner must not make this flaky.)
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
        assert_ne!(
            self.u
                .with_db(|c| get_document(c, &id))
                .unwrap()
                .unwrap()
                .text_status,
            TextStatus::Pending,
            "extraction did not finish in 60 s"
        );
        self.u.with_db(|c| {
            set_text(c, &id, TextStatus::Done, Some(text), None, 1).unwrap();
            set_document_access(c, &id, Channel::Web, Some(web)).unwrap();
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
}

const F: Level = Level::Full;

impl Fx {
    async fn search(&self, params: &str) -> (u16, String) {
        let resp = self
            .t
            .hx_get(&format!("/search?mode=meaning&{params}"), &self.c)
            .await;
        (resp.status().as_u16(), body_string(resp).await)
    }

    async fn cats(&self) -> String {
        self.doc(
            "katze.txt",
            "Die Katze schläft den ganzen Tag auf dem warmen Sofa im Wohnzimmer.",
            &[],
            None,
            F,
            F,
        )
        .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn web_semantic_search_finds_cross_language_match() {
    let Some(m) = models_dir() else {
        eprintln!("SKIP web_semantic_search_finds_cross_language_match: no model");
        return;
    };
    let f = Fx::new(Some(m));
    let cat = f.cats().await;
    f.doc("tax.txt", "The quarterly corporate tax return must be filed with the revenue office before the deadline.", &[], None, F, F).await;
    let (status, html) = f.search("q=a+cat+sleeping+on+the+couch").await;
    assert_eq!(status, 200, "{html}");
    assert!(html.contains(&format!("/documents/{cat}")), "{html}");
    assert!(html.contains("title of katze.txt"), "{html}");
    assert!(html.contains("Die Katze schläft"), "{html}");
    assert!(html.contains("match "), "{html}");
    assert!(
        html.find("katze").unwrap() < html.find("tax.txt").unwrap(),
        "{html}"
    );
    // The page works without htmx too.
    let resp = f.t.get("/search?mode=meaning&q=cat+on+couch", &f.c).await;
    let full = body_string(resp).await;
    assert!(
        full.contains("<title>") && full.contains("Die Katze"),
        "{full}"
    );
    assert!(full.contains("value=\"meaning\" checked"), "{full}");
}

#[tokio::test(flavor = "multi_thread")]
async fn web_semantic_search_respects_switchboard() {
    let Some(m) = models_dir() else {
        eprintln!("SKIP web_semantic_search_respects_switchboard: no model");
        return;
    };
    let f = Fx::new(Some(m));
    let text = "Die Katze schläft den ganzen Tag auf dem warmen Sofa.";
    let off = f.doc("off.txt", text, &[], None, Level::Off, F).await;
    let meta = f.doc("meta.txt", text, &[], None, Level::Metadata, F).await;
    let nosem = f.doc("nosem.txt", text, &[], None, F, Level::Off).await;
    let ok = f.doc("ok.txt", text, &[], None, F, F).await;
    let (status, html) = f.search("q=cat+sleeping").await;
    assert_eq!(status, 200);
    assert!(html.contains(&ok), "{html}");
    for hidden in [off, meta, nosem] {
        assert!(!html.contains(&hidden), "{hidden} leaked: {html}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn web_semantic_search_without_model_shows_hint() {
    let f = Fx::new(None);
    let (status, html) = f.search("q=cat").await;
    assert_eq!(status, 200);
    let raw = "Search by meaning isn't available yet. Turn on the semantic index in Settings → Access defaults (or per document); the model downloads on first indexing.";
    assert!(html.contains(raw), "{html}");
    assert!(!html.contains("<html"), "partial only: {html}");
    // Full page, as without JS.
    let resp = f.t.get("/search?mode=meaning&q=cat", &f.c).await;
    assert!(body_string(resp).await.contains(raw));
}

#[tokio::test(flavor = "multi_thread")]
async fn web_semantic_search_no_indexed_documents_hint() {
    let Some(m) = models_dir() else {
        eprintln!("SKIP web_semantic_search_no_indexed_documents_hint: no model");
        return;
    };
    let f = Fx::new(Some(m));
    let (_, html) = f.search("q=cat").await;
    assert!(
        html.contains("No documents are indexed for meaning search yet."),
        "{html}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn web_semantic_concurrent_query_gets_429() {
    let f = Fx::new(None);
    let sid = f.c.cookie.clone();
    let _slot = f.t.state.sessions.try_begin_meaning(&sid).unwrap();
    let (status, html) = f.search("q=cat").await;
    assert_eq!(status, 429, "{html}");
    assert!(html.contains("already running"), "{html}");
    // Words search is unaffected.
    let resp = f.t.hx_get("/search?q=cat", &f.c).await;
    assert_eq!(resp.status(), 200);
    drop(_slot);
    let (status, _) = f.search("q=cat").await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn web_semantic_query_not_in_access_log() {
    // Same global-subscriber approach as `access_log_omits_query_and_path_params`.
    let buf = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    #[derive(Clone)]
    struct W(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for W {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let w = W(buf.clone());
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || w.clone())
        .finish();
    // Only this test installs a subscriber in this binary.
    tracing::subscriber::set_global_default(sub).unwrap();
    let f = Fx::new(None);
    let (status, _) = f.search("q=Steuergeheimnis").await;
    assert_eq!(status, 200);
    // The model path too: a real query that embeds and searches.
    if let Some(m) = models_dir() {
        let g = Fx::new(Some(m));
        g.doc(
            "tax.txt",
            "The quarterly corporate tax return must be filed before the deadline.",
            &[],
            None,
            F,
            F,
        )
        .await;
        let (status, html) = g.search("q=Geheimwort-Nachtigall").await;
        assert_eq!(status, 200, "{html}");
        assert!(html.contains("title of tax.txt"), "{html}");
        let (status, _) = g.search("q=Geheimwort-Nachtigall&tag=Zaunkoenig").await;
        assert_eq!(status, 200);
    } else {
        panic!("PM_TEST_MODELS_DIR must point at the test models (no SKIP allowed)");
    }
    let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(!out.contains("Geheimwort"), "{out}");
    assert!(!out.contains("Nachtigall"), "{out}");
    assert!(!out.contains("Steuergeheimnis"), "{out}");
    assert!(!out.contains("meaning"), "{out}");
    assert!(
        out.lines()
            .any(|l| l.contains("path=\"/search\"") && l.contains("status=200")),
        "no access log line: {out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn meaning_toggle_rendered() {
    let f = Fx::new(None);
    let html = body_string(f.t.get("/documents", &f.c).await).await;
    assert!(
        html.contains("name=\"mode\" value=\"words\" checked"),
        "{html}"
    );
    assert!(html.contains("name=\"mode\" value=\"meaning\""), "{html}");
    assert!(html.contains("Meaning"), "{html}");
    // The toggle is part of the htmx-driven search form, history stays off.
    assert!(html.contains("hx-push-url=\"false\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn meaning_form_replaces_in_flight_requests() {
    let f = Fx::new(None);
    let html = body_string(f.t.get("/documents", &f.c).await).await;
    let form = &html[html.find("<form class=\"search\"").unwrap()..];
    let form = &form[..form.find('>').unwrap()];
    assert!(form.contains("hx-sync=\"this:replace\""), "{form}");
}

#[tokio::test(flavor = "multi_thread")]
async fn meaning_empty_with_filters_says_no_matches_for_filters() {
    let Some(m) = models_dir() else {
        panic!("PM_TEST_MODELS_DIR must point at the test models (no SKIP allowed)");
    };
    let f = Fx::new(Some(m));
    // Nothing is indexed and no filter: the index hint.
    let (_, html) = f.search("q=cat").await;
    assert!(html.contains("No documents are indexed"), "{html}");
    // With a tag filter the hint must not claim that nothing is indexed.
    let (_, html) = f.search("q=cat&tag=Steuer").await;
    assert!(html.contains("No matches for these filters."), "{html}");
    assert!(!html.contains("No documents are indexed"), "{html}");
    let (_, html) = f.search("q=cat&from=2020-01-01").await;
    assert!(html.contains("No matches for these filters."), "{html}");
}
