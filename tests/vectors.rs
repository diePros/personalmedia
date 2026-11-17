//! Encrypted chunk vectors, migration v2 and the switchboard-governed indexing
//! pipeline.
//!
//! Tests that run the real model need it present (see tests/embed.rs; set
//! `PM_TEST_MODELS_DIR`) and print `SKIP` otherwise.

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use personal_media::accounts::Accounts;
use personal_media::config::Config;
use personal_media::documents::{Documents, OnDuplicate, StoreOutcome, UploadMeta};
use personal_media::embed::model::{MODEL_FILE, TOKENIZER_FILE};
use personal_media::embed::{Chunk, Engine, MODEL};
use personal_media::extract::{
    EMBED_BATCH, EmbedEvent, EmbedRuntime, ExtractConfig, ExtractQueue, start_workers,
};
use personal_media::keyring::{Keyring, Unlocked, index_db_path};
use personal_media::system_db::{Role, SYSTEM_DB_FILE, SystemDb};
use personal_media::user_db::vectors::{
    docs_needing_embedding, get_embed_status, get_vectors, replace_vectors, vector_count,
};
use personal_media::user_db::{
    AccessDefaults, Channel, Level, TextStatus, get_access_defaults, open_user_db,
    set_access_defaults, set_document_access, set_text,
};
use rusqlite::Connection;

const NOW: i64 = 1_800_000_000;
const PW: &str = "correct horse battery";

fn models_dir() -> PathBuf {
    let root =
        std::env::var("PM_TEST_MODELS_DIR").unwrap_or_else(|_| "/tmp/pms-test-models".into());
    PathBuf::from(root).join("models")
}

fn model_or_skip(test: &str) -> Option<PathBuf> {
    let dir = MODEL.dir(&models_dir());
    if dir.join(MODEL_FILE).exists() && dir.join(TOKENIZER_FILE).exists() {
        Some(models_dir())
    } else {
        eprintln!("SKIP {test}: model files not found in {}", dir.display());
        None
    }
}

type Hook = Arc<dyn Fn(EmbedEvent) + Send + Sync>;

struct Env {
    _dir: tempfile::TempDir,
    data: PathBuf,
    docs: Arc<Documents>,
    queue: ExtractQueue,
    u: Arc<Unlocked>,
}

impl Env {
    /// `models` = Some starts workers with a real engine; None starts none.
    fn new(models: Option<(PathBuf, Option<Hook>)>) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_path_buf();
        let cfg_ = Config::for_tests(data.clone());
        let sys = Arc::new(SystemDb::open(&data.join(SYSTEM_DB_FILE)).unwrap());
        let (queue, rx) = ExtractQueue::channel();
        let keyring = Arc::new(Keyring::new(data.clone(), Arc::new(queue.clone())));
        let accounts = Accounts::new(&cfg_, sys, keyring);
        let docs = Arc::new(Documents::new(
            data.clone(),
            100 << 20,
            Arc::new(queue.clone()),
        ));
        if let Some((models, hook)) = models {
            let engine = Arc::new(Engine::new(models, Duration::from_secs(600)));
            let cfg =
                ExtractConfig::new(data.join("tmp")).with_embed(EmbedRuntime { engine, hook });
            start_workers(1, cfg, docs.clone(), rx);
        }
        let url = accounts.create_invite(Role::User, NOW).unwrap();
        let token = url.rsplit('/').next().unwrap().to_string();
        let (u, _, _) = accounts.signup(&token, "sebi", PW, NOW).unwrap();
        Env {
            _dir: dir,
            data,
            docs,
            queue,
            u,
        }
    }

    async fn upload_text(&self, name: &str, text: &str) -> String {
        let meta = UploadMeta {
            filename: name.into(),
            mime: Some("text/plain".into()),
            title: None,
            tags: vec![],
            document_date: None,
        };
        let body =
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from(text.to_owned()))]);
        match self
            .docs
            .store(&self.u, meta, body, OnDuplicate::Keep, None, NOW)
            .await
            .unwrap()
        {
            StoreOutcome::Stored { id } => id,
            other => panic!("{other:?}"),
        }
    }

    fn set_default(&self, sem: Level) {
        let mut d = self.u.with_db(get_access_defaults).unwrap();
        d.0.insert(Channel::SemanticIndex, sem);
        self.u.with_db(|c| set_access_defaults(c, &d)).unwrap();
    }

    fn count(&self, id: &str) -> i64 {
        self.u.with_db(|c| vector_count(c, id)).unwrap()
    }

    fn status(&self, id: &str) -> String {
        self.u
            .with_db(|c| get_embed_status(c, id))
            .unwrap()
            .unwrap()
    }

    fn wait(&self, what: &str, cond: impl Fn(&Env) -> bool) {
        let end = Instant::now() + Duration::from_secs(180);
        while !cond(self) {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn wait_text_done(&self, id: &str) {
        self.wait("text", |e| {
            e.u.with_db(|c| personal_media::user_db::get_document(c, id))
                .unwrap()
                .is_some_and(|d| d.text_status == TextStatus::Done)
        });
    }
}

const SAMPLE: &str = "Der Mietvertrag regelt die Kündigungsfrist von drei Monaten.";

fn fake_vec(seed: f32) -> Vec<f32> {
    (0..384).map(|i| seed + i as f32 * 0.0137).collect()
}

#[test]
fn migration_v2_upgrades_v1_db_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.db");
    let key = personal_media::crypto::Key32::random();
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!(
            "PRAGMA key = \"x'{}'\";",
            hex::encode(key.as_bytes())
        ))
        .unwrap();
        conn.execute_batch(&format!(
            "BEGIN; {} PRAGMA user_version = 1; COMMIT;",
            personal_media::user_db::SCHEMA_V1
        ))
        .unwrap();
        conn.execute(
            "INSERT INTO documents(id, wrapped_dek, original_filename, title, mime, size, sha256,
                                   created_at, updated_at)
             VALUES ('d1', x'00', 'a.txt', 'Old doc', 'text/plain', 3, x'01', 1, 1)",
            [],
        )
        .unwrap();
    }
    for _ in 0..2 {
        let conn = open_user_db(&path, &key).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 2);
        let (title, status): (String, String) = conn
            .query_row(
                "SELECT title, embed_status FROM documents WHERE id = 'd1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((title.as_str(), status.as_str()), ("Old doc", "none"));
        let n: i64 = conn
            .query_row("SELECT count(*) FROM chunk_vectors", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_full_semantic_index_documents_get_vectors() {
    let Some(models) = model_or_skip("only_full") else {
        return;
    };
    let e = Env::new(Some((models, None)));
    let off = e.upload_text("off.txt", SAMPLE).await;
    let meta = e
        .upload_text("meta.txt", "Zweiter Text über Rechnungen.")
        .await;
    let full = e
        .upload_text("full.txt", "Dritter Text über Versicherungen.")
        .await;
    for id in [&off, &meta, &full] {
        e.wait_text_done(id);
    }
    e.u.with_db(|c| set_document_access(c, &meta, Channel::SemanticIndex, Some(Level::Metadata)))
        .unwrap();
    e.u.with_db(|c| set_document_access(c, &full, Channel::SemanticIndex, Some(Level::Full)))
        .unwrap();
    e.queue.enqueue_embeds_needed(&e.u);
    e.wait("full doc vectors", |e| e.count(&full) > 0);
    assert_eq!(e.status(&full), "done");
    let vs = e.u.with_db(|c| get_vectors(c, &full)).unwrap();
    assert_eq!(vs[0].model, MODEL.name);
    assert_eq!(vs[0].vector.len(), 384);
    // Give a wrongly queued job time to show up.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(e.count(&off), 0);
    assert_eq!(e.count(&meta), 0);
    assert_eq!(e.status(&off), "none");
}

#[tokio::test(flavor = "multi_thread")]
async fn extraction_of_new_document_embeds_when_default_full() {
    let Some(models) = model_or_skip("extraction_embeds") else {
        return;
    };
    let e = Env::new(Some((models, None)));
    e.set_default(Level::Full);
    let id = e.upload_text("a.txt", SAMPLE).await;
    e.wait("vectors", |e| e.count(&id) > 0);
}

#[test]
fn lowering_semantic_index_deletes_vectors_immediately() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let e = rt.block_on(async {
        let e = Env::new(None);
        let id = e.upload_text("a.txt", SAMPLE).await;
        (e, id)
    });
    let (e, id) = e;
    e.u.with_db(|c| set_text(c, &id, TextStatus::Done, Some(SAMPLE), None, NOW))
        .unwrap();
    let items = vec![(Chunk { start: 0, end: 10 }, fake_vec(0.1))];

    // Per-document override.
    e.u.with_db(|c| set_document_access(c, &id, Channel::SemanticIndex, Some(Level::Full)))
        .unwrap();
    e.u.with_db(|c| replace_vectors(c, &id, MODEL.name, &items))
        .unwrap();
    assert_eq!(e.count(&id), 1);
    assert_eq!(e.status(&id), "done");
    e.u.with_db(|c| set_document_access(c, &id, Channel::SemanticIndex, Some(Level::Metadata)))
        .unwrap();
    assert_eq!(e.count(&id), 0);
    assert_eq!(e.status(&id), "none");

    // Removing the override falls back to the (off) default.
    e.u.with_db(|c| set_document_access(c, &id, Channel::SemanticIndex, Some(Level::Full)))
        .unwrap();
    e.u.with_db(|c| replace_vectors(c, &id, MODEL.name, &items))
        .unwrap();
    e.u.with_db(|c| set_document_access(c, &id, Channel::SemanticIndex, None))
        .unwrap();
    assert_eq!(e.count(&id), 0);

    // Lowering the default.
    e.set_default(Level::Full);
    e.u.with_db(|c| replace_vectors(c, &id, MODEL.name, &items))
        .unwrap();
    assert_eq!(e.count(&id), 1);
    e.u.with_db(|c| set_access_defaults(c, &AccessDefaults::default()))
        .unwrap();
    assert_eq!(e.count(&id), 0);
    assert_eq!(e.status(&id), "none");

    // A default lowered below an override that still says full keeps vectors.
    e.set_default(Level::Full);
    e.u.with_db(|c| set_document_access(c, &id, Channel::SemanticIndex, Some(Level::Full)))
        .unwrap();
    e.u.with_db(|c| replace_vectors(c, &id, MODEL.name, &items))
        .unwrap();
    e.set_default(Level::Off);
    assert_eq!(e.count(&id), 1);
    drop(rt);
}

#[tokio::test(flavor = "multi_thread")]
async fn lowering_semantic_index_mid_job_leaves_no_vectors() {
    let Some(models) = model_or_skip("mid_job") else {
        return;
    };
    let (reached_tx, reached_rx) = mpsc::channel::<()>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let go_rx = Mutex::new(go_rx);
    let reached_tx = Mutex::new(reached_tx);
    let hook: Hook = Arc::new(move |ev| {
        if ev == EmbedEvent::BeforeCommit {
            reached_tx.lock().unwrap().send(()).unwrap();
            let _ = go_rx.lock().unwrap().recv_timeout(Duration::from_secs(60));
        }
    });
    let e = Env::new(Some((models, Some(hook))));
    e.set_default(Level::Full);
    let id = e.upload_text("a.txt", SAMPLE).await;
    tokio::task::spawn_blocking(move || {
        reached_rx.recv_timeout(Duration::from_secs(120)).unwrap();
        reached_rx
    })
    .await
    .unwrap();
    // The job holds computed vectors and waits. Lower the level now.
    e.u.with_db(|c| set_document_access(c, &id, Channel::SemanticIndex, Some(Level::Metadata)))
        .unwrap();
    go_tx.send(()).unwrap();
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(e.count(&id), 0);
    assert_eq!(e.status(&id), "none");
}

#[tokio::test(flavor = "multi_thread")]
async fn raising_default_enqueues_existing_documents() {
    let Some(models) = model_or_skip("raising_default") else {
        return;
    };
    let e = Env::new(Some((models, None)));
    let a = e.upload_text("a.txt", SAMPLE).await;
    let b = e
        .upload_text("b.txt", "Noch ein Dokument über Steuern.")
        .await;
    e.wait_text_done(&a);
    e.wait_text_done(&b);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(e.count(&a) + e.count(&b), 0);
    assert!(
        e.u.with_db(|c| docs_needing_embedding(c, MODEL.name))
            .unwrap()
            .is_empty()
    );

    e.set_default(Level::Full);
    assert_eq!(
        e.u.with_db(|c| docs_needing_embedding(c, MODEL.name))
            .unwrap()
            .len(),
        2
    );
    e.queue.enqueue_embeds_needed(&e.u);
    e.wait("both embedded", |e| e.count(&a) > 0 && e.count(&b) > 0);
    // Embedding is idempotent: nothing is left to do.
    assert!(
        e.u.with_db(|c| docs_needing_embedding(c, MODEL.name))
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn long_document_embeds_in_batches() {
    let Some(models) = model_or_skip("long_document") else {
        return;
    };
    let batches: Arc<Mutex<Vec<usize>>> = Arc::default();
    let seen = batches.clone();
    let hook: Hook = Arc::new(move |ev| {
        if let EmbedEvent::Batch(n) = ev {
            seen.lock().unwrap().push(n);
        }
    });
    let e = Env::new(Some((models, Some(hook))));
    e.set_default(Level::Full);
    let text: String = (0..5000)
        .map(|i| {
            format!(
                "Vertrag Nummer {i} regelt die Kündigungsfrist und Zahlung {}. ",
                i * 7
            )
        })
        .collect();
    let id = e.upload_text("long.txt", &text).await;
    e.wait("vectors", |e| e.status(&id) == "done");
    let n = e.count(&id) as usize;
    assert!(n >= 150, "expected about 200 chunks, got {n}");
    let sizes = batches.lock().unwrap().clone();
    assert_eq!(sizes.len(), n.div_ceil(EMBED_BATCH));
    assert!(sizes.iter().all(|s| *s <= EMBED_BATCH), "{sizes:?}");
    assert_eq!(sizes.iter().sum::<usize>(), n);
}

#[test]
fn vectors_never_plaintext_on_disk() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let marker = "ZQXJ-UNIQUE-CHUNK-MARKER-7731";
    let text = format!("{marker} Kündigungsfrist");
    let (e, id) = rt.block_on(async {
        let e = Env::new(None);
        let id = e.upload_text("a.txt", &text).await;
        (e, id)
    });
    e.u.with_db(|c| set_text(c, &id, TextStatus::Done, Some(&text), None, NOW))
        .unwrap();
    let known = fake_vec(0.4242);
    let items = vec![
        (Chunk { start: 0, end: 20 }, known.clone()),
        (Chunk { start: 5, end: 30 }, fake_vec(0.9)),
    ];
    e.u.with_db(|c| replace_vectors(c, &id, MODEL.name, &items))
        .unwrap();
    // The vector is really stored (and round-trips) ...
    let back = e.u.with_db(|c| get_vectors(c, &id)).unwrap();
    assert_eq!(back[0].vector, known);
    // ... but no byte on disk (db, WAL, journal) shows it, nor the text.
    let pattern: Vec<u8> = known[..16].iter().flat_map(|f| f.to_le_bytes()).collect();
    let db = index_db_path(&e.data, &e.u.user_id);
    let mut files = vec![db.clone()];
    for suffix in ["-wal", "-journal"] {
        let mut p = db.as_os_str().to_owned();
        p.push(suffix);
        files.push(PathBuf::from(p));
    }
    let mut total = 0;
    for f in files {
        let Ok(bytes) = std::fs::read(&f) else {
            continue;
        };
        total += bytes.len();
        assert!(
            !bytes
                .windows(pattern.len())
                .any(|w| w == pattern.as_slice())
        );
        assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
    }
    assert!(total > 0);
    drop(rt);
}
