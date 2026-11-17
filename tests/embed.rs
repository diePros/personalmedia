//! Embedding engine tests.
//!
//! The model-gated tests need the real model files. Fetch them once with
//!
//!     cargo run -- fetch-model --data /tmp/pms-test-models
//!
//! (files land in `/tmp/pms-test-models/models/multilingual-e5-small/`). Use
//! another location by setting `PM_TEST_MODELS_DIR` (the *data* dir, i.e. the
//! parent of `models/`) for both the command and `cargo test`. Without the
//! files these tests print `SKIP` and pass. The network test downloads the
//! model into a temp dir and prints `SKIP` when huggingface.co is unreachable.

use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use personal_media::embed::model::{MODEL_FILE, TOKENIZER_FILE};
use personal_media::embed::{CHUNK_OVERLAP, CHUNK_TOKENS, Engine, MODEL, ensure_model};

fn test_models_dir() -> PathBuf {
    let root =
        std::env::var("PM_TEST_MODELS_DIR").unwrap_or_else(|_| "/tmp/pms-test-models".into());
    PathBuf::from(root).join("models")
}

/// The models dir if the real model files are present, else prints SKIP.
fn model_or_skip(test: &str) -> Option<PathBuf> {
    let dir = MODEL.dir(&test_models_dir());
    if dir.join(MODEL_FILE).exists() && dir.join(TOKENIZER_FILE).exists() {
        Some(test_models_dir())
    } else {
        eprintln!("SKIP {test}: model files not found in {}", dir.display());
        None
    }
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[test]
fn corrupt_model_file_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = MODEL.dir(tmp.path());
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(MODEL_FILE);
    std::fs::write(&path, b"garbage, not an onnx model").unwrap();
    let err = ensure_model(tmp.path(), &MODEL).unwrap_err();
    assert!(err.to_string().contains("SHA-256"), "{err}");
    assert!(!path.exists(), "corrupt file must be removed");
}

#[test]
fn fetch_model_downloads_verifies_and_is_idempotent() {
    // Opt-in: depends on huggingface.co response times and was flaky in CI. The
    // Docker build stage already exercises the real download via `fetch-model`.
    if std::env::var_os("PM_NETWORK_TESTS").is_none() {
        eprintln!(
            "skipped (set PM_NETWORK_TESTS=1): fetch_model_downloads_verifies_and_is_idempotent"
        );
        return;
    }
    let online = "huggingface.co:443"
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(5)).is_ok());
    if !online {
        eprintln!("SKIP fetch_model_downloads_verifies_and_is_idempotent: offline");
        return;
    }
    // next to the cached model rather than in /tmp (tmpfs, may be small)
    let root = test_models_dir().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    let tmp = tempfile::tempdir_in(root).unwrap();
    let dir = ensure_model(tmp.path(), &MODEL).unwrap();
    let mtimes: Vec<_> = MODEL
        .files
        .iter()
        .map(|f| {
            let m = std::fs::metadata(dir.join(f.name)).unwrap();
            (m.len(), m.modified().unwrap())
        })
        .collect();
    assert!(mtimes.iter().all(|(len, _)| *len > 1_000_000));
    assert!(
        std::fs::read_dir(&dir)
            .unwrap()
            .all(|e| { !e.unwrap().file_name().to_string_lossy().ends_with(".part") })
    );
    // second run: nothing is downloaded again
    let again = ensure_model(tmp.path(), &MODEL).unwrap();
    assert_eq!(again, dir);
    for (f, (len, mtime)) in MODEL.files.iter().zip(mtimes) {
        let m = std::fs::metadata(dir.join(f.name)).unwrap();
        assert_eq!((m.len(), m.modified().unwrap()), (len, mtime));
    }
}

#[test]
fn embeddings_are_normalised_and_deterministic() {
    let Some(dir) = model_or_skip("embeddings_are_normalised_and_deterministic") else {
        return;
    };
    let engine = Engine::new(dir, Duration::from_secs(600));
    let texts: Vec<String> = (0..20)
        .map(|i| format!("Dokument Nummer {i} über Verträge"))
        .collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let a = engine.embed_passages(&refs).unwrap();
    let b = engine.embed_passages(&refs).unwrap();
    assert_eq!(a.len(), 20); // spans two batches of 16
    for v in &a {
        assert_eq!(v.len(), MODEL.dims);
        let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((n - 1.0).abs() < 1e-3, "norm {n}");
    }
    assert_eq!(a, b);
    // batch composition may shift int8 activation scales slightly, not the meaning
    let single = engine.embed_passages(&refs[3..4]).unwrap();
    let c = cosine(&single[0], &a[3]);
    assert!(c > 0.99, "cosine {c}");
    let q = engine.embed_query("Verträge").unwrap();
    assert_eq!(q.len(), MODEL.dims);
}

#[test]
fn cross_language_similarity() {
    let Some(dir) = model_or_skip("cross_language_similarity") else {
        return;
    };
    let engine = Engine::new(dir, Duration::from_secs(600));
    let q = engine.embed_query("Kündigung Mietvertrag").unwrap();
    let p = engine
        .embed_passages(&["termination of rental agreement", "Stromrechnung"])
        .unwrap();
    let (related, unrelated) = (cosine(&q, &p[0]), cosine(&q, &p[1]));
    assert!(related > unrelated, "{related} <= {unrelated}");
}

#[test]
fn real_tokenizer_chunks_respect_limits() {
    let Some(dir) = model_or_skip("real_tokenizer_chunks_respect_limits") else {
        return;
    };
    let engine = Engine::new(dir, Duration::from_secs(600));
    let text = "Der Mieter kündigt den Mietvertrag fristgerecht zum Monatsende. ".repeat(200);
    let chunks = engine.chunk(&text).unwrap();
    assert!(chunks.len() > 3);
    let total = text.chars().count();
    assert_eq!(chunks[0].start, 0);
    assert_eq!(chunks.last().unwrap().end, total);
    for w in chunks.windows(2) {
        assert!(w[1].start < w[0].end, "chunks must overlap");
    }
    // re-tokenised chunk text stays within the budget (plus boundary slack)
    let tok = tokenizers::Tokenizer::from_file(MODEL.dir(&test_models_dir()).join(TOKENIZER_FILE))
        .unwrap();
    for c in &chunks {
        let s: String = text.chars().skip(c.start).take(c.end - c.start).collect();
        let n = tok.encode(s.as_str(), false).unwrap().len();
        assert!(n <= CHUNK_TOKENS + 2, "chunk of {n} tokens");
    }
    assert_eq!((CHUNK_TOKENS, CHUNK_OVERLAP), (300, 50));
}

#[tokio::test]
async fn engine_unloads_after_idle() {
    let Some(dir) = model_or_skip("engine_unloads_after_idle") else {
        return;
    };
    let engine = Arc::new(Engine::new(dir, Duration::from_secs(1)));
    let _reaper = engine.start_idle_reaper();
    assert!(!engine.is_loaded());
    let e = engine.clone();
    tokio::task::spawn_blocking(move || e.embed_query("hallo").unwrap())
        .await
        .unwrap();
    assert!(engine.is_loaded());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while engine.is_loaded() {
        assert!(std::time::Instant::now() < deadline, "not unloaded in time");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // and it lazily reloads
    let e = engine.clone();
    tokio::task::spawn_blocking(move || e.embed_query("nochmal").unwrap())
        .await
        .unwrap();
    assert!(engine.is_loaded());
}
