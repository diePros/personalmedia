//! In-process multilingual embedding engine (ONNX Runtime + `tokenizers`).
//!
//! The model is loaded lazily on first use and dropped again after
//! [`Engine::new`]'s `idle` period without use (see [`Engine::start_idle_reaper`]).
//! All methods are blocking: call them from `tokio::task::spawn_blocking`.
//! Inference is serialised (one job at a time, one intra-op thread).

pub mod chunk;
pub mod model;
pub mod selftest;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ort::session::Session;
use ort::value::Tensor;
use tokenizers::Tokenizer;

pub use chunk::{CHUNK_OVERLAP, CHUNK_TOKENS, Chunk, Chunked, WINDOW_CHARS, chunk_text};
use model::ensure_model_with;
pub use model::{DownloadPolicy, MODEL, ModelFile, ModelSpec, ensure_model, verify_model};

const BATCH: usize = 16;

/// At most this many characters of one document are embedded (about 600
/// pages). Bounds tokenizer memory, embedding time and the vectors held per
/// document. Longer documents are stored as `partial`.
pub const MAX_EMBED_CHARS: usize = 2_000_000;

struct Loaded {
    session: Session,
    /// No truncation or padding configured: the chunker needs raw offsets.
    tokenizer: Tokenizer,
    pad_id: i64,
    needs_token_type_ids: bool,
}

struct State {
    loaded: Option<Loaded>,
    last_used: Instant,
}

pub struct Engine {
    spec: &'static ModelSpec,
    policy: DownloadPolicy,
    models_dir: PathBuf,
    idle: Duration,
    /// The inference lock: held while the session runs a batch, never while a
    /// model file is downloaded or hashed.
    state: Mutex<State>,
    /// Mirrors `state.loaded.is_some()` so availability checks never wait for
    /// a running inference.
    loaded_flag: AtomicBool,
    /// Serialises model downloads inside the process.
    download: Mutex<()>,
    /// When and why the last download or load failed.
    failure: Mutex<Option<(Instant, String)>>,
}

/// ONNX Runtime allows one environment per process. Telemetry stays off.
fn environment() -> Result<&'static ort::environment::Environment> {
    static ENV: OnceLock<Result<ort::environment::Environment, String>> = OnceLock::new();
    ENV.get_or_init(|| {
        ort::init()
            .with_telemetry(false)
            .build()
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| anyhow::anyhow!("onnx runtime init: {e}"))
}

fn ort_err(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("onnx runtime: {e}")
}

impl Engine {
    pub fn new(models_dir: PathBuf, idle: Duration) -> Engine {
        Engine::with_spec(models_dir, idle, &MODEL, DownloadPolicy::default())
    }

    /// An engine for another file set or network policy. The inference
    /// constants (prefixes, dimensions) still come from [`MODEL`]; this exists
    /// to test downloads and failure handling against a fake server.
    #[doc(hidden)]
    pub fn with_spec(
        models_dir: PathBuf,
        idle: Duration,
        spec: &'static ModelSpec,
        policy: DownloadPolicy,
    ) -> Engine {
        Engine {
            spec,
            policy,
            models_dir,
            idle,
            state: Mutex::new(State {
                loaded: None,
                last_used: Instant::now(),
            }),
            loaded_flag: AtomicBool::new(false),
            download: Mutex::new(()),
            failure: Mutex::new(None),
        }
    }

    /// Whether the model is loaded or its files are on disk (hashes are
    /// checked on load). Never downloads and never waits for an inference;
    /// it may stat two files, so call it off the async threads.
    pub fn is_available(&self) -> bool {
        self.is_loaded() || self.spec.files_present(&self.models_dir)
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded_flag.load(Ordering::Acquire)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop the session if unused for `idle`. Returns true if it unloaded.
    /// Does not wait for a running inference (that counts as use).
    pub fn unload_if_idle(&self) -> bool {
        let Ok(mut st) = self.state.try_lock() else {
            return false;
        };
        if st.loaded.is_some() && st.last_used.elapsed() >= self.idle {
            st.loaded = None;
            self.loaded_flag.store(false, Ordering::Release);
            release_freed_memory();
            return true;
        }
        false
    }

    /// Periodic idle check on the tokio runtime. The task ends when the engine
    /// is dropped.
    pub fn start_idle_reaper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        let tick = (self.idle / 4).clamp(Duration::from_millis(100), Duration::from_secs(30));
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(tick);
            loop {
                iv.tick().await;
                let Some(engine) = weak.upgrade() else { break };
                if engine.unload_if_idle() {
                    tracing::info!("embedding model unloaded after idle");
                }
            }
        })
    }

    fn load(&self) -> Result<Loaded> {
        // Files were fetched and hashed before the inference lock was taken;
        // this only re-checks them (cheap) and never downloads.
        let dir = verify_model(&self.models_dir, self.spec)?;
        let started = Instant::now();
        let session = Session::builder(environment()?)
            .map_err(ort_err)?
            .with_intra_threads(1)
            .map_err(ort_err)?
            .with_inter_threads(1)
            .map_err(ort_err)?
            .commit_from_file(dir.join(model::MODEL_FILE))
            .map_err(ort_err)?;
        let mut tokenizer = Tokenizer::from_file(dir.join(model::TOKENIZER_FILE))
            .map_err(|e| anyhow::anyhow!("load tokenizer: {e}"))?;
        // Truncation is done by hand in `run_batch`; the chunker needs it off.
        tokenizer
            .with_truncation(None)
            .map_err(|e| anyhow::anyhow!("tokenizer: {e}"))?;
        tokenizer.with_padding(None);
        let pad_id = tokenizer.token_to_id("<pad>").unwrap_or(1) as i64;
        let needs_token_type_ids = session
            .inputs()
            .iter()
            .any(|i| i.name() == "token_type_ids");
        tracing::info!(
            ms = started.elapsed().as_millis() as u64,
            "embedding model loaded"
        );
        Ok(Loaded {
            session,
            tokenizer,
            pad_id,
            needs_token_type_ids,
        })
    }

    /// Remaining back-off after a failed download or load, as an error.
    fn check_backoff(&self) -> Result<()> {
        let failure = self.failure.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, why)) = failure.as_ref()
            && at.elapsed() < self.policy.failure_backoff
        {
            let left = self.policy.failure_backoff - at.elapsed();
            anyhow::bail!(
                "embedding model unavailable after a recent failure ({why}); next attempt in {}s",
                left.as_secs() + 1
            );
        }
        Ok(())
    }

    fn record_failure(&self, e: &anyhow::Error) {
        *self.failure.lock().unwrap_or_else(|x| x.into_inner()) =
            Some((Instant::now(), format!("{e:#}")));
    }

    /// Get the model files verified on disk, downloading them if `download`.
    /// Runs without the inference lock, under the download mutex.
    fn prepare_files(&self, download: bool) -> Result<()> {
        self.check_backoff()?;
        let _dl = self.download.lock().unwrap_or_else(|e| e.into_inner());
        // Someone else may have failed (or succeeded) while this call waited.
        self.check_backoff()?;
        let res = if download {
            ensure_model_with(&self.models_dir, self.spec, &self.policy, &mut |_| {}).map(|_| ())
        } else {
            verify_model(&self.models_dir, self.spec).map(|_| ())
        };
        // A search that finds the files gone must not lock indexing out.
        if download && let Err(e) = &res {
            self.record_failure(e);
        }
        res
    }

    /// Run `f` with the loaded model, loading it first if necessary. With
    /// `download` the files are fetched when missing (indexing only; a search
    /// never downloads).
    fn with_loaded<T>(
        &self,
        download: bool,
        f: impl FnOnce(&mut Loaded) -> Result<T>,
    ) -> Result<T> {
        if !self.is_loaded() {
            self.prepare_files(download)?;
        }
        let mut st = self.lock();
        if st.loaded.is_none() {
            match self.load() {
                Ok(l) => {
                    st.loaded = Some(l);
                    self.loaded_flag.store(true, Ordering::Release);
                }
                Err(e) => {
                    self.record_failure(&e);
                    return Err(e);
                }
            }
        }
        let out = f(st.loaded.as_mut().expect("loaded above"));
        st.last_used = Instant::now();
        out
    }

    /// Split `text` into chunks of [`CHUNK_TOKENS`] tokens with
    /// [`CHUNK_OVERLAP`] overlap, as character ranges into `text`. Only the
    /// first [`MAX_EMBED_CHARS`] characters are chunked.
    pub fn chunk(&self, text: &str) -> Result<Vec<Chunk>> {
        Ok(self.chunk_bounded(text, MAX_EMBED_CHARS)?.chunks)
    }

    /// [`Engine::chunk`] over at most the first `max_chars` characters,
    /// tokenised in windows (see [`chunk::chunk_text_bounded`]).
    pub fn chunk_bounded(&self, text: &str, max_chars: usize) -> Result<Chunked> {
        self.with_loaded(true, |l| {
            chunk::chunk_text_bounded(text, &l.tokenizer, CHUNK_TOKENS, CHUNK_OVERLAP, max_chars)
        })
    }

    /// Embed document passages (`"passage: "` prefix); L2-normalised, 384 dims.
    pub fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        let prefixed: Vec<String> = texts
            .iter()
            .map(|t| format!("{}{t}", MODEL.passage_prefix))
            .collect();
        self.embed_all(prefixed, true)
    }

    /// Embed a search query (`"query: "` prefix).
    pub fn embed_query(&self, text: &str) -> Result<Vec<f32>> {
        let mut v = self.embed_all(vec![format!("{}{text}", MODEL.query_prefix)], false)?;
        v.pop().context("no embedding returned")
    }

    fn embed_all(&self, texts: Vec<String>, download: bool) -> Result<Vec<Vec<f32>>> {
        self.with_loaded(download, |l| {
            let mut out = Vec::with_capacity(texts.len());
            for batch in texts.chunks(BATCH) {
                out.extend(run_batch(l, batch)?);
            }
            Ok(out)
        })
    }
}

/// Hand freed heap pages back to the OS (glibc keeps them otherwise), so the
/// idle footprint really drops after the model is unloaded.
fn release_freed_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: `malloc_trim` is always safe to call.
    unsafe {
        libc::malloc_trim(0);
    }
}

fn run_batch(l: &mut Loaded, batch: &[String]) -> Result<Vec<Vec<f32>>> {
    let encs = l
        .tokenizer
        .encode_batch(batch.to_vec(), true)
        .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;
    let max = MODEL.max_tokens;
    let len = encs.iter().map(|e| e.len().min(max)).max().unwrap_or(0);
    let n = encs.len();
    let mut ids = vec![l.pad_id; n * len];
    let mut mask = vec![0i64; n * len];
    for (r, e) in encs.iter().enumerate() {
        let t = e.get_ids();
        let k = t.len().min(max);
        for (c, id) in t[..k].iter().enumerate() {
            ids[r * len + c] = *id as i64;
            mask[r * len + c] = 1;
        }
        if t.len() > max {
            // keep the closing </s>
            ids[r * len + k - 1] = t[t.len() - 1] as i64;
        }
    }
    let shape = [n, len];
    let mut inputs = ort::inputs![
        "input_ids" => Tensor::from_array((shape, ids)).map_err(ort_err)?,
        "attention_mask" => Tensor::from_array((shape, mask.clone())).map_err(ort_err)?,
    ];
    if l.needs_token_type_ids {
        inputs.push((
            "token_type_ids".into(),
            Tensor::from_array((shape, vec![0i64; n * len]))
                .map_err(ort_err)?
                .into(),
        ));
    }
    let outputs = l.session.run(inputs).map_err(ort_err)?;
    let (shp, data) = outputs[0].try_extract_tensor::<f32>().map_err(ort_err)?;
    let dims = MODEL.dims;
    anyhow::ensure!(
        shp.len() == 3 && shp[0] as usize == n && shp[1] as usize == len && shp[2] as usize == dims,
        "unexpected model output shape {shp:?}"
    );
    Ok((0..n)
        .map(|r| {
            let mut v = vec![0f32; dims];
            let mut count = 0f32;
            for c in 0..len {
                if mask[r * len + c] == 0 {
                    continue;
                }
                count += 1.0;
                let row = &data[(r * len + c) * dims..(r * len + c + 1) * dims];
                for (a, b) in v.iter_mut().zip(row) {
                    *a += b;
                }
            }
            let count = count.max(1.0);
            v.iter_mut().for_each(|x| *x /= count);
            let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-12);
            v.iter_mut().for_each(|x| *x /= norm);
            v
        })
        .collect())
}
