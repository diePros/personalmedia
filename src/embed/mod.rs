//! In-process multilingual embedding engine (ONNX Runtime + `tokenizers`).
//!
//! The model is loaded lazily on first use and dropped again after
//! [`Engine::new`]'s `idle` period without use (see [`Engine::start_idle_reaper`]).
//! All methods are blocking: call them from `tokio::task::spawn_blocking`.
//! Inference is serialised (one job at a time, one intra-op thread).

pub mod chunk;
pub mod model;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ort::session::Session;
use ort::value::Tensor;
use tokenizers::Tokenizer;

pub use chunk::{CHUNK_OVERLAP, CHUNK_TOKENS, Chunk, chunk_text};
pub use model::{MODEL, ModelSpec, ensure_model};

const BATCH: usize = 16;

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
    models_dir: PathBuf,
    idle: Duration,
    state: Mutex<State>,
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
        Engine {
            models_dir,
            idle,
            state: Mutex::new(State {
                loaded: None,
                last_used: Instant::now(),
            }),
        }
    }

    /// Whether the model is loaded or its files are on disk (hashes are
    /// checked on load). Never downloads.
    pub fn is_available(&self) -> bool {
        let dir = MODEL.dir(&self.models_dir);
        self.is_loaded()
            || (dir.join(model::MODEL_FILE).is_file() && dir.join(model::TOKENIZER_FILE).is_file())
    }

    pub fn is_loaded(&self) -> bool {
        self.lock().loaded.is_some()
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
        let dir = ensure_model(&self.models_dir, &MODEL)?;
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

    /// Run `f` with the loaded model, loading it first if necessary.
    fn with_loaded<T>(&self, f: impl FnOnce(&mut Loaded) -> Result<T>) -> Result<T> {
        let mut st = self.lock();
        if st.loaded.is_none() {
            st.loaded = Some(self.load()?);
        }
        let out = f(st.loaded.as_mut().expect("loaded above"));
        st.last_used = Instant::now();
        out
    }

    /// Split `text` into chunks of [`CHUNK_TOKENS`] tokens with
    /// [`CHUNK_OVERLAP`] overlap, as character ranges into `text`.
    pub fn chunk(&self, text: &str) -> Result<Vec<Chunk>> {
        self.with_loaded(|l| chunk_text(text, &l.tokenizer, CHUNK_TOKENS, CHUNK_OVERLAP))
    }

    /// Embed document passages (`"passage: "` prefix); L2-normalised, 384 dims.
    pub fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        let prefixed: Vec<String> = texts
            .iter()
            .map(|t| format!("{}{t}", MODEL.passage_prefix))
            .collect();
        self.embed_all(prefixed)
    }

    /// Embed a search query (`"query: "` prefix).
    pub fn embed_query(&self, text: &str) -> Result<Vec<f32>> {
        let mut v = self.embed_all(vec![format!("{}{text}", MODEL.query_prefix)])?;
        v.pop().context("no embedding returned")
    }

    fn embed_all(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
        self.with_loaded(|l| {
            let mut out = Vec::with_capacity(texts.len());
            for batch in texts.chunks(BATCH) {
                out.extend(run_batch(l, batch)?);
            }
            Ok(out)
        })
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
