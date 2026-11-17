//! Text extraction (pdftotext, tesseract) and the background workers that run it.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::documents::{Documents, Enqueue};
use crate::embed::{Chunk, Engine, MAX_EMBED_CHARS, MODEL};
use crate::keyring::{OnUnlock, Unlocked};
use crate::user_db::vectors::{
    docs_needing_embedding, enforce_all, get_document_text_prefix, needs_embedding,
    replace_vectors_guarded, set_embed_status,
};
use crate::user_db::{TextStatus, pending_document_ids, set_text};

/// Chunks embedded per `embed_passages` call.
pub const EMBED_BATCH: usize = 16;

/// Test instrumentation points inside an embed job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbedEvent {
    /// A batch of this many chunks was just embedded.
    Batch(usize),
    /// All vectors are computed; the guarded write comes next.
    BeforeCommit,
    /// The embed job ended (stored, discarded, skipped or failed).
    Finished,
}

pub type EmbedHookFn = dyn Fn(EmbedEvent) + Send + Sync;

/// The shared embedding engine plus an optional test hook.
#[derive(Clone)]
pub struct EmbedRuntime {
    pub engine: Arc<Engine>,
    pub hook: Option<Arc<EmbedHookFn>>,
    /// Characters of one document that are embedded at most
    /// ([`MAX_EMBED_CHARS`]); longer texts are indexed as `partial`.
    pub max_chars: usize,
}

impl EmbedRuntime {
    pub fn new(engine: Arc<Engine>, hook: Option<Arc<EmbedHookFn>>) -> EmbedRuntime {
        EmbedRuntime {
            engine,
            hook,
            max_chars: MAX_EMBED_CHARS,
        }
    }
}

impl std::fmt::Debug for EmbedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbedRuntime").finish_non_exhaustive()
    }
}

const PDFINFO_TIMEOUT: Duration = Duration::from_secs(30);
const PDFTOTEXT_TIMEOUT: Duration = Duration::from_secs(60);
const PDFTOPPM_TIMEOUT: Duration = Duration::from_secs(600);
const TESSERACT_TIMEOUT: Duration = Duration::from_secs(120);
const OCR_LANG: &str = "deu+eng";
const MIN_CHARS_PER_PAGE: usize = 50;

/// Resource limits applied to every extraction subprocess (via `pre_exec`).
/// Defence in depth against parser bugs, not a sandbox.
#[derive(Clone, Copy, Debug)]
pub struct ChildLimits {
    /// `RLIMIT_AS`: address space.
    pub as_bytes: u64,
    /// `RLIMIT_FSIZE`: largest file the child may write.
    pub fsize_bytes: u64,
    /// `RLIMIT_NOFILE`: open file descriptors.
    pub nofile: u64,
    /// `RLIMIT_CPU` = the subprocess timeout in seconds plus this many.
    pub extra_cpu_secs: u64,
}

impl Default for ChildLimits {
    fn default() -> Self {
        ChildLimits {
            as_bytes: 2 << 30,
            fsize_bytes: 1 << 30,
            nofile: 64,
            extra_cpu_secs: 5,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExtractConfig {
    pub tmp_dir: PathBuf,
    pub max_pages: u32,
    pub job_timeout: Duration,
    pub limits: ChildLimits,
    /// Without it embed jobs are skipped.
    pub embed: Option<EmbedRuntime>,
}

impl ExtractConfig {
    pub fn new(tmp_dir: PathBuf) -> ExtractConfig {
        ExtractConfig {
            tmp_dir,
            max_pages: 200,
            job_timeout: Duration::from_secs(30 * 60),
            limits: ChildLimits::default(),
            embed: None,
        }
    }

    pub fn with_embed(mut self, embed: EmbedRuntime) -> ExtractConfig {
        self.embed = Some(embed);
        self
    }
}

#[derive(Debug)]
pub struct Extracted {
    pub text: String,
    pub page_count: Option<u32>,
}

#[derive(Debug)]
pub enum ExtractError {
    Unsupported,
    Failed(String),
}

/// Removes everything inside `tmp_dir` (creating it if missing). Run at startup.
pub fn wipe_tmp(tmp_dir: &Path) -> io::Result<()> {
    match fs::read_dir(tmp_dir) {
        Ok(entries) => {
            for e in entries {
                let p = e?.path();
                if p.is_dir() && !p.is_symlink() {
                    fs::remove_dir_all(&p)?;
                } else {
                    fs::remove_file(&p)?;
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir_all(tmp_dir),
        Err(e) => Err(e),
    }
}

/// Removes a directory tree on drop.
struct DirGuard(PathBuf);

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Creates `{tmp_dir}/{random hex}` with mode 0700.
fn make_job_dir(tmp_dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(tmp_dir)?;
    let dir = tmp_dir.join(uuid::Uuid::new_v4().simple().to_string());
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

fn set_rlimit(resource: libc::c_int, value: u64) -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: setrlimit is async-signal-safe and only reads `lim`.
    if unsafe { libc::setrlimit(resource as _, &lim) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Runs a subprocess with a deadline, returning its stdout. The child is killed on timeout.
///
/// The child gets an empty environment except `PATH`, `OMP_THREAD_LIMIT=1`
/// and `LANG`, runs in `cwd` (the job scratch dir) and is resource-limited
/// per `limits`.
pub fn run_cmd(
    program: &str,
    args: &[&std::ffi::OsStr],
    timeout: Duration,
    cwd: &Path,
    limits: &ChildLimits,
) -> Result<Vec<u8>, String> {
    let limits = *limits;
    let cpu_secs = timeout.as_secs() + limits.extra_cpu_secs;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("OMP_THREAD_LIMIT", "1")
        .env("LANG", "C.UTF-8")
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: the closure only calls setrlimit, which is async-signal-safe,
    // and does not allocate.
    unsafe {
        cmd.pre_exec(move || {
            set_rlimit(libc::RLIMIT_AS as libc::c_int, limits.as_bytes)?;
            set_rlimit(libc::RLIMIT_CPU as libc::c_int, cpu_secs)?;
            set_rlimit(libc::RLIMIT_FSIZE as libc::c_int, limits.fsize_bytes)?;
            set_rlimit(libc::RLIMIT_NOFILE as libc::c_int, limits.nofile)?;
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("{program}: spawn failed: {e}"))?;
    let mut stdout = child.stdout.take().expect("stdout piped");
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("{program}: timed out"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("{program}: wait failed: {e}"));
            }
        }
    };
    let out = reader.join().unwrap_or_default();
    let status = status?;
    if status.success() {
        Ok(out)
    } else {
        Err(format!("{program}: exited with {status}"))
    }
}

/// Per-job time budget shared by all subprocesses, plus where and how they run.
struct Budget<'a> {
    deadline: Instant,
    scratch: &'a Path,
    limits: &'a ChildLimits,
}

impl Budget<'_> {
    fn run(
        &self,
        program: &str,
        args: &[&std::ffi::OsStr],
        limit: Duration,
    ) -> Result<Vec<u8>, String> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("job timed out".into());
        }
        run_cmd(
            program,
            args,
            limit.min(remaining),
            self.scratch,
            self.limits,
        )
    }
}

fn os(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

fn non_ws(s: &str) -> usize {
    s.chars().filter(|c| !c.is_whitespace()).count()
}

fn ocr_image(budget: &Budget<'_>, img: &Path) -> Result<String, String> {
    let out = budget.run(
        "tesseract",
        &[img.as_os_str(), os("-"), os("-l"), os(OCR_LANG)],
        TESSERACT_TIMEOUT,
    )?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn extract_pdf(
    path: &Path,
    cfg: &ExtractConfig,
    budget: &Budget,
    scratch: &Path,
) -> Result<Extracted, String> {
    let info = budget.run("pdfinfo", &[path.as_os_str()], PDFINFO_TIMEOUT)?;
    let info = String::from_utf8_lossy(&info);
    let pages: u32 = info
        .lines()
        .find_map(|l| l.strip_prefix("Pages:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or("pdfinfo: no page count")?;
    let pages = pages.min(cfg.max_pages);
    let max = pages.max(1).to_string();

    let out = budget.run(
        "pdftotext",
        &[
            os("-l"),
            os(&max),
            os("-enc"),
            os("UTF-8"),
            path.as_os_str(),
            os("-"),
        ],
        PDFTOTEXT_TIMEOUT,
    )?;
    let text = String::from_utf8_lossy(&out).into_owned();
    if non_ws(&text) >= MIN_CHARS_PER_PAGE * pages as usize {
        return Ok(Extracted {
            text,
            page_count: Some(pages),
        });
    }

    // OCR one page at a time so the scratch dir never holds more than one PNG.
    // A page failure or an exhausted job budget stops the loop and keeps the
    // text gathered so far.
    let prefix = scratch.join("p");
    let mut ocr = String::new();
    let mut pages_done = 0u32;
    let mut first_error: Option<String> = None;
    for n in 1..=pages {
        match ocr_page(budget, path, scratch, &prefix, n) {
            Ok(page) => {
                if !ocr.is_empty() {
                    ocr.push('\n');
                }
                ocr.push_str(&page);
                pages_done += 1;
            }
            Err(e) => {
                first_error = Some(e);
                break;
            }
        }
    }
    if pages_done == 0 && non_ws(&text) == 0 {
        return Err(first_error.unwrap_or_else(|| "no pages to OCR".into()));
    }
    // Keep whichever source produced more text.
    let text = if non_ws(&ocr) > non_ws(&text) {
        ocr
    } else {
        text
    };
    Ok(Extracted {
        text,
        page_count: Some(pages),
    })
}

/// Renders page `n` to a PNG in `scratch`, OCRs it and deletes the PNG again
/// (also on failure).
fn ocr_page(
    budget: &Budget<'_>,
    pdf: &Path,
    scratch: &Path,
    prefix: &Path,
    n: u32,
) -> Result<String, String> {
    debug_assert!(png_files(scratch)?.is_empty(), "stale page PNG in scratch");
    let page = n.to_string();
    let rendered = budget.run(
        "pdftoppm",
        &[
            os("-r"),
            os("300"),
            os("-f"),
            os(&page),
            os("-l"),
            os(&page),
            os("-png"),
            pdf.as_os_str(),
            prefix.as_os_str(),
        ],
        PDFTOPPM_TIMEOUT,
    );
    let result = rendered.and_then(|_| {
        let imgs = png_files(scratch)?;
        let [img] = imgs.as_slice() else {
            return Err(format!("pdftoppm produced {} images", imgs.len()));
        };
        ocr_image(budget, img)
    });
    // Whatever happened, no PNG outlives its page.
    for img in png_files(scratch).unwrap_or_default() {
        let _ = fs::remove_file(img);
    }
    result
}

fn png_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(fs::read_dir(dir)
        .map_err(|e| format!("read scratch: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "png"))
        .collect())
}

/// Extracts text from the file at `path` (blocking).
pub fn extract_text(
    path: &Path,
    mime: &str,
    cfg: &ExtractConfig,
) -> Result<Extracted, ExtractError> {
    let mime = mime.split(';').next().unwrap_or("").trim();
    let kind = match mime {
        "application/pdf" => 0,
        "image/png" | "image/jpeg" | "image/tiff" | "image/webp" => 1,
        "text/plain" | "text/markdown" => 2,
        _ => return Err(ExtractError::Unsupported),
    };
    if kind == 2 {
        let bytes = fs::read(path).map_err(|e| ExtractError::Failed(format!("read: {e}")))?;
        return Ok(Extracted {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            page_count: None,
        });
    }
    let scratch = make_job_dir(&cfg.tmp_dir).map_err(|e| ExtractError::Failed(e.to_string()))?;
    let _guard = DirGuard(scratch.clone());
    let budget = Budget {
        deadline: Instant::now() + cfg.job_timeout,
        scratch: &scratch,
        limits: &cfg.limits,
    };
    let res = if kind == 0 {
        extract_pdf(path, cfg, &budget, &scratch)
    } else {
        ocr_image(&budget, path).map(|text| Extracted {
            text,
            page_count: None,
        })
    };
    res.map_err(ExtractError::Failed)
}

/// What a queued job does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    /// Text extraction (pdftotext / OCR) of a new upload.
    Extract,
    /// Embedding the text of one document.
    Embed,
}

type QueuedJob = (Arc<Unlocked>, String);

#[derive(Default)]
struct Queues {
    extract: VecDeque<QueuedJob>,
    embed: VecDeque<QueuedJob>,
    /// Jobs waiting in either queue, by (user, document, kind).
    pending: HashSet<(String, String, JobKind)>,
    closed: bool,
}

/// Two FIFO queues behind one lock. Extraction always goes first, so a
/// backlog of embed jobs never delays a new upload's OCR; identical pending
/// jobs are queued once.
struct Shared {
    q: Mutex<Queues>,
    notify: Notify,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Queues> {
        self.q.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue a job unless an identical one is already waiting. Returns
    /// whether it was added.
    fn push(&self, kind: JobKind, u: &Arc<Unlocked>, id: &str) -> bool {
        let mut q = self.lock();
        if !q.pending.insert((u.user_id.clone(), id.to_string(), kind)) {
            return false;
        }
        let job = (u.clone(), id.to_string());
        match kind {
            JobKind::Extract => q.extract.push_back(job),
            JobKind::Embed => q.embed.push_back(job),
        }
        drop(q);
        self.notify.notify_one();
        true
    }

    /// The next job: extraction before embedding, re-decided on every call
    /// (so between any two embed jobs).
    fn take(&self) -> Option<(JobKind, Arc<Unlocked>, String)> {
        let mut q = self.lock();
        let (kind, (u, id)) = match q.extract.pop_front() {
            Some(j) => (JobKind::Extract, j),
            None => (JobKind::Embed, q.embed.pop_front()?),
        };
        q.pending.remove(&(u.user_id.clone(), id.clone(), kind));
        Some((kind, u, id))
    }

    /// Waits for a job; `None` once the queue is closed and empty.
    async fn next(&self) -> Option<(JobKind, Arc<Unlocked>, String)> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Registered before looking, so a push in between is not missed.
            notified.as_mut().enable();
            if let Some(j) = self.take() {
                return Some(j);
            }
            if self.lock().closed {
                return None;
            }
            notified.await;
        }
    }

    fn enqueue_embed_if_needed(&self, u: &Arc<Unlocked>, doc_id: &str) {
        match u.with_db(|c| needs_embedding(c, doc_id, MODEL.name)) {
            Ok(true) => {
                if self.push(JobKind::Embed, u, doc_id) {
                    mark_pending(u, doc_id);
                }
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(doc_id, error = %e, "could not check embedding need"),
        }
    }

    fn enqueue_embeds_needed(&self, u: &Arc<Unlocked>) {
        match u.with_db(|c| docs_needing_embedding(c, MODEL.name)) {
            Ok(ids) => {
                for id in ids {
                    // Already waiting: leave it (and its status) alone.
                    if self.push(JobKind::Embed, u, &id) {
                        mark_pending(u, &id);
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not list documents needing embedding"),
        }
    }
}

fn mark_pending(u: &Arc<Unlocked>, doc_id: &str) {
    if let Err(e) = u.with_db(|c| set_embed_status(c, doc_id, "pending")) {
        tracing::warn!(doc_id, error = %e, "could not mark document pending");
    }
}

/// Closes the queues when the last [`ExtractQueue`] handle is dropped, so
/// workers end (they only hold [`Shared`]).
struct Closer(Arc<Shared>);

impl Drop for Closer {
    fn drop(&mut self) {
        self.0.lock().closed = true;
        self.0.notify.notify_waiters();
    }
}

#[derive(Clone)]
pub struct ExtractQueue {
    shared: Arc<Shared>,
    _closer: Arc<Closer>,
}

pub struct ExtractReceiver {
    shared: Arc<Shared>,
}

impl ExtractReceiver {
    /// Pops the next job in priority order without running it (extraction
    /// before embedding). Workers use the same order; this is for tests.
    pub fn try_next(&self) -> Option<(JobKind, String)> {
        self.shared.take().map(|(k, _, id)| (k, id))
    }
}

impl ExtractQueue {
    pub fn channel() -> (ExtractQueue, ExtractReceiver) {
        let shared = Arc::new(Shared {
            q: Mutex::new(Queues::default()),
            notify: Notify::new(),
        });
        (
            ExtractQueue {
                shared: shared.clone(),
                _closer: Arc::new(Closer(shared.clone())),
            },
            ExtractReceiver { shared },
        )
    }

    /// Queue embedding of `doc_id` without checking eligibility (the job
    /// re-checks it). Ignored while an identical job is already waiting.
    pub fn enqueue_embed(&self, u: &Arc<Unlocked>, doc_id: &str) {
        self.shared.push(JobKind::Embed, u, doc_id);
    }

    /// Enqueue embedding of one document if it needs it (effective
    /// `semantic_index` full, text done, no vectors for the current model).
    pub fn enqueue_embed_if_needed(&self, u: &Arc<Unlocked>, doc_id: &str) {
        self.shared.enqueue_embed_if_needed(u, doc_id);
    }

    /// Enqueue every document that needs vectors. Call after anything that
    /// may raise `semantic_index` (overrides, defaults) and on unlock.
    /// Documents already waiting in the queue are not queued again.
    pub fn enqueue_embeds_needed(&self, u: &Arc<Unlocked>) {
        self.shared.enqueue_embeds_needed(u);
    }
}

impl Enqueue for ExtractQueue {
    fn enqueue(&self, u: Arc<Unlocked>, doc_id: String) {
        self.shared.push(JobKind::Extract, &u, &doc_id);
    }
}

impl OnUnlock for ExtractQueue {
    fn unlocked(&self, u: &Arc<Unlocked>) {
        // Vectors exist only for documents at semantic_index = full. A
        // downgrade/upgrade cycle (or an older version) may have left others.
        if let Err(e) = u.with_db(enforce_all) {
            tracing::warn!(error = %e, "could not enforce semantic index levels");
        }
        match u.with_db(pending_document_ids) {
            Ok(ids) => {
                for id in ids {
                    self.enqueue(u.clone(), id);
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not list pending documents"),
        }
        self.enqueue_embeds_needed(u);
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Spawns `n` worker tasks (needs a running tokio runtime).
pub fn start_workers(n: usize, cfg: ExtractConfig, docs: Arc<Documents>, rx: ExtractReceiver) {
    for _ in 0..n.max(1) {
        let cfg = cfg.clone();
        let docs = docs.clone();
        let shared = rx.shared.clone();
        tokio::spawn(async move {
            while let Some((kind, u, id)) = shared.next().await {
                match kind {
                    JobKind::Extract => {
                        if run_job(&docs, &cfg, u.clone(), id.clone()).await {
                            shared.enqueue_embed_if_needed(&u, &id);
                        }
                    }
                    JobKind::Embed => run_embed_job(&cfg, u, id).await,
                }
            }
        });
    }
}

/// Returns true if text extraction finished with `Done` and was stored.
async fn run_job(docs: &Arc<Documents>, cfg: &ExtractConfig, u: Arc<Unlocked>, id: String) -> bool {
    let (docs2, cfg2, u2, id2) = (docs.clone(), cfg.clone(), u.clone(), id.clone());
    let res = tokio::task::spawn_blocking(move || {
        let dir = make_job_dir(&cfg2.tmp_dir).map_err(|e| ExtractError::Failed(e.to_string()))?;
        let _guard = DirGuard(dir.clone());
        let input = dir.join("input");
        let doc = docs2
            .decrypt_to_path(&u2, &id2, &input)
            .map_err(|e| ExtractError::Failed(e.to_string()))?;
        extract_text(&input, &doc.mime, &cfg2)
    })
    .await
    .unwrap_or_else(|_| Err(ExtractError::Failed("worker panicked".into())));

    let (outcome, status, text, pages) = match &res {
        Ok(x) => (
            "done",
            TextStatus::Done,
            Some(x.text.as_str()),
            x.page_count,
        ),
        Err(ExtractError::Unsupported) => ("unsupported", TextStatus::Unsupported, None, None),
        Err(ExtractError::Failed(_)) => ("failed", TextStatus::Failed, None, None),
    };
    if let Err(e) = u.with_db(|c| set_text(c, &id, status, text, pages, now_secs())) {
        tracing::warn!(doc_id = %id, error = %e, "could not store extraction result");
        return false;
    }
    tracing::info!(doc_id = %id, outcome, "extraction finished");
    status == TextStatus::Done
}

async fn run_embed_job(cfg: &ExtractConfig, u: Arc<Unlocked>, id: String) {
    let Some(rt) = cfg.embed.clone() else {
        return;
    };
    let rt2 = rt.clone();
    let started = Instant::now();
    let (u2, id2) = (u.clone(), id.clone());
    let res = tokio::task::spawn_blocking(move || embed_document(&rt, &u2, &id2))
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("worker panicked")));
    match res {
        Ok(outcome) => tracing::info!(
            doc_id = %id,
            outcome,
            ms = started.elapsed().as_millis() as u64,
            "embedding finished"
        ),
        Err(e) => {
            // Only the outcome is logged (the error may name model files, never text).
            tracing::warn!(doc_id = %id, error = %e, "embedding failed");
            let _ = u.with_db(|c| set_embed_status(c, &id, "failed"));
        }
    }
    if let Some(h) = &rt2.hook {
        h(EmbedEvent::Finished);
    }
}

/// Walks forward through `text` to turn character ranges into byte ranges
/// without a per-character table. Ranges must come in non-decreasing `start`
/// order (the chunker's order).
struct CharCursor {
    chars: usize,
    bytes: usize,
}

impl CharCursor {
    fn slice<'a>(&mut self, text: &'a str, start: usize, end: usize) -> &'a str {
        let advance = |chars: &mut usize, bytes: &mut usize, to: usize| {
            for c in text[*bytes..].chars() {
                if *chars >= to {
                    break;
                }
                *chars += 1;
                *bytes += c.len_utf8();
            }
        };
        advance(&mut self.chars, &mut self.bytes, start);
        let from = self.bytes;
        let (mut c, mut b) = (self.chars, self.bytes);
        advance(&mut c, &mut b, end);
        &text[from..b]
    }
}

/// Embeds one document and stores its vectors. Blocking.
fn embed_document(rt: &EmbedRuntime, u: &Arc<Unlocked>, id: &str) -> anyhow::Result<&'static str> {
    // Eligibility is re-checked now, the job may have waited in the queue.
    // Only a bounded prefix of the text is read and embedded.
    let max_chars = rt.max_chars;
    let loaded = u.with_db(|c| {
        if !needs_embedding(c, id, MODEL.name)? {
            return anyhow::Ok(None);
        }
        let text = get_document_text_prefix(c, id, max_chars)?;
        if text.is_some() {
            set_embed_status(c, id, "pending")?;
        }
        anyhow::Ok(text)
    })?;
    let Some((text, partial)) = loaded else {
        return Ok("skipped");
    };
    let chunks: Vec<Chunk> = rt.engine.chunk_bounded(&text, max_chars)?.chunks;
    let mut cursor = CharCursor { chars: 0, bytes: 0 };
    let mut items: Vec<(Chunk, Vec<f32>)> = Vec::with_capacity(chunks.len());
    for batch in chunks.chunks(EMBED_BATCH) {
        let passages: Vec<&str> = batch
            .iter()
            .map(|c| cursor.slice(&text, c.start, c.end))
            .collect();
        let vectors = rt.engine.embed_passages(&passages)?;
        anyhow::ensure!(vectors.len() == batch.len(), "embedding count mismatch");
        if let Some(h) = &rt.hook {
            h(EmbedEvent::Batch(batch.len()));
        }
        items.extend(batch.iter().copied().zip(vectors));
    }
    if let Some(h) = &rt.hook {
        h(EmbedEvent::BeforeCommit);
    }
    let stored =
        u.with_db(|c| replace_vectors_guarded(c, id, MODEL.name, &text, partial, &items))?;
    if !stored {
        // Level lowered, text changed or document gone: nothing is kept.
        // A raise that happened meanwhile enqueued its own job.
        return Ok("discarded");
    }
    Ok(if partial { "partial" } else { "done" })
}
