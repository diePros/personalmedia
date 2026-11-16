//! Text extraction (pdftotext, tesseract) and the background workers that run it.

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::documents::{Documents, Enqueue};
use crate::keyring::{OnUnlock, Unlocked};
use crate::user_db::{TextStatus, pending_document_ids, set_text};

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
}

impl ExtractConfig {
    pub fn new(tmp_dir: PathBuf) -> ExtractConfig {
        ExtractConfig {
            tmp_dir,
            max_pages: 200,
            job_timeout: Duration::from_secs(30 * 60),
            limits: ChildLimits::default(),
        }
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

type Job = (Arc<Unlocked>, String);

#[derive(Clone)]
pub struct ExtractQueue {
    tx: UnboundedSender<Job>,
}

pub struct ExtractReceiver(Arc<tokio::sync::Mutex<UnboundedReceiver<Job>>>);

impl ExtractQueue {
    pub fn channel() -> (ExtractQueue, ExtractReceiver) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            ExtractQueue { tx },
            ExtractReceiver(Arc::new(tokio::sync::Mutex::new(rx))),
        )
    }
}

impl Enqueue for ExtractQueue {
    fn enqueue(&self, u: Arc<Unlocked>, doc_id: String) {
        let _ = self.tx.send((u, doc_id));
    }
}

impl OnUnlock for ExtractQueue {
    fn unlocked(&self, u: &Arc<Unlocked>) {
        match u.with_db(pending_document_ids) {
            Ok(ids) => {
                for id in ids {
                    self.enqueue(u.clone(), id);
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not list pending documents"),
        }
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
        let rx = rx.0.clone();
        tokio::spawn(async move {
            loop {
                let job = rx.lock().await.recv().await;
                let Some((u, id)) = job else { break };
                run_job(&docs, &cfg, u, id).await;
            }
        });
    }
}

async fn run_job(docs: &Arc<Documents>, cfg: &ExtractConfig, u: Arc<Unlocked>, id: String) {
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
        return;
    }
    tracing::info!(doc_id = %id, outcome, "extraction finished");
}
