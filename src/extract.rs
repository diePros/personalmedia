//! Text extraction (pdftotext, tesseract) and the background workers that run it.

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
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

#[derive(Clone, Debug)]
pub struct ExtractConfig {
    pub tmp_dir: PathBuf,
    pub max_pages: u32,
    pub job_timeout: Duration,
}

impl ExtractConfig {
    pub fn new(tmp_dir: PathBuf) -> ExtractConfig {
        ExtractConfig {
            tmp_dir,
            max_pages: 200,
            job_timeout: Duration::from_secs(30 * 60),
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

/// Runs a subprocess with a deadline, returning its stdout. The child is killed on timeout.
fn run_cmd(program: &str, args: &[&std::ffi::OsStr], timeout: Duration) -> Result<Vec<u8>, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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

/// Per-job time budget shared by all subprocesses.
struct Budget(Instant);

impl Budget {
    fn run(
        &self,
        program: &str,
        args: &[&std::ffi::OsStr],
        limit: Duration,
    ) -> Result<Vec<u8>, String> {
        let remaining = self.0.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("job timed out".into());
        }
        run_cmd(program, args, limit.min(remaining))
    }
}

fn os(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

fn non_ws(s: &str) -> usize {
    s.chars().filter(|c| !c.is_whitespace()).count()
}

fn ocr_image(budget: &Budget, img: &Path) -> Result<String, String> {
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

    let prefix = scratch.join("p");
    budget.run(
        "pdftoppm",
        &[
            os("-r"),
            os("300"),
            os("-l"),
            os(&max),
            os("-png"),
            path.as_os_str(),
            prefix.as_os_str(),
        ],
        PDFTOPPM_TIMEOUT,
    )?;
    let mut images: Vec<PathBuf> = fs::read_dir(scratch)
        .map_err(|e| format!("read scratch: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "png"))
        .collect();
    images.sort();
    let mut ocr = String::new();
    for img in &images {
        let page = ocr_image(budget, img)?;
        if !ocr.is_empty() {
            ocr.push('\n');
        }
        ocr.push_str(&page);
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
    let budget = Budget(Instant::now() + cfg.job_timeout);
    let scratch = make_job_dir(&cfg.tmp_dir).map_err(|e| ExtractError::Failed(e.to_string()))?;
    let _guard = DirGuard(scratch.clone());
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
