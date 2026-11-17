//! Pinned model manifest, download and verification.
//!
//! The model files are public (no user data). They are fetched once over HTTPS
//! from revision-pinned URLs, verified against pinned SHA-256 values and only
//! then moved into place. An unverified file is never loaded.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// One pinned model file.
#[derive(Debug, Clone, Copy)]
pub struct ModelFile {
    pub name: &'static str,
    /// HTTPS url, revision-pinned.
    pub url: &'static str,
    pub sha256: &'static str,
    /// Expected size in bytes; a download is aborted beyond
    /// [`DownloadPolicy::max_size_factor`] times this.
    pub size: u64,
}

pub struct ModelSpec {
    pub name: &'static str,
    pub files: &'static [ModelFile],
    pub dims: usize,
    pub max_tokens: usize,
    pub query_prefix: &'static str,
    pub passage_prefix: &'static str,
}

pub const MODEL_FILE: &str = "model_qint8_avx512_vnni.onnx";
pub const TOKENIZER_FILE: &str = "tokenizer.json";

/// intfloat/multilingual-e5-small (MIT), int8 ONNX, revision-pinned.
pub const MODEL: ModelSpec = ModelSpec {
    name: "multilingual-e5-small",
    files: &[
        ModelFile {
            name: MODEL_FILE,
            url: "https://huggingface.co/intfloat/multilingual-e5-small/resolve/614241f622f53c4eeff9890bdc4f31cfecc418b3/onnx/model_qint8_avx512_vnni.onnx",
            sha256: "dd476dd0c2514e9b9be83aeb3853fac0763e0bdf4a71645407587d77c48a2d88",
            size: 118_346_824,
        },
        ModelFile {
            name: TOKENIZER_FILE,
            url: "https://huggingface.co/intfloat/multilingual-e5-small/resolve/614241f622f53c4eeff9890bdc4f31cfecc418b3/tokenizer.json",
            sha256: "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
            size: 17_082_730,
        },
    ],
    dims: 384,
    max_tokens: 512,
    query_prefix: "query: ",
    passage_prefix: "passage: ",
};

impl ModelSpec {
    /// Directory holding this model's files below `models_dir`.
    pub fn dir(&self, models_dir: &Path) -> PathBuf {
        models_dir.join(self.name)
    }

    /// Whether every file is present (hashes are checked on load).
    pub fn files_present(&self, models_dir: &Path) -> bool {
        let dir = self.dir(models_dir);
        self.files.iter().all(|f| dir.join(f.name).is_file())
    }
}

/// Network and failure handling of model downloads.
#[derive(Debug, Clone)]
pub struct DownloadPolicy {
    /// Plain `http://` is refused unless this is set (tests only).
    pub allow_http: bool,
    pub connect_timeout: Duration,
    /// No response header or no body bytes for this long aborts the download.
    pub idle_timeout: Duration,
    /// Whole download, per file.
    pub total_timeout: Duration,
    /// A file may be at most this many times its expected size.
    pub max_size_factor: u64,
    /// After a failed download or load, the engine does not try again for this
    /// long (jobs fail immediately instead).
    pub failure_backoff: Duration,
}

impl Default for DownloadPolicy {
    fn default() -> Self {
        DownloadPolicy {
            allow_http: false,
            connect_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(60),
            total_timeout: Duration::from_secs(30 * 60),
            max_size_factor: 2,
            failure_backoff: Duration::from_secs(15 * 60),
        }
    }
}

/// Files already hashed in this process, keyed by path, length and mtime so a
/// modified file is hashed again.
static VERIFIED: Mutex<Option<HashSet<(PathBuf, u64, SystemTime)>>> = Mutex::new(None);

fn stamp(path: &Path) -> Result<(PathBuf, u64, SystemTime)> {
    let md = fs::metadata(path)?;
    Ok((path.to_path_buf(), md.len(), md.modified()?))
}

/// Whether `path` is unchanged since it was verified. A changed file drops
/// every stale entry for the path.
fn is_verified(path: &Path) -> bool {
    let key = stamp(path).ok();
    let mut guard = VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(set) = guard.as_mut() else {
        return false;
    };
    if key.as_ref().is_some_and(|k| set.contains(k)) {
        return true;
    }
    set.retain(|(p, _, _)| p != path);
    false
}

fn mark_verified(path: &Path) {
    if let Ok(key) = stamp(path) {
        VERIFIED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert_with(HashSet::new)
            .insert(key);
    }
}

fn sha256_reader(mut r: impl Read) -> Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Hash a file on disk; a mismatch deletes it and is an error.
fn verify_file(path: &Path, expected: &str) -> Result<()> {
    if is_verified(path) {
        return Ok(());
    }
    let got = sha256_reader(File::open(path)?)?;
    if got != expected {
        let _ = fs::remove_file(path);
        bail!(
            "{} failed SHA-256 verification and was removed (expected {expected}, got {got})",
            path.display()
        );
    }
    mark_verified(path);
    Ok(())
}

/// Advisory `flock` on `<models_dir>/.lock`, released on drop. It serialises
/// every downloader on the directory, across processes (`fetch-model`,
/// `embed-selftest`, the server) and across threads.
struct DirLock(#[allow(dead_code)] File);

impl DirLock {
    fn acquire(models_dir: &Path) -> Result<DirLock> {
        use std::os::fd::AsRawFd;
        fs::create_dir_all(models_dir)
            .with_context(|| format!("create {}", models_dir.display()))?;
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(models_dir.join(".lock"))
            .context("open model lock file")?;
        loop {
            // SAFETY: plain syscall on a file descriptor we own.
            let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
            if rc == 0 {
                return Ok(DirLock(f));
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err).context("lock model directory");
            }
        }
    }
}

/// Forwards body chunks from a helper thread so the consumer can enforce an
/// idle timeout (ureq only offers a total body timeout).
fn spawn_reader(
    mut body: impl Read + Send + 'static,
) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(4);
    std::thread::spawn(move || {
        loop {
            let mut buf = vec![0u8; 256 * 1024];
            match body.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf.truncate(n);
                    if tx.send(Ok(buf)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                    break;
                }
            }
        }
    });
    rx
}

/// Stream `file.url` into a unique temporary file next to `dest`, hashing on
/// the fly; after `fsync` the file on disk is hashed again and only then
/// renamed into place.
fn download(
    file: &ModelFile,
    dest: &Path,
    policy: &DownloadPolicy,
    progress: &mut dyn FnMut(&str),
) -> Result<()> {
    let url = file.url;
    anyhow::ensure!(
        policy.allow_http || url.starts_with("https://"),
        "refusing non-HTTPS url"
    );
    let cap = file.size.saturating_mul(policy.max_size_factor);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(!policy.allow_http)
        .timeout_connect(Some(policy.connect_timeout))
        .timeout_recv_response(Some(policy.idle_timeout))
        .timeout_global(Some(policy.total_timeout))
        .build()
        .into();
    let name = file.name;
    progress(&format!("downloading {name}"));
    let resp = agent
        .get(url)
        .call()
        .with_context(|| format!("download of {name} failed"))?;
    let total: Option<u64> = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if let Some(t) = total {
        anyhow::ensure!(
            t <= cap,
            "{name}: server announces {t} bytes, more than the allowed {cap}"
        );
    }
    let chunks = spawn_reader(resp.into_body().into_reader());

    let mut tmp = dest.as_os_str().to_owned();
    tmp.push(format!(
        ".{}.{:016x}.part",
        std::process::id(),
        rand::random::<u64>()
    ));
    let tmp = PathBuf::from(tmp);
    let result = (|| -> Result<()> {
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        let mut h = Sha256::new();
        let (mut done, mut last_pct) = (0u64, 0u64);
        loop {
            let chunk = match chunks.recv_timeout(policy.idle_timeout) {
                Ok(c) => c?,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    bail!(
                        "{name}: download stalled (no data for {:?})",
                        policy.idle_timeout
                    )
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
            done += chunk.len() as u64;
            anyhow::ensure!(
                done <= cap,
                "{name}: download exceeds {cap} bytes (expected about {}); aborted",
                file.size
            );
            h.update(&chunk);
            out.write_all(&chunk)?;
            if let Some(t) = total.filter(|t| *t > 0) {
                let pct = done * 100 / t / 10 * 10;
                if pct > last_pct {
                    last_pct = pct;
                    progress(&format!("  {name}: {pct}%"));
                }
            }
        }
        out.sync_all()?;
        drop(out);
        let streamed = hex::encode(h.finalize());
        if streamed != file.sha256 {
            bail!(
                "{name}: SHA-256 mismatch (expected {}, got {streamed}); download discarded",
                file.sha256
            );
        }
        // What is renamed into place is what is on disk, not what was streamed.
        let on_disk = sha256_reader(File::open(&tmp)?)?;
        if on_disk != file.sha256 {
            bail!(
                "{name}: file on disk differs from the download (expected {}, got {on_disk}); discarded",
                file.sha256
            );
        }
        Ok(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    mark_verified(dest);
    Ok(())
}

/// Make sure every model file exists and matches its pinned hash; returns the
/// model directory. Present files are verified (once per process), missing
/// ones are downloaded.
pub fn ensure_model(models_dir: &Path, spec: &ModelSpec) -> Result<PathBuf> {
    ensure_model_with_progress(models_dir, spec, &mut |_| {})
}

pub fn ensure_model_with_progress(
    models_dir: &Path,
    spec: &ModelSpec,
    progress: &mut dyn FnMut(&str),
) -> Result<PathBuf> {
    ensure_model_with(models_dir, spec, &DownloadPolicy::default(), progress)
}

/// [`ensure_model`] with an explicit [`DownloadPolicy`]. The whole fetch runs
/// under an exclusive lock on `<models_dir>/.lock`.
pub fn ensure_model_with(
    models_dir: &Path,
    spec: &ModelSpec,
    policy: &DownloadPolicy,
    progress: &mut dyn FnMut(&str),
) -> Result<PathBuf> {
    let dir = spec.dir(models_dir);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let _lock = DirLock::acquire(models_dir)?;
    // Holding the lock, every `.part` file is a leftover of a dead download.
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".part") {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    for file in spec.files {
        let path = dir.join(file.name);
        if path.exists() {
            verify_file(&path, file.sha256)?;
            progress(&format!("{}: present, verified", file.name));
        } else {
            download(file, &path, policy, progress)?;
            progress(&format!("{}: downloaded, verified", file.name));
        }
    }
    Ok(dir)
}

/// Like [`ensure_model`] but never downloads: every file must be present and
/// matches its hash (hashed once per process and file state).
pub fn verify_model(models_dir: &Path, spec: &ModelSpec) -> Result<PathBuf> {
    let dir = spec.dir(models_dir);
    for file in spec.files {
        let path = dir.join(file.name);
        anyhow::ensure!(path.exists(), "model file {} is missing", file.name);
        verify_file(&path, file.sha256)?;
    }
    Ok(dir)
}
