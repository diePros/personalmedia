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

pub struct ModelSpec {
    pub name: &'static str,
    /// `(file name, https url, sha256 hex)`
    pub files: &'static [(&'static str, &'static str, &'static str)],
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
        (
            MODEL_FILE,
            "https://huggingface.co/intfloat/multilingual-e5-small/resolve/614241f622f53c4eeff9890bdc4f31cfecc418b3/onnx/model_qint8_avx512_vnni.onnx",
            "dd476dd0c2514e9b9be83aeb3853fac0763e0bdf4a71645407587d77c48a2d88",
        ),
        (
            TOKENIZER_FILE,
            "https://huggingface.co/intfloat/multilingual-e5-small/resolve/614241f622f53c4eeff9890bdc4f31cfecc418b3/tokenizer.json",
            "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
        ),
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
}

/// Files already hashed in this process, keyed by path, length and mtime so a
/// modified file is hashed again.
static VERIFIED: Mutex<Option<HashSet<(PathBuf, u64, SystemTime)>>> = Mutex::new(None);

fn stamp(path: &Path) -> Result<(PathBuf, u64, SystemTime)> {
    let md = fs::metadata(path)?;
    Ok((path.to_path_buf(), md.len(), md.modified()?))
}

fn is_verified(path: &Path) -> bool {
    let Ok(key) = stamp(path) else { return false };
    VERIFIED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|s| s.contains(&key))
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

/// Stream `url` into `dest.part`, hashing on the fly; rename on success.
fn download(url: &str, dest: &Path, expected: &str, progress: &mut dyn FnMut(&str)) -> Result<()> {
    anyhow::ensure!(url.starts_with("https://"), "refusing non-HTTPS url");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(Duration::from_secs(30 * 60)))
        .build()
        .into();
    let name = dest.file_name().unwrap_or_default().to_string_lossy();
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
    let mut body = resp.into_body().into_reader();

    let mut part = dest.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let result = (|| -> Result<()> {
        let mut out = File::create(&part)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        let (mut done, mut last_pct) = (0u64, 0u64);
        loop {
            let n = body.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            done += n as u64;
            if let Some(t) = total.filter(|t| *t > 0) {
                let pct = done * 100 / t / 10 * 10;
                if pct > last_pct {
                    last_pct = pct;
                    progress(&format!("  {name}: {pct}%"));
                }
            }
        }
        out.sync_all()?;
        let got = hex::encode(h.finalize());
        if got != expected {
            bail!("{name}: SHA-256 mismatch (expected {expected}, got {got}); download discarded");
        }
        Ok(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    fs::rename(&part, dest)?;
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
    let dir = spec.dir(models_dir);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    for (file, url, sha) in spec.files {
        let path = dir.join(file);
        if path.exists() {
            verify_file(&path, sha)?;
            progress(&format!("{file}: present, verified"));
        } else {
            download(url, &path, sha, progress)?;
            progress(&format!("{file}: downloaded, verified"));
        }
    }
    Ok(dir)
}
