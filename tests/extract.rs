use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use personal_media::accounts::Accounts;
use personal_media::config::Config;
use personal_media::documents::{Documents, OnDuplicate, StoreOutcome, UploadMeta};
use personal_media::extract::{
    ExtractConfig, ExtractError, ExtractQueue, extract_text, start_workers,
};
use personal_media::keyring::{Keyring, Unlocked};
use personal_media::system_db::{Role, SYSTEM_DB_FILE, SystemDb};
use personal_media::user_db::{ListFilter, TextStatus, get_document, search};

const NOW: i64 = 1_800_000_000;
const PW: &str = "correct horse battery";

fn have_tesseract() -> bool {
    let ok = std::process::Command::new("which")
        .arg("tesseract")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        println!("SKIP");
    }
    ok
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn cfg(tmp: &Path) -> ExtractConfig {
    ExtractConfig::new(tmp.to_path_buf())
}

#[test]
fn text_pdf_uses_pdftotext() {
    if !have_tesseract() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let r = extract_text(&fixture("text.pdf"), "application/pdf", &cfg(tmp.path())).unwrap();
    assert!(r.text.contains("Kündigungsfrist"), "{:?}", r.text);
    assert_eq!(r.page_count, Some(1));
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn scanned_pdf_falls_back_to_ocr() {
    if !have_tesseract() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let r = extract_text(&fixture("scanned.pdf"), "application/pdf", &cfg(tmp.path())).unwrap();
    assert!(r.text.contains("Versicherungsnummer"), "{:?}", r.text);
    assert_eq!(r.page_count, Some(1));
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn png_ocr() {
    if !have_tesseract() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let r = extract_text(&fixture("scan.png"), "image/png", &cfg(tmp.path())).unwrap();
    assert!(r.text.contains("Versicherungsnummer"), "{:?}", r.text);
}

#[test]
fn unsupported_and_plain_text() {
    let tmp = tempfile::tempdir().unwrap();
    let c = cfg(tmp.path());
    assert!(matches!(
        extract_text(&fixture("text.pdf"), "application/zip", &c),
        Err(ExtractError::Unsupported)
    ));
    let p = tmp.path().join("t.txt");
    std::fs::write(&p, "hällo").unwrap();
    let r = extract_text(&p, "text/plain; charset=utf-8", &c).unwrap();
    assert_eq!(r.text, "hällo");
    assert_eq!(r.page_count, None);
}

#[test]
fn corrupt_and_empty_inputs_fail_cleanly() {
    if !have_tesseract() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    for name in ["corrupt.pdf", "empty.pdf"] {
        match extract_text(&fixture(name), "application/pdf", &cfg(tmp.path())) {
            Err(ExtractError::Failed(_)) => {}
            Ok(r) => assert!(r.text.trim().is_empty(), "{name}"),
            Err(e) => panic!("{name}: {e:?}"),
        }
    }
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

struct Env {
    dir: tempfile::TempDir,
    tmp: PathBuf,
    accounts: Accounts,
    docs: Arc<Documents>,
    u: Option<Arc<Unlocked>>,
}

impl Env {
    /// Workers are started only when `workers` is true.
    fn new(workers: bool) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join("tmp");
        let cfg_ = Config::for_tests(dir.path().to_path_buf());
        let sys = Arc::new(SystemDb::open(&dir.path().join(SYSTEM_DB_FILE)).unwrap());
        let (queue, rx) = ExtractQueue::channel();
        let keyring = Arc::new(Keyring::new(
            dir.path().to_path_buf(),
            Arc::new(queue.clone()),
        ));
        let accounts = Accounts::new(&cfg_, sys, keyring);
        let docs = Arc::new(Documents::new(
            dir.path().to_path_buf(),
            100 << 20,
            Arc::new(queue.clone()),
            personal_media::quota::Quotas::unlimited(dir.path().to_path_buf()),
        ));
        if workers {
            start_workers(2, ExtractConfig::new(tmp.clone()), docs.clone(), rx);
        }
        let url = accounts.create_invite(Role::User, NOW).unwrap();
        let token = url.rsplit('/').next().unwrap().to_string();
        let (u, _, _) = accounts.signup(&token, "sebi", PW, NOW).unwrap();
        Env {
            dir,
            tmp,
            accounts,
            docs,
            u: Some(u),
        }
    }

    async fn upload(&self, name: &str) -> String {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let meta = UploadMeta {
            filename: name.into(),
            mime: None,
            title: None,
            tags: vec![],
            document_date: None,
        };
        let body = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from(bytes))]);
        match self
            .docs
            .store(
                self.u.as_ref().unwrap(),
                meta,
                body,
                OnDuplicate::Keep,
                None,
                NOW,
            )
            .await
            .unwrap()
        {
            StoreOutcome::Stored { id } => id,
            other => panic!("{other:?}"),
        }
    }
}

async fn wait_status(u: &Unlocked, id: &str, want: TextStatus) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let st = u
            .with_db(|c| get_document(c, id))
            .unwrap()
            .unwrap()
            .text_status;
        if st == want {
            return;
        }
        assert!(Instant::now() < deadline, "timeout, status {st:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_end_to_end() {
    if !have_tesseract() {
        return;
    }
    let env = Env::new(true);
    let id = env.upload("scanned.pdf").await;
    let u = env.u.as_ref().unwrap();
    wait_status(u, &id, TextStatus::Done).await;
    let hits = u
        .with_db(|c| search(c, "versicherungsnummer", &ListFilter::default()))
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].doc.id, id);
    assert_eq!(std::fs::read_dir(&env.tmp).unwrap().count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_survives_failure() {
    if !have_tesseract() {
        return;
    }
    let env = Env::new(true);
    let bad = env.upload("corrupt.pdf").await;
    let good = env.upload("text.pdf").await;
    let u = env.u.as_ref().unwrap();
    wait_status(u, &bad, TextStatus::Failed).await;
    wait_status(u, &good, TextStatus::Done).await;
    assert_eq!(std::fs::read_dir(&env.tmp).unwrap().count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_resumed_on_unlock() {
    if !have_tesseract() {
        return;
    }
    let mut env = Env::new(true);
    // Store while the real queue is wired but make the doc pending again, then lock.
    let id = env.upload("text.pdf").await;
    wait_status(env.u.as_ref().unwrap(), &id, TextStatus::Done).await;
    env.u
        .as_ref()
        .unwrap()
        .with_db(|c| {
            personal_media::user_db::set_text(c, &id, TextStatus::Pending, None, None, NOW)
        })
        .unwrap();
    env.u = None;
    // No Arc<Unlocked> remains, so the next login is a fresh unlock.
    let (u, _) = env.accounts.login("sebi", PW, None).unwrap();
    wait_status(&u, &id, TextStatus::Done).await;
    let _ = &env.dir;
}

// ---- subprocess isolation (I5) ----

use personal_media::extract::{ChildLimits, run_cmd};

fn sh(script: &str, dir: &Path, limits: &ChildLimits) -> Result<Vec<u8>, String> {
    run_cmd(
        "sh",
        &[std::ffi::OsStr::new("-c"), std::ffi::OsStr::new(script)],
        Duration::from_secs(20),
        dir,
        limits,
    )
}

#[test]
fn child_limits_default_values() {
    let l = ChildLimits::default();
    assert_eq!(l.as_bytes, 2 << 30);
    assert_eq!(l.fsize_bytes, 1 << 30);
    assert_eq!(l.nofile, 64);
    assert_eq!(l.extra_cpu_secs, 5);
}

#[test]
fn child_gets_clean_env_and_scratch_cwd() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_cmd(
        "env",
        &[],
        Duration::from_secs(10),
        dir.path(),
        &ChildLimits::default(),
    )
    .unwrap();
    let mut lines: Vec<&str> = std::str::from_utf8(&out).unwrap().lines().collect();
    lines.sort();
    assert_eq!(
        lines,
        ["LANG=C.UTF-8", "OMP_THREAD_LIMIT=1", "PATH=/usr/bin:/bin"]
    );
    let out = run_cmd(
        "pwd",
        &[],
        Duration::from_secs(10),
        dir.path(),
        &ChildLimits::default(),
    )
    .unwrap();
    let cwd = std::str::from_utf8(&out).unwrap().trim();
    assert_eq!(Path::new(cwd), dir.path().canonicalize().unwrap());
}

#[test]
fn child_exceeding_fsize_limit_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let limits = ChildLimits {
        fsize_bytes: 1 << 20,
        ..ChildLimits::default()
    };
    let err = sh("head -c 8000000 /dev/zero > big", dir.path(), &limits).unwrap_err();
    assert!(err.contains("exited"), "{err}");
    let len = std::fs::metadata(dir.path().join("big")).unwrap().len();
    assert!(len <= 1 << 20, "wrote {len} bytes");
    // Within the limit it works.
    sh("head -c 1000 /dev/zero > ok", dir.path(), &limits).unwrap();
}

#[test]
fn child_exceeding_address_space_limit_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let script = r#"x=$(head -c 300000000 /dev/zero | tr '\0' a); echo ${#x}"#;
    // Unrestricted it succeeds ...
    let out = sh(script, dir.path(), &ChildLimits::default()).unwrap();
    assert_eq!(String::from_utf8_lossy(&out).trim(), "300000000");
    // ... under a 128 MiB address-space limit it fails.
    let limits = ChildLimits {
        as_bytes: 128 << 20,
        ..ChildLimits::default()
    };
    assert!(sh(script, dir.path(), &limits).is_err());
}

// ---- page-by-page OCR (I6) ----

/// A 3-page scanned PDF built from the one-page fixture with pdfunite.
fn scanned3(dir: &Path) -> PathBuf {
    let one = fixture("scanned.pdf");
    let out = dir.join("scanned3.pdf");
    let st = std::process::Command::new("pdfunite")
        .arg(&one)
        .arg(&one)
        .arg(&one)
        .arg(&out)
        .status()
        .unwrap();
    assert!(st.success());
    out
}

fn count_pngs(dir: &Path) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                n += count_pngs(&p);
            } else if p.extension().is_some_and(|x| x == "png") {
                n += 1;
            }
        }
    }
    n
}

#[test]
fn scratch_never_holds_more_than_one_page_png() {
    if !have_tesseract() {
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let pdf = scanned3(work.path());
    let tmp = tempfile::tempdir().unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let max_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let watcher = {
        let (stop, max_seen, dir) = (stop.clone(), max_seen.clone(), tmp.path().to_path_buf());
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering::SeqCst;
            while !stop.load(SeqCst) {
                max_seen.fetch_max(count_pngs(&dir), SeqCst);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let r = extract_text(&pdf, "application/pdf", &cfg(tmp.path())).unwrap();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    watcher.join().unwrap();
    assert_eq!(r.page_count, Some(3));
    assert_eq!(
        r.text.matches("Versicherungsnummer").count(),
        3,
        "{:?}",
        r.text
    );
    assert!(max_seen.load(std::sync::atomic::Ordering::SeqCst) <= 1);
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn ocr_keeps_partial_text_on_budget_exhaustion() {
    if !have_tesseract() {
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let pdf = scanned3(work.path());
    let tmp = tempfile::tempdir().unwrap();
    // Time a full run, then give the job about half of that.
    let t = Instant::now();
    extract_text(&pdf, "application/pdf", &cfg(tmp.path())).unwrap();
    let full = t.elapsed();
    let mut c = cfg(tmp.path());
    c.job_timeout = full / 2;
    let r = extract_text(&pdf, "application/pdf", &c).unwrap();
    let pages_done = r.text.matches("Versicherungsnummer").count();
    assert!(
        (1..3).contains(&pages_done),
        "expected partial text, got {pages_done} pages: {:?}",
        r.text
    );
    assert_eq!(r.page_count, Some(3));
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn ocr_fails_when_no_page_succeeds_and_no_text_layer() {
    if !have_tesseract() {
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let pdf = scanned3(work.path());
    let tmp = tempfile::tempdir().unwrap();
    let mut c = cfg(tmp.path());
    // Enough for pdfinfo + pdftotext, nowhere near enough for a page.
    c.job_timeout = Duration::from_millis(150);
    match extract_text(&pdf, "application/pdf", &c) {
        Err(ExtractError::Failed(_)) => {}
        Ok(r) => assert!(r.text.trim().is_empty()),
        Err(e) => panic!("{e:?}"),
    }
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}
