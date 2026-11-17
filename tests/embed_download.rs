//! Model download integrity, size cap, timeouts and failure back-off, against
//! a fake HTTP server. No real model needed.

mod fakeserver;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fakeserver::*;
use personal_media::embed::model::{DownloadPolicy, ensure_model_with};
use personal_media::embed::{Engine, ModelSpec};

fn policy() -> DownloadPolicy {
    DownloadPolicy {
        allow_http: true,
        connect_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(10),
        total_timeout: Duration::from_secs(60),
        max_size_factor: 2,
        failure_backoff: Duration::from_secs(60),
    }
}

fn fetch(dir: &Path, spec: &ModelSpec, p: &DownloadPolicy) -> anyhow::Result<()> {
    ensure_model_with(dir, spec, p, &mut |_| {}).map(|_| ())
}

fn leftovers(dir: &Path, spec: &ModelSpec) -> Vec<String> {
    let d = spec.dir(dir);
    fs::read_dir(&d)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".part"))
                .collect()
        })
        .unwrap_or_default()
}

/// Serves `body` in small pieces so concurrent callers overlap.
fn slow_server(body: Vec<u8>) -> FakeServer {
    FakeServer::start(move |s, _, _| {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = s.write_all(head.as_bytes());
        for piece in body.chunks(64 * 1024) {
            if s.write_all(piece).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })
}

#[test]
fn concurrent_downloads_cannot_install_corrupt_file() {
    let body = body_of(1 << 20);
    let server = slow_server(body.clone());
    let spec = spec_for(&server.url, "concurrent", &body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let dir = tmp.path().to_path_buf();
    let results: Vec<anyhow::Result<()>> = std::thread::scope(|sc| {
        let handles: Vec<_> = (0..5)
            .map(|_| sc.spawn(|| fetch(&dir, spec, &policy())))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in &results {
        r.as_ref().unwrap();
    }
    // The lock serialised them: one download, the others found the file.
    assert_eq!(server.hits(), 1);
    let got = fs::read(spec.dir(&dir).join("a.bin")).unwrap();
    assert_eq!(sha_hex(&got), sha_hex(&body));
    assert!(leftovers(&dir, spec).is_empty());
}

#[test]
fn file_changed_while_downloading_is_not_installed() {
    // The stream hashes correctly, but the file on disk is tampered with before
    // the rename (what a second writer on a shared `.part` path would do).
    let body = body_of(512 * 1024);
    let half = body.len() / 2;
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let go_rx = std::sync::Mutex::new(go_rx);
    let b2 = body.clone();
    let server = FakeServer::start(move |s, _, ctl| {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            b2.len()
        );
        let _ = s.write_all(head.as_bytes());
        let _ = s.write_all(&b2[..half]);
        let _ = s.flush();
        // wait for the test to tamper, or for shutdown
        while !ctl.is_stopped() {
            if go_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_millis(20))
                .is_ok()
            {
                break;
            }
        }
        let _ = s.write_all(&b2[half..]);
    });
    let spec = spec_for(&server.url, "tamper", &body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let dir = tmp.path().to_path_buf();
    let model_dir = spec.dir(&dir);
    let res = std::thread::scope(|sc| {
        let h = sc.spawn(|| fetch(&dir, spec, &policy()));
        // find the unique temp file, wait until half the body is on disk
        let end = Instant::now() + Duration::from_secs(20);
        let part = loop {
            assert!(Instant::now() < end, "no .part file appeared");
            let found = fs::read_dir(&model_dir).ok().and_then(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .find(|p| p.to_string_lossy().ends_with(".part"))
            });
            if let Some(p) = found
                && fs::metadata(&p)
                    .map(|m| m.len() as usize >= half)
                    .unwrap_or(false)
            {
                break p;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // unique name: pid and random part, never a fixed `a.bin.part`
        let n = part.file_name().unwrap().to_string_lossy().into_owned();
        assert!(n.starts_with("a.bin.") && n != "a.bin.part", "{n}");
        let mut f = fs::OpenOptions::new().write(true).open(&part).unwrap();
        f.write_all(&[0u8; 4096]).unwrap();
        f.sync_all().unwrap();
        go_tx.send(()).unwrap();
        h.join().unwrap()
    });
    let err = res.unwrap_err().to_string();
    assert!(err.contains("on disk"), "{err}");
    assert!(!model_dir.join("a.bin").exists(), "corrupt file installed");
    assert!(leftovers(&dir, spec).is_empty());
}

#[test]
fn download_waits_for_the_directory_lock() {
    let body = body_of(64 * 1024);
    let server = FakeServer::serving(body.clone());
    let spec = spec_for(&server.url, "locked", &body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let dir = tmp.path().to_path_buf();
    // Another process holds the lock.
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join(".lock"))
        .unwrap();
    use std::os::fd::AsRawFd;
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    std::thread::scope(|sc| {
        let h = sc.spawn(|| fetch(&dir, spec, &policy()));
        std::thread::sleep(Duration::from_millis(400));
        assert!(!h.is_finished(), "fetch ran without the lock");
        assert_eq!(server.hits(), 0);
        drop(lock);
        h.join().unwrap().unwrap();
    });
    assert_eq!(server.hits(), 1);
}

#[test]
fn oversized_download_rejected() {
    let spec_body = body_of(1000);
    let big = body_of(10_000);
    // (a) the server announces too much
    let b = big.clone();
    let announced = FakeServer::start(move |s, _, _| respond(s, 200, &b));
    let spec = spec_for(&announced.url, "oversize-a", &spec_body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let err = fetch(tmp.path(), spec, &policy()).unwrap_err().to_string();
    assert!(err.contains("allowed"), "{err}");
    assert!(!spec.dir(tmp.path()).join("a.bin").exists());
    assert!(leftovers(tmp.path(), spec).is_empty());

    // (b) no content-length: the stream is cut off when it passes the cap
    let b = big.clone();
    let unsized_ = FakeServer::start(move |s, _, _| {
        respond_unsized_head(s);
        for piece in b.chunks(500) {
            if s.write_all(piece).is_err() {
                return;
            }
        }
    });
    let spec = spec_for(&unsized_.url, "oversize-b", &spec_body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let err = fetch(tmp.path(), spec, &policy()).unwrap_err().to_string();
    assert!(err.contains("exceeds"), "{err}");
    assert!(!spec.dir(tmp.path()).join("a.bin").exists());
    assert!(leftovers(tmp.path(), spec).is_empty());

    // exactly the expected size is fine
    let ok = FakeServer::serving(spec_body.clone());
    let spec = spec_for(&ok.url, "oversize-c", &spec_body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    fetch(tmp.path(), spec, &policy()).unwrap();
}

#[test]
fn stalled_download_is_aborted() {
    let body = body_of(100_000);
    // never answers
    let silent = FakeServer::start(|_, _, ctl| ctl.wait_for_shutdown());
    let spec = spec_for(&silent.url, "stall-a", &body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let p = DownloadPolicy {
        idle_timeout: Duration::from_millis(500),
        ..policy()
    };
    let t = Instant::now();
    assert!(fetch(tmp.path(), spec, &p).is_err());
    assert!(t.elapsed() < Duration::from_secs(8), "{:?}", t.elapsed());

    // stops in the middle of the body
    let b = body.clone();
    let half = FakeServer::start(move |s, _, ctl| {
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", b.len());
        let _ = s.write_all(head.as_bytes());
        let _ = s.write_all(&b[..b.len() / 2]);
        let _ = s.flush();
        ctl.wait_for_shutdown();
    });
    let spec = spec_for(&half.url, "stall-b", &body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let t = Instant::now();
    let err = fetch(tmp.path(), spec, &p).unwrap_err().to_string();
    assert!(err.contains("stalled"), "{err}");
    assert!(t.elapsed() < Duration::from_secs(8), "{:?}", t.elapsed());
    assert!(leftovers(tmp.path(), spec).is_empty());
}

#[test]
fn modified_file_is_hashed_again() {
    let body = body_of(10_000);
    let server = FakeServer::serving(body.clone());
    let spec = spec_for(&server.url, "rehash", &body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    fetch(tmp.path(), spec, &policy()).unwrap();
    fetch(tmp.path(), spec, &policy()).unwrap(); // verified once, cached
    // same length, different bytes, different mtime
    let path = spec.dir(tmp.path()).join("a.bin");
    let mut evil = body.clone();
    evil[0] ^= 0xff;
    fs::write(&path, &evil).unwrap();
    let f = fs::File::options().write(true).open(&path).unwrap();
    f.set_modified(std::time::SystemTime::now() + Duration::from_secs(5))
        .unwrap();
    let err = fetch(tmp.path(), spec, &policy()).unwrap_err().to_string();
    assert!(err.contains("SHA-256"), "{err}");
    assert!(!path.exists());
}

#[test]
fn failed_load_backs_off() {
    let body = body_of(10_000);
    let server = FakeServer::start(|s, _, _| respond(s, 500, b"nope"));
    let spec = spec_for(&server.url, "backoff", &body);
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let p = DownloadPolicy {
        failure_backoff: Duration::from_millis(800),
        ..policy()
    };
    let engine = Arc::new(Engine::with_spec(
        tmp.path().to_path_buf(),
        Duration::from_secs(600),
        spec,
        p,
    ));
    assert!(engine.embed_passages(&["x"]).is_err());
    assert_eq!(server.hits(), 1);
    // inside the window: fails at once, without touching the network
    let t = Instant::now();
    let err = engine.embed_passages(&["x"]).unwrap_err().to_string();
    assert!(err.contains("recent failure"), "{err}");
    assert!(engine.chunk("text").is_err());
    assert!(
        t.elapsed() < Duration::from_millis(300),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(server.hits(), 1);
    // after the window the next call tries again
    std::thread::sleep(Duration::from_millis(900));
    assert!(engine.embed_passages(&["x"]).is_err());
    assert_eq!(server.hits(), 2);
    // a query never downloads, backoff or not
    std::thread::sleep(Duration::from_millis(900));
    assert!(engine.embed_query("x").is_err());
    assert_eq!(server.hits(), 2);
}
