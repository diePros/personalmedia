//! A tiny plain-HTTP server for download tests (the production code only
//! speaks HTTPS; tests opt into HTTP through `DownloadPolicy::allow_http`).

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use personal_media::embed::{ModelFile, ModelSpec};
use sha2::{Digest, Sha256};

/// Called once per request with the accepted stream (request already read)
/// and the 0-based request number.
pub type Handler = dyn Fn(&mut TcpStream, usize, &Control) + Send + Sync;

/// Lets handlers wait until the test is over.
#[derive(Clone, Default)]
pub struct Control {
    stop: Arc<AtomicBool>,
}

impl Control {
    /// Sleeps until the server is shut down.
    pub fn wait_for_shutdown(&self) {
        while !self.stop.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

pub struct FakeServer {
    pub url: String,
    hits: Arc<AtomicUsize>,
    control: Control,
    addr: std::net::SocketAddr,
    accept: Option<JoinHandle<()>>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl FakeServer {
    pub fn start(
        handler: impl Fn(&mut TcpStream, usize, &Control) + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let control = Control::default();
        let handler: Arc<Handler> = Arc::new(handler);
        let conns: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let (h2, c2, k2, conns2) = (hits.clone(), control.clone(), handler, conns.clone());
        let accept = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if c2.is_stopped() {
                    break;
                }
                let Ok(mut stream) = stream else { break };
                let n = h2.fetch_add(1, Ordering::SeqCst);
                let (k, c) = (k2.clone(), c2.clone());
                let t = std::thread::spawn(move || {
                    let mut req = Vec::new();
                    let mut b = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut b) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&b[..n]),
                        }
                    }
                    k(&mut stream, n, &c);
                    let _ = stream.shutdown(Shutdown::Both);
                });
                conns2.lock().unwrap().push(t);
            }
        });
        FakeServer {
            url: format!("http://{addr}/file.bin"),
            hits,
            control,
            addr,
            accept: Some(accept),
            conns,
        }
    }

    /// Serves `body` (with a content-length) to every request.
    pub fn serving(body: Vec<u8>) -> Self {
        FakeServer::start(move |s, _, _| respond(s, 200, &body))
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn control(&self) -> Control {
        self.control.clone()
    }

    /// Waits until at least `n` requests arrived.
    pub fn wait_hits(&self, n: usize) {
        let end = Instant::now() + Duration::from_secs(20);
        while self.hits() < n {
            assert!(
                Instant::now() < end,
                "server saw {} of {n} requests",
                self.hits()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.control.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr); // wake the accept loop
        if let Some(t) = self.accept.take() {
            let _ = t.join();
        }
        for t in self.conns.lock().unwrap().drain(..) {
            let _ = t.join();
        }
    }
}

pub fn respond(s: &mut TcpStream, status: u16, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
}

/// Headers without a content-length: the body ends when the connection closes.
pub fn respond_unsized_head(s: &mut TcpStream) {
    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
}

pub fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// A one-file spec for `body` served at `url` (leaked: specs are `'static`).
pub fn spec_for(url: &str, name: &'static str, body: &[u8]) -> &'static ModelSpec {
    let file = ModelFile {
        name: "a.bin",
        url: Box::leak(url.to_owned().into_boxed_str()),
        sha256: Box::leak(sha_hex(body).into_boxed_str()),
        size: body.len() as u64,
    };
    Box::leak(Box::new(ModelSpec {
        name,
        files: Box::leak(Box::new([file])),
        dims: 384,
        max_tokens: 512,
        query_prefix: "query: ",
        passage_prefix: "passage: ",
    }))
}

/// Deterministic pseudo-random bytes.
pub fn body_of(len: usize) -> Vec<u8> {
    let mut x = 0x2545F4914F6CDD1Du64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}
