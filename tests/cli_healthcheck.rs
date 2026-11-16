use std::io::{Read, Write};
use std::net::TcpListener;

use assert_cmd::Command;

/// Serves one canned response on a free port; returns the bind address.
fn serve_once(response: &'static str) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).unwrap_or(0);
            assert!(buf[..n].starts_with(b"GET /login HTTP/1.1"));
            let _ = s.write_all(response.as_bytes());
        }
    });
    addr
}

fn run(bind: &str) -> assert_cmd::assert::Assert {
    Command::cargo_bin("personal-media")
        .unwrap()
        .arg("healthcheck")
        .env("PM_BIND", bind)
        .assert()
}

#[test]
fn healthy_on_200() {
    let addr = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
    run(&addr).success();
}

#[test]
fn unhealthy_on_500() {
    let addr = serve_once("HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n");
    run(&addr).code(1);
}

#[test]
fn unhealthy_when_nothing_listens() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    run(&addr).code(1);
}
