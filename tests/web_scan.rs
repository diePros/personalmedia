//! The Scan screen: `GET /scan`, `POST /api/scan` and the standalone app shell.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::*;
use personal_media::keyring::user_dir;
use personal_media::system_db::QuotaSetting;
use serde_json::Value;

const P1: &[u8] = include_bytes!("fixtures/scan1.jpg");
const P2: &[u8] = include_bytes!("fixtures/scan2.jpg");
const PNG: &[u8] = include_bytes!("fixtures/scan.png");

fn have(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn pdfinfo(pdf: &[u8]) -> String {
    let mut child = Command::new("pdfinfo")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(pdf).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "pdfinfo failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn blob_count(t: &TestApp, user: &str) -> usize {
    let id = t.state.sys.user_by_name(user).unwrap().unwrap().id;
    std::fs::read_dir(user_dir(t.dir.path(), &id).join("blobs"))
        .map(|d| d.count())
        .unwrap_or(0)
}

async fn scan(t: &TestApp, c: &Client, fields: &[(&str, &str)], pages: &[&[u8]]) -> (u16, Value) {
    let files: Vec<(&str, &str, &str, &[u8])> = pages
        .iter()
        .map(|p| ("page", "page.jpg", "image/jpeg", *p))
        .collect();
    let resp = t.post_multipart("/api/scan", fields, &files, c).await;
    let status = resp.status().as_u16();
    let body = body_string(resp).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_three_pages_builds_valid_pdf() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let (status, v) = scan(
        &t,
        &c,
        &[
            ("title", "Rent"),
            ("tags", "inbox, home"),
            ("date", "2026-11-01"),
        ],
        &[P1, P2, P1],
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["status"], "stored");
    let id = v["id"].as_str().unwrap();

    let detail = body_string(t.get(&format!("/documents/{id}"), &c).await).await;
    assert!(detail.contains("Rent"));
    assert!(detail.contains("inbox"));
    assert!(detail.contains("2026-11-01"));

    let dl = t.get(&format!("/documents/{id}/download"), &c).await;
    assert_eq!(dl.status(), 200);
    assert!(header_str(&dl, "content-disposition").contains("Scan "));
    let pdf = body_bytes(dl).await;
    assert!(pdf.starts_with(b"%PDF-1.4"));
    if have("pdfinfo") {
        assert!(pdfinfo(&pdf).contains("Pages:           3"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_default_title_and_filename_are_the_timestamp() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let (status, v) = scan(&t, &c, &[], &[P1]).await;
    assert_eq!(status, 200);
    let id = v["id"].as_str().unwrap();
    let detail = body_string(t.get(&format!("/documents/{id}"), &c).await).await;
    let marker = "Scan 20";
    let i = detail.find(marker).expect("title starts with Scan 20");
    let stamp = &detail[i..i + "Scan 2026-11-17 12-08".len()];
    let b = stamp.as_bytes();
    assert_eq!(
        (b[9], b[12], b[15], b[18]),
        (b'-', b'-', b' ', b'-'),
        "{stamp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_rejects_bad_input_without_blob() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    for (label, pages) in [
        ("png", vec![P1, PNG]),
        ("text", vec![b"not an image".as_slice()]),
        ("truncated", vec![&P2[..P2.len() / 2]]),
        ("none", vec![]),
    ] {
        let (status, v) = scan(&t, &c, &[], &pages).await;
        assert_eq!(status, 422, "{label}: {v}");
        assert!(v["error"].is_string(), "{label}: {v}");
    }
    let (_, v) = scan(&t, &c, &[], &[P1, PNG]).await;
    assert!(v["error"].as_str().unwrap().contains("page 2"));
    assert_eq!(blob_count(&t, "alice"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_limits_page_count_and_form_fields() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let fifty_one = vec![P1; 51];
    let (status, v) = scan(&t, &c, &[], &fifty_one).await;
    assert_eq!(status, 422, "{v}");
    assert!(v["error"].as_str().unwrap().contains("50"));
    let (status, _) = scan(&t, &c, &[("title", &"t".repeat(301))], &[P1]).await;
    assert_eq!(status, 422);
    let big = "x".repeat(9 * 1024);
    let (status, _) = scan(&t, &c, &[("title", &big)], &[P1]).await;
    assert_eq!(status, 413);
    assert_eq!(blob_count(&t, "alice"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_page_over_8_mib_is_413() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    // JPEG header and EOI around filler: the size check comes first.
    let mut big = P1.to_vec();
    big.resize(8 * 1024 * 1024 + 1, 0);
    let (status, _) = scan(&t, &c, &[], &[&big]).await;
    assert_eq!(status, 413);
    assert_eq!(blob_count(&t, "alice"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_respects_quota() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = t.state.sys.user_by_name("alice").unwrap().unwrap().id;
    let base = t.state.quotas.usage(&id).await;
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(base + 10 * 1024))
        .unwrap();
    let (status, v) = scan(&t, &c, &[], &[P1, P2]).await;
    assert_eq!(status, 413);
    assert_eq!(v["status"], "quota_exceeded");
    assert!(v["message"].is_string());
    assert_eq!(blob_count(&t, "alice"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_requires_session_and_csrf() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let resp = t
        .post_multipart(
            "/api/scan",
            &[],
            &[("page", "p.jpg", "image/jpeg", P1)],
            &Client::anon(),
        )
        .await;
    assert_ne!(resp.status(), 200);
    let bad = Client {
        cookie: c.cookie.clone(),
        csrf: "wrong".into(),
    };
    let resp = t
        .post_multipart(
            "/api/scan",
            &[],
            &[("page", "p.jpg", "image/jpeg", P1)],
            &bad,
        )
        .await;
    assert_eq!(resp.status(), 403);
    assert_eq!(blob_count(&t, "alice"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_page_requires_login_and_returns_to_scan() {
    let t = TestApp::new();
    let resp = t.get("/scan", &Client::anon()).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/login?next=scan");
    // The login form carries the return target through.
    let login = body_string(t.get("/login?next=scan", &Client::anon()).await).await;
    assert!(login.contains("name=\"next\" value=\"scan\""));
    let plain = body_string(t.get("/login", &Client::anon()).await).await;
    assert!(!plain.contains("name=\"next\""));

    t.signup_and_login("alice").await;
    let resp = t
        .post_form_raw(
            "/login",
            &[
                ("username", "alice"),
                ("password", PASSWORD),
                ("next", "scan"),
            ],
            &Client::anon(),
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/scan");
    // Anything but the known target is ignored.
    let resp = t
        .post_form_raw(
            "/login",
            &[
                ("username", "alice"),
                ("password", PASSWORD),
                ("next", "//evil.example"),
            ],
            &Client::anon(),
        )
        .await;
    assert_eq!(header_str(&resp, "location"), "/documents");

    let c = t.session_for("bob");
    let resp = t.get("/scan", &c).await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    assert!(html.contains("id=\"scan-app\""));
    assert!(html.contains("/static/scan.js"));
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_page_has_every_screen_state() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let html = body_string(t.get("/scan", &c).await).await;
    // Empty state: camera, library and files inputs.
    assert!(html.contains("accept=\"image/*\" capture=\"environment\""));
    assert!(html.contains("id=\"scan-library\""));
    assert!(html.contains("accept=\"image/*,application/pdf\" multiple"));
    // Pages strip, sticky save, save sheet, progress, success, offline banner.
    for id in [
        "scan-pages",
        "scan-save",
        "scan-sheet",
        "scan-title",
        "scan-date",
        "scan-tags",
        "scan-upload",
        "scan-progress",
        "scan-cancel",
        "scan-done",
        "scan-another",
        "scan-open",
        "scan-offline",
        "scan-error",
        "scan-viewer",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")), "missing #{id}");
    }
    assert!(html.contains("Saved — text recognition runs in the background"));
    // No inline script or style (strict CSP).
    assert!(!html.contains("<style"));
    assert!(!html.contains("onclick="));
    assert!(!html.contains("style=\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_page_offers_recent_tags_and_inbox() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let (status, _) = scan(&t, &c, &[("tags", "zebra,apple")], &[P1]).await;
    assert_eq!(status, 200);
    let html = body_string(t.get("/scan", &c).await).await;
    assert!(html.contains("data-tag=\"inbox\""));
    assert!(html.contains("data-tag=\"zebra\""));
    assert!(html.contains("data-tag=\"apple\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn standalone_shell_markup_present() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    for path in ["/documents", "/scan", "/settings"] {
        let html = body_string(t.get(path, &c).await).await;
        assert!(html.contains("class=\"tabbar\""), "{path}");
        for href in ["/documents", "/scan", "/documents#q", "/settings"] {
            assert!(html.contains(&format!("href=\"{href}\"")), "{path} {href}");
        }
        assert!(html.contains("<svg"), "{path}");
        assert_eq!(html.matches("class=\"tab\"").count(), 4, "{path}");
    }
    // Anonymous pages have no tab bar.
    let login = body_string(t.get("/login", &Client::anon()).await).await;
    assert!(!login.contains("class=\"tabbar\""));
    // JS marks the standalone state; CSS only acts under it.
    let js = include_str!("../static/app.js");
    assert!(js.contains("classList.add(\"standalone\")"));
    assert!(js.contains("aria-current"));
}

#[tokio::test(flavor = "multi_thread")]
async fn non_standalone_layout_unchanged() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let html = body_string(t.get("/documents", &c).await).await;
    // The header markup is exactly what it was.
    let header = "<header class=\"site-header\">\n<a class=\"brand\" href=\"/documents\">PMS</a>\n<nav class=\"site-nav\" aria-label=\"Main\">\n<a href=\"/documents\">Documents</a>\n<a href=\"/settings\">Settings</a>\n";
    assert!(html.contains(header), "{html}");
    // The tab bar sits after <main>, so it cannot move the header or content.
    assert!(html.find("</main>").unwrap() < html.find("class=\"tabbar\"").unwrap());
    // CSS: hidden by default, shown and the header hidden only when standalone.
    let css = include_str!("../static/app.css");
    let tab_rule = css.split(".tabbar {").nth(1).expect(".tabbar rule");
    assert!(
        tab_rule
            .split('}')
            .next()
            .unwrap()
            .contains("display: none")
    );
    let standalone: Vec<&str> = css
        .split("@media (display-mode: standalone)")
        .skip(1)
        .collect();
    assert!(!standalone.is_empty());
    assert!(css.contains(".standalone .site-header"));
    assert!(css.contains(".standalone .tabbar"));
    // Outside the standalone media block, only `.standalone`-scoped rules may
    // hide the header.
    let mut plain = String::new();
    let mut rest = css;
    while let Some(i) = rest.find("@media (display-mode: standalone)") {
        plain.push_str(&rest[..i]);
        let mut depth = 0;
        let mut end = rest.len();
        for (k, ch) in rest[i..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + k + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = &rest[end..];
    }
    plain.push_str(rest);
    for rule in plain.split('}') {
        if rule.contains(".site-header") && rule.contains("display: none") {
            assert!(rule.contains(".standalone"), "{rule}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_assets_are_served_and_precached() {
    let t = TestApp::new();
    for path in ["/static/scan.js", "/static/scan.css"] {
        let resp = t.get(path, &Client::anon()).await;
        assert_eq!(resp.status(), 200, "{path}");
    }
    let sw = body_string(t.get("/sw.js", &Client::anon()).await).await;
    assert!(sw.contains("\"/static/scan.js\""));
    assert!(sw.contains("\"/static/scan.css\""));
    let manifest = body_string(t.get("/manifest.webmanifest", &Client::anon()).await).await;
    assert!(manifest.contains("\"start_url\": \"/scan\""));
}

/// A two-page scan goes through OCR and both pages become searchable.
#[tokio::test(flavor = "multi_thread")]
async fn scan_end_to_end_ocr_search() {
    if !have("tesseract") {
        println!("SKIP");
        return;
    }
    let t = TestApp::new();
    let c = t.session_for("alice");
    let (status, _) = scan(&t, &c, &[], &[P1, P2]).await;
    assert_eq!(status, 200);
    for word in ["versicherungsnummer", "kuendigungsfrist"] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            let html = body_string(t.hx_get(&format!("/documents?q={word}"), &c).await).await;
            if html.contains("doc-item") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{word} never became searchable"
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}
