mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, header};
use axum::response::Response;
use common::*;

const PDF: &[u8] = include_bytes!("fixtures/text.pdf");
const BOUNDARY: &str = "share-boundary-5d1e";

/// `POST /share` the way the OS sends it: multipart, no CSRF token, a
/// cross-site `Sec-Fetch-Site`, and the session cookie if the client has one.
async fn os_share(t: &TestApp, client: &Client, files: &[(&str, &[u8])], title: &str) -> Response {
    let mut body = Vec::new();
    for (name, value) in [("title", title), ("text", "ignored")] {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    for (filename, bytes) in files {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    let req = builder(Method::POST, "/share", client)
        .header("sec-fetch-site", "cross-site")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(body))
        .unwrap();
    t.request(req).await
}

fn location(resp: &Response) -> String {
    header_str(resp, "location").to_owned()
}

fn set_cookies(resp: &Response) -> Vec<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

fn doc_count(t: &TestApp, c: &Client) -> i64 {
    let s = t.state.sessions.get(&c.cookie).unwrap();
    s.unlocked
        .with_db(|db| db.query_row("SELECT COUNT(*) FROM documents", [], |r| r.get(0)))
        .unwrap()
}

fn files_under(dir: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            if rel == "tmp" {
                continue; // OCR scratch tmpfs
            }
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                out.insert(rel);
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(dir, dir, &mut out);
    out
}

async fn open_review(t: &TestApp, c: &Client, id: &str) -> Response {
    t.get(&format!("/share/{id}"), c).await
}

fn staging_id(location: &str) -> String {
    location.strip_prefix("/share/").unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn share_with_session_redirects_to_review_and_saves() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let resp = os_share(&t, &c, &[("scan.pdf", PDF)], "Water bill").await;
    assert_eq!(resp.status(), 303);
    let loc = location(&resp);
    assert!(loc.starts_with("/share/"), "{loc}");
    assert!(set_cookies(&resp).is_empty());
    let id = staging_id(&loc);

    let page = open_review(&t, &c, &id).await;
    assert_eq!(page.status(), 200);
    let html = body_string(page).await;
    assert!(html.contains("scan.pdf"));
    assert!(html.contains("Water bill"), "title is prefilled");

    let resp = t
        .post_form(
            &format!("/share/{id}"),
            &[("title", "March water bill"), ("tags", "bills, home")],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), "/documents");
    assert_eq!(doc_count(&t, &c), 1);
    let list = body_string(t.get("/documents", &c).await).await;
    assert!(list.contains("March water bill"));
    assert!(list.contains("bills"));
    // The share is consumed.
    assert_eq!(open_review(&t, &c, &id).await.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn share_without_session_continues_after_login() {
    let t = TestApp::new();
    t.signup_and_login("alice").await;
    let resp = os_share(&t, &Client::anon(), &[("scan.pdf", PDF)], "").await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), "/login");
    let cookies = set_cookies(&resp);
    assert_eq!(cookies.len(), 1);
    let (pair, attrs) = cookies[0].split_once("; ").unwrap();
    assert!(pair.starts_with("__Host-pm_continue="), "{pair}");
    assert_eq!(attrs, "HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=900");
    let id = pair.strip_prefix("__Host-pm_continue=").unwrap().to_owned();
    assert_eq!(id.len(), 43);

    // The staged share is not reachable without a session.
    assert_eq!(open_review(&t, &Client::anon(), &id).await.status(), 303);

    // Log in carrying the continue cookie.
    let req = builder(Method::POST, "/login", &Client::anon())
        .header("sec-fetch-site", "same-origin")
        .header(header::COOKIE, pair)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "username=alice&password={}",
            "correct%20horse%20battery"
        )))
        .unwrap();
    let resp = t.request(req).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), format!("/share/{id}"));
    let cookies = set_cookies(&resp);
    assert!(cookies.iter().any(|c| c.starts_with("__Host-pm_session=")));
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("__Host-pm_continue=;") && c.contains("Max-Age=0"))
    );
    let c = client_from_response(&resp);
    let page = open_review(&t, &c, &id).await;
    assert_eq!(page.status(), 200);
    assert!(body_string(page).await.contains("scan.pdf"));
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_login_ignores_unknown_continue_cookie() {
    let t = TestApp::new();
    t.signup_and_login("alice").await;
    let req = builder(Method::POST, "/login", &Client::anon())
        .header("sec-fetch-site", "same-origin")
        .header(
            header::COOKIE,
            format!("__Host-pm_continue={}", "A".repeat(43)),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "username=alice&password=correct%20horse%20battery",
        ))
        .unwrap();
    let resp = t.request(req).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), "/documents");
}

#[tokio::test(flavor = "multi_thread")]
async fn share_post_cannot_store_without_review() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let before = doc_count(&t, &c);
    let resp = os_share(&t, &c, &[("a.pdf", PDF), ("b.pdf", b"other")], "x").await;
    assert_eq!(resp.status(), 303);
    assert_eq!(doc_count(&t, &c), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn save_and_discard_need_csrf_and_same_origin() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = staging_id(&location(&os_share(&t, &c, &[("a.pdf", PDF)], "").await));

    // No token.
    let resp = t
        .post_form_raw(&format!("/share/{id}"), &[("title", "x")], &c)
        .await;
    assert_eq!(resp.status(), 403);
    let resp = t
        .post_form_raw(&format!("/share/{id}/discard"), &[], &c)
        .await;
    assert_eq!(resp.status(), 403);
    // Cross-site, even with the token.
    let req = builder(Method::POST, &format!("/share/{id}"), &c)
        .header("sec-fetch-site", "cross-site")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf={}", c.csrf)))
        .unwrap();
    assert_eq!(t.request(req).await.status(), 403);
    // Multipart to the save route is not exempt either.
    let resp = t
        .post_multipart(
            &format!("/share/{id}"),
            &[],
            &[],
            &Client {
                csrf: String::new(),
                ..c.clone()
            },
        )
        .await;
    assert_eq!(resp.status(), 403);
    assert_eq!(doc_count(&t, &c), 0);
    assert_eq!(open_review(&t, &c, &id).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn discard_drops_the_share() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = staging_id(&location(&os_share(&t, &c, &[("a.pdf", PDF)], "").await));
    let resp = t.post_form(&format!("/share/{id}/discard"), &[], &c).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(open_review(&t, &c, &id).await.status(), 404);
    assert_eq!(doc_count(&t, &c), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_share_is_bound_to_one_user() {
    let t = TestApp::new();
    let alice = t.session_for("alice");
    let bob = t.session_for("bob");

    // Staged with a session: bound to alice at once.
    let id = staging_id(&location(
        &os_share(&t, &alice, &[("a.pdf", PDF)], "").await,
    ));
    assert_eq!(open_review(&t, &bob, &id).await.status(), 404);
    assert_eq!(
        t.post_form(&format!("/share/{id}"), &[], &bob)
            .await
            .status(),
        404
    );
    assert_eq!(
        t.post_form(&format!("/share/{id}/discard"), &[], &bob)
            .await
            .status(),
        404
    );
    assert_eq!(open_review(&t, &alice, &id).await.status(), 200);

    // Staged without one: bound to whoever opens it first.
    let resp = os_share(&t, &Client::anon(), &[("b.pdf", PDF)], "").await;
    let cookie = set_cookies(&resp).remove(0);
    let id = cookie
        .strip_prefix("__Host-pm_continue=")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(open_review(&t, &bob, &id).await.status(), 200);
    assert_eq!(open_review(&t, &alice, &id).await.status(), 404);
    assert_eq!(open_review(&t, &bob, &id).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn staged_share_expires() {
    let t = TestApp::with_config(|c| c.share_ttl = Duration::from_secs(1));
    let c = t.session_for("alice");
    let id = staging_id(&location(&os_share(&t, &c, &[("a.pdf", PDF)], "").await));
    assert_eq!(open_review(&t, &c, &id).await.status(), 200);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(open_review(&t, &c, &id).await.status(), 404);
    assert_eq!(
        t.post_form(&format!("/share/{id}"), &[], &c).await.status(),
        404
    );
    assert_eq!(doc_count(&t, &c), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn share_too_large_413() {
    let t = TestApp::with_config(|c| c.max_upload_bytes = 1024);
    let c = t.session_for("alice");
    let big = vec![b'x'; 2000];
    let resp = os_share(&t, &c, &[("big.pdf", &big)], "").await;
    assert_eq!(resp.status(), 413);
    // Two files that only together exceed the cap.
    let part = vec![b'x'; 600];
    let resp = os_share(&t, &c, &[("a.pdf", &part), ("b.pdf", &part)], "").await;
    assert_eq!(resp.status(), 413);

    // Global cap: 4 x max_upload_bytes over all staged shares.
    let part = vec![b'y'; 1000];
    for _ in 0..4 {
        let resp = os_share(&t, &c, &[("a.pdf", &part)], "").await;
        assert_eq!(resp.status(), 303);
    }
    let resp = os_share(&t, &c, &[("a.pdf", &part)], "").await;
    assert_eq!(resp.status(), 413);
}

#[tokio::test(flavor = "multi_thread")]
async fn share_never_touches_disk() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let before = files_under(t.dir.path());
    let big = vec![b'z'; 512 * 1024];
    for client in [&c, &Client::anon()] {
        let resp = os_share(&t, client, &[("a.pdf", PDF), ("big.pdf", &big)], "t").await;
        assert_eq!(resp.status(), 303);
    }
    assert_eq!(files_under(t.dir.path()), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_is_shown_on_the_result_page() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let first = staging_id(&location(&os_share(&t, &c, &[("a.pdf", PDF)], "").await));
    let resp = t
        .post_form(&format!("/share/{first}"), &[("title", "Original")], &c)
        .await;
    assert_eq!(resp.status(), 303);

    let again = staging_id(&location(&os_share(&t, &c, &[("same.pdf", PDF)], "").await));
    let resp = t.post_form(&format!("/share/{again}"), &[], &c).await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    assert!(html.contains("already in your vault"), "{html}");
    assert!(html.contains("Original"));
    assert_eq!(doc_count(&t, &c), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn review_form_applies_input_caps_and_keeps_the_share() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = staging_id(&location(&os_share(&t, &c, &[("a.pdf", PDF)], "").await));
    let long_title = "t".repeat(301);
    let resp = t
        .post_form(&format!("/share/{id}"), &[("title", &long_title)], &c)
        .await;
    assert_eq!(resp.status(), 422);
    let many = (0..51)
        .map(|i| format!("t{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let resp = t
        .post_form(&format!("/share/{id}"), &[("tags", &many)], &c)
        .await;
    assert_eq!(resp.status(), 422);
    let long_tag = "g".repeat(65);
    let resp = t
        .post_form(&format!("/share/{id}"), &[("tags", &long_tag)], &c)
        .await;
    assert_eq!(resp.status(), 422);
    assert_eq!(doc_count(&t, &c), 0);
    assert_eq!(open_review(&t, &c, &id).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn share_without_files_is_400_and_bad_id_is_404() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let resp = os_share(&t, &c, &[], "only a title").await;
    assert_eq!(resp.status(), 400);
    let resp = t.get("/share/not-an-id", &c).await;
    assert_eq!(resp.status(), 404);
}
