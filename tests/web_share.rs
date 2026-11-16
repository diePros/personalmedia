mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, header};
use axum::response::Response;
use common::*;

const PDF: &[u8] = include_bytes!("fixtures/text.pdf");
const BOUNDARY: &str = "share-boundary-5d1e";

/// `POST /share` the way the OS sends it: multipart, no CSRF token, a
/// cross-site `Sec-Fetch-Site`, and the session cookie if the client has one.
async fn os_share(t: &TestApp, client: &Client, files: &[(&str, &[u8])], title: &str) -> Response {
    t.request(share_request(client, files, title)).await
}

/// Like [`os_share`], but arriving from `peer` instead of the default test peer.
async fn os_share_from(
    t: &TestApp,
    client: &Client,
    files: &[(&str, &[u8])],
    peer: &str,
) -> Response {
    let mut req = share_request(client, files, "");
    req.extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    t.request(req).await
}

fn share_request(client: &Client, files: &[(&str, &[u8])], title: &str) -> Request<Body> {
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
    builder(Method::POST, "/share", client)
        .header("sec-fetch-site", "cross-site")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(body))
        .unwrap()
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

/// A GET carrying the session cookie and the `__Host-pm_continue` cookie.
async fn get_with_continue(t: &TestApp, c: &Client, path: &str, id: &str) -> Response {
    let mut cookie = format!("__Host-pm_continue={id}");
    if !c.cookie.is_empty() {
        cookie.push_str(&format!("; __Host-pm_session={}", c.cookie));
    }
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    t.request(req).await
}

/// Stages a share without a session; returns the staging id from the cookie.
async fn anon_share(t: &TestApp, name: &str) -> String {
    let resp = os_share(t, &Client::anon(), &[(name, PDF)], "Attacker title").await;
    assert_eq!(resp.status(), 303);
    continue_id_of(&resp)
}

fn continue_id_of(resp: &Response) -> String {
    set_cookies(resp)
        .iter()
        .find_map(|c| c.strip_prefix("__Host-pm_continue="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn login_with_continue(t: &TestApp, user: &str, id: &str) -> Response {
    let req = builder(Method::POST, "/login", &Client::anon())
        .header("sec-fetch-site", "same-origin")
        .header(header::COOKIE, format!("__Host-pm_continue={id}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "username={user}&password=correct%20horse%20battery"
        )))
        .unwrap();
    t.request(req).await
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
    let resp = login_with_continue(&t, "alice", &id).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), format!("/share/{id}"));
    let cookies = set_cookies(&resp);
    assert!(cookies.iter().any(|c| c.starts_with("__Host-pm_session=")));
    // The review page needs the cookie as proof, so login keeps it.
    assert!(!cookies.iter().any(|c| c.starts_with("__Host-pm_continue=")));
    let c = client_from_response(&resp);
    let page = get_with_continue(&t, &c, &format!("/share/{id}"), &id).await;
    assert_eq!(page.status(), 200);
    assert!(
        set_cookies(&page)
            .iter()
            .any(|c| c.starts_with("__Host-pm_continue=;") && c.contains("Max-Age=0"))
    );
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
    let id = staging_id(&location(
        &os_share(&t, &alice, &[("a.pdf", PDF)], "").await,
    ));
    assert_eq!(open_review(&t, &bob, &id).await.status(), 404);
    // Not even with a continue cookie naming it.
    assert_eq!(
        get_with_continue(&t, &bob, &format!("/share/{id}"), &id)
            .await
            .status(),
        404
    );
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
}

#[tokio::test(flavor = "multi_thread")]
async fn anon_share_cannot_be_claimed_via_bare_url() {
    let t = TestApp::new();
    let alice = t.session_for("alice");
    let id = anon_share(&t, "evil.pdf").await;
    // Whoever knows the id but did not send the share gets nothing.
    assert_eq!(open_review(&t, &alice, &id).await.status(), 404);
    assert_eq!(
        t.post_form(&format!("/share/{id}"), &[], &alice)
            .await
            .status(),
        404
    );
    assert_eq!(
        t.post_form(&format!("/share/{id}/discard"), &[], &alice)
            .await
            .status(),
        404
    );
    assert_eq!(doc_count(&t, &alice), 0);
    // The entry is still there for its sender.
    let page = get_with_continue(&t, &alice, &format!("/share/{id}"), &id).await;
    assert_eq!(page.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn anon_share_claimed_with_continue_cookie_binds_to_one_user() {
    let t = TestApp::new();
    let alice = t.session_for("alice");
    let bob = t.session_for("bob");
    let id = anon_share(&t, "mine.pdf").await;
    let page = get_with_continue(&t, &bob, &format!("/share/{id}"), &id).await;
    assert_eq!(page.status(), 200);
    // Now bound to bob: alice is out even with the cookie, bob needs no more.
    assert_eq!(
        get_with_continue(&t, &alice, &format!("/share/{id}"), &id)
            .await
            .status(),
        404
    );
    assert_eq!(open_review(&t, &bob, &id).await.status(), 200);
    let resp = t.post_form(&format!("/share/{id}"), &[], &bob).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(doc_count(&t, &bob), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn anon_review_warns_and_does_not_prefill() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = anon_share(&t, "scan.pdf").await;
    let page = get_with_continue(&t, &c, &format!("/share/{id}"), &id).await;
    let html = body_string(page).await;
    assert!(
        html.contains("These files were sent to Personal Media before you logged in. Only save them if you just shared them yourself."),
        "{html}"
    );
    assert!(
        !html.contains("Attacker title"),
        "title must not be prefilled"
    );
    // A share staged with a session has neither.
    let id = staging_id(&location(
        &os_share(&t, &c, &[("b.pdf", b"other")], "My title").await,
    ));
    let html = body_string(open_review(&t, &c, &id).await).await;
    assert!(!html.contains("before you logged in"));
    assert!(html.contains("My title"));
}

#[tokio::test(flavor = "multi_thread")]
async fn login_page_with_session_and_continue_cookie_goes_to_the_share() {
    let t = TestApp::new();
    let alice = t.session_for("alice");
    let bob = t.session_for("bob");
    let id = anon_share(&t, "scan.pdf").await;
    let resp = get_with_continue(&t, &alice, "/login", &id).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), format!("/share/{id}"));
    // No continue cookie, an unknown one, or no session: the plain login page.
    assert_eq!(t.get("/login", &alice).await.status(), 200);
    assert_eq!(
        get_with_continue(&t, &alice, "/login", &"A".repeat(43))
            .await
            .status(),
        200
    );
    assert_eq!(
        get_with_continue(&t, &Client::anon(), "/login", &id)
            .await
            .status(),
        200
    );
    // A share bound to someone else is not offered.
    let own = staging_id(&location(&os_share(&t, &bob, &[("b.pdf", b"b")], "").await));
    assert_eq!(
        get_with_continue(&t, &alice, "/login", &own).await.status(),
        200
    );
    // A session that has not confirmed its recovery key stays on /login.
    let pending = t.pending_session_for("carol");
    assert_eq!(
        get_with_continue(&t, &pending, "/login", &id)
            .await
            .status(),
        200
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn login_ignores_a_share_bound_to_someone_else() {
    let t = TestApp::new();
    t.signup_and_login("alice").await;
    let bob = t.session_for("bob");
    let own = staging_id(&location(&os_share(&t, &bob, &[("b.pdf", b"b")], "").await));
    let resp = login_with_continue(&t, "alice", &own).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), "/documents");
    assert!(
        set_cookies(&resp)
            .iter()
            .any(|c| c.starts_with("__Host-pm_continue=;"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_login_keeps_the_share_until_the_key_is_confirmed() {
    let t = TestApp::new();
    // A user who never confirmed the recovery key: login shows it again.
    let _ = t.pending_session_for("alice");
    let id = anon_share(&t, "scan.pdf").await;
    let resp = login_with_continue(&t, "alice", &id).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), "/recovery-key");
    assert!(
        !set_cookies(&resp)
            .iter()
            .any(|c| c.starts_with("__Host-pm_continue=")),
        "the continue cookie must survive until the key is confirmed"
    );
    let mut c = client_from_response(&resp);
    let page = t.get("/recovery-key", &c).await;
    c.csrf = csrf_from_html(&body_string(page).await);
    let req = builder(Method::POST, "/recovery-key", &c)
        .header("sec-fetch-site", "same-origin")
        .header(
            header::COOKIE,
            format!("__Host-pm_session={}; __Host-pm_continue={id}", c.cookie),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("saved=on&csrf={}", c.csrf)))
        .unwrap();
    let resp = t.request(req).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), format!("/share/{id}"));
    let page = get_with_continue(&t, &c, &format!("/share/{id}"), &id).await;
    assert_eq!(page.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn share_with_unconfirmed_recovery_session_is_staged_anonymously() {
    let t = TestApp::new();
    let pending = t.pending_session_for("alice");
    let resp = os_share(&t, &pending, &[("a.pdf", PDF)], "").await;
    assert_eq!(resp.status(), 303);
    assert_eq!(location(&resp), "/login");
    let id = continue_id_of(&resp);
    // Not bound to the pending user: bare URL is refused.
    assert_eq!(open_review(&t, &pending, &id).await.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn text_only_share_explains_that_only_files_work() {
    let t = TestApp::new();
    let resp = os_share(&t, &Client::anon(), &[], "a link").await;
    assert_eq!(resp.status(), 400);
    let html = body_string(resp).await;
    assert!(html.contains("only save shared files"), "{html}");
    assert!(html.contains("<html"), "rendered in the base template");
    assert_eq!(t.state.shared.budget_used(), 0);
    // The anonymous slot is free again.
    assert_eq!(
        os_share(&t, &Client::anon(), &[("a.pdf", PDF)], "")
            .await
            .status(),
        303
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn share_origin_exemption_is_post_only() {
    let t = TestApp::new();
    for method in [Method::PUT, Method::DELETE, Method::PATCH] {
        let req = builder(method.clone(), "/share", &Client::anon())
            .header("sec-fetch-site", "cross-site")
            .body(Body::empty())
            .unwrap();
        assert_eq!(t.request(req).await.status(), 403, "{method}");
    }
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

    // Per-user cap: max_upload_bytes over all of one user's staged shares.
    let part = vec![b'y'; 1000];
    let resp = os_share(&t, &c, &[("a.pdf", &part)], "").await;
    assert_eq!(resp.status(), 303);
    let resp = os_share(&t, &c, &[("a.pdf", &part)], "").await;
    assert_eq!(resp.status(), 413);
    // Global cap: 2 x max_upload_bytes over all users.
    let bob = t.session_for("bob");
    assert_eq!(
        os_share(&t, &bob, &[("a.pdf", &part)], "").await.status(),
        303
    );
    let carol = t.session_for("carol");
    assert_eq!(
        os_share(&t, &carol, &[("a.pdf", &part)], "").await.status(),
        413
    );
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

#[tokio::test(flavor = "multi_thread")]
async fn anon_staging_capped_at_25mib() {
    let t = TestApp::new();
    let over = vec![b'a'; 26 * 1024 * 1024];
    let resp = os_share(&t, &Client::anon(), &[("big.pdf", &over)], "").await;
    assert_eq!(resp.status(), 413);
    assert_eq!(
        t.state.shared.budget_used(),
        0,
        "rejected bytes are released"
    );
    let ok = vec![b'a'; 24 * 1024 * 1024];
    let resp = os_share(&t, &Client::anon(), &[("ok.pdf", &ok)], "").await;
    assert_eq!(resp.status(), 303);
    // An authenticated share may be larger than the anonymous cap.
    let c = t.session_for("alice");
    let resp = os_share(&t, &c, &[("big.pdf", &over)], "").await;
    assert_eq!(resp.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn one_anon_entry_per_ip() {
    let t = TestApp::new();
    let anon = Client::anon();
    let a = "203.0.113.50:1000";
    let resp = os_share_from(&t, &anon, &[("a.pdf", PDF)], a).await;
    assert_eq!(resp.status(), 303);
    let resp = os_share_from(&t, &anon, &[("b.pdf", b"other")], a).await;
    assert_eq!(resp.status(), 429);
    // Another IP is fine; so is an IPv6 address in a different /64.
    let resp = os_share_from(&t, &anon, &[("c.pdf", b"c")], "203.0.113.51:1000").await;
    assert_eq!(resp.status(), 303);
    let v6 = |s: &str| format!("[{s}]:1000");
    let resp = os_share_from(&t, &anon, &[("d.pdf", b"d")], &v6("2001:db8:1:2::1")).await;
    assert_eq!(resp.status(), 303);
    // Same /64, other host bits: still the same client.
    let resp = os_share_from(&t, &anon, &[("e.pdf", b"e")], &v6("2001:db8:1:2::ffff")).await;
    assert_eq!(resp.status(), 429);
    // A logged-in share is not limited per IP.
    let c = t.session_for("alice");
    let resp = os_share_from(&t, &c, &[("f.pdf", b"f")], a).await;
    assert_eq!(resp.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_share_uploads_limited() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let p1 = t.state.share_permits.clone().try_acquire_owned().unwrap();
    let p2 = t.state.share_permits.clone().try_acquire_owned().unwrap();
    let resp = os_share(&t, &c, &[("a.pdf", PDF)], "").await;
    assert_eq!(resp.status(), 503);
    assert_eq!(header_str(&resp, "retry-after"), "5");
    drop(p1);
    let resp = os_share(&t, &c, &[("a.pdf", PDF)], "").await;
    assert_eq!(resp.status(), 303);
    drop(p2);
}

#[tokio::test(flavor = "multi_thread")]
async fn staging_budget_counts_bytes_while_streaming() {
    use personal_media::web::session::Owner;
    let t = TestApp::with_config(|c| c.max_upload_bytes = 1000);
    let shared = &t.state.shared;
    // Per user: max_upload_bytes in flight plus staged.
    let mut r = shared.begin(Owner::User("u1".into())).unwrap();
    assert!(r.reserve(600).is_ok());
    assert!(r.reserve(500).is_err());
    let mut r2 = shared.begin(Owner::User("u1".into())).unwrap();
    assert!(r2.reserve(500).is_err(), "second upload of the same user");
    // Global: 2 x max_upload_bytes over all users.
    let mut other = shared.begin(Owner::User("u2".into())).unwrap();
    assert!(other.reserve(1000).is_ok());
    let mut third = shared.begin(Owner::User("u3".into())).unwrap();
    assert!(third.reserve(500).is_err(), "would pass the global cap");
    assert_eq!(shared.budget_used(), 1600);
    drop((r, r2, other, third));
    assert_eq!(shared.budget_used(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_released_on_discard_and_expiry() {
    let t = TestApp::with_config(|c| {
        c.max_upload_bytes = 1024;
        c.share_ttl = Duration::from_secs(1);
    });
    let c = t.session_for("alice");
    let part = vec![b'y'; 1000];
    let id = staging_id(&location(&os_share(&t, &c, &[("a.pdf", &part)], "").await));
    // Per-user budget is used up.
    assert_eq!(
        os_share(&t, &c, &[("b.pdf", &part)], "").await.status(),
        413
    );
    assert_eq!(t.state.shared.budget_used(), 1000);
    // Discard releases it.
    let resp = t.post_form(&format!("/share/{id}/discard"), &[], &c).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(t.state.shared.budget_used(), 0);
    let resp = os_share(&t, &c, &[("b.pdf", &part)], "").await;
    assert_eq!(resp.status(), 303);
    // So does expiry (nobody sweeps in this test: staging itself purges).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let resp = os_share(&t, &c, &[("c.pdf", &part)], "").await;
    assert_eq!(resp.status(), 303);
    assert_eq!(t.state.shared.budget_used(), 1000);
    // And saving.
    let id = staging_id(&location(&resp));
    let resp = t.post_form(&format!("/share/{id}"), &[], &c).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(t.state.shared.budget_used(), 0);
}
