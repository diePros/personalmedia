mod common;

use assert_cmd::Command;
use common::*;
use personal_media::system_db::Role;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn invite_path(app: &TestApp) -> String {
    let url = app.state.accounts.create_invite(Role::User, now()).unwrap();
    url.strip_prefix("https://test.example").unwrap().to_owned()
}

async fn signup(app: &TestApp, username: &str) -> (Client, String) {
    let path = invite_path(app);
    let resp = app
        .post_form(
            &path,
            &[
                ("username", username),
                ("password", PASSWORD),
                ("password_confirm", PASSWORD),
            ],
            &Client::anon(),
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/recovery-key");
    let mut client = client_from_response(&resp);
    let html = body_string(app.get("/recovery-key", &client).await).await;
    client.csrf = csrf_from_html(&html);
    (client, html)
}

fn extract_key(html: &str) -> String {
    let start = html.find("<code").unwrap();
    let inner = &html[start..];
    let a = inner.find('>').unwrap() + 1;
    let b = inner.find("</code>").unwrap();
    inner[a..b].trim().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn full_signup_flow_requires_recovery_confirmation() {
    let app = TestApp::new();
    let path = invite_path(&app);
    let page = body_string(app.get(&path, &Client::anon()).await).await;
    assert!(page.contains("The server operator cannot read them at rest."));
    assert!(page.contains(r#"autocomplete="new-password""#));

    let (client, html) = signup(&app, "alice").await;
    let key = extract_key(&html);
    assert_eq!(key.len(), 52 + 12);
    assert!(html.contains("password manager"));

    let resp = app.get("/documents", &client).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/recovery-key");

    // Checkbox missing: re-rendered with an error, still pending.
    let resp = app.post_form("/recovery-key", &[], &client).await;
    assert_eq!(resp.status(), 400);
    assert_eq!(app.get("/documents", &client).await.status(), 303);

    let resp = app
        .post_form("/recovery-key", &[("saved", "on")], &client)
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/documents");
    assert_eq!(app.get("/documents", &client).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_form_errors() {
    let app = TestApp::new();
    app.session_for("taken");
    let path = invite_path(&app);
    let post = |u: &'static str, p: &'static str, c: &'static str| {
        let (app, path) = (&app, path.clone());
        async move {
            let r = app
                .post_form(
                    &path,
                    &[("username", u), ("password", p), ("password_confirm", c)],
                    &Client::anon(),
                )
                .await;
            (r.status(), body_string(r).await)
        }
    };
    let (s, b) = post("taken", PASSWORD, PASSWORD).await;
    assert_eq!(s, 409);
    assert!(b.contains("already taken"));
    let (s, b) = post("a!", PASSWORD, PASSWORD).await;
    assert_eq!(s, 400);
    assert!(b.contains("3 to 32 characters"));
    let (s, b) = post("fresh", "short", "short").await;
    assert_eq!(s, 400);
    assert!(b.contains("at least 10"));
    let (s, b) = post("fresh", PASSWORD, "different password").await;
    assert_eq!(s, 400);
    assert!(b.contains("do not match"));
    // The invite survived all of that.
    let (s, _) = post("fresh", PASSWORD, PASSWORD).await;
    assert_eq!(s, 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_key_shown_only_once() {
    let app = TestApp::new();
    let (client, _) = signup(&app, "alice").await;
    app.post_form("/recovery-key", &[("saved", "on")], &client)
        .await;
    let resp = app.get("/recovery-key", &client).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/documents");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_logout() {
    let app = TestApp::new();
    app.signup_and_login("alice").await;

    let page = body_string(app.get("/login", &Client::anon()).await).await;
    assert!(page.contains(r#"autocomplete="current-password""#));
    assert!(page.contains(r#"autocomplete="one-time-code""#));

    let bad = app
        .post_form(
            "/login",
            &[("username", "alice"), ("password", "wrong password")],
            &Client::anon(),
        )
        .await;
    assert_eq!(bad.status(), 401);
    assert!(
        body_string(bad)
            .await
            .contains("Invalid username, password or code")
    );

    let resp = app
        .post_form(
            "/login",
            &[("username", "Alice"), ("password", PASSWORD)],
            &Client::anon(),
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/documents");
    let cookie = header_str(&resp, "set-cookie").to_owned();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let mut client = client_from_response(&resp);
    let html = body_string(app.get("/documents", &client).await).await;
    client.csrf = csrf_from_html(&html);

    let resp = app.post_form("/logout", &[], &client).await;
    assert_eq!(resp.status(), 303);
    assert!(header_str(&resp, "set-cookie").contains("Max-Age=0"));
    assert_eq!(app.get("/documents", &client).await.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_account_message() {
    let app = TestApp::new();
    app.session_for("bob");
    let user = app.state.sys.user_by_name("bob").unwrap().unwrap();
    app.state.accounts.set_disabled(&user.id, true).unwrap();
    let resp = app
        .post_form(
            "/login",
            &[("username", "bob"), ("password", PASSWORD)],
            &Client::anon(),
        )
        .await;
    assert_eq!(resp.status(), 403);
    assert!(body_string(resp).await.contains("This account is disabled"));
}

#[tokio::test(flavor = "multi_thread")]
async fn login_with_totp() {
    let app = TestApp::new();
    app.signup_and_login("alice").await;
    let (u, _) = app.state.accounts.login("alice", PASSWORD, None).unwrap();
    let setup = app.state.accounts.totp_begin("alice");
    let code = current_code(&setup.secret_b32);
    app.state
        .accounts
        .totp_enable(&u, &setup.secret_b32, &code)
        .unwrap();

    let no_code = app
        .post_form(
            "/login",
            &[("username", "alice"), ("password", PASSWORD)],
            &Client::anon(),
        )
        .await;
    assert_eq!(no_code.status(), 401);

    let code = current_code(&setup.secret_b32);
    let ok = app
        .post_form(
            "/login",
            &[
                ("username", "alice"),
                ("password", PASSWORD),
                ("code", &code),
            ],
            &Client::anon(),
        )
        .await;
    assert_eq!(ok.status(), 303);
}

fn current_code(secret_b32: &str) -> String {
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(totp_rs::Secret::try_from_base32(secret_b32).unwrap())
        .build()
        .unwrap()
        .generate_current()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn recover_flow_then_old_key_invalid() {
    let app = TestApp::new();
    let (client, html) = signup(&app, "alice").await;
    let old_key = extract_key(&html);
    app.post_form("/recovery-key", &[("saved", "on")], &client)
        .await;

    let new_pw = "a brand new passphrase";
    let anon = Client::anon();
    let resp = app
        .post_form(
            "/recover",
            &[
                ("username", "alice"),
                ("recovery_key", &old_key),
                ("new_password", new_pw),
                ("new_password_confirm", new_pw),
            ],
            &anon,
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/recovery-key");
    let mut c2 = client_from_response(&resp);
    let html2 = body_string(app.get("/recovery-key", &c2).await).await;
    c2.csrf = csrf_from_html(&html2);
    let new_key = extract_key(&html2);
    assert_ne!(new_key, old_key);

    // Old key no longer works; the new password does.
    let again = app
        .post_form(
            "/recover",
            &[
                ("username", "alice"),
                ("recovery_key", &old_key),
                ("new_password", new_pw),
                ("new_password_confirm", new_pw),
            ],
            &anon,
        )
        .await;
    assert_eq!(again.status(), 401);
    let login = app
        .post_form(
            "/login",
            &[("username", "alice"), ("password", new_pw)],
            &anon,
        )
        .await;
    assert_eq!(login.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_token_invalid_404() {
    let app = TestApp::new();
    let anon = Client::anon();
    let bogus = format!("/invite/{}", "0".repeat(64));
    assert_eq!(app.get(&bogus, &anon).await.status(), 404);
    assert_eq!(app.get("/invite/nothex", &anon).await.status(), 404);
    let post = app
        .post_form(
            &bogus,
            &[
                ("username", "alice"),
                ("password", PASSWORD),
                ("password_confirm", PASSWORD),
            ],
            &anon,
        )
        .await;
    assert_eq!(post.status(), 404);

    // A used invite is also a 404.
    let path = invite_path(&app);
    let fields = [
        ("username", "alice"),
        ("password", PASSWORD),
        ("password_confirm", PASSWORD),
    ];
    assert_eq!(app.post_form(&path, &fields, &anon).await.status(), 303);
    assert_eq!(app.get(&path, &anon).await.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_rate_limited_returns_429() {
    let app = TestApp::new();
    let anon = Client::anon();
    for _ in 0..10 {
        let r = app
            .post_form(
                "/login",
                &[("username", "ghost"), ("password", "nope nope nope")],
                &anon,
            )
            .await;
        assert_eq!(r.status(), 401);
    }
    let r = app
        .post_form(
            "/login",
            &[("username", "ghost"), ("password", "nope nope nope")],
            &anon,
        )
        .await;
    assert_eq!(r.status(), 429);
    assert!(r.headers().contains_key("retry-after"));
}

#[tokio::test(flavor = "multi_thread")]
async fn root_redirects_to_documents() {
    let app = TestApp::new();
    let r = app.get("/", &Client::anon()).await;
    assert!(r.status().is_redirection());
    assert_eq!(header_str(&r, "location"), "/documents");
}

#[test]
fn cli_invite_prints_url() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("personal-media")
        .unwrap()
        .args(["invite", "--admin"])
        .env("PM_DATA_DIR", dir.path())
        .env("PM_PUBLIC_URL", "https://test.example")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    let url = out.trim_end_matches('\n');
    let token = url.strip_prefix("https://test.example/invite/").unwrap();
    assert_eq!(token.len(), 64);
    assert!(
        token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

async fn login_with(app: &TestApp, extra: &[(&str, &str)]) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::{Method, header};
    let mut b = common::builder(Method::POST, "/login", &Client::anon())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let body = format!("username=alice&password={}", PASSWORD.replace(' ', "+"));
    app.request(b.body(Body::from(body)).unwrap()).await
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_site_login_post_is_403() {
    let app = TestApp::new();
    app.session_for("alice");
    assert_eq!(
        login_with(&app, &[("sec-fetch-site", "cross-site")])
            .await
            .status(),
        403
    );
    assert_eq!(
        login_with(&app, &[("origin", "https://evil.example")])
            .await
            .status(),
        403
    );
    assert_eq!(login_with(&app, &[("origin", "null")]).await.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn same_origin_login_post_ok() {
    let app = TestApp::new();
    app.session_for("alice");
    let r = login_with(
        &app,
        &[
            ("origin", "https://test.example"),
            ("sec-fetch-site", "same-origin"),
        ],
    )
    .await;
    assert_eq!(r.status(), 303);
    assert_eq!(login_with(&app, &[]).await.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn bearer_request_without_cookie_skips_origin_check() {
    let app = TestApp::new();
    let hdrs = [
        ("authorization", "Bearer pm_x"),
        ("origin", "https://evil.example"),
    ];
    // Passes the guard (the login handler then answers, not a 403).
    assert_ne!(login_with(&app, &hdrs).await.status(), 403);
    // With a session cookie the exemption does not apply.
    let c = app.session_for("alice");
    use axum::body::Body;
    use axum::http::Method;
    let req = common::builder(Method::POST, "/logout", &c)
        .header("authorization", "Bearer pm_x")
        .header("origin", "https://evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.request(req).await.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn relogin_removes_previous_session() {
    let app = TestApp::new();
    let old = app.signup_and_login("alice").await;
    assert_eq!(app.get("/documents", &old).await.status(), 200);
    let resp = app
        .post_form(
            "/login",
            &[("username", "alice"), ("password", PASSWORD)],
            &old,
        )
        .await;
    assert_eq!(resp.status(), 303);
    let new = client_from_response(&resp);
    assert_ne!(new.cookie, old.cookie);
    assert_eq!(app.get("/documents", &old).await.status(), 303);
    assert_eq!(app.get("/documents", &new).await.status(), 200);
}
