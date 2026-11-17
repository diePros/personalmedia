mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, header};
use axum::response::Response;
use common::*;
use personal_media::web::ratelimit::ip_key;

const USER: &str = "alice";

fn set_cookies(resp: &Response) -> Vec<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

fn cookie_named(resp: &Response, name: &str) -> Option<String> {
    set_cookies(resp)
        .into_iter()
        .find_map(|c| c.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

/// Value of the device cookie a response sets.
fn device_of(resp: &Response) -> Option<String> {
    cookie_named(resp, "__Host-pm_device").map(|v| v.split(';').next().unwrap().to_owned())
}

fn session_of(resp: &Response) -> Option<String> {
    cookie_named(resp, "__Host-pm_session").map(|v| v.split(';').next().unwrap().to_owned())
}

async fn login(app: &TestApp, remember: bool) -> Response {
    let mut fields = vec![("username", USER), ("password", PASSWORD)];
    if remember {
        fields.push(("remember", "on"));
    }
    app.post_form("/login", &fields, &Client::anon()).await
}

/// A request carrying exactly the given cookies.
async fn send(
    app: &TestApp,
    method: Method,
    path: &str,
    cookies: &str,
    form: Option<&str>,
) -> Response {
    let mut b = Request::builder().method(method).uri(path);
    if !cookies.is_empty() {
        b = b.header(header::COOKIE, cookies);
    }
    let body = match form {
        Some(f) => {
            b = b
                .header("sec-fetch-site", "same-origin")
                .header("origin", "null")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(f.to_owned())
        }
        None => Body::empty(),
    };
    app.request(b.body(body).unwrap()).await
}

fn device_cookie_header(token: &str) -> String {
    format!("__Host-pm_device={token}")
}

async fn setup() -> (TestApp, String) {
    let app = TestApp::new();
    app.signup_and_login(USER).await;
    let resp = login(&app, true).await;
    assert_eq!(resp.status(), 303);
    let token = device_of(&resp).expect("device cookie");
    (app, token)
}

#[tokio::test(flavor = "multi_thread")]
async fn remembered_login_sets_device_cookie_and_survives_restart() {
    let (app, token) = setup().await;
    let resp = login(&app, true).await;
    let cookies = set_cookies(&resp);
    assert!(session_of(&resp).is_some(), "session cookie survives");
    let dev = cookies
        .iter()
        .find(|c| c.starts_with("__Host-pm_device=pmd_"))
        .expect("device cookie");
    for attr in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=7776000",
    ] {
        assert!(dev.contains(attr), "{dev} lacks {attr}");
    }

    let app2 = app.restart();
    let resp = send(
        &app2,
        Method::GET,
        "/documents",
        &device_cookie_header(&token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert!(session_of(&resp).is_some(), "a new session cookie is set");
}

#[tokio::test(flavor = "multi_thread")]
async fn unchecked_remember_sets_no_device_cookie() {
    let app = TestApp::new();
    app.signup_and_login(USER).await;
    let resp = login(&app, false).await;
    assert_eq!(resp.status(), 303);
    assert!(session_of(&resp).is_some());
    assert!(device_of(&resp).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn login_and_recover_pages_offer_the_checkbox_checked() {
    let app = TestApp::new();
    for path in ["/login", "/recover"] {
        let html = body_string(app.get(path, &Client::anon()).await).await;
        assert!(
            html.contains(r#"name="remember" value="on" checked"#),
            "{path}"
        );
        assert!(html.contains("Remember this device"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn session_expiry_is_silently_renewed() {
    let app = TestApp::with_config(|c| c.session_idle = Duration::from_secs(1));
    app.signup_and_login(USER).await;
    let resp = login(&app, true).await;
    let session = session_of(&resp).unwrap();
    let token = device_of(&resp).unwrap();
    let cookies = format!(
        "__Host-pm_session={session}; {}",
        device_cookie_header(&token)
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let resp = send(&app, Method::GET, "/documents", &cookies, None).await;
    assert_eq!(resp.status(), 200);
    let renewed = session_of(&resp).expect("a fresh session cookie");
    assert_ne!(renewed, session);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_resumes_share_one_session() {
    let (app, token) = setup().await;
    let app = app.restart();
    let cookies = device_cookie_header(&token);
    let (a, b, c, d, e) = tokio::join!(
        send(&app, Method::GET, "/documents", &cookies, None),
        send(&app, Method::GET, "/documents", &cookies, None),
        send(&app, Method::GET, "/documents", &cookies, None),
        send(&app, Method::GET, "/documents", &cookies, None),
        send(&app, Method::GET, "/documents", &cookies, None),
    );
    let sessions: Vec<String> = [&a, &b, &c, &d, &e]
        .iter()
        .map(|r| {
            assert_eq!(r.status(), 200);
            session_of(r).expect("session cookie")
        })
        .collect();
    assert!(sessions.iter().all(|s| *s == sessions[0]), "{sessions:?}");
    let user_id = app.state.sessions.get(&sessions[0]).unwrap().user_id;
    assert_eq!(app.state.sessions.count_for_user(&user_id), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_device_cookie_clears_it_and_counts_failure() {
    let (app, token) = setup().await;
    let mut bad = token.clone();
    let last = if bad.ends_with('0') { '1' } else { '0' };
    bad.pop();
    bad.push(last);
    let ip = ip_key(PEER.parse::<std::net::SocketAddr>().unwrap().ip());
    for _ in 0..10 {
        assert!(app.state.limiter.check(std::slice::from_ref(&ip)).is_ok());
        let resp = send(
            &app,
            Method::GET,
            "/documents",
            &device_cookie_header(&bad),
            None,
        )
        .await;
        assert_eq!(resp.status(), 303);
        assert_eq!(header_str(&resp, "location"), "/login");
        let cleared = set_cookies(&resp)
            .into_iter()
            .find(|c| c.starts_with("__Host-pm_device=;"))
            .expect("device cookie cleared");
        assert!(cleared.contains("Max-Age=0"));
    }
    assert!(app.state.limiter.check(&[ip]).is_err(), "IP is limited");
    // Even the genuine cookie is not tried while the IP is locked out.
    let resp = send(
        &app,
        Method::GET,
        "/documents",
        &device_cookie_header(&token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_user_cannot_resume() {
    let (app, token) = setup().await;
    let app = app.restart();
    let user = app.state.sys.user_by_name(USER).unwrap().unwrap();
    app.state.accounts.set_disabled(&user.id, true).unwrap();
    let resp = send(
        &app,
        Method::GET,
        "/documents",
        &device_cookie_header(&token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/login");
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_revokes_only_this_device() {
    let (app, token_a) = setup().await;
    let resp_a = login(&app, true).await; // a second remembered login, kept as B
    let token_b = device_of(&resp_a).unwrap();
    assert_ne!(token_a, token_b);
    let session_b = session_of(&resp_a).unwrap();

    // Log out device A: resume it, then log out with the new session.
    let a = send(
        &app,
        Method::GET,
        "/documents",
        &device_cookie_header(&token_a),
        None,
    )
    .await;
    assert_eq!(a.status(), 200);
    let session_a = session_of(&a).unwrap();
    let html = body_string(a).await;
    let client_a = Client {
        cookie: session_a,
        csrf: csrf_from_html(&html),
    };
    let resp = app.post_form("/logout", &[], &client_a).await;
    assert_eq!(resp.status(), 303);
    assert!(
        set_cookies(&resp)
            .iter()
            .any(|c| c.starts_with("__Host-pm_device=;") && c.contains("Max-Age=0"))
    );

    let resp = send(
        &app,
        Method::GET,
        "/documents",
        &device_cookie_header(&token_a),
        None,
    )
    .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/login");

    let _ = session_b;
    let resp = send(
        &app.restart(),
        Method::GET,
        "/documents",
        &device_cookie_header(&token_b),
        None,
    )
    .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn post_after_idle_resumes_but_needs_fresh_csrf() {
    let (app, token) = setup().await;
    let app = app.restart();
    // A page rendered before the restart carried a CSRF token that is gone now.
    let stale = "stale-csrf-token";
    let resp = send(
        &app,
        Method::POST,
        "/logout",
        &device_cookie_header(&token),
        Some(&format!("csrf={stale}")),
    )
    .await;
    assert_eq!(resp.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn device_cookie_rejected_at_mcp() {
    let (app, token) = setup().await;
    let resp = app
        .request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), 401);
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

const LOGIN_FORM: &str = "username=alice&password=correct+horse+battery";

#[tokio::test(flavor = "multi_thread")]
async fn resume_resends_the_device_cookie() {
    let (app, token) = setup().await;
    let app = app.restart();
    let resp = send(
        &app,
        Method::GET,
        "/documents",
        &device_cookie_header(&token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let c = set_cookies(&resp)
        .into_iter()
        .find(|c| c.starts_with(&format!("__Host-pm_device={token};")))
        .expect("device cookie re-sent");
    assert!(c.contains("Max-Age=7776000"), "{c}");
}

#[tokio::test(flavor = "multi_thread")]
async fn non_remember_login_over_a_remembered_browser_forgets_the_device() {
    let (app, token) = setup().await;
    let app = app.restart();
    // Resume (session S1 with the device), then log in again without remember.
    let r1 = send(
        &app,
        Method::GET,
        "/documents",
        &device_cookie_header(&token),
        None,
    )
    .await;
    let s1 = session_of(&r1).unwrap();
    let cookies = format!("__Host-pm_session={s1}; {}", device_cookie_header(&token));
    let r2 = send(&app, Method::POST, "/login", &cookies, Some(LOGIN_FORM)).await;
    assert_eq!(r2.status(), 303);
    assert!(
        device_of(&r2).is_some_and(|v| v.is_empty()),
        "cookie cleared"
    );
    let s2 = session_of(&r2).unwrap();

    // Log out of S2, even with the stale device cookie still sent.
    let page = send(
        &app,
        Method::GET,
        "/documents",
        &format!("__Host-pm_session={s2}"),
        None,
    )
    .await;
    let csrf = csrf_from_html(&body_string(page).await);
    let out = send(
        &app,
        Method::POST,
        "/logout",
        &format!("__Host-pm_session={s2}; {}", device_cookie_header(&token)),
        Some(&format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(out.status(), 303);
    assert!(
        set_cookies(&out)
            .iter()
            .any(|c| c.starts_with("__Host-pm_device=;") && c.contains("Max-Age=0"))
    );
    let back = send(
        &app,
        Method::GET,
        "/documents",
        &device_cookie_header(&token),
        None,
    )
    .await;
    assert_eq!(back.status(), 303);
    assert_eq!(header_str(&back, "location"), "/login");
}

#[tokio::test(flavor = "multi_thread")]
async fn remember_login_replaces_the_presented_device() {
    let (app, old) = setup().await;
    let resp = send(
        &app,
        Method::POST,
        "/login",
        &device_cookie_header(&old),
        Some(&format!("{LOGIN_FORM}&remember=on")),
    )
    .await;
    let new = device_of(&resp).unwrap();
    assert_ne!(new, old);
    let app2 = app.restart();
    let gone = send(
        &app2,
        Method::GET,
        "/documents",
        &device_cookie_header(&old),
        None,
    )
    .await;
    assert_eq!(gone.status(), 303);
    let ok = send(
        &app2,
        Method::GET,
        "/documents",
        &device_cookie_header(&new),
        None,
    )
    .await;
    assert_eq!(ok.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_with_pending_recovery_key_goes_to_recovery_key() {
    let app = TestApp::new();
    let c = app.pending_session_for(USER);
    let unlocked = app.state.sessions.get(&c.cookie).unwrap().unlocked;
    let token =
        personal_media::devices::create_device(&app.state.sys, &unlocked, "test", now()).unwrap();
    let app = app.restart();
    let resp = send(
        &app,
        Method::GET,
        "/documents",
        &device_cookie_header(&token),
        None,
    )
    .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/recovery-key");
}

#[tokio::test(flavor = "multi_thread")]
async fn remember_on_recover_sets_device_cookie() {
    let app = TestApp::new();
    let url = app
        .state
        .accounts
        .create_invite(personal_media::system_db::Role::User, now())
        .unwrap();
    let path = url.strip_prefix("https://test.example").unwrap();
    let resp = app
        .post_form(
            path,
            &[
                ("username", USER),
                ("password", PASSWORD),
                ("password_confirm", PASSWORD),
                ("understand", "on"),
            ],
            &Client::anon(),
        )
        .await;
    let mut client = client_from_response(&resp);
    let html = body_string(app.get("/recovery-key", &client).await).await;
    let start = html.find("<code").unwrap();
    let inner = &html[start..];
    let key = inner[inner.find('>').unwrap() + 1..inner.find("</code>").unwrap()].trim();
    client.csrf = csrf_from_html(&html);
    app.post_form("/recovery-key", &[("saved", "on")], &client)
        .await;

    let pw = "a brand new passphrase";
    let fields = |remember: bool| {
        let mut f = vec![
            ("username", USER),
            ("recovery_key", key),
            ("new_password", pw),
            ("new_password_confirm", pw),
        ];
        if remember {
            f.push(("remember", "on"));
        }
        f
    };
    let resp = app
        .post_form("/recover", &fields(true), &Client::anon())
        .await;
    assert_eq!(resp.status(), 303);
    let token = device_of(&resp).expect("device cookie after recover");
    assert!(token.starts_with("pmd_"));
    assert!(session_of(&resp).is_some());
    // And it resumes (the recovery key is still pending, so /recovery-key).
    let resumed = send(
        &app.restart(),
        Method::GET,
        "/documents",
        &device_cookie_header(&token),
        None,
    )
    .await;
    assert_eq!(header_str(&resumed, "location"), "/recovery-key");
}
