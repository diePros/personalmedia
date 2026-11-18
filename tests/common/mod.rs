//! Shared harness for the web integration tests.
//!
//! Each test file does `mod common;` and uses only part of this module, so
//! everything here is `#[allow(dead_code)]`.
#![allow(dead_code)]

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, header};
use axum::response::Response;
use http_body_util::BodyExt;
use personal_media::config::Config;
use personal_media::system_db::Role;
use personal_media::web::{AppState, build_app};
use tower::ServiceExt;

pub const PASSWORD: &str = "correct horse battery";
/// The TCP peer every test request appears to come from. It differs from
/// `Config::for_tests`' trusted proxy (127.0.0.1), so `X-Forwarded-For` is
/// ignored unless a test sets the peer itself.
pub const PEER: &str = "203.0.113.7:40000";

/// A browser stand-in: the session cookie value and the session's CSRF token.
/// `Client::anon()` has neither.
#[derive(Clone, Debug, Default)]
pub struct Client {
    pub cookie: String,
    pub csrf: String,
}

impl Client {
    pub fn anon() -> Client {
        Client::default()
    }
}

pub struct TestApp {
    pub dir: std::sync::Arc<tempfile::TempDir>,
    pub state: AppState,
    pub app: Router,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

impl TestApp {
    /// A fresh app on a tempdir with `Config::for_tests`. Needs a running
    /// multi-thread runtime: `#[tokio::test(flavor = "multi_thread")]`.
    pub fn new() -> TestApp {
        TestApp::with_config(|_| {})
    }

    /// Like [`TestApp::new`], with a chance to adjust the config first.
    pub fn with_config(adjust: impl FnOnce(&mut Config)) -> TestApp {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_tests(dir.path().to_path_buf());
        adjust(&mut cfg);
        let state = AppState::build(cfg).unwrap();
        let app = build_app(state.clone());
        TestApp {
            dir: std::sync::Arc::new(dir),
            state,
            app,
        }
    }

    /// A second app on the same data dir and config, as after a server
    /// restart: in-memory state (sessions, rate limits, unlocked keys) is gone.
    pub fn restart(&self) -> TestApp {
        let state = AppState::build((*self.state.cfg).clone()).unwrap();
        let app = build_app(state.clone());
        TestApp {
            dir: self.dir.clone(),
            state,
            app,
        }
    }

    /// Like [`TestApp::new`] with a ready-made embedding engine.
    pub fn with_engine(engine: std::sync::Arc<personal_media::embed::Engine>) -> TestApp {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::for_tests(dir.path().to_path_buf());
        let state = AppState::build_with_engine(cfg, engine).unwrap();
        let app = build_app(state.clone());
        TestApp {
            dir: std::sync::Arc::new(dir),
            state,
            app,
        }
    }

    /// Send a request as if it arrived from [`PEER`] (unless the request
    /// already carries a `ConnectInfo` extension).
    pub async fn request(&self, mut req: Request<Body>) -> Response {
        if req.extensions().get::<ConnectInfo<SocketAddr>>().is_none() {
            let peer: SocketAddr = PEER.parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
        }
        self.app.clone().oneshot(req).await.unwrap()
    }

    /// Creates an invite, signs `username` up, confirms the recovery key and
    /// opens a session, all through `state` (no HTTP).
    pub fn session_for(&self, username: &str) -> Client {
        self.session_with_role(username, Role::User)
    }

    pub fn admin_session_for(&self, username: &str) -> Client {
        self.session_with_role(username, Role::Admin)
    }

    fn session_with_role(&self, username: &str, role: Role) -> Client {
        let client = self.pending_session_with_role(username, role);
        let user_id = self.state.sessions.get(&client.cookie).unwrap().user_id;
        self.state.accounts.confirm_recovery(&user_id).unwrap();
        self.state.sessions.confirm_recovery(&client.cookie);
        client
    }

    /// Like [`TestApp::session_for`], but the recovery key is not confirmed yet.
    pub fn pending_session_for(&self, username: &str) -> Client {
        self.pending_session_with_role(username, Role::User)
    }

    fn pending_session_with_role(&self, username: &str, role: Role) -> Client {
        let url = self.state.accounts.create_invite(role, now()).unwrap();
        let token = url.rsplit('/').next().unwrap();
        let (unlocked, user, recovery) = self
            .state
            .accounts
            .signup(token, username, PASSWORD, now())
            .unwrap();
        wait_date_backfill(&unlocked);
        let (cookie, csrf) = self
            .state
            .sessions
            .create(&user, unlocked, Some(recovery), None);
        Client { cookie, csrf }
    }

    /// Signs up through the real routes, confirms the recovery key and logs in.
    pub async fn signup_and_login(&self, username: &str) -> Client {
        let url = self
            .state
            .accounts
            .create_invite(Role::User, now())
            .unwrap();
        let path = url.strip_prefix("https://test.example").unwrap();
        let resp = self
            .post_form(
                path,
                &[
                    ("username", username),
                    ("password", PASSWORD),
                    ("password_confirm", PASSWORD),
                    ("understand", "on"),
                ],
                &Client::anon(),
            )
            .await;
        let mut client = client_from_response(&resp);
        let page = self.get("/recovery-key", &client).await;
        client.csrf = csrf_from_html(&body_string(page).await);
        let resp = self
            .post_form("/recovery-key", &[("saved", "on")], &client)
            .await;
        assert_eq!(resp.status(), 303);
        client
    }

    pub async fn get(&self, path: &str, client: &Client) -> Response {
        self.request(
            builder(Method::GET, path, client)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// htmx-style GET (`HX-Request: true`).
    pub async fn hx_get(&self, path: &str, client: &Client) -> Response {
        let req = builder(Method::GET, path, client)
            .header("hx-request", "true")
            .body(Body::empty())
            .unwrap();
        self.request(req).await
    }

    /// A plain HTML form POST as a browser sends it (`Sec-Fetch-Site: same-origin`,
    /// `Origin: null` under `no-referrer`). The client's CSRF token is sent as the `csrf`
    /// field unless `fields` already contains one.
    pub async fn post_form(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        client: &Client,
    ) -> Response {
        let mut all: Vec<(&str, &str)> = fields.to_vec();
        if !client.csrf.is_empty() && !fields.iter().any(|(k, _)| *k == "csrf") {
            all.push(("csrf", &client.csrf));
        }
        self.post_form_raw(path, &all, client).await
    }

    /// A form POST with exactly `fields` (no CSRF field is added).
    pub async fn post_form_raw(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        client: &Client,
    ) -> Response {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let req = builder(Method::POST, path, client)
            .header("sec-fetch-site", "same-origin")
            .header("origin", "null")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        self.request(req).await
    }

    /// A multipart POST as `app.js` sends it: text `fields`, then `files` as
    /// `(field name, filename, content type, bytes)`, with the CSRF token in
    /// the `X-CSRF-Token` header.
    pub async fn post_multipart(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        files: &[(&str, &str, &str, &[u8])],
        client: &Client,
    ) -> Response {
        const BOUNDARY: &str = "pm-test-boundary-7f3a9c";
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        for (name, filename, content_type, bytes) in files {
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        let mut b = builder(Method::POST, path, client)
            .header("sec-fetch-site", "same-origin")
            .header("origin", "null")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={BOUNDARY}"),
            );
        if !client.csrf.is_empty() {
            b = b.header("x-csrf-token", &client.csrf);
        }
        let b = b.header(header::CONTENT_LENGTH, body.len());
        self.request(b.body(Body::from(body)).unwrap()).await
    }
}

/// A request builder for `path` carrying the client's session cookie (if any).
pub fn builder(method: Method, path: &str, client: &Client) -> axum::http::request::Builder {
    let b = Request::builder().method(method).uri(path);
    if client.cookie.is_empty() {
        b
    } else {
        b.header(
            header::COOKIE,
            format!("__Host-pm_session={}", client.cookie),
        )
    }
}

pub fn header_str<'a>(resp: &'a Response, name: &str) -> &'a str {
    resp.headers()
        .get(name)
        .unwrap_or_else(|| panic!("missing header {name}"))
        .to_str()
        .unwrap()
}

pub async fn body_bytes(resp: Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

pub async fn body_string(resp: Response) -> String {
    String::from_utf8(body_bytes(resp).await).unwrap()
}

/// The `__Host-pm_session` cookie a response sets, as a client without a CSRF token.
pub fn client_from_response(resp: &Response) -> Client {
    let cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix("__Host-pm_session="))
        .map(|v| v.split(';').next().unwrap().to_owned())
        .expect("no __Host-pm_session cookie set");
    Client {
        cookie,
        csrf: String::new(),
    }
}

/// The token from `<meta name="csrf-token" content="...">`.
pub fn csrf_from_html(html: &str) -> String {
    let marker = "<meta name=\"csrf-token\" content=\"";
    let start = html.find(marker).expect("no csrf meta tag") + marker.len();
    html[start..].split('"').next().unwrap().to_owned()
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Waits (up to 5 s) until `user_id` is no longer unlocked. A background task
/// (the date backfill) may hold a strong reference for a few milliseconds after
/// the last session is gone.
#[allow(dead_code)]
pub async fn wait_locked(keyring: &personal_media::keyring::Keyring, user_id: &str) {
    for _ in 0..500 {
        if keyring.get(user_id).is_none() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("user is still unlocked");
}

/// Waits (bounded) until the one-time date backfill that every unlock starts
/// in the background has written its marker, so tests that measure the index
/// (quota, WAL size) start from a settled state. Returns quietly after the
/// bound when no backfill runs (e.g. an app built without the hook).
pub fn wait_date_backfill(u: &personal_media::keyring::Unlocked) {
    for _ in 0..200 {
        if u.with_db(personal_media::user_db::backfill_is_done)
            .unwrap_or(false)
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
