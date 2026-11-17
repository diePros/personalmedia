mod common;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use common::{Client, TestApp, body_string, builder, header_str, wait_locked};
use personal_media::web::ratelimit::{RateLimiter, client_ip, ip_key, user_key};

const CSP: &str = "default-src 'self'; img-src 'self' data:; object-src 'self'; \
                   frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

fn assert_security_headers(resp: &axum::response::Response) {
    assert_eq!(header_str(resp, "content-security-policy"), CSP);
    assert_eq!(header_str(resp, "x-content-type-options"), "nosniff");
    assert_eq!(header_str(resp, "referrer-policy"), "no-referrer");
    assert_eq!(
        header_str(resp, "strict-transport-security"),
        "max-age=31536000"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn security_headers_present() {
    let app = TestApp::new();
    let alice = app.session_for("alice");

    // A page, a redirect, a static file and a 404 all carry them.
    let page = app.get("/documents", &alice).await;
    assert_eq!(page.status(), StatusCode::OK);
    assert_security_headers(&page);
    assert_security_headers(&app.get("/documents", &Client::anon()).await);
    assert_security_headers(&app.get("/static/app.css", &Client::anon()).await);
    let missing = app.get("/no/such/page", &Client::anon()).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_security_headers(&missing);
}

#[tokio::test(flavor = "multi_thread")]
async fn base_template_carries_csrf_meta_and_nav() {
    let app = TestApp::new();
    let alice = app.session_for("alice");
    let html = body_string(app.get("/documents", &alice).await).await;
    assert!(html.contains(&format!(
        r#"<meta name="csrf-token" content="{}">"#,
        alice.csrf
    )));
    assert!(html.contains(
        r#"<meta name="htmx-config" content='{"includeIndicatorStyles":false,"allowEval":false,"historyCacheSize":0,"allowScriptTags":false}'>"#
    ));
    assert!(html.contains(r#"href="/static/app.css?v="#));
    assert!(html.contains(r#"src="/static/htmx.min.js?v="#));
    assert!(html.contains(r#"src="/static/app.js?v="#));
    assert!(html.contains(r#"action="/logout""#));
    assert!(
        !html.contains(r#"href="/admin""#),
        "users see no admin link"
    );
    assert!(!html.contains("style="), "no inline styles");

    let root = app.admin_session_for("root");
    let html = body_string(app.get("/documents", &root).await).await;
    assert!(html.contains(r#"href="/admin""#));

    // Without a session there is no token and no nav.
    let html = body_string(app.get("/login", &Client::anon()).await).await;
    assert!(html.contains("login"));
    assert!(!html.contains("csrf-token"));
    assert!(!html.contains(r#"action="/logout""#));
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_redirects_to_login() {
    let app = TestApp::new();
    let resp = app.get("/documents", &Client::anon()).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(header_str(&resp, "location"), "/login");

    // An unknown session id is no session.
    let forged = Client {
        cookie: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        csrf: String::new(),
    };
    let resp = app.get("/documents", &forged).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(header_str(&resp, "location"), "/login");
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_recovery_redirects_to_recovery_key() {
    let app = TestApp::new();
    let bob = app.pending_session_for("bob");
    let resp = app.get("/documents", &bob).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(header_str(&resp, "location"), "/recovery-key");

    app.state.sessions.confirm_recovery(&bob.cookie);
    assert_eq!(app.get("/documents", &bob).await.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn htmx_unauthenticated_gets_hx_redirect() {
    let app = TestApp::new();
    let resp = app.hx_get("/documents", &Client::anon()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(header_str(&resp, "hx-redirect"), "/login");
    assert!(resp.headers().get("location").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn post_without_csrf_is_403() {
    let app = TestApp::new();
    let alice = app.session_for("alice");
    let still_logged_in = |app: &TestApp| app.state.sessions.get(&alice.cookie).is_some();

    // Plain form without the csrf field: rejected by the handler's form check.
    let resp = app.post_form_raw("/logout", &[], &alice).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Wrong field value.
    let resp = app
        .post_form_raw("/logout", &[("csrf", "nope")], &alice)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Another session's token.
    let mallory = app.session_for("mallory");
    let resp = app
        .post_form_raw("/logout", &[("csrf", &mallory.csrf)], &alice)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Anything that is not a plain form needs the header: rejected by the middleware.
    let no_body = builder(Method::POST, "/logout", &alice)
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.request(no_body).await.status(), StatusCode::FORBIDDEN);
    let json = builder(Method::POST, "/logout", &alice)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(app.request(json).await.status(), StatusCode::FORBIDDEN);
    let multipart = builder(Method::POST, "/logout", &alice)
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=x")
        .body(Body::from("--x--\r\n"))
        .unwrap();
    assert_eq!(app.request(multipart).await.status(), StatusCode::FORBIDDEN);
    // htmx requests need the header even when they are form-encoded.
    let hx = builder(Method::POST, "/logout", &alice)
        .header("hx-request", "true")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf={}", alice.csrf)))
        .unwrap();
    assert_eq!(app.request(hx).await.status(), StatusCode::FORBIDDEN);
    // A wrong header is not rescued by a correct field.
    let wrong_header = builder(Method::POST, "/logout", &alice)
        .header("x-csrf-token", "nope")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("csrf={}", alice.csrf)))
        .unwrap();
    assert_eq!(
        app.request(wrong_header).await.status(),
        StatusCode::FORBIDDEN
    );
    // The middleware also guards routes that do not exist (yet).
    let unknown = builder(Method::POST, "/no/such/route", &alice)
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.request(unknown).await.status(), StatusCode::FORBIDDEN);

    assert!(still_logged_in(&app), "no rejected request logged out");

    // With the form field it works: logged out, cookie cleared.
    let resp = app.post_form("/logout", &[], &alice).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(header_str(&resp, "location"), "/login");
    let cleared = header_str(&resp, "set-cookie");
    assert!(cleared.starts_with("__Host-pm_session=;"));
    assert!(cleared.contains("Max-Age=0"));
    assert!(!still_logged_in(&app));

    // And with the header (htmx / pmFetch).
    let hx = builder(Method::POST, "/logout", &mallory)
        .header("hx-request", "true")
        .header("x-csrf-token", &mallory.csrf)
        .body(Body::empty())
        .unwrap();
    let resp = app.request(hx).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(header_str(&resp, "hx-redirect"), "/login");
    assert!(app.state.sessions.get(&mallory.cookie).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn session_cookie_flags_and_id_format() {
    use personal_media::web::session::session_cookie;
    let app = TestApp::new();
    let alice = app.session_for("alice");
    // 32 random bytes as unpadded base64url.
    assert_eq!(alice.cookie.len(), 43);
    assert!(
        alice
            .cookie
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    );
    assert_ne!(alice.cookie, alice.csrf);
    assert_ne!(alice.cookie, app.session_for("bob").cookie);
    assert_eq!(
        session_cookie(&alice.cookie).to_str().unwrap(),
        format!(
            "__Host-pm_session={}; HttpOnly; Secure; SameSite=Strict; Path=/",
            alice.cookie
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_store_removal_and_pending_totp() {
    let app = TestApp::new();
    let a1 = app.session_for("alice");
    let bob = app.session_for("bob");
    let user_id = app.state.sessions.get(&a1.cookie).unwrap().user_id;

    app.state.sessions.set_pending_totp(
        &a1.cookie,
        Some(zeroize::Zeroizing::new("SECRET".to_owned())),
    );
    let pending = |app: &TestApp| {
        app.state
            .sessions
            .get(&a1.cookie)
            .unwrap()
            .pending_totp_secret
    };
    assert_eq!(pending(&app).as_ref().map(|s| s.as_str()), Some("SECRET"));
    app.state.sessions.set_pending_totp(&a1.cookie, None);
    assert!(pending(&app).is_none());

    app.state.sessions.remove_user(&user_id);
    assert!(app.state.sessions.get(&a1.cookie).is_none());
    assert!(app.state.sessions.get(&bob.cookie).is_some());
    // The session held the last reference to alice's unlocked state.
    wait_locked(&app.state.keyring, &user_id).await;

    app.state.sessions.remove(&bob.cookie);
    assert!(app.state.sessions.get(&bob.cookie).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn session_idle_expiry() {
    let app = TestApp::with_config(|cfg| cfg.session_idle = Duration::from_secs(1));
    let alice = app.session_for("alice");
    assert_eq!(app.get("/documents", &alice).await.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let resp = app.get("/documents", &alice).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(header_str(&resp, "location"), "/login");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_activity_extends_idle_but_not_max() {
    let app = TestApp::with_config(|cfg| {
        cfg.session_idle = Duration::from_secs(1);
        cfg.session_max = Duration::from_secs(2);
    });
    let alice = app.session_for("alice");
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(app.get("/documents", &alice).await.status(), StatusCode::OK);
    }
    // 1.5 s in: still alive only because each request refreshed last_seen.
    tokio::time::sleep(Duration::from_millis(700)).await;
    // 2.2 s in: past the absolute maximum despite recent activity.
    assert_eq!(
        app.get("/documents", &alice).await.status(),
        StatusCode::SEE_OTHER
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sweep_drops_expired_sessions_and_their_keys() {
    let app = TestApp::with_config(|cfg| cfg.session_idle = Duration::from_millis(200));
    let alice = app.session_for("alice");
    let user_id = app.state.sessions.get(&alice.cookie).unwrap().user_id;
    assert!(app.state.keyring.get(&user_id).is_some());
    tokio::time::sleep(Duration::from_millis(300)).await;
    app.state.sessions.sweep();
    wait_locked(&app.state.keyring, &user_id).await;
}

#[test]
fn client_ip_trusts_xff_only_from_proxy() {
    let trusted: IpAddr = "127.0.0.1".parse().unwrap();
    let proxy: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let stranger: SocketAddr = "198.51.100.9:5000".parse().unwrap();
    let xff = |v: &'static str| {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static(v));
        h
    };
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();

    assert_eq!(
        client_ip(proxy, &xff("203.0.113.50"), trusted),
        ip("203.0.113.50")
    );
    assert_eq!(
        client_ip(proxy, &xff("2001:db8::1"), trusted),
        ip("2001:db8::1")
    );
    // Not from the proxy: the header is attacker-controlled and ignored.
    assert_eq!(
        client_ip(stranger, &xff("203.0.113.50"), trusted),
        ip("198.51.100.9")
    );
    // No or unusable header from the proxy: the peer address.
    assert_eq!(
        client_ip(proxy, &HeaderMap::new(), trusted),
        ip("127.0.0.1")
    );
    assert_eq!(client_ip(proxy, &xff("garbage"), trusted), ip("127.0.0.1"));
    // A client-supplied prefix cannot spoof: only what the proxy appended counts.
    assert_eq!(
        client_ip(proxy, &xff("10.0.0.1, 203.0.113.50"), trusted),
        ip("203.0.113.50")
    );
    // An IPv4-mapped peer still counts as the trusted proxy.
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:5000".parse().unwrap();
    assert_eq!(
        client_ip(mapped, &xff("203.0.113.50"), trusted),
        ip("203.0.113.50")
    );
}

#[test]
fn rate_limit_locks_after_10_failures_and_reports_retry_after() {
    let limiter = RateLimiter::new();
    let ip = ip_key("203.0.113.50".parse().unwrap());
    let user = user_key("alice");
    assert_eq!(ip, "ip:203.0.113.50");
    assert_eq!(user, "user:alice");
    let keys = [ip.clone(), user.clone()];

    for _ in 0..9 {
        limiter.begin(&keys).unwrap().failure();
    }
    let ninth = limiter.begin(&keys).expect("9 failures do not lock");
    ninth.failure();

    let retry = limiter.begin(&keys).err().unwrap();
    assert!(retry <= Duration::from_secs(15 * 60));
    assert!(retry > Duration::from_secs(14 * 60));
    // Each key is locked on its own.
    assert!(limiter.begin(std::slice::from_ref(&ip)).is_err());
    assert!(limiter.begin(std::slice::from_ref(&user)).is_err());
    assert!(limiter.begin(&["user:bob".to_string()]).is_ok());

    // Ten failures on an ip key lock it.
    let carol_ip = ["ip:198.51.100.1".to_string()];
    for _ in 0..10 {
        limiter.begin(&carol_ip).unwrap().failure();
    }
    assert!(limiter.begin(&carol_ip).is_err());

    // A success in between resets the count.
    let carol = [user_key("carol")];
    for _ in 0..9 {
        limiter.begin(&carol).unwrap().failure();
    }
    limiter.begin(&carol).unwrap().success();
    limiter.begin(&carol).unwrap().failure();
    assert!(limiter.begin(&carol).is_ok());
}

#[test]
fn ipv6_clients_are_keyed_by_their_64_prefix() {
    let a = ip_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap());
    let b = ip_key("2001:db8:1:2:1::1".parse().unwrap());
    let other = ip_key("2001:db8:1:3::1".parse().unwrap());
    assert_eq!(a, "ip:2001:db8:1:2::/64");
    assert_eq!(a, b);
    assert_ne!(a, other);
    // An IPv4-mapped address is keyed as the IPv4 address.
    assert_eq!(
        ip_key("::ffff:203.0.113.9".parse().unwrap()),
        "ip:203.0.113.9"
    );
}

#[test]
fn user_key_is_lowercased_and_capped_at_64_chars() {
    assert_eq!(user_key("ALice"), "user:alice");
    let long = "A".repeat(2_000_000);
    let key = user_key(&long);
    assert_eq!(key, format!("user:{}", "a".repeat(64)));
    assert_eq!(
        user_key(&"é".repeat(100)).chars().count(),
        "user:".len() + 64
    );
}

#[test]
fn in_flight_attempts_count_toward_the_limit() {
    let limiter = RateLimiter::new();
    let keys = [user_key("dave")];
    let held: Vec<_> = (0..10).map(|_| limiter.begin(&keys).unwrap()).collect();
    assert!(
        limiter.begin(&keys).is_err(),
        "10 in flight reserve all slots"
    );
    // Settling as success frees the slots without recording failures.
    for a in held {
        a.success();
    }
    assert!(limiter.begin(&keys).is_ok());
}

#[test]
fn dropping_an_unsettled_attempt_counts_as_failure() {
    let limiter = RateLimiter::new();
    let keys = [user_key("erin")];
    for _ in 0..10 {
        drop(limiter.begin(&keys).unwrap());
    }
    assert!(limiter.begin(&keys).is_err(), "ten drops lock the key");
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_requests_response_has_retry_after() {
    let resp = personal_media::web::ratelimit::too_many_requests(Duration::from_millis(61_500));
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(header_str(&resp, "retry-after"), "62");
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Installs a process-wide subscriber that writes into a shared buffer.
///
/// Global rather than `tracing::subscriber::with_default`: tracing caches each
/// callsite's interest when it is first hit, and with a thread-local
/// subscriber a parallel test hitting the access-log callsite first would
/// cache "nobody listens" for this test too. Other tests' lines land in the
/// buffer as well, which the assertions below tolerate.
fn install_capture() -> Capture {
    static CAPTURE: OnceLock<Capture> = OnceLock::new();
    CAPTURE
        .get_or_init(|| {
            let capture = Capture::default();
            let writer = capture.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
            capture
        })
        .clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn access_log_omits_query_and_path_params() {
    let capture = install_capture();

    let app = TestApp::new();
    let alice = app.session_for("alice");
    let uuid = "3f2b8c1e-9d4a-4b7e-8a6f-5c0d1e2f3a4b";

    let resp = app.get("/search?q=Steuergeheimnis", &alice).await;
    assert_eq!(resp.status(), StatusCode::OK);
    app.get(&format!("/documents/{uuid}"), &alice).await;
    app.get(&format!("/static/{uuid}.css?v=Steuergeheimnis"), &alice)
        .await;
    app.get(&format!("/{uuid}/Steuergeheimnis"), &Client::anon())
        .await;

    let out = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!out.contains("Steuergeheimnis"), "{out}");
    assert!(!out.contains(uuid), "{out}");
    assert!(!out.contains(&alice.cookie), "{out}");
    assert!(!out.contains(&alice.csrf), "{out}");
    // What is logged: method, route template, status, latency.
    let line = out
        .lines()
        .find(|l| l.contains("path=\"/documents\"") && l.contains("status=200"))
        .unwrap_or_else(|| panic!("no access log line for /documents in: {out}"));
    assert!(line.contains("method=GET"), "{line}");
    assert!(line.contains("status=200"), "{line}");
    assert!(line.contains("ms="), "{line}");
    assert!(out.contains("path=\"/static/{file}\""), "{out}");
    assert!(out.contains("path=\"<unmatched>\""), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn static_assets_cached_pages_not() {
    let app = TestApp::new();
    let alice = app.session_for("alice");

    for (file, content_type) in [
        ("app.css", "text/css; charset=utf-8"),
        ("app.js", "text/javascript; charset=utf-8"),
        ("htmx.min.js", "text/javascript; charset=utf-8"),
    ] {
        let resp = app.get(&format!("/static/{file}"), &Client::anon()).await;
        assert_eq!(resp.status(), StatusCode::OK, "{file}");
        assert_eq!(header_str(&resp, "cache-control"), "no-cache", "{file}");
        assert_eq!(header_str(&resp, "content-type"), content_type, "{file}");
        assert!(!common::body_bytes(resp).await.is_empty(), "{file}");
    }
    let htmx = common::body_bytes(app.get("/static/htmx.min.js", &Client::anon()).await).await;
    assert_eq!(htmx, include_bytes!("../static/htmx.min.js"));

    let missing = app.get("/static/nope.js", &Client::anon()).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(header_str(&missing, "cache-control"), "no-store");

    for resp in [
        app.get("/documents", &alice).await,
        app.get("/documents", &Client::anon()).await,
        app.get("/login", &Client::anon()).await,
        app.get("/no/such/page", &Client::anon()).await,
    ] {
        assert_eq!(header_str(&resp, "cache-control"), "no-store");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn healthz_is_204_and_not_access_logged() {
    let capture = install_capture();
    let app = TestApp::new();
    let resp = app.get("/healthz", &Client::anon()).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // A logged request right after proves the subscriber is live.
    app.get("/login", &Client::anon()).await;
    let out = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(out.contains("path=\"/login\""), "{out}");
    assert!(!out.contains("healthz"), "{out}");
}
