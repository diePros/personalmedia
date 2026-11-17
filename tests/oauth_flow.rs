//! OAuth authorization code + PKCE flow, driven over HTTP like a client.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, header};
use common::*;
use data_encoding::BASE64URL_NOPAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REDIRECT: &str = "http://127.0.0.1:8123/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn challenge_of(verifier: &str) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()))
}

fn enc(s: &str) -> String {
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

struct Flow {
    t: TestApp,
    alice: Client,
    client_id: String,
}

impl Flow {
    async fn new() -> Flow {
        let t = TestApp::new();
        let alice = t.session_for("alice");
        let client_id = register(&t, "Hermes", &[REDIRECT]).await;
        Flow {
            t,
            alice,
            client_id,
        }
    }

    fn authorize_uri(&self, extra: &str) -> String {
        format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}\
             &code_challenge_method=S256&state=st8&resource={}{extra}",
            self.client_id,
            enc(REDIRECT),
            challenge_of(VERIFIER),
            enc("https://test.example/mcp"),
        )
    }

    /// GET authorize as the logged-in user; returns the consent page's `req` id.
    async fn consent_req(&self, extra: &str) -> String {
        let resp = self.t.get(&self.authorize_uri(extra), &self.alice).await;
        assert_eq!(resp.status(), 200);
        req_id(&body_string(resp).await)
    }

    /// Full authorize + consent; returns the code.
    async fn code(&self, fields: &[(&str, &str)]) -> String {
        let req = self.consent_req("").await;
        let mut all = vec![
            ("req", req.as_str()),
            ("decision", "approve"),
            ("password", PASSWORD),
        ];
        all.extend_from_slice(fields);
        let resp = self
            .t
            .post_form("/oauth/authorize", &all, &self.alice)
            .await;
        assert_eq!(resp.status(), 302);
        let loc = header_str(&resp, "location").to_owned();
        assert!(loc.starts_with(&format!("{REDIRECT}?")), "{loc}");
        assert_eq!(query_param(&loc, "state").as_deref(), Some("st8"));
        query_param(&loc, "code").expect("code")
    }

    async fn exchange(&self, code: &str, verifier: &str) -> (u16, Value) {
        self.token(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", &self.client_id),
            ("code_verifier", verifier),
        ])
        .await
    }

    async fn refresh(&self, token: &str) -> (u16, Value) {
        self.token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", &self.client_id),
        ])
        .await
    }

    async fn token(&self, fields: &[(&str, &str)]) -> (u16, Value) {
        let resp = self.t.request(token_request(fields)).await;
        let status = resp.status().as_u16();
        assert_eq!(header_str(&resp, "cache-control"), "no-store");
        (
            status,
            serde_json::from_slice(&body_bytes(resp).await).unwrap_or(Value::Null),
        )
    }

    /// A normal exchange; returns `(access, refresh)`.
    async fn tokens(&self, fields: &[(&str, &str)]) -> (String, String) {
        let code = self.code(fields).await;
        let (s, v) = self.exchange(&code, VERIFIER).await;
        assert_eq!(s, 200, "{v}");
        (
            v["access_token"].as_str().unwrap().to_owned(),
            v["refresh_token"].as_str().unwrap().to_owned(),
        )
    }

    async fn mcp(&self, token: &str, body: &Value) -> (u16, Option<String>, Value) {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = self.t.request(req).await;
        let status = resp.status().as_u16();
        let www = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = body_bytes(resp).await;
        let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, www, v)
    }

    async fn tools_list(&self, token: &str) -> (u16, Option<String>, Value) {
        self.mcp(
            token,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await
    }
}

fn token_request(fields: &[(&str, &str)]) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        // A server-side client: cross-site, never cookie-authenticated.
        .header("sec-fetch-site", "cross-site")
        .body(Body::from(body))
        .unwrap()
}

async fn register(t: &TestApp, name: &str, uris: &[&str]) -> String {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"client_name": name, "redirect_uris": uris}).to_string(),
        ))
        .unwrap();
    let resp = t.request(req).await;
    assert_eq!(resp.status(), 201);
    let v: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    v["client_id"].as_str().unwrap().to_owned()
}

fn req_id(html: &str) -> String {
    let m = "name=\"req\" value=\"";
    let i = html.find(m).expect("req field") + m.len();
    html[i..].split('"').next().unwrap().to_owned()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    serde_urlencoded::from_str::<Vec<(String, String)>>(q)
        .unwrap()
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

fn sys_conn(f: &Flow) -> rusqlite::Connection {
    rusqlite::Connection::open(f.t.dir.path().join("system.db")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn full_flow_register_authorize_token_mcp_refresh() {
    let f = Flow::new().await;

    // The consent page shows who asks and where it goes, and cannot be framed.
    let resp = f.t.get(&f.authorize_uri(""), &f.alice).await;
    assert_eq!(resp.status(), 200);
    let csp = header_str(&resp, "content-security-policy").to_owned();
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("form-action 'self' http://127.0.0.1:8123"));
    let html = body_string(resp).await;
    assert!(html.contains("Hermes wants access to your documents"));
    assert!(html.contains("It will send you back to: <strong>127.0.0.1:8123</strong>"));
    assert!(html.contains("Restrict to a new tag"));
    assert!(!html.contains("<script>") && !html.contains("<style"));

    let (access, refresh) = f
        .tokens(&[("access", "read_write"), ("content", "full_text")])
        .await;
    assert!(access.starts_with("pma_") && refresh.starts_with("pmr_"));

    let code = f.code(&[]).await;
    let (s, v) = f.exchange(&code, VERIFIER).await;
    assert_eq!(s, 200);
    assert_eq!(v["token_type"], "Bearer");
    assert_eq!(v["expires_in"], 3600);
    assert_eq!(v["scope"], "mcp:read offline_access");

    // MCP works with the access token; a refresh token is not a bearer.
    let (s, _, v) = f.tools_list(&access).await;
    assert_eq!(s, 200);
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"upload_document") && names.contains(&"get_document"));
    let (s, www, _) = f.tools_list(&refresh).await;
    assert_eq!(s, 401);
    assert!(www.unwrap().contains("resource_metadata"));

    // Refresh rotates the pair under the same grant.
    let (s, v) = f.refresh(&refresh).await;
    assert_eq!(s, 200, "{v}");
    let (access2, refresh2) = (
        v["access_token"].as_str().unwrap().to_owned(),
        v["refresh_token"].as_str().unwrap().to_owned(),
    );
    assert_ne!(access2, access);
    assert_ne!(refresh2, refresh);
    assert_eq!(v["scope"], "mcp:write content:full offline_access");
    assert_eq!(f.tools_list(&access2).await.0, 200);
    // The old access token died with the rotation.
    assert_eq!(f.tools_list(&access).await.0, 401);

    // The old refresh token fails and, past the grace window, takes the grant
    // with it.
    f.t.state.oauth.set_refresh_grace(std::time::Duration::ZERO);
    let (s, v) = f.refresh(&refresh).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
    assert_eq!(f.tools_list(&access2).await.0, 401);
    let (s, v) = f.refresh(&refresh2).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_code_single_use_and_bound() {
    let f = Flow::new().await;

    // Used twice: the second exchange fails and so does everything minted.
    let code = f.code(&[]).await;
    let (s, v) = f.exchange(&code, VERIFIER).await;
    assert_eq!(s, 200);
    let access = v["access_token"].as_str().unwrap().to_owned();
    let (s, v) = f.exchange(&code, VERIFIER).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
    let _ = access;

    // Wrong verifier.
    let code = f.code(&[]).await;
    let (s, v) = f
        .exchange(&code, "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww")
        .await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
    // A spent code cannot be retried with the right verifier.
    assert_eq!(f.exchange(&code, VERIFIER).await.0, 400);

    // Different redirect_uri.
    let code = f.code(&[]).await;
    let (s, v) = f
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://127.0.0.1:9999/cb"),
            ("client_id", &f.client_id),
            ("code_verifier", VERIFIER),
        ])
        .await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));

    // Different client.
    let other = register(&f.t, "Other", &[REDIRECT]).await;
    let code = f.code(&[]).await;
    let (s, v) = f
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", &other),
            ("code_verifier", VERIFIER),
        ])
        .await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));

    // Unknown client is invalid_client (401).
    let (s, v) = f
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", "x"),
            ("redirect_uri", REDIRECT),
            ("client_id", "pmc_nope"),
            ("code_verifier", VERIFIER),
        ])
        .await;
    assert_eq!((s, v["error"].as_str()), (401, Some("invalid_client")));

    // After 60 s (shortened for the test).
    f.t.state
        .oauth
        .set_code_ttl(std::time::Duration::from_millis(50));
    let code = f.code(&[]).await;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let (s, v) = f.exchange(&code, VERIFIER).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));

    // Every failed exchange removed the grant it had minted.
    let n: i64 = sys_conn(&f)
        .query_row(
            "SELECT count(*) FROM tokens WHERE grant_id IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // Only the first (successful) exchange's pair remains.
    assert_eq!(n, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_reuse_revokes_grant() {
    let f = Flow::new().await;
    let (access1, refresh1) = f.tokens(&[]).await;
    let (s, v) = f.refresh(&refresh1).await;
    assert_eq!(s, 200);
    let access2 = v["access_token"].as_str().unwrap().to_owned();
    let refresh2 = v["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(f.tools_list(&access2).await.0, 200);

    // Replaying the consumed token after the grace window fails and revokes
    // the whole grant.
    f.t.state.oauth.set_refresh_grace(std::time::Duration::ZERO);
    let (s, v) = f.refresh(&refresh1).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
    assert_eq!(f.tools_list(&access2).await.0, 401);
    assert_eq!(f.tools_list(&access1).await.0, 401);
    let (s, v) = f.refresh(&refresh2).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
    let n: i64 = sys_conn(&f)
        .query_row("SELECT count(*) FROM tokens", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
    // The grant metadata is gone too (the user is unlocked).
    let u = f.t.state.sessions.get(&f.alice.cookie).unwrap().unlocked;
    let metas = u.with_db(personal_media::user_db::list_token_meta).unwrap();
    assert!(metas.is_empty());

    // A refresh token for another client is refused and does not rotate.
    let (_, refresh) = f.tokens(&[]).await;
    let other = register(&f.t, "Other", &[REDIRECT]).await;
    let (s, v) = f
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &other),
        ])
        .await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
    assert_eq!(f.refresh(&refresh).await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_retry_within_grace_does_not_revoke() {
    let f = Flow::new().await;
    let (_, refresh1) = f.tokens(&[]).await;
    let (s, v) = f.refresh(&refresh1).await;
    assert_eq!(s, 200);
    let access2 = v["access_token"].as_str().unwrap().to_owned();
    let refresh2 = v["refresh_token"].as_str().unwrap().to_owned();

    // The response was lost and the client retries with the old token.
    let (s, v) = f.refresh(&refresh1).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
    // The newest pair is untouched.
    assert_eq!(f.tools_list(&access2).await.0, 200);
    assert_eq!(f.refresh(&refresh2).await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_access_token_401_with_metadata_pointer() {
    let f = Flow::new().await;
    let (access, refresh) = f.tokens(&[]).await;
    assert_eq!(f.tools_list(&access).await.0, 200);

    // Expire the access row directly.
    let id = access
        .strip_prefix("pma_")
        .unwrap()
        .split('_')
        .next()
        .unwrap();
    sys_conn(&f)
        .execute("UPDATE tokens SET expires_at = 1 WHERE token_id = ?1", [id])
        .unwrap();
    let (s, www, _) = f.tools_list(&access).await;
    assert_eq!(s, 401);
    assert_eq!(
        www.as_deref(),
        Some(
            "Bearer resource_metadata=\"https://test.example/.well-known/oauth-protected-resource\""
        )
    );
    // The row was deleted lazily.
    let n: i64 = sys_conn(&f)
        .query_row("SELECT count(*) FROM tokens WHERE token_id=?1", [id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(n, 0);

    // The client then refreshes and carries on.
    let (s, v) = f.refresh(&refresh).await;
    assert_eq!(s, 200);
    assert_eq!(
        f.tools_list(v["access_token"].as_str().unwrap()).await.0,
        200
    );

    // An expired refresh token is invalid_grant.
    let rid = v["refresh_token"].as_str().unwrap().to_owned();
    let rrow = rid
        .strip_prefix("pmr_")
        .unwrap()
        .split('_')
        .next()
        .unwrap()
        .to_owned();
    sys_conn(&f)
        .execute(
            "UPDATE tokens SET expires_at = 1 WHERE token_id = ?1",
            [&rrow],
        )
        .unwrap();
    let (s, v) = f.refresh(&rid).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_grant_kills_access_and_refresh() {
    let f = Flow::new().await;
    let (access, refresh) = f.tokens(&[]).await;
    // Warm the token cache.
    assert_eq!(f.tools_list(&access).await.0, 200);
    assert_eq!(f.t.state.tokens.len(), 1);

    // Settings revoke (the grant's metadata id is its grant id).
    let u = f.t.state.sessions.get(&f.alice.cookie).unwrap().unlocked;
    let metas = u.with_db(personal_media::user_db::list_token_meta).unwrap();
    assert_eq!(metas.len(), 1);
    let grant = metas[0].grant.clone().unwrap();
    assert_eq!(grant.client_name, "Hermes");
    assert_eq!(grant.redirect_host, "127.0.0.1:8123");
    let resp =
        f.t.post_form(
            &format!("/settings/tokens/{}/revoke", metas[0].id),
            &[],
            &f.alice,
        )
        .await;
    assert_eq!(resp.status(), 303);

    assert_eq!(f.tools_list(&access).await.0, 401);
    assert_eq!(f.t.state.tokens.len(), 0);
    let (s, v) = f.refresh(&refresh).await;
    assert_eq!((s, v["error"].as_str()), (400, Some("invalid_grant")));
    let n: i64 = sys_conn(&f)
        .query_row("SELECT count(*) FROM tokens", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_revoke_endpoint_is_rfc7009() {
    let f = Flow::new().await;
    let post = |token: String| {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/oauth/revoke")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "cross-site")
            .body(Body::from(format!("token={}", enc(&token))))
            .unwrap();
        f.t.request(req)
    };
    // Garbage and unknown tokens: still 200.
    assert_eq!(post("junk".into()).await.status(), 200);
    assert_eq!(
        post(format!("pmr_{}_{}", "a".repeat(32), "b".repeat(64)))
            .await
            .status(),
        200
    );

    let (access, refresh) = f.tokens(&[]).await;
    // A token with the right id but a wrong secret revokes nothing.
    let id = refresh
        .strip_prefix("pmr_")
        .unwrap()
        .split('_')
        .next()
        .unwrap();
    assert_eq!(
        post(format!("pmr_{id}_{}", "0".repeat(64))).await.status(),
        200
    );
    assert_eq!(f.tools_list(&access).await.0, 200);

    // Revoking the access token only ends that token.
    assert_eq!(post(access.clone()).await.status(), 200);
    assert_eq!(f.tools_list(&access).await.0, 401);
    assert_eq!(f.refresh(&refresh).await.0, 200);

    // Revoking a refresh token ends the grant.
    let (access, refresh) = f.tokens(&[]).await;
    assert_eq!(f.tools_list(&access).await.0, 200);
    let resp = post(refresh.clone()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header_str(&resp, "cache-control"), "no-store");
    assert_eq!(f.tools_list(&access).await.0, 401);
    assert_eq!(f.refresh(&refresh).await.0, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_uri_allow_list_enforced() {
    let f = Flow::new().await;

    // Registration half: a non-allowed URI is refused.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"client_name":"evil","redirect_uris":["https://evil.example/cb"]}).to_string(),
        ))
        .unwrap();
    assert_eq!(f.t.request(req).await.status(), 400);

    // Authorize half: an unregistered URI renders an error page and never redirects.
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}\
         &code_challenge_method=S256&state=x",
        f.client_id,
        enc("http://127.0.0.1:8123/other"),
        challenge_of(VERIFIER)
    );
    let resp = f.t.get(&uri, &f.alice).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.headers().get(header::LOCATION).is_none());
    // A different port on loopback is the same registration (RFC 8252).
    let uri = uri.replace(
        &enc("http://127.0.0.1:8123/other"),
        &enc("http://127.0.0.1:5555/cb"),
    );
    assert_eq!(f.t.get(&uri, &f.alice).await.status(), 200);

    // Unknown client: error page.
    let resp =
        f.t.get(
            &format!(
                "/oauth/authorize?response_type=code&client_id=pmc_nope&redirect_uri={}",
                enc(REDIRECT)
            ),
            &f.alice,
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert!(resp.headers().get(header::LOCATION).is_none());

    // With a trusted redirect, protocol errors go back to the client.
    let base = format!(
        "/oauth/authorize?client_id={}&redirect_uri={}&state=s1",
        f.client_id,
        enc(REDIRECT)
    );
    for (extra, code) in [
        ("&response_type=token", "unsupported_response_type"),
        ("&response_type=code", "invalid_request"),
        (
            &format!(
                "&response_type=code&code_challenge={}&code_challenge_method=plain",
                challenge_of(VERIFIER)
            )[..],
            "invalid_request",
        ),
        (
            &format!(
                "&response_type=code&code_challenge={}&code_challenge_method=S256&resource={}",
                challenge_of(VERIFIER),
                enc("https://other.example/mcp")
            )[..],
            "invalid_target",
        ),
    ] {
        let resp = f.t.get(&format!("{base}{extra}"), &f.alice).await;
        assert_eq!(resp.status(), 302, "{extra}");
        let loc = header_str(&resp, "location");
        assert!(loc.starts_with(REDIRECT));
        assert_eq!(query_param(loc, "error").as_deref(), Some(code), "{extra}");
        assert_eq!(query_param(loc, "state").as_deref(), Some("s1"));
    }

    // Unknown scopes are ignored, not rejected: the consent page opens.
    let resp =
        f.t.get(&f.authorize_uri("&scope=admin%20read"), &f.alice)
            .await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    assert!(!html.contains("admin"), "unknown scopes are not echoed");
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_scope_enforced_like_static_tokens() {
    let f = Flow::new().await;
    // A tag-restricted, metadata-only, read-only consent via the new-tag field.
    let (access, _) = f.tokens(&[("new_tag", "hermes")]).await;
    let u = f.t.state.sessions.get(&f.alice.cookie).unwrap().unlocked;
    let metas = u.with_db(personal_media::user_db::list_token_meta).unwrap();
    let scope = &metas[0].scope;
    assert_eq!(scope.access, personal_media::user_db::Access::Read);
    assert_eq!(
        scope.content,
        personal_media::user_db::Content::MetadataOnly
    );
    let tag = u
        .with_db(|c| personal_media::user_db::tag_ids(c, &["hermes".to_owned()]))
        .unwrap();
    assert_eq!(scope.tags.as_deref(), Some(&tag[..]));

    // Read-only: the write tools are not offered and a call is refused.
    let (s, _, v) = f.tools_list(&access).await;
    assert_eq!(s, 200);
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(!names.contains(&"upload_document") && !names.contains(&"update_document"));
    let (s, _, v) = f
        .mcp(
            &access,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                    "params":{"name":"upload_document","arguments":{}}}),
        )
        .await;
    assert_eq!(s, 200);
    assert!(
        v["error"].is_object() || v["result"]["isError"] == true,
        "{v}"
    );

    // Tag allow-list and metadata-only level, enforced on real documents.
    let hermes = store_doc(&f, &u, "in-scope.txt", &["hermes"]).await;
    let other = store_doc(&f, &u, "out-of-scope.txt", &["private"]).await;
    let call = async |name: &str, args: Value| {
        let body = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                          "params":{"name":name,"arguments":args}});
        f.mcp(&access, &body).await
    };
    let (s, _, v) = call("list_documents", json!({})).await;
    assert_eq!(s, 200);
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains(&hermes), "{text}");
    assert!(!text.contains(&other), "{text}");
    assert!(!text.contains("private"), "{text}");
    let (_, _, v) = call("get_document", json!({"id": other})).await;
    assert_eq!(v["result"]["isError"], true, "{v}");
    let (_, _, v) = call("get_document", json!({"id": hermes})).await;
    assert_ne!(v["result"]["isError"], true, "{v}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("title of in-scope.txt"), "{text}");
    assert!(!text.contains("secret words"), "{text}");
}

async fn store_doc(
    f: &Flow,
    u: &std::sync::Arc<personal_media::keyring::Unlocked>,
    name: &str,
    tags: &[&str],
) -> String {
    use personal_media::documents::{OnDuplicate, UploadMeta};
    use personal_media::user_db::{Channel, Level, TextStatus, set_document_access, set_text};
    let meta = UploadMeta {
        filename: name.to_owned(),
        mime: Some("application/octet-stream".into()),
        title: Some(format!("title of {name}")),
        tags: tags.iter().map(|s| s.to_string()).collect(),
        document_date: None,
    };
    let body = futures_util::stream::once(std::future::ready(Ok::<_, anyhow::Error>(
        bytes::Bytes::from(format!("bytes of {name}")),
    )));
    let out =
        f.t.state
            .docs
            .store(u, meta, Box::pin(body), OnDuplicate::Keep, None, 1)
            .await
            .unwrap();
    let id = serde_json::to_value(out).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    u.with_db(|c| {
        set_text(c, &id, TextStatus::Done, Some("secret words"), None, 1).unwrap();
        set_document_access(c, &id, Channel::Mcp, Some(Level::Full)).unwrap();
    });
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn consent_deny_and_csrf_and_escaping() {
    let f = Flow::new().await;
    // Requested scopes are shown as text only; the form defaults to the least
    // access whatever the app asked for.
    let resp =
        f.t.get(
            &f.authorize_uri("&scope=mcp%3Awrite%20content%3Afull"),
            &f.alice,
        )
        .await;
    let html = body_string(resp).await;
    assert!(html.contains("<option value=\"read\" selected>"));
    assert!(html.contains("<option value=\"metadata_only\" selected>"));
    assert!(!html.contains("<option value=\"read_write\" selected>"));
    assert!(!html.contains("<option value=\"full_text\" selected>"));
    assert!(html.contains("The app asked for: write access, full text"));
    assert!(html.contains("registered less than a minute ago"));
    assert!(html.contains("Only approve if you just started connecting this app yourself."));
    assert!(html.contains("name=\"password\""));

    // Deny goes back with access_denied and the state.
    let req = req_id(&html);
    let resp =
        f.t.post_form(
            "/oauth/authorize",
            &[("req", &req), ("decision", "deny")],
            &f.alice,
        )
        .await;
    assert_eq!(resp.status(), 302);
    let loc = header_str(&resp, "location");
    assert_eq!(query_param(loc, "error").as_deref(), Some("access_denied"));
    assert_eq!(query_param(loc, "state").as_deref(), Some("st8"));
    assert!(query_param(loc, "code").is_none());
    // The request was consumed.
    let resp =
        f.t.post_form(
            "/oauth/authorize",
            &[
                ("req", &req),
                ("decision", "approve"),
                ("password", PASSWORD),
            ],
            &f.alice,
        )
        .await;
    assert_eq!(resp.status(), 400);

    // The consent POST is CSRF protected.
    let req = f.consent_req("").await;
    let resp =
        f.t.post_form_raw(
            "/oauth/authorize",
            &[
                ("req", &req),
                ("decision", "approve"),
                ("password", PASSWORD),
                ("csrf", "wrong"),
            ],
            &f.alice,
        )
        .await;
    assert_eq!(resp.status(), 403);
    // ... and needs a session.
    let resp =
        f.t.post_form(
            "/oauth/authorize",
            &[("req", &req), ("decision", "approve")],
            &Client::anon(),
        )
        .await;
    assert_ne!(resp.status(), 302);

    // Client names are escaped and truncated to 64 characters.
    let evil = register(
        &f.t,
        &format!("<script>alert(1)</script>{}", "x".repeat(100)),
        &[REDIRECT],
    )
    .await;
    let uri = f.authorize_uri("").replace(&f.client_id, &evil);
    let html = body_string(f.t.get(&uri, &f.alice).await).await;
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("&#60;script&#62;") || html.contains("&lt;script&gt;"));
    assert!(!html.contains(&"x".repeat(60)));
}

#[tokio::test(flavor = "multi_thread")]
async fn consent_requires_password() {
    let f = Flow::new().await;
    let req = f.consent_req("").await;
    let tokens_before = |f: &Flow| -> i64 {
        sys_conn(f)
            .query_row("SELECT count(*) FROM tokens", [], |r| r.get(0))
            .unwrap()
    };

    // No password and a wrong one: the consent page again, no redirect, no grant.
    for fields in [
        vec![("req", req.as_str()), ("decision", "approve")],
        vec![
            ("req", req.as_str()),
            ("decision", "approve"),
            ("password", "not the password"),
        ],
    ] {
        let resp = f.t.post_form("/oauth/authorize", &fields, &f.alice).await;
        assert_eq!(resp.status(), 401);
        assert!(resp.headers().get(header::LOCATION).is_none());
        let html = body_string(resp).await;
        assert!(html.contains("The password is wrong."));
        assert_eq!(req_id(&html), req, "the same request stays pending");
        assert_eq!(tokens_before(&f), 0);
    }

    // The right password on the same request goes through.
    let resp =
        f.t.post_form(
            "/oauth/authorize",
            &[
                ("req", &req),
                ("decision", "approve"),
                ("password", PASSWORD),
            ],
            &f.alice,
        )
        .await;
    assert_eq!(resp.status(), 302);
    assert!(query_param(header_str(&resp, "location"), "code").is_some());
    assert_eq!(tokens_before(&f), 2);

    // The consent page allows the redirect target in form-action.
    let resp = f.t.get(&f.authorize_uri(""), &f.alice).await;
    let csp = header_str(&resp, "content-security-policy");
    assert!(
        csp.contains("form-action 'self' http://127.0.0.1:8123"),
        "{csp}"
    );

    // Wrong passwords are rate limited like logins.
    let req = f.consent_req("").await;
    let mut last = 0;
    for _ in 0..15 {
        last =
            f.t.post_form(
                "/oauth/authorize",
                &[("req", &req), ("decision", "approve"), ("password", "x")],
                &f.alice,
            )
            .await
            .status()
            .as_u16();
        if last == 429 {
            break;
        }
    }
    assert_eq!(last, 429);
}

#[tokio::test(flavor = "multi_thread")]
async fn authorize_without_session_logs_in_then_continues() {
    let f = Flow::new().await;
    let _bob = f.t.signup_and_login("bob").await;

    // Anonymous: parked behind the login, with the continue cookie.
    let resp = f.t.get(&f.authorize_uri(""), &Client::anon()).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/login");
    let cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix("__Host-pm_continue="))
        .map(|v| v.split(';').next().unwrap().to_owned())
        .unwrap();
    // The cookie holds an opaque id, not the request.
    assert!(!cookie.contains("code_challenge") && !cookie.contains("pmc_"));

    // Log in with the cookie: back to the authorize flow.
    let body = format!("username=bob&password={}", enc(PASSWORD));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .header(header::COOKIE, format!("__Host-pm_continue={cookie}"))
        .body(Body::from(body))
        .unwrap();
    let resp = f.t.request(req).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/oauth/authorize/resume");
    let session = client_from_response(&resp);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/oauth/authorize/resume")
        .header(
            header::COOKIE,
            format!(
                "__Host-pm_session={}; __Host-pm_continue={cookie}",
                session.cookie
            ),
        )
        .body(Body::empty())
        .unwrap();
    let resp = f.t.request(req).await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    assert!(html.contains("Hermes wants access to your documents"));
}

#[tokio::test(flavor = "multi_thread")]
async fn token_endpoint_rejects_non_form_and_counts_failures() {
    let f = Flow::new().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = f.t.request(req).await;
    assert_eq!(resp.status(), 400);
    let v: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["error"], "invalid_request");

    let (s, v) = f
        .token(&[("grant_type", "password"), ("client_id", &f.client_id)])
        .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (400, Some("unsupported_grant_type"))
    );

    // Wrong credentials lock the address out like MCP token failures do.
    let mut last = 0;
    for _ in 0..40 {
        last = f
            .refresh(&format!("pmr_{}_{}", "a".repeat(32), "b".repeat(64)))
            .await
            .0;
        if last == 429 {
            break;
        }
    }
    assert_eq!(last, 429);
}

#[tokio::test(flavor = "multi_thread")]
async fn static_tokens_still_work_next_to_grants() {
    let f = Flow::new().await;
    let u = f.t.state.sessions.get(&f.alice.cookie).unwrap().unlocked;
    let tok = personal_media::tokens::create_token(
        &f.t.state.sys,
        &u,
        "static",
        personal_media::user_db::TokenScope {
            access: personal_media::user_db::Access::Read,
            content: personal_media::user_db::Content::MetadataOnly,
            tags: None,
        },
        1,
    )
    .unwrap();
    assert_eq!(f.tools_list(&tok).await.0, 200);
    let (access, _) = f.tokens(&[]).await;
    assert_eq!(f.tools_list(&access).await.0, 200);
    assert_eq!(f.tools_list(&tok).await.0, 200);
}
