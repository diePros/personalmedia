//! OAuth metadata, dynamic client registration and the v3 system schema.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, header};
use common::{TestApp, body_bytes, body_string, header_str};
use personal_media::system_db::{MIGRATION_V2, OauthClient, SCHEMA_V1, SYSTEM_DB_FILE, SystemDb};
use serde_json::{Value, json};

const MCP_METADATA: &str = "https://test.example/.well-known/oauth-protected-resource";

fn post_json(path: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        // A cross-site fetch: register must not be blocked by the origin guard.
        .header("sec-fetch-site", "cross-site")
        .header("origin", "https://claude.ai")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json_of(resp: axum::response::Response) -> Value {
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

fn version(p: &std::path::Path) -> i64 {
    rusqlite::Connection::open(p)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}

#[test]
fn system_migration_v3_upgrades_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SYSTEM_DB_FILE);
    {
        // A real v2 database: v1 schema plus the v2 migration.
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(SCHEMA_V1).unwrap();
        c.execute_batch(MIGRATION_V2).unwrap();
        c.execute(
            "INSERT INTO users (id, username, role, disabled, created_at, salt, argon2_m, \
             argon2_t, argon2_p, umk_by_password, umk_by_recovery, index_key_wrapped) \
             VALUES ('u1','old','user',0,1,x'00000000000000000000000000000000',8,1,1,x'01',x'02',x'03')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO tokens (token_id, user_id, umk_wrapped) VALUES ('t1','u1',x'0102')",
            [],
        )
        .unwrap();
    }
    assert_eq!(version(&path), 2);
    // Read-only works on v2 and does not migrate.
    SystemDb::open_readonly(&path).unwrap();
    assert_eq!(version(&path), 2);

    let db = SystemDb::open(&path).unwrap();
    assert_eq!(version(&path), 3);
    // Existing tokens became static and never expire.
    let c = rusqlite::Connection::open(&path).unwrap();
    let (kind, exp, grant): (String, Option<i64>, Option<String>) = c
        .query_row(
            "SELECT kind, expires_at, grant_id FROM tokens WHERE token_id='t1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((kind.as_str(), exp, grant), ("static", None, None));
    assert_eq!(db.oauth_client_count().unwrap(), 0);
    let client = OauthClient {
        client_id: "pmc_x".into(),
        client_name: "X".into(),
        redirect_uris: vec!["http://127.0.0.1:1/cb".into()],
        created_at: 5,
        last_grant_at: None,
    };
    assert!(db.insert_oauth_client(&client, 10).unwrap());
    drop(db);

    // A second open neither re-runs the migration nor loses data.
    let db = SystemDb::open(&path).unwrap();
    assert_eq!(version(&path), 3);
    assert_eq!(db.oauth_client("pmc_x").unwrap().unwrap(), client);
    drop(db);
    // Read-only works on v3 too.
    let ro = SystemDb::open_readonly(&path).unwrap();
    assert_eq!(ro.user_by_id("u1").unwrap().unwrap().username, "old");
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_resource_metadata_matches_mcp_url() {
    let app = TestApp::new();
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let resp = app.get(path, &common::Client::anon()).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(header_str(&resp, "content-type"), "application/json");
        assert_eq!(header_str(&resp, "cache-control"), "no-store");
        let v = json_of(resp).await;
        assert_eq!(v["resource"], "https://test.example/mcp");
        assert_eq!(v["authorization_servers"][0], "https://test.example");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn as_metadata_advertises_dcr_pkce_none_auth() {
    let app = TestApp::new();
    let resp = app
        .get(
            "/.well-known/oauth-authorization-server",
            &common::Client::anon(),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header_str(&resp, "content-type"), "application/json");
    assert_eq!(header_str(&resp, "cache-control"), "no-store");
    let v = json_of(resp).await;
    assert_eq!(v["issuer"], "https://test.example");
    assert_eq!(
        v["registration_endpoint"],
        "https://test.example/oauth/register"
    );
    assert_eq!(
        v["authorization_endpoint"],
        "https://test.example/oauth/authorize"
    );
    assert_eq!(v["token_endpoint"], "https://test.example/oauth/token");
    assert_eq!(v["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(v["token_endpoint_auth_methods_supported"], json!(["none"]));
    assert_eq!(
        v["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(v["response_types_supported"], json!(["code"]));
    assert!(
        v["scopes_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("offline_access"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_401_has_resource_metadata_pointer() {
    let app = TestApp::new();
    let want = format!("Bearer resource_metadata=\"{MCP_METADATA}\"");
    let user = app.session_for("alice");
    let _ = user;
    let attempts: [Option<&str>; 5] = [
        None,
        Some("Bearer"),
        Some("Basic abc"),
        Some("Bearer garbage"),
        Some(&format!("Bearer pm_{}_{}", "0".repeat(32), "1".repeat(64))),
    ];
    for auth in attempts {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        let resp = app.request(b.body(Body::from("{}")).unwrap()).await;
        assert_eq!(resp.status(), 401, "{auth:?}");
        assert_eq!(header_str(&resp, "www-authenticate"), want, "{auth:?}");
        assert!(body_bytes(resp).await.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dcr_registers_public_client() {
    let app = TestApp::new();
    let resp = app
        .request(post_json(
            "/oauth/register",
            &json!({
                "client_name": "Claude",
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            }),
        ))
        .await;
    assert_eq!(resp.status(), 201);
    assert_eq!(header_str(&resp, "cache-control"), "no-store");
    let v = json_of(resp).await;
    let id = v["client_id"].as_str().unwrap();
    assert!(id.starts_with("pmc_") && id.len() == 36);
    assert!(
        id[4..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert!(v["client_id_issued_at"].as_i64().unwrap() > 0);
    assert_eq!(v["token_endpoint_auth_method"], "none");
    assert!(v.get("client_secret").is_none());
    let stored = app.state.sys.oauth_client(id).unwrap().unwrap();
    assert_eq!(stored.client_name, "Claude");
    assert_eq!(
        stored.redirect_uris,
        vec!["https://claude.ai/api/mcp/auth_callback"]
    );
    assert_eq!(stored.last_grant_at, None);

    // Long names are capped at 64 characters.
    let resp = app
        .request(post_json(
            "/oauth/register",
            &json!({"client_name": "n".repeat(500),
                    "redirect_uris": ["http://127.0.0.1:9/cb"]}),
        ))
        .await;
    assert_eq!(resp.status(), 201);
    assert_eq!(
        json_of(resp).await["client_name"].as_str().unwrap().len(),
        64
    );

    // Confidential clients are refused.
    for method in [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
    ] {
        let resp = app
            .request(post_json(
                "/oauth/register",
                &json!({"redirect_uris": ["http://127.0.0.1:9/cb"],
                        "token_endpoint_auth_method": method}),
            ))
            .await;
        assert_eq!(resp.status(), 400);
        assert_eq!(json_of(resp).await["error"], "invalid_client_metadata");
    }
    // Not JSON.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/register")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("redirect_uris=x"))
        .unwrap();
    assert_eq!(app.request(req).await.status(), 400);
    // Missing redirect URIs.
    let resp = app.request(post_json("/oauth/register", &json!({}))).await;
    assert_eq!(json_of(resp).await["error"], "invalid_client_metadata");
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_uri_allow_list_enforced() {
    let app = TestApp::with_config(|c| {
        c.oauth_extra_redirect_hosts = vec!["app.example.org".into()];
    });
    let try_uri = |u: &'static str| {
        let app = &app;
        async move {
            let resp = app
                .request(post_json("/oauth/register", &json!({"redirect_uris": [u]})))
                .await;
            let status = resp.status().as_u16();
            let v = json_of(resp).await;
            (status, v["error"].as_str().unwrap_or("").to_owned())
        }
    };
    for ok in [
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        "http://127.0.0.1:53682/callback",
        "http://localhost:8080/oauth/cb",
        "https://app.example.org/cb",
    ] {
        assert_eq!(try_uri(ok).await.0, 201, "{ok}");
    }
    // Spread over several IPs would be needed beyond 10; stay under the limit.
    for bad in [
        "https://evil.example/cb",
        "http://claude.ai/api/mcp/auth_callback",
        "https://claude.ai/api/mcp/auth_callback/x",
        "http://127.0.0.1/cb",
        "http://127.0.0.1.evil.com:80/cb",
    ] {
        let (status, err) = try_uri(bad).await;
        assert_eq!(
            (status, err.as_str()),
            (400, "invalid_redirect_uri"),
            "{bad}"
        );
    }
    // One bad URI among good ones rejects the registration; nothing is stored.
    assert_eq!(app.state.sys.oauth_client_count().unwrap(), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn dcr_rate_limited_and_capped() {
    let app = TestApp::new();
    let body = json!({"redirect_uris": ["http://127.0.0.1:9/cb"]});
    for _ in 0..10 {
        assert_eq!(
            app.request(post_json("/oauth/register", &body))
                .await
                .status(),
            201
        );
    }
    let resp = app.request(post_json("/oauth/register", &body)).await;
    assert_eq!(resp.status(), 429);
    assert!(resp.headers().contains_key("retry-after"));

    // The cap: 200 clients, then 503 temporarily_unavailable (fresh IP).
    let app = TestApp::new();
    for i in 0..200 {
        let c = OauthClient {
            client_id: format!("pmc_{i:032x}"),
            client_name: "c".into(),
            redirect_uris: vec![],
            created_at: 1,
            last_grant_at: None,
        };
        assert!(app.state.sys.insert_oauth_client(&c, 200).unwrap());
    }
    let resp = app.request(post_json("/oauth/register", &body)).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(json_of(resp).await["error"], "temporarily_unavailable");
    assert_eq!(app.state.sys.oauth_client_count().unwrap(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn unused_clients_pruned_after_24h() {
    let app = TestApp::new();
    let mk = |id: &str, created: i64, grant: Option<i64>| OauthClient {
        client_id: id.into(),
        client_name: "c".into(),
        redirect_uris: vec![],
        created_at: created,
        last_grant_at: grant,
    };
    let sys = &app.state.sys;
    sys.insert_oauth_client(&mk("pmc_old_unused", 1000, None), 200)
        .unwrap();
    sys.insert_oauth_client(&mk("pmc_new_unused", 90_000, None), 200)
        .unwrap();
    sys.insert_oauth_client(&mk("pmc_old_used", 1000, Some(2000)), 200)
        .unwrap();
    let now = 1000 + 24 * 3600 + 1;
    assert_eq!(sys.prune_oauth_clients(now - 24 * 3600).unwrap(), 1);
    assert!(sys.oauth_client("pmc_old_unused").unwrap().is_none());
    assert!(sys.oauth_client("pmc_new_unused").unwrap().is_some());
    assert!(sys.oauth_client("pmc_old_used").unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn token_and_revoke_stubs_skip_origin_guard_for_post_only() {
    let app = TestApp::new();
    for path in ["/oauth/token", "/oauth/revoke"] {
        let resp = app.request(post_json(path, &json!({}))).await;
        assert_eq!(resp.status(), 501, "{path}");
    }
    // The consent endpoint is not exempt.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/authorize")
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.request(req).await.status(), 403);
    let _ = body_string;
}
