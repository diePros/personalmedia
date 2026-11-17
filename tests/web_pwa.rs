mod common;

use axum::http::Method;
use common::*;

const PDF: &[u8] = include_bytes!("fixtures/text.pdf");
const SW: &str = include_str!("../static/sw.js");

#[tokio::test(flavor = "multi_thread")]
async fn manifest_valid_json_with_required_fields() {
    let t = TestApp::new();
    let resp = t.get("/manifest.webmanifest", &Client::anon()).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        header_str(&resp, "content-type"),
        "application/manifest+json"
    );
    assert_eq!(header_str(&resp, "cache-control"), "no-cache");
    let etag = header_str(&resp, "etag").to_owned();
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "strong ETag: {etag}"
    );
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["name"], "Personal Media System");
    assert_eq!(v["short_name"], "PMS");
    assert_eq!(v["start_url"], "/scan");
    assert_eq!(v["scope"], "/");
    assert_eq!(v["display"], "standalone");
    assert!(v["theme_color"].as_str().unwrap().starts_with('#'));
    assert!(v["background_color"].as_str().unwrap().starts_with('#'));
    let icons = v["icons"].as_array().unwrap();
    assert!(icons.iter().any(|i| i["purpose"] == "maskable"));
    for icon in icons {
        let src = icon["src"].as_str().unwrap();
        assert!(src.starts_with("/static/icons/"));
        let resp = t.get(src, &Client::anon()).await;
        assert_eq!(resp.status(), 200, "{src}");
        assert_eq!(
            header_str(&resp, "content-type"),
            icon["type"].as_str().unwrap(),
            "{src}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sw_served_with_scope_header() {
    let t = TestApp::new();
    let resp = t.get("/sw.js", &Client::anon()).await;
    assert_eq!(resp.status(), 200);
    assert!(header_str(&resp, "content-type").starts_with("text/javascript"));
    assert_eq!(header_str(&resp, "cache-control"), "no-cache");
    assert_eq!(header_str(&resp, "service-worker-allowed"), "/");
    assert_eq!(
        body_string(resp).await,
        SW.replace("__ASSET_VERSION__", &personal_media::web::ASSET_VERSION)
    );
}

fn precache_entries() -> Vec<String> {
    let start = SW.find("PRECACHE = [").expect("PRECACHE literal") + "PRECACHE = [".len();
    let end = start + SW[start..].find(']').unwrap();
    SW[start..end]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn sw_precache_list_contains_only_static_paths() {
    let entries = precache_entries();
    assert!(entries.len() >= 6, "{entries:?}");
    let t = TestApp::new();
    for e in &entries {
        assert!(e.starts_with("/static/"), "{e}");
        let resp = t.get(e, &Client::anon()).await;
        assert_eq!(resp.status(), 200, "{e} must be served");
    }
    assert!(entries.contains(&"/static/offline.html".to_owned()));
}

#[test]
fn sw_has_no_cache_put_outside_precache() {
    // `cache.put` / `cache.add(All)` may only appear inside the install handler.
    let install_start = SW.find("addEventListener(\"install\"").unwrap();
    let install_end = SW.find("addEventListener(\"activate\"").unwrap();
    assert!(install_start < install_end);
    for needle in [".put(", ".add(", ".addAll("] {
        for (i, _) in SW.match_indices(needle) {
            assert!(
                (install_start..install_end).contains(&i),
                "{needle} outside install handler"
            );
        }
    }
    assert!(!SW.contains(".put("));
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_pages_are_no_store() {
    let t = TestApp::new();
    let c = t.admin_session_for("alice");
    let resp = t
        .post_multipart(
            "/api/upload",
            &[],
            &[("file", "a.pdf", "application/pdf", PDF)],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let id = v["id"].as_str().unwrap();
    for path in [
        "/documents".to_owned(),
        format!("/documents/{id}"),
        format!("/documents/{id}/raw"),
        "/settings".to_owned(),
        "/admin".to_owned(),
    ] {
        let resp = t.get(&path, &c).await;
        assert_eq!(resp.status(), 200, "{path}");
        assert_eq!(header_str(&resp, "cache-control"), "no-store", "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn static_assets_revalidate_with_etag() {
    let t = TestApp::new();
    for path in ["/static/app.js", "/static/icons/icon-192.png"] {
        let resp = t.get(path, &Client::anon()).await;
        assert_eq!(resp.status(), 200, "{path}");
        assert_eq!(header_str(&resp, "cache-control"), "no-cache", "{path}");
        let etag = header_str(&resp, "etag").to_owned();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");

        let req = builder(axum::http::Method::GET, path, &Client::anon())
            .header("if-none-match", &etag)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = t.request(req).await;
        assert_eq!(resp.status(), 304, "{path}");
        assert_eq!(header_str(&resp, "etag"), etag);
        assert!(body_bytes(resp).await.is_empty());

        let req = builder(axum::http::Method::GET, path, &Client::anon())
            .header("if-none-match", "\"other\"")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(t.request(req).await.status(), 200);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sw_cache_name_tracks_asset_version() {
    let t = TestApp::new();
    let body = body_string(t.get("/sw.js", &Client::anon()).await).await;
    let version = &*personal_media::web::ASSET_VERSION;
    assert!(!version.is_empty());
    assert!(body.contains(&format!("\"pm-shell-{version}\"")), "{body}");
    assert!(!body.contains("__ASSET_VERSION__"));
    assert!(body.contains("cache: \"reload\""));
}

#[test]
fn sw_fetch_handler_ignores_non_get_requests() {
    // The share target is a POST navigation; the worker must not respondWith
    // it. Matched with all whitespace removed so formatting changes are fine.
    let squashed: String = SW.chars().filter(|c| !c.is_whitespace()).collect();
    let fetch_start = squashed.find("addEventListener(\"fetch\"").unwrap();
    let guard = squashed[fetch_start..]
        .find("if(req.method!==\"GET\"){return;}")
        .expect("early return for non-GET")
        + fetch_start;
    let first_respond = squashed[fetch_start..].find("event.respondWith(").unwrap() + fetch_start;
    assert!(guard < first_respond);
}

#[test]
fn sw_offline_fallback_never_resolves_undefined() {
    let squashed: String = SW.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        squashed.contains("caches.match(OFFLINE).then("),
        "the offline lookup must be followed by a fallback"
    );
    assert!(squashed.contains("r||Response.error()"));
}

async fn conditional(
    t: &TestApp,
    method: Method,
    path: &str,
    inm: &str,
) -> axum::response::Response {
    let req = builder(method, path, &Client::anon())
        .header("if-none-match", inm)
        .body(axum::body::Body::empty())
        .unwrap();
    t.request(req).await
}

#[tokio::test(flavor = "multi_thread")]
async fn conditional_requests_weak_star_and_head() {
    let t = TestApp::new();
    for path in ["/static/app.js", "/manifest.webmanifest"] {
        let resp = t.get(path, &Client::anon()).await;
        let etag = header_str(&resp, "etag").to_owned();
        for (method, inm) in [
            (Method::GET, format!("W/{etag}")),
            (Method::GET, "*".to_owned()),
            (Method::GET, format!("\"nope\", {etag}")),
            (Method::HEAD, etag.clone()),
            (Method::HEAD, "*".to_owned()),
        ] {
            let resp = conditional(&t, method.clone(), path, &inm).await;
            assert_eq!(resp.status(), 304, "{method} {path} {inm}");
            assert_eq!(header_str(&resp, "etag"), etag);
            assert_eq!(header_str(&resp, "cache-control"), "no-cache");
            assert!(body_bytes(resp).await.is_empty());
        }
        let resp = conditional(&t, Method::HEAD, path, "\"nope\"").await;
        assert_eq!(resp.status(), 200, "HEAD {path}");
        assert!(body_bytes(resp).await.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn manifest_declares_share_target() {
    let t = TestApp::new();
    let resp = t.get("/manifest.webmanifest", &Client::anon()).await;
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(
        v["share_target"],
        serde_json::json!({
            "action": "/share",
            "method": "POST",
            "enctype": "multipart/form-data",
            "params": {
                "title": "title",
                "text": "text",
                "files": [{"name": "files", "accept": ["application/pdf", "image/*", "text/plain"]}]
            }
        })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn favicon_and_icons_served_with_correct_types() {
    let t = TestApp::new();
    for (name, ty) in [
        ("icon.svg", "image/svg+xml"),
        ("favicon.svg", "image/svg+xml"),
        ("favicon-32.png", "image/png"),
        ("favicon-16.png", "image/png"),
        ("apple-touch-icon.png", "image/png"),
        ("icon-192.png", "image/png"),
        ("icon-512.png", "image/png"),
        ("icon-maskable-512.png", "image/png"),
    ] {
        let path = format!("/static/icons/{name}");
        let resp = t.get(&path, &Client::anon()).await;
        assert_eq!(resp.status(), 200, "{path}");
        assert_eq!(header_str(&resp, "content-type"), ty, "{path}");
        let body = body_bytes(resp).await;
        if ty == "image/png" {
            assert!(body.starts_with(b"\x89PNG"), "{path}");
        } else {
            assert!(body.starts_with(b"<svg"), "{path}");
        }
    }
    // The pages link them.
    let html = body_string(t.get("/login", &Client::anon()).await).await;
    for needle in [
        r#"rel="icon" type="image/svg+xml" href="/static/icons/favicon.svg""#,
        r#"href="/static/icons/favicon-32.png""#,
        r#"href="/static/icons/favicon-16.png""#,
        r#"rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png""#,
    ] {
        assert!(html.contains(needle), "{needle}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn manifest_lists_new_icons_and_start_url_scan() {
    let t = TestApp::new();
    let resp = t.get("/manifest.webmanifest", &Client::anon()).await;
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["start_url"], "/scan");
    let icons = v["icons"].as_array().unwrap();
    let has = |src: &str, purpose: &str| {
        icons
            .iter()
            .any(|i| i["src"] == src && i["purpose"] == purpose)
    };
    assert!(has("/static/icons/icon-192.png", "any"));
    assert!(has("/static/icons/icon-512.png", "any"));
    assert!(has("/static/icons/icon-maskable-512.png", "maskable"));
    assert!(has("/static/icons/icon.svg", "any"));
    // New icons are precached too.
    let pre = precache_entries();
    for e in [
        "/static/icons/apple-touch-icon.png",
        "/static/icons/favicon.svg",
    ] {
        assert!(pre.contains(&e.to_owned()), "{e}");
    }
    // /scan never 404s (until Task 30): it leads to the documents page / login.
    let resp = t.get("/scan", &Client::anon()).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/documents");
}

#[tokio::test(flavor = "multi_thread")]
async fn install_hint_markup_present_and_scripts_external() {
    let t = TestApp::new();
    let c = t.admin_session_for("alice");
    let html = body_string(t.get("/documents", &c).await).await;
    assert!(html.contains(r#"id="install-hint""#));
    assert!(html.contains("Install PMS for quick scanning"));
    assert!(html.contains("Add to Home Screen"));
    assert!(html.contains(r#"id="install-hint-dismiss""#));
    // The hint starts hidden; app.js reveals it.
    let tag = &html[html.find(r#"id="install-hint""#).unwrap()..];
    assert!(tag[..tag.find('>').unwrap()].contains("hidden"));
    // No inline script or handler.
    assert!(!html.contains("onclick="));
    for chunk in html.split("<script").skip(1) {
        let open = &chunk[..chunk.find('>').unwrap()];
        assert!(open.contains("src=\"/static/"), "inline script: {open}");
    }
    let js = include_str!("../static/app.js");
    assert!(js.contains("pms.installHint.dismissed"));
    assert!(js.contains("beforeinstallprompt"));
}
