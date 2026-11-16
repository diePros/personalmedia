mod common;

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
    assert_eq!(header_str(&resp, "cache-control"), "public, max-age=86400");
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(v["name"], "Personal Media");
    assert_eq!(v["short_name"], "Media");
    assert_eq!(v["start_url"], "/documents");
    assert_eq!(v["scope"], "/");
    assert_eq!(v["display"], "standalone");
    assert!(v["theme_color"].as_str().unwrap().starts_with('#'));
    assert!(v["background_color"].as_str().unwrap().starts_with('#'));
    let icons = v["icons"].as_array().unwrap();
    assert_eq!(icons.len(), 3);
    assert!(icons.iter().any(|i| i["purpose"] == "maskable"));
    for icon in icons {
        let src = icon["src"].as_str().unwrap();
        assert!(src.starts_with("/static/icons/"));
        let resp = t.get(src, &Client::anon()).await;
        assert_eq!(resp.status(), 200, "{src}");
        assert_eq!(header_str(&resp, "content-type"), "image/png");
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
