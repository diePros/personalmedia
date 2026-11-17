//! Per-user storage quotas: migration, limits, enforcement and the forms.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, header};
use bytes::Bytes;
use common::*;
use data_encoding::BASE64;
use futures_util::stream;
use personal_media::documents::{DocError, OnDuplicate, StoreOutcome, UploadMeta};
use personal_media::keyring::{Unlocked, user_dir};
use personal_media::system_db::{QuotaSetting, SCHEMA_V1, SYSTEM_DB_FILE, SystemDb};
use personal_media::tokens::create_token;
use personal_media::user_db::{Access, Content, TokenScope};
use serde_json::{Value, json};

const GIB: u64 = 1 << 30;
const PDF: &[u8] = include_bytes!("fixtures/text.pdf");

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn uid(t: &TestApp, name: &str) -> String {
    t.state.sys.user_by_name(name).unwrap().unwrap().id
}

fn unlocked(t: &TestApp, c: &Client) -> Arc<Unlocked> {
    t.state.sessions.get(&c.cookie).unwrap().unlocked
}

fn blob_count(t: &TestApp, id: &str) -> usize {
    std::fs::read_dir(user_dir(t.dir.path(), id).join("blobs"))
        .map(|d| d.count())
        .unwrap_or(0)
}

fn meta(name: &str) -> UploadMeta {
    UploadMeta {
        filename: name.into(),
        mime: Some("application/octet-stream".into()),
        title: None,
        tags: vec![],
        document_date: None,
    }
}

/// `n` bytes that differ per `seed` (so duplicates never collapse).
fn payload(n: usize, seed: u8) -> Bytes {
    Bytes::from(vec![seed; n])
}

async fn store(
    t: &TestApp,
    u: &Arc<Unlocked>,
    name: &str,
    data: Bytes,
) -> Result<StoreOutcome, DocError> {
    let body = stream::iter(
        data.chunks(8192)
            .map(|c| Ok::<_, anyhow::Error>(Bytes::copy_from_slice(c)))
            .collect::<Vec<_>>(),
    );
    t.state
        .docs
        .store(
            u,
            meta(name),
            Box::pin(body),
            OnDuplicate::Keep,
            None,
            now(),
        )
        .await
}

#[test]
fn system_migration_v2_upgrades_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SYSTEM_DB_FILE);
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(SCHEMA_V1).unwrap();
        c.execute(
            "INSERT INTO users (id, username, role, disabled, created_at, salt, argon2_m, \
             argon2_t, argon2_p, umk_by_password, umk_by_recovery, index_key_wrapped) \
             VALUES ('u1','old','user',0,1,x'00000000000000000000000000000000',8,1,1,x'01',x'02',x'03')",
            [],
        )
        .unwrap();
        c.pragma_update(None, "user_version", 1).unwrap();
    }
    // Recovery opens a v1 database read-only, without migrating it.
    {
        let ro = SystemDb::open_readonly(&path).unwrap();
        assert_eq!(
            ro.user_by_id("u1").unwrap().unwrap().quota,
            QuotaSetting::Default
        );
    }
    let version = |p: &std::path::Path| -> i64 {
        rusqlite::Connection::open(p)
            .unwrap()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap()
    };
    assert_eq!(version(&path), 1);

    let db = SystemDb::open(&path).unwrap();
    assert_eq!(version(&path), 2);
    assert_eq!(db.default_quota().unwrap(), Some(10 * GIB));
    assert_eq!(
        db.user_by_id("u1").unwrap().unwrap().quota,
        QuotaSetting::Default
    );
    db.set_default_quota(Some(5 * GIB)).unwrap();
    drop(db);

    // A second open neither re-runs the migration nor reseeds the default.
    let db = SystemDb::open(&path).unwrap();
    assert_eq!(version(&path), 2);
    assert_eq!(db.default_quota().unwrap(), Some(5 * GIB));
    drop(db);
    // Read-only also works on a v2 database.
    let ro = SystemDb::open_readonly(&path).unwrap();
    assert_eq!(ro.user_by_id("u1").unwrap().unwrap().username, "old");
}

#[test]
fn default_quota_seeded_10_gib() {
    let dir = tempfile::tempdir().unwrap();
    let db = SystemDb::open(&dir.path().join(SYSTEM_DB_FILE)).unwrap();
    assert_eq!(db.default_quota().unwrap(), Some(10_737_418_240));
    db.set_default_quota(None).unwrap();
    assert_eq!(db.default_quota().unwrap(), None);
    db.set_default_quota(Some(123)).unwrap();
    assert_eq!(db.default_quota().unwrap(), Some(123));
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_and_unlimited_override_default() {
    let t = TestApp::new();
    t.session_for("alice");
    let id = uid(&t, "alice");
    assert_eq!(t.state.quotas.limit_for(&id), Some(10 * GIB));
    t.state.sys.set_default_quota(Some(2 * GIB)).unwrap();
    assert_eq!(t.state.quotas.limit_for(&id), Some(2 * GIB));
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(7))
        .unwrap();
    assert_eq!(t.state.quotas.limit_for(&id), Some(7));
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Unlimited)
        .unwrap();
    assert_eq!(t.state.quotas.limit_for(&id), None);
    t.state.sys.set_default_quota(None).unwrap();
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Default)
        .unwrap();
    assert_eq!(t.state.quotas.limit_for(&id), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_over_quota_is_413_and_leaves_no_blob() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = uid(&t, "alice");
    // The index database already counts: leave 50 KiB of room on top of it.
    let base = t.state.quotas.usage(&id).await;
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(base + 50 * 1024))
        .unwrap();
    let big = payload(200 * 1024, 1);
    let resp = t
        .post_multipart(
            "/api/upload",
            &[],
            &[("file", "big.bin", "application/octet-stream", &big)],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 413);
    let v: Value = serde_json::from_str(&body_string(resp).await).unwrap();
    assert_eq!(v["status"], "quota_exceeded");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .starts_with("Storage quota reached ("),
        "{v}"
    );
    assert_eq!(blob_count(&t, &id), 0, "no blob and no .part left");
    // Small uploads still fit.
    let small = payload(1024, 2);
    let resp = t
        .post_multipart(
            "/api/upload",
            &[],
            &[("file", "s.bin", "application/octet-stream", &small)],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_uploads_cannot_exceed_quota() {
    let t = Arc::new(TestApp::new());
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let id = uid(&t, "alice");
    let limit = t.state.quotas.usage(&id).await + 100 * 1024;
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(limit))
        .unwrap();
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        let (t, u) = (t.clone(), u.clone());
        tasks.push(tokio::spawn(async move {
            store(&t, &u, &format!("f{i}"), payload(40 * 1024, i + 1)).await
        }));
    }
    let mut ok = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => ok += 1,
            Err(DocError::QuotaExceeded { .. }) => {}
            Err(e) => panic!("{e}"),
        }
    }
    assert!((1..=2).contains(&ok), "{ok} uploads fit");
    assert!(t.state.quotas.usage(&id).await <= limit);
    let on_disk = personal_media::quota::dir_size(&user_dir(t.dir.path(), &id));
    assert!(on_disk <= limit, "{on_disk} > {limit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn lowering_quota_blocks_uploads_only() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let id = uid(&t, "alice");
    let StoreOutcome::Stored { id: doc } =
        store(&t, &u, "a.bin", payload(20 * 1024, 1)).await.unwrap()
    else {
        panic!()
    };
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(1024))
        .unwrap();
    assert!(matches!(
        store(&t, &u, "b.bin", payload(10, 2)).await,
        Err(DocError::QuotaExceeded { .. })
    ));
    // Reading, listing and deleting are unaffected.
    assert_eq!(t.get("/documents", &c).await.status(), 200);
    let mut out = Vec::new();
    std::io::copy(
        &mut t.state.docs.open_plaintext(&u, &doc).unwrap().1,
        &mut out,
    )
    .unwrap();
    assert_eq!(out.len(), 20 * 1024);
    t.state.docs.delete(&u, &doc).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_enforced_on_all_upload_paths() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let id = uid(&t, "alice");
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(10 * 1024))
        .unwrap();
    let big = payload(64 * 1024, 3);

    // Session upload.
    let resp = t
        .post_multipart(
            "/api/upload",
            &[],
            &[("file", "a.bin", "application/octet-stream", &big)],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 413);

    // Bearer upload.
    let scope = TokenScope {
        access: Access::ReadWrite,
        content: Content::FullText,
        tags: None,
    };
    let token = create_token(&t.state.sys, &u, "bot", scope, now()).unwrap();
    let boundary = "qb-1";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"b.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(&big);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/upload")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    let resp = t.request(req).await;
    assert_eq!(resp.status(), 413);
    assert_eq!(
        serde_json::from_str::<Value>(&body_string(resp).await).unwrap()["status"],
        "quota_exceeded"
    );

    // MCP upload.
    let call = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"upload_document",
        "arguments":{"filename":"c.bin","content_base64":BASE64.encode(&big)}}});
    let req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(call.to_string()))
        .unwrap();
    let v: Value = serde_json::from_slice(&body_bytes(t.request(req).await).await).unwrap();
    assert_eq!(v["result"]["isError"], true, "{v}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("Storage quota reached ("), "{text}");

    // Share-save lists the file that did not fit.
    let boundary = "qs-1";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"shared.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(&big);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let req = builder(Method::POST, "/share", &c)
        .header("sec-fetch-site", "cross-site")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    let resp = t.request(req).await;
    assert_eq!(resp.status(), 303);
    let loc = header_str(&resp, "location").to_owned();
    let resp = t.post_form(&loc, &[("title", "x"), ("tags", "")], &c).await;
    let html = body_string(resp).await;
    assert!(html.contains("shared.pdf"), "{html}");
    assert!(html.contains("Storage quota reached"), "{html}");

    assert_eq!(blob_count(&t, &id), 0);
    let _ = PDF;
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_frees_quota_immediately() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let id = uid(&t, "alice");
    let before = t.state.quotas.usage(&id).await;
    let StoreOutcome::Stored { id: doc } =
        store(&t, &u, "a.bin", payload(30 * 1024, 1)).await.unwrap()
    else {
        panic!()
    };
    let during = t.state.quotas.usage(&id).await;
    assert!(during >= before + 30 * 1024, "{before} {during}");
    t.state.docs.delete(&u, &doc).unwrap();
    let after = t.state.quotas.usage(&id).await;
    assert!(after < during - 29 * 1024, "{during} {after}");
    // The freed space is usable at once.
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(after + 40 * 1024))
        .unwrap();
    assert!(store(&t, &u, "b.bin", payload(30 * 1024, 2)).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_shows_storage_usage() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = uid(&t, "alice");
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(html.contains("Storage: "), "{html}");
    assert!(html.contains("of 10.0 GiB"), "{html}");
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Unlimited)
        .unwrap();
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(html.contains("(unlimited)"), "{html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_quota_forms_roundtrip() {
    let t = TestApp::new();
    let admin = t.admin_session_for("root");
    t.session_for("bob");
    let bob = uid(&t, "bob");

    let html = body_string(t.get("/admin", &admin).await).await;
    assert!(html.contains("/ 10.0 GiB"), "{html}");

    let r = t.post_form("/admin/quota", &[("gib", "2.5")], &admin).await;
    assert_eq!(r.status(), 303);
    assert_eq!(t.state.sys.default_quota().unwrap(), Some(GIB * 5 / 2));
    let html = body_string(t.get("/admin", &admin).await).await;
    assert!(html.contains("/ 2.5 GiB"), "{html}");
    assert!(html.contains("value=\"2.5\""), "{html}");

    let r = t
        .post_form("/admin/quota", &[("gib", ""), ("unlimited", "on")], &admin)
        .await;
    assert_eq!(r.status(), 303);
    assert_eq!(t.state.sys.default_quota().unwrap(), None);

    for bad in ["-1", "abc", "", "1048577"] {
        let r = t.post_form("/admin/quota", &[("gib", bad)], &admin).await;
        assert_eq!(r.status(), 400, "{bad}");
    }
    assert_eq!(
        t.state.sys.default_quota().unwrap(),
        None,
        "unchanged by bad input"
    );

    let path = format!("/admin/users/{bob}/quota");
    let r = t
        .post_form(&path, &[("mode", "custom"), ("gib", "0.5")], &admin)
        .await;
    assert_eq!(r.status(), 303);
    assert_eq!(
        t.state.sys.user_by_id(&bob).unwrap().unwrap().quota,
        QuotaSetting::Custom(GIB / 2)
    );
    let html = body_string(t.get("/admin", &admin).await).await;
    assert!(html.contains("/ 512.0 MiB"), "{html}");
    let r = t
        .post_form(&path, &[("mode", "custom"), ("gib", "-3")], &admin)
        .await;
    assert_eq!(r.status(), 400);
    let r = t
        .post_form(&path, &[("mode", "unlimited"), ("gib", "")], &admin)
        .await;
    assert_eq!(r.status(), 303);
    assert_eq!(
        t.state.sys.user_by_id(&bob).unwrap().unwrap().quota,
        QuotaSetting::Unlimited
    );
    let r = t.post_form(&path, &[("mode", "default")], &admin).await;
    assert_eq!(r.status(), 303);
    assert_eq!(
        t.state.sys.user_by_id(&bob).unwrap().unwrap().quota,
        QuotaSetting::Default
    );

    // Unknown user and non-admins.
    let r = t
        .post_form("/admin/users/nobody/quota", &[("mode", "default")], &admin)
        .await;
    assert_eq!(r.status(), 404);
    let user = t.session_for("carol");
    assert_eq!(
        t.post_form("/admin/quota", &[("gib", "1")], &user)
            .await
            .status(),
        403
    );
    assert_eq!(
        t.post_form(&path, &[("mode", "default")], &user)
            .await
            .status(),
        403
    );
}
