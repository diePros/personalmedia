//! Per-user storage quotas: migration, limits, enforcement and the forms.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, header};
use bytes::Bytes;
use common::*;
use data_encoding::BASE64;
use futures_util::{StreamExt, stream};
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

/// Like `store`, but with a size hint and a body that waits for `gate`
/// before its first chunk (so the reservation is made before any write).
async fn store_hinted(
    t: &TestApp,
    u: &Arc<Unlocked>,
    name: &str,
    data: Bytes,
    gate: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<StoreOutcome, DocError> {
    let hint = data.len() as u64;
    let chunks = data
        .chunks(8192)
        .map(|c| Ok::<_, anyhow::Error>(Bytes::copy_from_slice(c)))
        .collect::<Vec<_>>();
    let body = stream::once(async move {
        if let Some(g) = gate {
            let _ = g.await;
        }
        stream::iter(chunks)
    })
    .flatten();
    t.state
        .docs
        .store_sized(
            u,
            meta(name),
            Box::pin(body),
            OnDuplicate::Keep,
            None,
            now(),
            Some(hint),
        )
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_uploads_cannot_exceed_quota() {
    // Two uploads that each need more than half the free space: with the
    // reservation made up front, exactly one wins, whatever the timing.
    let t = Arc::new(TestApp::new());
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let id = uid(&t, "alice");
    for _ in 0..5 {
        let room = t.state.quotas.usage(&id).await + 100 * 1024;
        t.state
            .sys
            .set_user_quota(&id, QuotaSetting::Custom(room))
            .unwrap();
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel();
        let (t1, u1) = (t.clone(), u.clone());
        let a = tokio::spawn(async move {
            store_hinted(&t1, &u1, "a", payload(60 * 1024, 1), Some(gate_rx)).await
        });
        let (t2, u2) = (t.clone(), u.clone());
        let b =
            tokio::spawn(
                async move { store_hinted(&t2, &u2, "b", payload(60 * 1024, 2), None).await },
            );
        // b is done (stored or refused) before a may write: a reserved
        // before either wrote, or lost the race.
        let rb = b.await.unwrap();
        gate_tx.send(()).ok();
        let ra = a.await.unwrap();
        let stored = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
        let refused = [&ra, &rb]
            .iter()
            .filter(|r| matches!(r, Err(DocError::QuotaExceeded { .. })))
            .count();
        assert_eq!((stored, refused), (1, 1), "{ra:?} / {rb:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn many_hinted_uploads_fit_exactly_what_fits() {
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
            store_hinted(&t, &u, &format!("f{i}"), payload(40 * 1024, i + 1), None).await
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
    assert_eq!(ok, 2, "two 40 KiB uploads fit into 100 KiB, no more");
    assert!(t.state.quotas.usage(&id).await <= limit);
}

#[tokio::test(flavor = "multi_thread")]
async fn reservation_covers_ciphertext_overhead() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let id = uid(&t, "alice");
    let size = 1usize << 20;
    let base = t.state.quotas.usage(&id).await;
    // Room for the plaintext and the 1 KiB allowance only: the 256 bytes of
    // tags do not fit, so the upload is refused instead of going over.
    let tight = base + size as u64 + 1024;
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(tight))
        .unwrap();
    let r = store(&t, &u, "x", payload(size, 7)).await;
    assert!(matches!(r, Err(DocError::QuotaExceeded { .. })), "{r:?}");
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(tight + 512))
        .unwrap();
    let r = store(&t, &u, "x", payload(size, 7)).await;
    assert!(r.is_ok(), "{r:?}");
    assert!(t.state.quotas.usage(&id).await <= tight + 512);
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

#[tokio::test(flavor = "multi_thread")]
async fn quota_413_body_has_message_and_is_early() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = uid(&t, "alice");
    let base = t.state.quotas.usage(&id).await;
    t.state
        .sys
        .set_user_quota(&id, QuotaSetting::Custom(base + 10 * 1024))
        .unwrap();
    // The declared length does not fit; the body must never be read.
    let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = polled.clone();
    let body = Body::from_stream(stream::once(async move {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok::<_, std::io::Error>(Bytes::from(vec![0u8; 64]))
    }));
    let b = builder(Method::POST, "/api/upload", &c)
        .header("sec-fetch-site", "same-origin")
        .header("origin", "null")
        .header("x-csrf-token", &c.csrf)
        .header(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=pm-test-boundary-7f3a9c",
        )
        .header(header::CONTENT_LENGTH, 64 * 1024);
    let resp = t.request(b.body(body).unwrap()).await;
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
    assert!(
        !polled.load(std::sync::atomic::Ordering::SeqCst),
        "the body was read before the refusal"
    );
    // The page script shows the message, not just the status.
    let js =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/static/app.js")).unwrap();
    assert!(js.contains("data.message || data.error || resp.status"));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_custom_quota_resubmit_is_a_no_op() {
    let t = TestApp::new();
    let admin = t.admin_session_for("root");
    t.session_for("bob");
    let bob = uid(&t, "bob");
    let path = format!("/admin/users/{bob}/quota");
    for bytes in [40u64 << 20, (5 << 28) + 12_345] {
        t.state
            .sys
            .set_user_quota(&bob, QuotaSetting::Custom(bytes))
            .unwrap();
        let html = body_string(t.get("/admin", &admin).await).await;
        let marker = format!("id=\"quota-gib-{bob}\" name=\"gib\" inputmode=\"decimal\" value=\"");
        let from = html.find(&marker).expect("quota field") + marker.len();
        let shown = &html[from..from + html[from..].find('"').unwrap()];
        let r = t
            .post_form(&path, &[("mode", "custom"), ("gib", shown)], &admin)
            .await;
        assert_eq!(r.status(), 303, "{shown}");
        assert_eq!(
            t.state.sys.user_by_id(&bob).unwrap().unwrap().quota,
            QuotaSetting::Custom(bytes),
            "re-submitting {shown} changed the quota"
        );
    }
}

fn quota_dir(files: &[(&str, usize)]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let u = user_dir(dir.path(), "u1");
    for (name, n) in files {
        let p = u.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, vec![0u8; *n]).unwrap();
    }
    (dir, u)
}

#[tokio::test]
async fn walk_racing_a_delete_is_discarded_and_repeated() {
    use personal_media::quota::Quotas;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (dir, _) = quota_dir(&[]);
    let q = Quotas::unlimited(dir.path().to_path_buf());
    let calls = Arc::new(AtomicUsize::new(0));
    let (q2, c2) = (q.clone(), calls.clone());
    let rt = tokio::runtime::Handle::current();
    // First walk: a delete lands while the walk runs and the walk still saw
    // the deleted blob (1000). The retry sees the settled state (400).
    q.load_with("u1", move || {
        if c2.fetch_add(1, Ordering::SeqCst) == 0 {
            let _g = rt.enter();
            q2.on_delete("u1", 600);
            1000
        } else {
            400
        }
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(q.usage("u1").await, 400);
}

#[tokio::test]
async fn commit_counts_index_growth() {
    use personal_media::quota::Quotas;
    let (dir, u) = quota_dir(&[("index.db", 1000), ("blobs/a", 500)]);
    let q = Quotas::unlimited(dir.path().to_path_buf());
    assert_eq!(q.usage("u1").await, 1500);
    // The index grows by 700 bytes (OCR text, vectors) before the next upload.
    std::fs::write(u.join("index.db"), vec![0u8; 1700]).unwrap();
    let r = q.reserve("u1", 100).await.unwrap();
    r.commit(60);
    assert_eq!(q.usage("u1").await, 1500 + 60 + 700);
}

#[tokio::test]
async fn startup_sweep_removes_stale_part_files_and_walk_counts_them() {
    use personal_media::quota::{Quotas, sweep_stale_parts};
    let (dir, u) = quota_dir(&[
        ("blobs/done", 100),
        ("blobs/crashed.part", 4000),
        ("index.db", 50),
    ]);
    let q = Quotas::unlimited(dir.path().to_path_buf());
    assert_eq!(q.usage("u1").await, 4150, "the leftover counts until swept");
    assert_eq!(sweep_stale_parts(dir.path()), 1);
    assert!(!u.join("blobs/crashed.part").exists());
    assert!(u.join("blobs/done").exists());
    let q = Quotas::unlimited(dir.path().to_path_buf());
    assert_eq!(q.usage("u1").await, 150);
}

#[tokio::test]
async fn dropped_reservation_is_released_and_users_are_independent() {
    let t = TestApp::new();
    let _a = t.session_for("alice");
    let _b = t.session_for("bob");
    let (a, b) = (uid(&t, "alice"), uid(&t, "bob"));
    let (ua, ub) = (
        t.state.quotas.usage(&a).await,
        t.state.quotas.usage(&b).await,
    );
    t.state
        .sys
        .set_user_quota(&a, QuotaSetting::Custom(ua + 10_000))
        .unwrap();
    t.state
        .sys
        .set_user_quota(&b, QuotaSetting::Custom(ub + 10_000))
        .unwrap();
    let held = t.state.quotas.reserve(&a, 9_000).await.unwrap();
    assert_eq!(t.state.quotas.usage(&a).await, ua + 9_000);
    // Bob is unaffected by Alice's reservation.
    assert!(t.state.quotas.reserve(&b, 9_000).await.is_ok());
    assert!(t.state.quotas.reserve(&a, 2_000).await.is_err());
    // Dropping without commit gives the bytes back.
    drop(held);
    assert_eq!(t.state.quotas.usage(&a).await, ua);
    assert!(t.state.quotas.reserve(&a, 9_000).await.is_ok());
}

#[tokio::test]
async fn forget_drops_the_cached_figure() {
    use personal_media::quota::Quotas;
    let (dir, u) = quota_dir(&[("blobs/a", 300)]);
    let q = Quotas::unlimited(dir.path().to_path_buf());
    assert_eq!(q.usage("u1").await, 300);
    std::fs::write(u.join("blobs/a"), vec![0u8; 900]).unwrap();
    assert_eq!(q.usage("u1").await, 300, "cached");
    q.forget("u1");
    assert_eq!(q.usage("u1").await, 900, "re-walked after forget");
}

#[tokio::test]
async fn stale_entry_is_rewalked_after_the_refresh_interval() {
    use personal_media::quota::Quotas;
    use std::time::Duration;
    let (dir, u) = quota_dir(&[("blobs/a", 300)]);
    let q = Quotas::unlimited_with_refresh(dir.path().to_path_buf(), Duration::from_millis(50));
    assert_eq!(q.usage("u1").await, 300);
    std::fs::write(u.join("blobs/a"), vec![0u8; 900]).unwrap();
    assert_eq!(q.usage("u1").await, 300, "still fresh");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(q.usage("u1").await, 900, "refreshed");
    // Never while an upload is in flight.
    let r = q.reserve("u1", 10).await.unwrap();
    std::fs::write(u.join("blobs/a"), vec![0u8; 1200]).unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(q.usage("u1").await, 910);
    drop(r);
}
