mod common;

use common::*;
use personal_media::user_db::{Channel, Level, document_overrides};
use personal_media::web::docs::content_disposition;

const PDF: &[u8] = include_bytes!("fixtures/text.pdf");

async fn upload(
    t: &TestApp,
    c: &Client,
    name: &str,
    mime: &str,
    bytes: &[u8],
    fields: &[(&str, &str)],
) -> serde_json::Value {
    let resp = t
        .post_multipart("/api/upload", fields, &[("file", name, mime, bytes)], c)
        .await;
    assert_eq!(resp.status(), 200, "upload {name}");
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

async fn upload_id(t: &TestApp, c: &Client, name: &str, mime: &str, bytes: &[u8]) -> String {
    let v = upload(t, c, name, mime, bytes, &[]).await;
    assert_eq!(v["status"], "stored");
    v["id"].as_str().unwrap().to_owned()
}

fn set_access(t: &TestApp, c: &Client, id: &str, level: Option<Level>) {
    let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
    u.with_db(|conn| {
        personal_media::user_db::set_document_access(conn, id, Channel::Web, level).unwrap()
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_list_detail_download_roundtrip() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let v = upload(
        &t,
        &c,
        "Rechnung.pdf",
        "application/pdf",
        PDF,
        &[
            ("title", "Meine Rechnung"),
            ("tags", " a , b,,"),
            ("date", "2024-03-01"),
        ],
    )
    .await;
    let id = v["id"].as_str().unwrap().to_owned();

    let list = body_string(t.get("/documents", &c).await).await;
    assert!(list.contains("Meine Rechnung"));
    assert!(list.contains(&format!("/documents/{id}")));

    let detail = t.get(&format!("/documents/{id}"), &c).await;
    assert_eq!(detail.status(), 200);
    let html = body_string(detail).await;
    assert!(html.contains(&format!(
        "<iframe class=\"preview\" src=\"/documents/{id}/raw\""
    )));
    assert!(html.contains("2024-03-01"));

    let raw = t.get(&format!("/documents/{id}/raw"), &c).await;
    assert_eq!(raw.status(), 200);
    assert_eq!(header_str(&raw, "content-type"), "application/pdf");
    assert!(header_str(&raw, "content-disposition").starts_with("inline;"));
    assert_eq!(header_str(&raw, "x-frame-options"), "SAMEORIGIN");
    assert_eq!(
        header_str(&raw, "content-security-policy"),
        "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; object-src 'self'; frame-ancestors 'self'"
    );
    assert_eq!(header_str(&raw, "content-length"), PDF.len().to_string());
    assert_eq!(body_bytes(raw).await, PDF);

    let dl = t.get(&format!("/documents/{id}/download"), &c).await;
    assert_eq!(dl.status(), 200);
    assert_eq!(header_str(&dl, "content-type"), "application/octet-stream");
    assert!(
        header_str(&dl, "content-disposition").starts_with("attachment; filename=\"Rechnung.pdf\"")
    );
    assert_eq!(body_bytes(dl).await, PDF);
}

#[tokio::test(flavor = "multi_thread")]
async fn search_partial_for_htmx() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    upload(
        &t,
        &c,
        "n.txt",
        "text/plain",
        b"Vertrag mit Inhalt",
        &[("title", "Notiz")],
    )
    .await;
    wait_extracted(&t, &c, "vertrag").await;
    let resp = t.hx_get("/documents?q=vertrag", &c).await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    assert!(!html.contains("<html"));
    assert!(html.contains("Notiz"));
    let full = body_string(t.get("/documents?q=vertrag", &c).await).await;
    assert!(full.contains("<html"));
    assert!(full.contains("hx-push-url=\"false\""));
}

async fn wait_extracted(t: &TestApp, c: &Client, q: &str) {
    for _ in 0..100 {
        let html = body_string(t.hx_get(&format!("/documents?q={q}"), c).await).await;
        if html.contains("doc-item") {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("text not indexed");
}

#[tokio::test(flavor = "multi_thread")]
async fn snippet_is_escaped() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    upload(
        &t,
        &c,
        "x.txt",
        "text/plain",
        b"<script>alert(1)</script> Vertrag",
        &[("title", "Plain")],
    )
    .await;
    wait_extracted(&t, &c, "vertrag").await;
    let html = body_string(t.hx_get("/documents?q=vertrag", &c).await).await;
    assert!(html.contains("&lt;script&gt;"), "{html}");
    assert!(html.contains("<mark>Vertrag</mark>"), "{html}");
    assert!(!html.contains("<script>"));
}

#[tokio::test(flavor = "multi_thread")]
async fn html_and_svg_uploads_are_never_inline() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    for (name, mime) in [("x.html", "text/html"), ("x.svg", "image/svg+xml")] {
        let body = format!("<svg onload=alert(1)> {name}");
        let id = upload_id(&t, &c, name, mime, body.as_bytes()).await;
        let raw = t.get(&format!("/documents/{id}/raw"), &c).await;
        assert_eq!(raw.status(), 303);
        assert_eq!(
            header_str(&raw, "location"),
            format!("/documents/{id}/download")
        );
        let dl = t.get(&format!("/documents/{id}/download"), &c).await;
        assert_eq!(header_str(&dl, "content-type"), "application/octet-stream");
        assert!(header_str(&dl, "content-disposition").starts_with("attachment"));
        let detail = body_string(t.get(&format!("/documents/{id}"), &c).await).await;
        assert!(!detail.contains("class=\"preview\""));
    }
}

#[test]
fn content_disposition_handles_hostile_names() {
    let long = "x".repeat(300);
    let long_ext = format!("{}.pdf", "y".repeat(300));
    for name in [
        "a\"b\r\nc.pdf",
        "Prüfung.pdf",
        "../../etc/passwd",
        &long,
        &long_ext,
        "a\\b.txt",
    ] {
        let v = content_disposition("attachment", name);
        let s = v.to_str().expect("header is visible ASCII");
        assert!(!s.contains('\r') && !s.contains('\n'));
        let rest = s.strip_prefix("attachment; filename=\"").unwrap();
        let (fallback, tail) = rest.split_once('"').unwrap();
        assert!(!fallback.contains('\\') && !fallback.contains('/'));
        assert!(fallback.is_ascii() && fallback.len() <= 150, "{fallback}");
        assert!(tail.starts_with("; filename*=UTF-8''"));
    }
    let s = content_disposition("attachment", &long_ext);
    assert!(s.to_str().unwrap().contains(".pdf\";"));
    let s = content_disposition("attachment", "Prüfung.pdf");
    let s = s.to_str().unwrap();
    assert!(s.contains("filename=\"Pr_fung.pdf\""));
    assert!(s.contains("Pr%C3%BCfung.pdf"));
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_too_large_413() {
    let t = TestApp::with_config(|cfg| cfg.max_upload_bytes = 1024);
    let c = t.session_for("alice");
    let resp = t
        .post_multipart(
            "/api/upload",
            &[],
            &[(
                "file",
                "big.bin",
                "application/octet-stream",
                &vec![7u8; 2048],
            )],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 413);
    let resp = t
        .post_multipart(
            "/api/upload",
            &[("date", "2024-13-45")],
            &[("file", "a.bin", "application/octet-stream", b"hi")],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 422);
    let resp = t
        .post_multipart("/api/upload", &[("title", "x")], &[], &c)
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_text_field_before_the_file_is_413() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let big = "x".repeat(8 * 1024 + 1);
    let resp = t
        .post_multipart(
            "/api/upload",
            &[("title", &big)],
            &[("file", "a.bin", "application/octet-stream", b"hi")],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 413);
    // 8 KiB passes the field cap but is over the 300-character title cap.
    let at_cap = "x".repeat(8 * 1024);
    let resp = t
        .post_multipart(
            "/api/upload",
            &[("title", &at_cap)],
            &[("file", "a.bin", "application/octet-stream", b"hi")],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 422);
    let ok = "x".repeat(300);
    let resp = t
        .post_multipart(
            "/api/upload",
            &[("title", &ok)],
            &[("file", "a.bin", "application/octet-stream", b"hi")],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn client_aborted_upload_is_400_not_500() {
    use axum::body::Body;
    use axum::http::{Method, header};
    let t = TestApp::new();
    let c = t.session_for("alice");
    // The body ends in the middle of the file part: no closing boundary.
    let body =
        "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.pdf\"\r\n\r\nPARTIAL";
    let req = builder(Method::POST, "/api/upload", &c)
        .header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", &c.csrf)
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=b")
        .body(Body::from(body))
        .unwrap();
    let resp = t.request(req).await;
    assert_eq!(resp.status(), 400);
    assert!(body_string(resp).await.contains("upload aborted"));
    let list = body_string(t.get("/documents", &c).await).await;
    assert!(list.contains("No documents yet."), "nothing was stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_upload_returns_duplicate_json() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = upload_id(&t, &c, "a.bin", "application/octet-stream", b"same").await;
    let v = upload(&t, &c, "b.bin", "application/octet-stream", b"same", &[]).await;
    assert_eq!(v["status"], "duplicate");
    assert_eq!(v["existing_id"], id);
    assert_eq!(v["existing_title"], "a");
    let v = upload(
        &t,
        &c,
        "b.bin",
        "application/octet-stream",
        b"same",
        &[("on_duplicate", "keep")],
    )
    .await;
    assert_eq!(v["status"], "stored");
    let kept = v["id"].as_str().unwrap().to_owned();
    // A hidden duplicate is stored as a new copy and not revealed.
    set_access(&t, &c, &id, Some(Level::Off));
    set_access(&t, &c, &kept, Some(Level::Off));
    let v = upload(&t, &c, "c.bin", "application/octet-stream", b"same", &[]).await;
    assert_eq!(v["status"], "stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_needs_csrf_header_and_session() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let mut no_csrf = c.clone();
    no_csrf.csrf.clear();
    let resp = t
        .post_multipart(
            "/api/upload",
            &[],
            &[("file", "a", "text/plain", b"x")],
            &no_csrf,
        )
        .await;
    assert_eq!(resp.status(), 403);
    let resp = t
        .post_multipart(
            "/api/upload",
            &[],
            &[("file", "a", "text/plain", b"x")],
            &Client::anon(),
        )
        .await;
    assert_ne!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn edit_tags_and_title() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = upload_id(&t, &c, "a.bin", "application/octet-stream", b"data").await;
    let resp = t
        .post_form(
            &format!("/documents/{id}"),
            &[
                ("title", "Neu"),
                ("date", "2023-05-06"),
                ("tags", " x, y ,,z "),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    let html = body_string(t.get(&format!("/documents/{id}"), &c).await).await;
    assert!(html.contains("<h1>Neu</h1>"));
    assert!(html.contains("2023-05-06"));
    assert!(html.contains("value=\"x, y, z\""));
    let resp = t
        .post_form(
            &format!("/documents/{id}"),
            &[("title", "Neu"), ("date", "bad"), ("tags", "")],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 422);
    let resp = t
        .post_form(
            &format!("/documents/{id}"),
            &[("title", "Neu"), ("date", ""), ("tags", "")],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    let html = body_string(t.get(&format!("/documents/{id}"), &c).await).await;
    assert!(!html.contains("2023-05-06"));
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_only_when_failed() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = upload_id(&t, &c, "a.bin", "application/octet-stream", b"data").await;
    let html = body_string(t.get(&format!("/documents/{id}"), &c).await).await;
    assert!(!html.contains("/retry"));
    let resp = t
        .post_form(&format!("/documents/{id}/retry"), &[], &c)
        .await;
    assert_eq!(resp.status(), 409);
    let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
    u.with_db(|conn| {
        personal_media::user_db::set_text(
            conn,
            &id,
            personal_media::user_db::TextStatus::Failed,
            None,
            None,
            1,
        )
        .unwrap()
    });
    let html = body_string(t.get(&format!("/documents/{id}"), &c).await).await;
    assert!(html.contains("/retry"));
    assert!(html.contains("Text extraction failed"));
    let resp = t
        .post_form(&format!("/documents/{id}/retry"), &[], &c)
        .await;
    assert_eq!(resp.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_requires_confirm() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = upload_id(&t, &c, "a.bin", "application/octet-stream", b"data").await;
    let resp = t
        .post_form(&format!("/documents/{id}/delete"), &[], &c)
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(t.get(&format!("/documents/{id}"), &c).await.status(), 200);
    let resp = t
        .post_form(&format!("/documents/{id}/delete"), &[("confirm", "on")], &c)
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(t.get(&format!("/documents/{id}"), &c).await.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn other_users_document_is_404() {
    let t = TestApp::new();
    let a = t.session_for("alice");
    let b = t.session_for("bob");
    let id = upload_id(&t, &a, "a.bin", "application/octet-stream", b"secret").await;
    for path in ["", "/raw", "/download"] {
        assert_eq!(
            t.get(&format!("/documents/{id}{path}"), &b).await.status(),
            404
        );
    }
    assert_eq!(
        t.post_form(&format!("/documents/{id}/delete"), &[("confirm", "on")], &b)
            .await
            .status(),
        404
    );
    assert_eq!(
        t.post_form(
            &format!("/documents/{id}/access"),
            &[("web", "full"), ("mcp", "full"), ("semantic_index", "full")],
            &b
        )
        .await
        .status(),
        404
    );
    assert_eq!(t.get(&format!("/documents/{id}"), &a).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn web_off_document_hidden_from_list_search_and_detail() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = upload(
        &t,
        &c,
        "geheim.txt",
        "text/plain",
        b"Vertrag",
        &[("title", "Geheimtitel")],
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    wait_extracted(&t, &c, "vertrag").await;
    set_access(&t, &c, &id, Some(Level::Off));
    assert!(
        !body_string(t.get("/documents", &c).await)
            .await
            .contains("Geheimtitel")
    );
    assert!(
        !body_string(t.get("/documents?q=vertrag", &c).await)
            .await
            .contains("Geheimtitel")
    );
    for path in ["", "/raw", "/download"] {
        assert_eq!(
            t.get(&format!("/documents/{id}{path}"), &c).await.status(),
            404
        );
    }
    for (path, fields) in [
        ("", vec![("title", "x"), ("date", ""), ("tags", "")]),
        ("/delete", vec![("confirm", "on")]),
        ("/retry", vec![]),
    ] {
        assert_eq!(
            t.post_form(&format!("/documents/{id}{path}"), &fields, &c)
                .await
                .status(),
            404
        );
    }
    // The owner can still un-hide it.
    let resp = t
        .post_form(
            &format!("/documents/{id}/access"),
            &[
                ("web", "default"),
                ("mcp", "default"),
                ("semantic_index", "default"),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert!(
        body_string(t.get("/documents", &c).await)
            .await
            .contains("Geheimtitel")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_level_detail_has_no_preview_or_download() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = upload_id(&t, &c, "a.pdf", "application/pdf", PDF).await;
    set_access(&t, &c, &id, Some(Level::Metadata));
    let resp = t.get(&format!("/documents/{id}"), &c).await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    assert!(html.contains("<h1>a</h1>"));
    assert!(!html.contains("<iframe") && !html.contains("<img"));
    assert!(!html.contains("/download") && !html.contains("/raw"));
    assert!(html.contains(&format!("action=\"/documents/{id}/delete\"")));
    assert!(html.contains(&format!("/documents/{id}/access")));
    assert_eq!(
        t.get(&format!("/documents/{id}/raw"), &c).await.status(),
        404
    );
    assert_eq!(
        t.get(&format!("/documents/{id}/download"), &c)
            .await
            .status(),
        404
    );
    assert!(
        body_string(t.get("/documents", &c).await)
            .await
            .contains("/documents/")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn access_override_form_roundtrip() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = upload_id(&t, &c, "a.bin", "application/octet-stream", b"data").await;
    let post = |web: &'static str, mcp: &'static str, sem: &'static str| {
        let (t, c, id) = (&t, &c, id.clone());
        async move {
            t.post_form(
                &format!("/documents/{id}/access"),
                &[("web", web), ("mcp", mcp), ("semantic_index", sem)],
                c,
            )
            .await
        }
    };
    let overrides = || {
        let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
        u.with_db(|conn| document_overrides(conn, &id).unwrap())
    };
    assert_eq!(post("full", "off", "metadata").await.status(), 303);
    let o = overrides();
    assert_eq!(o.get(&Channel::Web), Some(&Level::Full));
    assert_eq!(o.get(&Channel::Mcp), Some(&Level::Off));
    assert_eq!(o.get(&Channel::SemanticIndex), Some(&Level::Metadata));
    let html = body_string(t.get(&format!("/documents/{id}"), &c).await).await;
    assert!(html.contains("<option value=\"off\" selected>"));
    assert_eq!(post("default", "default", "metadata").await.status(), 303);
    let o = overrides();
    assert_eq!(o.len(), 1);
    assert_eq!(o.get(&Channel::SemanticIndex), Some(&Level::Metadata));
    assert_eq!(post("bogus", "default", "default").await.status(), 422);
    // Setting web to off sends the owner back to the list.
    let resp = post("off", "default", "default").await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/documents");
}

#[tokio::test(flavor = "multi_thread")]
async fn pagination_links() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    for i in 0..51 {
        upload_id(
            &t,
            &c,
            "f.bin",
            "application/octet-stream",
            format!("doc {i}").as_bytes(),
        )
        .await;
    }
    let html = body_string(t.get("/documents", &c).await).await;
    assert!(html.contains("rel=\"next\""));
    assert!(!html.contains("rel=\"prev\""));
    // Live pager: htmx swap without touching the address bar, plain href as fallback.
    assert!(html.contains(
        "href=\"/documents?page=2\" rel=\"next\" hx-get=\"/documents?page=2\" hx-target=\"#results\" hx-push-url=\"false\""
    ));
    let html = body_string(t.get("/documents?page=2", &c).await).await;
    assert!(html.contains("rel=\"prev\""));
    assert!(!html.contains("rel=\"next\""));
    assert_eq!(html.matches("doc-item").count(), 1);
}

fn have_tesseract() -> bool {
    std::process::Command::new("which")
        .arg("tesseract")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_ocr_search() {
    if !have_tesseract() {
        println!("SKIP");
        return;
    }
    let t = TestApp::new();
    let c = t.session_for("alice");
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/scanned.pdf"
    ))
    .unwrap();
    upload_id(&t, &c, "scanned.pdf", "application/pdf", &bytes).await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let html = body_string(t.hx_get("/documents?q=versicherungsnummer", &c).await).await;
        if html.contains("doc-item") {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "OCR text never became searchable"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn web_input_caps_are_422() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let up = |fields: Vec<(&'static str, String)>, name: String| {
        let (t, c) = (&t, &c);
        async move {
            let f: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
            t.post_multipart(
                "/api/upload",
                &f,
                &[("file", &name, "application/octet-stream", b"hi")],
                c,
            )
            .await
            .status()
        }
    };
    assert_eq!(
        up(vec![("title", "t".repeat(301))], "a.bin".into()).await,
        422
    );
    assert_eq!(up(vec![], "f".repeat(256)).await, 422);
    let many = (0..51)
        .map(|i| format!("t{i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(up(vec![("tags", many)], "a.bin".into()).await, 422);
    assert_eq!(
        up(vec![("tags", "x".repeat(65))], "a.bin".into()).await,
        422
    );
    // The limits themselves are fine.
    let fifty = (0..50)
        .map(|i| format!("t{i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        up(
            vec![("title", "t".repeat(300)), ("tags", fifty)],
            "g".repeat(255)
        )
        .await,
        200
    );

    let id = upload_id(&t, &c, "b.bin", "application/octet-stream", b"data2").await;
    let edit = |title: String, tags: String| {
        let (t, c, id) = (&t, &c, &id);
        async move {
            t.post_form(
                &format!("/documents/{id}"),
                &[("title", &title), ("date", ""), ("tags", &tags)],
                c,
            )
            .await
            .status()
        }
    };
    assert_eq!(edit("t".repeat(301), String::new()).await, 422);
    let many = (0..51)
        .map(|i| format!("t{i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(edit("ok".into(), many).await, 422);
    assert_eq!(edit("ok".into(), "x".repeat(65)).await, 422);
    assert_eq!(edit("t".repeat(300), "x".repeat(64)).await, 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn notes_edit_roundtrip_web() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let id = upload_id(&t, &c, "hand.bin", "application/octet-stream", b"data").await;
    let path = format!("/documents/{id}");

    let resp = t
        .post_form(
            &path,
            &[
                ("title", "Handwritten"),
                ("date", ""),
                ("tags", "a"),
                ("notes", "  tiramisu <b>recipe</b> "),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);

    let html = body_string(t.get(&path, &c).await).await;
    assert!(
        html.contains("tiramisu &#60;b&#62;recipe&#60;/b&#62;"),
        "{html}"
    );
    assert!(!html.contains("<b>recipe"));
    assert!(html.contains("<textarea id=\"notes\""));
    assert!(html.contains("recognised by OCR") || html.contains("Text"));

    // Searchable like the title.
    let list = body_string(t.get("/documents?q=tiramisu", &c).await).await;
    assert!(list.contains("Handwritten"), "{list}");

    // Cleared again.
    let resp = t
        .post_form(
            &path,
            &[
                ("title", "Handwritten"),
                ("date", ""),
                ("tags", "a"),
                ("notes", ""),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    let list = body_string(t.get("/documents?q=tiramisu", &c).await).await;
    assert!(!list.contains("Handwritten"));

    // Over the cap.
    let resp = t
        .post_form(&path, &[("title", "x"), ("notes", &"a".repeat(2001))], &c)
        .await;
    assert_eq!(resp.status(), 422);

    // The transcription badge.
    let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
    u.with_db(|conn| personal_media::user_db::set_transcription(conn, &id, "hi", 1_700_000_000))
        .unwrap();
    let html = body_string(t.get(&path, &c).await).await;
    assert!(html.contains("transcribed by an AI assistant"), "{html}");
}

/// Whether the "Needs transcription" checkbox is rendered checked.
fn checkbox_checked(html: &str) -> bool {
    let at = html.find("name=\"needs_transcription\"").expect("checkbox");
    let end = html[at..].find('>').unwrap();
    html[at..at + end].contains(" checked")
}

#[tokio::test]
async fn needs_transcription_filter_and_pagination_url() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let hw = upload(
        &t,
        &c,
        "a.bin",
        "application/octet-stream",
        b"hand",
        &[("tags", "handwritten")],
    )
    .await;
    upload_id(&t, &c, "b.bin", "application/octet-stream", b"other").await;
    let hw_id = hw["id"].as_str().unwrap();

    let html = body_string(t.get("/documents?needs_transcription=1", &c).await).await;
    assert_eq!(html.matches("doc-item").count(), 1, "{html}");
    assert!(checkbox_checked(&html));
    let all = body_string(t.get("/documents", &c).await).await;
    assert_eq!(all.matches("doc-item").count(), 2);
    assert!(!checkbox_checked(&all));

    let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
    u.with_db(|conn| personal_media::user_db::set_transcription(conn, hw_id, "text", 5))
        .unwrap();
    let html = body_string(t.get("/documents?needs_transcription=1", &c).await).await;
    assert_eq!(html.matches("doc-item").count(), 0);
}

#[tokio::test]
async fn needs_transcription_kept_in_pagination() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    for i in 0..51 {
        upload(
            &t,
            &c,
            "f.bin",
            "application/octet-stream",
            format!("hw {i}").as_bytes(),
            &[("tags", "handwritten")],
        )
        .await;
        upload_id(
            &t,
            &c,
            "g.bin",
            "application/octet-stream",
            format!("plain {i}").as_bytes(),
        )
        .await;
    }
    let html = body_string(t.get("/documents?needs_transcription=1", &c).await).await;
    assert_eq!(html.matches("doc-item").count(), 50);
    assert!(
        html.contains("href=\"/documents?needs_transcription=1&#38;page=2\""),
        "{html}"
    );
    // Page 2 holds the one remaining handwritten document, not plain ones.
    let html = body_string(t.get("/documents?needs_transcription=1&page=2", &c).await).await;
    assert_eq!(html.matches("doc-item").count(), 1);
    assert!(!html.contains("rel=\"next\""));
    // Any other value is off and not forwarded.
    let html = body_string(t.get("/documents?needs_transcription=yes", &c).await).await;
    assert!(!checkbox_checked(&html));
    assert!(html.contains("href=\"/documents?page=2\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn needs_transcription_with_words_search() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    upload(
        &t,
        &c,
        "hw.txt",
        "text/plain",
        b"zebra stripes",
        &[("tags", "handwritten")],
    )
    .await;
    upload_id(&t, &c, "plain.txt", "text/plain", b"zebra herd").await;
    wait_extracted(&t, &c, "herd").await;
    wait_extracted(&t, &c, "stripes").await;
    let both = body_string(t.get("/documents?q=zebra", &c).await).await;
    assert_eq!(both.matches("doc-item").count(), 2, "{both}");
    let one = body_string(t.get("/documents?q=zebra&needs_transcription=1", &c).await).await;
    assert_eq!(one.matches("doc-item").count(), 1, "{one}");
    assert!(one.contains(">handwritten<"));
    assert!(!one.contains("herd"));
}
