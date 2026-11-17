mod common;

use std::io::Read;

use common::*;
use personal_media::system_db::SYSTEM_DB_FILE;
use personal_media::user_db::{
    Access, Channel, Content, Level, TokenScope, get_access_defaults, get_token_meta,
    list_token_meta, set_document_access,
};

const PDF: &[u8] = include_bytes!("fixtures/text.pdf");

fn totp_code(secret_b32: &str) -> String {
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(totp_rs::Secret::try_from_base32(secret_b32).unwrap())
        .build()
        .unwrap()
        .generate_current()
        .to_string()
}

async fn upload_named(t: &TestApp, c: &Client, name: &str, bytes: &[u8], title: &str) -> String {
    let resp = t
        .post_multipart(
            "/api/upload",
            &[("title", title)],
            &[("file", name, "application/pdf", bytes)],
            c,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    v["id"].as_str().unwrap().to_owned()
}

fn unlocked(t: &TestApp, c: &Client) -> std::sync::Arc<personal_media::keyring::Unlocked> {
    t.state.sessions.get(&c.cookie).unwrap().unlocked
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_page_needs_login_and_lists_sections() {
    let t = TestApp::new();
    let anon = t.get("/settings", &Client::anon()).await;
    assert_eq!(anon.status(), 303);
    let c = t.session_for("alice");
    let resp = t.get("/settings", &c).await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    let positions: Vec<usize> = [
        "Access defaults",
        "Hidden from web",
        "Tokens",
        "Two-factor",
        "Password",
        "Recovery key",
        "Export",
    ]
    .iter()
    .map(|h| {
        html.find(&format!("<h2>{h}"))
            .unwrap_or_else(|| panic!("{h}"))
    })
    .collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]));
    assert!(html.contains(
        "Changing your password does not protect against someone who already copied a backup of the server."
    ));
    assert!(html.contains("Per-document settings on a document's page override these defaults."));
}

#[tokio::test(flavor = "multi_thread")]
async fn change_password_flow() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let other = {
        let row = t.state.sys.user_by_name("alice").unwrap().unwrap();
        let (cookie, csrf) = t.state.sessions.create(&row, unlocked(&t, &c), None);
        Client { cookie, csrf }
    };
    let new = "a brand new password";

    let wrong = t
        .post_form(
            "/settings/password",
            &[
                ("current", "nope nope nope"),
                ("new", new),
                ("new_confirm", new),
            ],
            &c,
        )
        .await;
    assert_eq!(wrong.status(), 401);
    assert!(
        body_string(wrong)
            .await
            .contains("The current password is wrong")
    );

    let mismatch = t
        .post_form(
            "/settings/password",
            &[
                ("current", PASSWORD),
                ("new", new),
                ("new_confirm", "different one"),
            ],
            &c,
        )
        .await;
    assert_eq!(mismatch.status(), 400);

    let weak = t
        .post_form(
            "/settings/password",
            &[
                ("current", PASSWORD),
                ("new", "short"),
                ("new_confirm", "short"),
            ],
            &c,
        )
        .await;
    assert_eq!(weak.status(), 400);

    let ok = t
        .post_form(
            "/settings/password",
            &[("current", PASSWORD), ("new", new), ("new_confirm", new)],
            &c,
        )
        .await;
    assert_eq!(ok.status(), 303);
    assert_eq!(header_str(&ok, "location"), "/settings?notice=password");

    assert!(t.state.accounts.login("alice", new, None).is_ok());
    assert!(t.state.accounts.login("alice", PASSWORD, None).is_err());
    // This browser stays logged in, the other one does not.
    assert_eq!(t.get("/settings", &c).await.status(), 200);
    assert_eq!(t.get("/settings", &other).await.status(), 303);
    let page = body_string(t.get("/settings?notice=password", &c).await).await;
    assert!(page.contains("Password changed."));
    assert!(page.contains("Existing MCP tokens keep working; revoke them in Settings if needed."));
}

#[tokio::test(flavor = "multi_thread")]
async fn password_forms_need_csrf() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let resp = t
        .post_form_raw(
            "/settings/password",
            &[
                ("current", PASSWORD),
                ("new", "another password"),
                ("new_confirm", "another password"),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 403);
    assert!(t.state.accounts.login("alice", PASSWORD, None).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn regenerate_recovery_requires_password_and_confirmation() {
    let t = TestApp::new();
    let c = t.pending_session_for("alice");
    let old_key = t
        .state
        .sessions
        .get(&c.cookie)
        .unwrap()
        .must_confirm_recovery
        .unwrap()
        .to_display();
    t.state.sessions.confirm_recovery(&c.cookie);

    let wrong = t
        .post_form(
            "/settings/recovery",
            &[("password", "wrong wrong wrong")],
            &c,
        )
        .await;
    assert_eq!(wrong.status(), 401);
    assert!(
        t.state
            .sessions
            .get(&c.cookie)
            .unwrap()
            .must_confirm_recovery
            .is_none()
    );

    let ok = t
        .post_form("/settings/recovery", &[("password", PASSWORD)], &c)
        .await;
    assert_eq!(ok.status(), 303);
    assert_eq!(header_str(&ok, "location"), "/recovery-key");

    // Until it is confirmed the session only reaches the recovery key page.
    assert_eq!(t.get("/settings", &c).await.status(), 303);
    let page = body_string(t.get("/recovery-key", &c).await).await;
    let new_key = t
        .state
        .sessions
        .get(&c.cookie)
        .unwrap()
        .must_confirm_recovery
        .unwrap()
        .to_display();
    assert_ne!(new_key, old_key);
    assert!(page.contains(&new_key));
    let confirm = t.post_form("/recovery-key", &[("saved", "on")], &c).await;
    assert_eq!(confirm.status(), 303);
    assert_eq!(t.get("/settings", &c).await.status(), 200);

    // The old key is dead, the new one works.
    assert!(
        t.state
            .accounts
            .recover("alice", &old_key, "some other password")
            .is_err()
    );
    assert!(
        t.state
            .accounts
            .recover("alice", &new_key, "some other password")
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn totp_enable_disable() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let uid = t.state.sessions.get(&c.cookie).unwrap().user_id;

    // Enabling without starting the setup fails.
    let early = t
        .post_form(
            "/settings/totp/enable",
            &[("code", "123456"), ("password", PASSWORD)],
            &c,
        )
        .await;
    assert_eq!(early.status(), 400);

    let begin = t.post_form("/settings/totp/begin", &[], &c).await;
    assert_eq!(begin.status(), 200);
    let html = body_string(begin).await;
    assert!(html.contains("<img src=\"data:image/png;base64,iVBORw0KGgo"));
    let secret = t
        .state
        .sessions
        .get(&c.cookie)
        .unwrap()
        .pending_totp_secret
        .unwrap()
        .to_string();
    assert!(html.contains(&secret));

    // A right code with the wrong password is refused, the setup stays on screen.
    let wrong_pw = t
        .post_form(
            "/settings/totp/enable",
            &[
                ("code", &totp_code(&secret)),
                ("password", "not the password"),
            ],
            &c,
        )
        .await;
    assert_eq!(wrong_pw.status(), 401);
    let wrong_pw_html = body_string(wrong_pw).await;
    assert!(wrong_pw_html.contains("The password is wrong"));
    assert!(wrong_pw_html.contains(&secret));
    assert!(!t.state.accounts.totp_enabled(&uid));
    // No password at all is the same.
    let none = t
        .post_form(
            "/settings/totp/enable",
            &[("code", &totp_code(&secret))],
            &c,
        )
        .await;
    assert_eq!(none.status(), 401);

    let bad = t
        .post_form(
            "/settings/totp/enable",
            &[("code", "000000"), ("password", PASSWORD)],
            &c,
        )
        .await;
    assert_eq!(bad.status(), 401);
    let bad_html = body_string(bad).await;
    assert!(bad_html.contains(&secret), "same secret stays on screen");
    assert!(bad_html.contains("data:image/png;base64,"));
    assert!(!t.state.accounts.totp_enabled(&uid));

    let ok = t
        .post_form(
            "/settings/totp/enable",
            &[("code", &totp_code(&secret)), ("password", PASSWORD)],
            &c,
        )
        .await;
    assert_eq!(ok.status(), 303);
    assert!(t.state.accounts.totp_enabled(&uid));
    assert!(
        t.state
            .sessions
            .get(&c.cookie)
            .unwrap()
            .pending_totp_secret
            .is_none()
    );
    // Login now needs a code.
    assert!(t.state.accounts.login("alice", PASSWORD, None).is_err());

    let again = t.post_form("/settings/totp/begin", &[], &c).await;
    assert_eq!(again.status(), 409);

    let bad_off = t
        .post_form("/settings/totp/disable", &[("code", "000000")], &c)
        .await;
    assert_eq!(bad_off.status(), 401);
    assert!(t.state.accounts.totp_enabled(&uid));
    let off = t
        .post_form(
            "/settings/totp/disable",
            &[("code", &totp_code(&secret))],
            &c,
        )
        .await;
    assert_eq!(off.status(), 303);
    assert!(!t.state.accounts.totp_enabled(&uid));
}

#[tokio::test(flavor = "multi_thread")]
async fn create_token_shows_once_and_lists_without_secret() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    upload_named(&t, &c, "a.pdf", PDF, "Doc").await;
    let tag_resp = t
        .post_multipart(
            "/api/upload",
            &[("tags", "medical")],
            &[("file", "b.pdf", "application/pdf", b"%PDF-1.4 other")],
            &c,
        )
        .await;
    assert_eq!(tag_resp.status(), 200);
    let tag_id = u.with_db(|conn| personal_media::user_db::list_tags(conn).unwrap())[0].0;

    let resp = t
        .post_form(
            "/settings/tokens",
            &[
                ("name", "Hermes"),
                ("access", "read_write"),
                ("content", "full_text"),
                ("tags[]", &tag_id.to_string()),
                ("password", PASSWORD),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header_str(&resp, "cache-control"), "no-store");
    let html = body_string(resp).await;
    let token = html
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .find(|w| w.starts_with("pm_"))
        .expect("token shown")
        .to_owned();
    let parts: Vec<&str> = token.split('_').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[1].len(), 32);
    assert_eq!(parts[2].len(), 64);
    assert!(
        token[3..]
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    );
    assert!(html.contains("mcp_servers:"));
    assert!(html.contains("https://test.example/mcp"));
    assert!(html.contains(&format!("Bearer {token}")));

    let metas = u.with_db(|conn| list_token_meta(conn).unwrap());
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].name, "Hermes");
    assert_eq!(
        metas[0].scope,
        TokenScope {
            access: Access::ReadWrite,
            content: Content::FullText,
            tags: Some(vec![tag_id]),
        }
    );
    assert_eq!(
        t.state.sys.token_ids_for_user(&u.user_id).unwrap(),
        vec![parts[1].to_owned()]
    );

    let settings = body_string(t.get("/settings", &c).await).await;
    assert!(settings.contains("Hermes"));
    assert!(settings.contains("tags: medical"));
    assert!(!settings.contains(parts[2]), "secret is never shown again");
    assert!(!settings.contains(&token));
}

#[tokio::test(flavor = "multi_thread")]
async fn create_token_validates_input_and_defaults_to_least_access() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    for fields in [
        vec![("name", "")],
        vec![("name", "   ")],
        vec![("name", "x"), ("access", "root")],
        vec![("name", "x"), ("content", "everything")],
        vec![("name", "x"), ("tags[]", "999")],
        vec![("name", "x"), ("tags[]", "abc")],
    ] {
        let mut fields = fields;
        fields.push(("password", PASSWORD));
        let resp = t.post_form("/settings/tokens", &fields, &c).await;
        assert_eq!(resp.status(), 400, "{fields:?}");
    }
    let long = "n".repeat(101);
    let resp = t
        .post_form(
            "/settings/tokens",
            &[("name", &long), ("password", PASSWORD)],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert!(u.with_db(|conn| list_token_meta(conn).unwrap()).is_empty());
    assert!(
        t.state
            .sys
            .token_ids_for_user(&u.user_id)
            .unwrap()
            .is_empty()
    );

    let ok = t
        .post_form(
            "/settings/tokens",
            &[("name", "plain"), ("password", PASSWORD)],
            &c,
        )
        .await;
    assert_eq!(ok.status(), 200);
    let metas = u.with_db(|conn| list_token_meta(conn).unwrap());
    assert_eq!(
        metas[0].scope,
        TokenScope {
            access: Access::Read,
            content: Content::MetadataOnly,
            tags: None
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_token_removes_rows() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let bob = t.session_for("bob");
    let u = unlocked(&t, &c);
    t.post_form(
        "/settings/tokens",
        &[("name", "one"), ("password", PASSWORD)],
        &c,
    )
    .await;
    let id = u.with_db(|conn| list_token_meta(conn).unwrap())[0]
        .id
        .clone();

    // Another user cannot revoke it.
    let denied = t
        .post_form(&format!("/settings/tokens/{id}/revoke"), &[], &bob)
        .await;
    assert_eq!(denied.status(), 404);
    assert_eq!(t.state.sys.token_ids_for_user(&u.user_id).unwrap().len(), 1);

    let resp = t
        .post_form(&format!("/settings/tokens/{id}/revoke"), &[], &c)
        .await;
    assert_eq!(resp.status(), 303);
    assert!(
        t.state
            .sys
            .token_ids_for_user(&u.user_id)
            .unwrap()
            .is_empty()
    );
    assert!(u.with_db(|conn| list_token_meta(conn).unwrap()).is_empty());
    let again = t
        .post_form(&format!("/settings/tokens/{id}/revoke"), &[], &c)
        .await;
    assert_eq!(again.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn token_rows_have_no_plaintext_name_in_system_db() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let resp = t
        .post_form(
            "/settings/tokens",
            &[("name", "HermesMedical"), ("password", PASSWORD)],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let uid = t.state.sessions.get(&c.cookie).unwrap().user_id;
    assert_eq!(t.state.sys.token_ids_for_user(&uid).unwrap().len(), 1);
    // Include the WAL, where recent writes may still live.
    for suffix in ["", "-wal"] {
        let path = t.dir.path().join(format!("{SYSTEM_DB_FILE}{suffix}"));
        if let Ok(bytes) = std::fs::read(path) {
            assert!(!bytes.windows(13).any(|w| w == b"HermesMedical"));
        }
    }
}

async fn export(t: &TestApp, c: &Client) -> axum::response::Response {
    t.post_form("/settings/export", &[("password", PASSWORD)], c)
        .await
}

fn entry_names(zip: &zip::ZipArchive<std::io::Cursor<Vec<u8>>>) -> Vec<String> {
    let mut names: Vec<String> = zip
        .file_names()
        .map(|n| n.expect("valid entry name").into_owned())
        .collect();
    names.sort();
    names
}

fn read_zip(bytes: Vec<u8>) -> zip::ZipArchive<std::io::Cursor<Vec<u8>>> {
    zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn export_zip_contains_all_files_and_metadata() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let other = t.session_for("bob");
    let a = upload_named(&t, &c, "Rechnung März.pdf", PDF, "Rechnung").await;
    let resp = t
        .post_multipart(
            "/api/upload",
            &[("title", "Notiz"), ("tags", "x, y"), ("date", "2024-05-06")],
            &[("file", "notiz.txt", "text/plain", "Grüße".as_bytes())],
            &c,
        )
        .await;
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let b = v["id"].as_str().unwrap().to_owned();
    upload_named(&t, &other, "bobs.pdf", PDF, "Bobs").await;
    // A document hidden from the web is part of the export.
    unlocked(&t, &c)
        .with_db(|conn| set_document_access(conn, &b, Channel::Web, Some(Level::Off)).unwrap());

    let resp = export(&t, &c).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header_str(&resp, "content-type"), "application/zip");
    assert_eq!(
        header_str(&resp, "content-disposition"),
        "attachment; filename=\"personal-media-export.zip\""
    );
    let mut zip = read_zip(body_bytes(resp).await);
    let names = entry_names(&zip);
    assert_eq!(
        names,
        [
            "files/Rechnung März.pdf",
            "files/notiz.txt",
            "metadata.json"
        ]
    );
    for i in 0..zip.len() {
        assert_eq!(
            zip.by_index(i).unwrap().compression(),
            zip::CompressionMethod::Stored
        );
    }
    let mut pdf = Vec::new();
    zip.by_name("files/Rechnung März.pdf")
        .unwrap()
        .read_to_end(&mut pdf)
        .unwrap();
    assert_eq!(pdf, PDF);
    let mut txt = String::new();
    zip.by_name("files/notiz.txt")
        .unwrap()
        .read_to_string(&mut txt)
        .unwrap();
    assert_eq!(txt, "Grüße");

    let mut meta = String::new();
    zip.by_name("metadata.json")
        .unwrap()
        .read_to_string(&mut meta)
        .unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta).unwrap();
    let meta = meta.as_array().unwrap();
    assert_eq!(meta.len(), 2);
    let find = |id: &str| meta.iter().find(|m| m["id"] == id).unwrap();
    let ma = find(&a);
    assert_eq!(ma["title"], "Rechnung");
    assert_eq!(ma["original_filename"], "Rechnung März.pdf");
    assert_eq!(ma["zip_path"], "files/Rechnung März.pdf");
    assert_eq!(ma["mime"], "application/pdf");
    assert!(ma["document_date"].is_null());
    assert!(ma["created_at"].is_i64());
    let mb = find(&b);
    assert_eq!(mb["document_date"], "2024-05-06");
    assert_eq!(mb["tags"], serde_json::json!(["x", "y"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn export_zip_entry_names_are_safe_and_unique() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    upload_named(&t, &c, "../a.pdf", PDF, "first").await;
    upload_named(&t, &c, "a.pdf", b"%PDF-1.4 second", "second").await;
    let resp = export(&t, &c).await;
    let zip = read_zip(body_bytes(resp).await);
    let names = entry_names(&zip);
    assert_eq!(names, ["files/a (2).pdf", "files/a.pdf", "metadata.json"]);
    assert!(
        names
            .iter()
            .all(|n| !n.contains("..") && !n.starts_with('/'))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn export_of_empty_vault_is_a_valid_zip() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let zip = read_zip(body_bytes(export(&t, &c).await).await);
    assert_eq!(entry_names(&zip), ["metadata.json"]);
    assert_eq!(export(&t, &Client::anon()).await.status(), 303);
}

#[tokio::test(flavor = "multi_thread")]
async fn export_requires_the_account_password() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    upload_named(&t, &c, "a.pdf", PDF, "Doc").await;
    // The old GET download is gone.
    assert_eq!(t.get("/settings/export.zip", &c).await.status(), 404);
    for fields in [
        vec![("password", "not the password")],
        vec![("password", "")],
    ] {
        let resp = t.post_form("/settings/export", &fields, &c).await;
        assert_eq!(resp.status(), 401, "{fields:?}");
        assert_ne!(
            resp.headers().get("content-type").map(|v| v.as_bytes()),
            Some(&b"application/zip"[..])
        );
    }
    let ok = t
        .post_form("/settings/export", &[("password", PASSWORD)], &c)
        .await;
    assert_eq!(ok.status(), 200);
    assert_eq!(header_str(&ok, "content-type"), "application/zip");
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(html.contains("Exports include every document, also those hidden from the web."));
}

#[tokio::test(flavor = "multi_thread")]
async fn token_and_totp_enrolment_require_the_password() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    for fields in [
        vec![("name", "x"), ("password", "wrong wrong wrong")],
        vec![("name", "x")],
    ] {
        let resp = t.post_form("/settings/tokens", &fields, &c).await;
        assert_eq!(resp.status(), 401, "{fields:?}");
        assert!(body_string(resp).await.contains("The password is wrong"));
    }
    assert!(u.with_db(|conn| list_token_meta(conn).unwrap()).is_empty());
    assert!(
        t.state
            .sys
            .token_ids_for_user(&u.user_id)
            .unwrap()
            .is_empty()
    );
    let ok = t
        .post_form(
            "/settings/tokens",
            &[("name", "x"), ("password", PASSWORD)],
            &c,
        )
        .await;
    assert_eq!(ok.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn token_form_lists_only_tags_on_documents() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    t.post_multipart(
        "/api/upload",
        &[("tags", "visible-tag")],
        &[("file", "a.pdf", "application/pdf", PDF)],
        &c,
    )
    .await;
    let hidden = t
        .post_multipart(
            "/api/upload",
            &[("tags", "hidden-only")],
            &[("file", "b.pdf", "application/pdf", b"%PDF-1.4 b")],
            &c,
        )
        .await;
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(hidden).await).unwrap();
    let hidden_id = v["id"].as_str().unwrap().to_owned();
    u.with_db(|conn| {
        set_document_access(conn, &hidden_id, Channel::Web, Some(Level::Off)).unwrap();
        // An orphan tag: it exists but no document carries it.
        let orphan = personal_media::user_db::tag_ids(conn, &["orphan".to_owned()]).unwrap();
        assert_eq!(orphan.len(), 1);
    });
    let html = body_string(t.get("/settings", &c).await).await;
    let form = &html[html.find("New token").unwrap()..];
    assert!(form.contains("visible-tag"));
    assert!(!form.contains("orphan"), "orphan tags are not offered");
    // Tags on web-hidden documents are still attached to a document.
    assert!(form.contains("hidden-only"));
}

#[tokio::test(flavor = "multi_thread")]
async fn access_defaults_form_roundtrip() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let resp = t
        .post_form(
            "/settings/access",
            &[
                ("web", "metadata"),
                ("mcp", "full"),
                ("semantic_index", "off"),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    let d = u.with_db(|conn| get_access_defaults(conn).unwrap());
    assert_eq!(d.level(Channel::Web), Level::Metadata);
    // Ruling AJ: a posted mcp field is accepted but ignored; the stored value is untouched.
    assert_eq!(d.level(Channel::Mcp), Level::Metadata);
    assert_eq!(d.level(Channel::SemanticIndex), Level::Off);

    let html = body_string(t.get("/settings", &c).await).await;
    assert!(html.contains("<option value=\"metadata\" selected>"));
    assert!(html.contains("<option value=\"off\" selected>"));

    let bad = t
        .post_form(
            "/settings/access",
            &[
                ("web", "everything"),
                ("mcp", "full"),
                ("semantic_index", "off"),
            ],
            &c,
        )
        .await;
    assert_eq!(bad.status(), 422);
    assert_eq!(
        u.with_db(|conn| get_access_defaults(conn).unwrap())
            .level(Channel::Web),
        Level::Metadata
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hidden_documents_listed_and_can_be_unhidden() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let shown = upload_named(&t, &c, "s.pdf", PDF, "Visible one").await;
    let hidden = upload_named(&t, &c, "h.pdf", b"%PDF-1.4 h", "Secret one").await;
    u.with_db(|conn| {
        set_document_access(conn, &hidden, Channel::Web, Some(Level::Off)).unwrap();
        set_document_access(conn, &hidden, Channel::Mcp, Some(Level::Full)).unwrap();
    });
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(html.contains("Secret one"));
    assert!(!html.contains("Visible one"));
    assert!(html.contains(&format!("action=\"/documents/{hidden}/access\"")));
    assert!(!html.contains(&format!("/documents/{shown}/access")));
    assert_eq!(
        t.get(&format!("/documents/{hidden}"), &c).await.status(),
        404
    );

    // The button's form posts web=default and keeps the other overrides.
    let resp = t
        .post_form(
            &format!("/documents/{hidden}/access"),
            &[
                ("web", "default"),
                ("mcp", "full"),
                ("semantic_index", "default"),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(
        t.get(&format!("/documents/{hidden}"), &c).await.status(),
        200
    );
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(!html.contains("Secret one"));
    assert!(html.contains("No documents are hidden"));
    let over =
        u.with_db(|conn| personal_media::user_db::document_overrides(conn, &hidden).unwrap());
    assert_eq!(over.get(&Channel::Mcp), Some(&Level::Full));
    assert_eq!(over.get(&Channel::Web), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn hidden_by_default_posts_full_and_preserves_other_overrides() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let id = upload_named(&t, &c, "h.pdf", PDF, "Hidden by default").await;
    u.with_db(|conn| {
        personal_media::user_db::set_access_defaults(
            conn,
            &personal_media::user_db::AccessDefaults(
                [
                    (Channel::Web, Level::Off),
                    (Channel::Mcp, Level::Metadata),
                    (Channel::SemanticIndex, Level::Off),
                ]
                .into(),
            ),
        )
        .unwrap();
        set_document_access(conn, &id, Channel::Mcp, Some(Level::Off)).unwrap();
    });
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(html.contains("Hidden by default"));
    assert!(html.contains("<input type=\"hidden\" name=\"web\" value=\"full\">"));
    assert!(html.contains("<input type=\"hidden\" name=\"mcp\" value=\"off\">"));
    assert!(html.contains("<input type=\"hidden\" name=\"semantic_index\" value=\"default\">"));
}

#[tokio::test(flavor = "multi_thread")]
async fn token_form_new_restricted_tag() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);

    // The input is offered even when the user has no tags at all.
    let html = body_string(t.get("/settings", &c).await).await;
    let form = &html[html.find("New token").unwrap()..];
    assert!(form.contains("Restrict to a new tag"), "{form}");
    assert!(form.contains("name=\"new_tag\""));

    // A new tag creates the tag and restricts the token to it.
    let resp = t
        .post_form(
            "/settings/tokens",
            &[
                ("name", "iPhone share"),
                ("access", "read_write"),
                ("content", "metadata_only"),
                ("new_tag", "  Inbox "),
                ("password", PASSWORD),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let tags = u.with_db(|conn| personal_media::user_db::list_tags(conn).unwrap());
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].1, "Inbox", "trimmed, case kept like any tag");
    let metas = u.with_db(|conn| list_token_meta(conn).unwrap());
    assert_eq!(metas[0].scope.tags, Some(vec![tags[0].0]));
    assert_eq!(metas[0].scope.access, Access::ReadWrite);
    let settings = body_string(t.get("/settings", &c).await).await;
    assert!(settings.contains("tags: Inbox"), "restriction is visible");

    // Combined with a ticked existing tag: both are on the allow-list.
    upload_named(&t, &c, "a.pdf", PDF, "Doc").await;
    t.post_multipart(
        "/api/upload",
        &[("tags", "medical")],
        &[("file", "b.pdf", "application/pdf", b"%PDF-1.4 other")],
        &c,
    )
    .await;
    let medical = u
        .with_db(|conn| personal_media::user_db::list_tags(conn).unwrap())
        .into_iter()
        .find(|(_, n)| n == "medical")
        .unwrap()
        .0;
    let id = medical.to_string();
    let resp = t
        .post_form(
            "/settings/tokens",
            &[
                ("name", "both"),
                ("tags[]", &id),
                ("new_tag", "inbox"),
                ("password", PASSWORD),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let metas = u.with_db(|conn| list_token_meta(conn).unwrap());
    let both = metas.iter().find(|m| m.name == "both").unwrap();
    assert_eq!(both.scope.tags.as_ref().unwrap().len(), 2);

    // An over-long tag is refused and nothing is created.
    let long = "g".repeat(65);
    let before = u.with_db(|conn| list_token_meta(conn).unwrap()).len();
    let resp = t
        .post_form(
            "/settings/tokens",
            &[("name", "x"), ("new_tag", &long), ("password", PASSWORD)],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(
        u.with_db(|conn| list_token_meta(conn).unwrap()).len(),
        before
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lowering_semantic_index_in_web_requests_deletes_vectors_before_response() {
    use personal_media::embed::{Chunk, MODEL};
    use personal_media::user_db::vectors::{replace_vectors, vector_count};
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let id = upload_named(&t, &c, "v.pdf", PDF, "Vectors").await;
    let store = |u: &std::sync::Arc<personal_media::keyring::Unlocked>| {
        u.with_db(|conn| {
            set_document_access(conn, &id, Channel::SemanticIndex, Some(Level::Full)).unwrap();
            replace_vectors(
                conn,
                &id,
                MODEL.name,
                &[(Chunk { start: 0, end: 1 }, vec![0.5; 384])],
            )
            .unwrap();
            vector_count(conn, &id).unwrap()
        })
    };
    // Per-document override lowered through the page's form.
    assert_eq!(store(&u), 1);
    let resp = t
        .post_form(
            &format!("/documents/{id}/access"),
            &[
                ("web", "default"),
                ("mcp", "default"),
                ("semantic_index", "metadata"),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(u.with_db(|conn| vector_count(conn, &id).unwrap()), 0);

    // Default lowered through settings.
    u.with_db(|conn| {
        set_document_access(conn, &id, Channel::SemanticIndex, None).unwrap();
        personal_media::user_db::set_access_defaults(
            conn,
            &personal_media::user_db::AccessDefaults(
                [
                    (Channel::Web, Level::Full),
                    (Channel::Mcp, Level::Metadata),
                    (Channel::SemanticIndex, Level::Full),
                ]
                .into(),
            ),
        )
        .unwrap();
        replace_vectors(
            conn,
            &id,
            MODEL.name,
            &[(Chunk { start: 0, end: 1 }, vec![0.5; 384])],
        )
        .unwrap();
    });
    let resp = t
        .post_form(
            "/settings/access",
            &[
                ("web", "full"),
                ("mcp", "metadata"),
                ("semantic_index", "off"),
            ],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(u.with_db(|conn| vector_count(conn, &id).unwrap()), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_shows_semantic_index_status() {
    use personal_media::user_db::vectors::set_embed_status;
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let a = upload_named(&t, &c, "a.pdf", PDF, "A").await;
    let b = upload_named(&t, &c, "b.pdf", b"%PDF-1.4 b", "B").await;
    let off = upload_named(&t, &c, "c.pdf", b"%PDF-1.4 c", "C").await;

    // Let the extraction workers finish, or they would race with the statuses set below.
    for _ in 0..400 {
        let pending = u.with_db(|conn| {
            [&a, &b, &off].iter().any(|id| {
                personal_media::user_db::get_document(conn, id)
                    .unwrap()
                    .unwrap()
                    .text_status
                    == personal_media::user_db::TextStatus::Pending
            })
        });
        if !pending {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    // Default is off: nothing eligible, no failed/pending noise.
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(
        html.contains("Semantic index: 0 of 0 documents indexed"),
        "{html}"
    );
    assert!(!html.contains("failed"));
    assert!(html.contains(
        "Semantic index lets your AI assistant (via MCP, full-text tokens only) search by meaning. Vectors are stored encrypted like your text."
    ));

    u.with_db(|conn| {
        set_document_access(conn, &a, Channel::SemanticIndex, Some(Level::Full)).unwrap();
        set_document_access(conn, &b, Channel::SemanticIndex, Some(Level::Full)).unwrap();
        set_document_access(conn, &off, Channel::SemanticIndex, Some(Level::Off)).unwrap();
        set_embed_status(conn, &a, "done").unwrap();
        set_embed_status(conn, &b, "failed").unwrap();
    });
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(
        html.contains("Semantic index: 1 of 2 documents indexed, 1 failed"),
        "{html}"
    );

    let detail = body_string(t.get(&format!("/documents/{a}"), &c).await).await;
    assert!(detail.contains("Indexed for semantic search"), "{detail}");
    let detail = body_string(t.get(&format!("/documents/{b}"), &c).await).await;
    assert!(detail.contains("Indexing failed"), "{detail}");
    let detail = body_string(t.get(&format!("/documents/{off}"), &c).await).await;
    assert!(detail.contains("Not indexed"), "{detail}");
}

fn make_grant(
    t: &TestApp,
    u: &personal_media::keyring::Unlocked,
    name: &str,
    scope: TokenScope,
) -> (String, personal_media::tokens::IssuedPair) {
    personal_media::tokens::create_grant(
        &t.state.sys,
        u,
        scope,
        personal_media::user_db::GrantInfo {
            client_id: "cid".into(),
            client_name: name.into(),
            redirect_host: "claude.ai".into(),
        },
        1_700_000_000,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn connected_apps_listed_and_revocable() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let bob = t.session_for("bob");
    let u = unlocked(&t, &c);

    let page = body_string(t.get("/settings", &c).await).await;
    assert!(page.contains("Connected apps"));
    assert!(page.contains("No apps connected."));

    let (gid, _pair) = make_grant(
        &t,
        &u,
        "<b>Evil</b> App",
        TokenScope {
            access: Access::Read,
            content: Content::MetadataOnly,
            tags: None,
        },
    );
    t.post_form(
        "/settings/tokens",
        &[("name", "static"), ("password", PASSWORD)],
        &c,
    )
    .await;

    let page = body_string(t.get("/settings", &c).await).await;
    assert!(!page.contains("No apps connected."));
    assert!(page.contains("&lt;b&gt;Evil&lt;/b&gt; App") || page.contains("&#60;b&#62;Evil"));
    assert!(!page.contains("<b>Evil</b>"));
    assert!(
        page.contains("Read · Metadata only · All documents"),
        "{page}"
    );
    assert!(page.contains("claude.ai"));
    assert!(page.contains(&format!("/settings/grants/{gid}/revoke")));
    // The static token is listed separately and has no grant revoke form.
    assert!(page.contains("static"));

    // Another user cannot revoke it.
    let denied = t
        .post_form(&format!("/settings/grants/{gid}/revoke"), &[], &bob)
        .await;
    assert_eq!(denied.status(), 404);
    assert_eq!(t.state.sys.token_ids_for_grant(&gid).unwrap().len(), 2);

    // A static token id is not a grant.
    let static_id = u
        .with_db(|conn| list_token_meta(conn).unwrap())
        .into_iter()
        .find(|m| m.grant.is_none())
        .unwrap()
        .id;
    let wrong = t
        .post_form(&format!("/settings/grants/{static_id}/revoke"), &[], &c)
        .await;
    assert_eq!(wrong.status(), 404);

    let resp = t
        .post_form(&format!("/settings/grants/{gid}/revoke"), &[], &c)
        .await;
    assert_eq!(resp.status(), 303);
    assert!(t.state.sys.token_ids_for_grant(&gid).unwrap().is_empty());
    assert!(
        u.with_db(|conn| get_token_meta(conn, &gid).unwrap())
            .is_none()
    );
    let page = body_string(t.get("/settings", &c).await).await;
    assert!(page.contains("No apps connected."));
    let again = t
        .post_form(&format!("/settings/grants/{gid}/revoke"), &[], &c)
        .await;
    assert_eq!(again.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_never_shows_token_secrets() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let (gid, pair) = make_grant(
        &t,
        &u,
        "Hermes",
        TokenScope {
            access: Access::ReadWrite,
            content: Content::FullText,
            tags: None,
        },
    );
    let page = body_string(t.get("/settings", &c).await).await;
    assert!(page.contains("Hermes"));
    for secret in [pair.access.as_str(), pair.refresh.as_str()] {
        assert!(!page.contains(secret));
        // Not even the secret half or the token id.
        let (id, sec) = secret.rsplit_once('_').unwrap();
        assert!(!page.contains(sec));
        assert!(!page.contains(id.rsplit('_').next().unwrap()));
    }
    assert!(!page.contains("pma_") && !page.contains("pmr_"));
    assert!(page.contains(&gid));
}

#[tokio::test(flavor = "multi_thread")]
async fn orphan_grant_meta_is_pruned_on_unlock() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);
    let scope = || TokenScope {
        access: Access::Read,
        content: Content::MetadataOnly,
        tags: None,
    };
    let (orphan, _p1) = make_grant(&t, &u, "Gone", scope());
    let (live, _p2) = make_grant(&t, &u, "Live", scope());
    // Revoked while the user was locked: only the system rows went away.
    t.state.sys.delete_grant_tokens(&orphan).unwrap();
    t.post_form(
        "/settings/tokens",
        &[("name", "st"), ("password", PASSWORD)],
        &c,
    )
    .await;

    personal_media::tokens::prune_orphan_grants(&t.state.sys, &u).unwrap();

    let ids: Vec<String> = u
        .with_db(|conn| list_token_meta(conn).unwrap())
        .into_iter()
        .map(|m| m.id)
        .collect();
    assert!(!ids.contains(&orphan));
    assert!(ids.contains(&live));
    // The static token's meta is untouched.
    assert_eq!(ids.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_shows_mcp_explanation_not_default_row() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(
        html.contains(
            "AI assistants (MCP) see what each token or connected app is allowed to see."
        )
    );
    assert!(html.contains("limit a specific document for every app."));
    assert!(!html.contains("default-mcp"));
    assert!(html.contains("id=\"default-web\""));
    assert!(html.contains("id=\"default-semantic_index\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn ios_setup_token_scope_and_password() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = unlocked(&t, &c);

    // The section is on the settings page.
    let html = body_string(t.get("/settings", &c).await).await;
    assert!(html.contains("Set up iPhone sharing"));

    // A wrong password mints nothing.
    let bad = t
        .post_form("/settings/ios", &[("password", "wrong")], &c)
        .await;
    assert_eq!(bad.status(), 401);
    assert!(u.with_db(|conn| list_token_meta(conn).unwrap()).is_empty());

    let resp = t
        .post_form("/settings/ios", &[("password", PASSWORD)], &c)
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header_str(&resp, "cache-control"), "no-store");
    let page = body_string(resp).await;
    assert!(page.contains("Ask the admin for the Shortcut link"));
    assert!(page.contains("When the Shortcut asks for the setup code, paste it."));
    assert!(page.contains("data-copy-target"));

    let tags = u.with_db(|conn| personal_media::user_db::list_tags(conn).unwrap());
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].1, "inbox");
    let metas = u.with_db(|conn| list_token_meta(conn).unwrap());
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].name, "iPhone Shortcut");
    assert_eq!(
        metas[0].scope,
        TokenScope {
            access: Access::ReadWrite,
            content: Content::MetadataOnly,
            tags: Some(vec![tags[0].0]),
        }
    );

    // Listed in the normal token list, no secret.
    let settings = body_string(t.get("/settings", &c).await).await;
    assert!(settings.contains("iPhone Shortcut"));
    assert!(settings.contains("tags: inbox"));

    // Setting up again reuses the existing tag.
    let again = t
        .post_form("/settings/ios", &[("password", PASSWORD)], &c)
        .await;
    assert_eq!(again.status(), 200);
    assert_eq!(
        u.with_db(|conn| personal_media::user_db::list_tags(conn).unwrap())
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ios_setup_code_format() {
    let t = TestApp::with_config(|cfg| {
        cfg.ios_shortcut_url =
            Some("https://www.icloud.com/shortcuts/0123456789abcdef0123456789abcdef".into());
    });
    let c = t.session_for("alice");
    let resp = t
        .post_form("/settings/ios", &[("password", PASSWORD)], &c)
        .await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    assert!(
        html.contains("href=\"https://www.icloud.com/shortcuts/0123456789abcdef0123456789abcdef\"")
    );
    let code = html
        .split("value=\"")
        .map(|s| s.split('"').next().unwrap())
        .find(|v| v.starts_with("https://test.example|"))
        .expect("setup code shown");
    let (url, token) = code.split_once('|').unwrap();
    assert_eq!(url, "https://test.example");
    assert!(token.starts_with("pm_"));
    let u = unlocked(&t, &c);
    let ids = t.state.sys.token_ids_for_user(&u.user_id).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(token.starts_with(&format!("pm_{}_", ids[0])));
}

#[test]
fn ios_shortcut_url_validated() {
    use personal_media::config::validate_ios_shortcut_url as ok;
    let id = "0123456789abcdef0123456789ABCDEF";
    assert!(ok(&format!("https://www.icloud.com/shortcuts/{id}")));
    assert!(ok(&format!("https://www.icloud.com/shortcuts/{id}/")));
    assert!(!ok("https://www.icloud.com/shortcuts/"));
    assert!(!ok("https://www.icloud.com/shortcuts/abc"));
    assert!(!ok(&format!("http://www.icloud.com/shortcuts/{id}")));
    assert!(!ok(&format!("https://evil.example/shortcuts/{id}")));
    assert!(!ok(&format!(
        "https://www.icloud.com.evil.example/shortcuts/{id}"
    )));
    assert!(!ok(&format!("https://www.icloud.com/shortcuts/{id}/x")));
    assert!(!ok(&format!(
        "https://www.icloud.com/shortcuts/{}z",
        &id[..31]
    )));
}

/// Every password field in Settings has a hidden `autocomplete="username"`
/// field with the account name, so password managers can fill it.
#[tokio::test(flavor = "multi_thread")]
async fn password_fields_carry_a_username_hint_for_password_managers() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let html = body_string(t.get("/settings", &c).await).await;
    let hint = r#"name="pm_username_hint" value="alice" autocomplete="username""#;
    let passwords = html.matches(r#"autocomplete="current-password""#).count();
    assert!(
        passwords >= 4,
        "expected several password forms, got {passwords}"
    );
    assert_eq!(html.matches(hint).count(), passwords);
}
