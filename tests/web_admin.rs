mod common;

use common::*;
use personal_media::system_db::Role;
use personal_media::tokens::create_token;
use personal_media::user_db::{Access, Content, TokenScope};

const PDF: &[u8] = include_bytes!("fixtures/text.pdf");

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn user_id(t: &TestApp, name: &str) -> String {
    t.state.sys.user_by_name(name).unwrap().unwrap().id
}

#[tokio::test(flavor = "multi_thread")]
async fn non_admin_gets_403() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    assert_eq!(t.get("/admin", &c).await.status(), 403);
    let id = user_id(&t, "alice");
    for path in [
        "/admin/invites".to_string(),
        "/admin/invites/abababab/revoke".to_string(),
        format!("/admin/users/{id}/disable"),
        format!("/admin/users/{id}/enable"),
        format!("/admin/users/{id}/delete"),
    ] {
        let resp = t.post_form(&path, &[("role", "user")], &c).await;
        assert_eq!(resp.status(), 403, "{path}");
    }
    assert_eq!(t.get("/admin", &Client::anon()).await.status(), 303);
    // The nav link is only for admins.
    let docs = body_string(t.get("/documents", &c).await).await;
    assert!(!docs.contains("href=\"/admin\""));
    let admin = t.admin_session_for("root");
    let docs = body_string(t.get("/documents", &admin).await).await;
    assert!(docs.contains("href=\"/admin\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_page_never_shows_titles_or_filenames() {
    let t = TestApp::new();
    let admin = t.admin_session_for("root");
    let b = t.session_for("bob");
    let resp = t
        .post_multipart(
            "/api/upload",
            &[("title", "Geheimakte")],
            &[("file", "Geheimakte.pdf", "application/pdf", PDF)],
            &b,
        )
        .await;
    assert!(resp.status().is_success(), "{}", resp.status());
    let resp = t.get("/admin", &admin).await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    assert!(!html.contains("Geheimakte"));
    assert!(html.contains("bob"));
    assert!(html.contains("root"));
    assert!(html.contains("KiB"), "storage used is shown: {html}");
    assert!(html.contains("cannot read users' documents or reset their passwords"));
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_create_and_revoke() {
    let t = TestApp::new();
    let admin = t.admin_session_for("root");
    let resp = t
        .post_form("/admin/invites", &[("role", "admin")], &admin)
        .await;
    assert_eq!(resp.status(), 200);
    let html = body_string(resp).await;
    let start = html
        .find("https://test.example/invite/")
        .expect("url shown");
    let url: String = html[start..]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '<' && *c != '"')
        .collect();
    let open = t.state.sys.list_open_invites(now()).unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].1, Role::Admin);
    // The URL is not shown again; the list only has the hash prefix.
    let page = body_string(t.get("/admin", &admin).await).await;
    assert!(!page.contains(&url));
    assert!(page.contains(&open[0].0));
    // Default role is user; garbage is rejected.
    let resp = t
        .post_form("/admin/invites", &[("role", "user")], &admin)
        .await;
    assert_eq!(resp.status(), 200);
    let resp = t
        .post_form("/admin/invites", &[("role", "root")], &admin)
        .await;
    assert_eq!(resp.status(), 400);
    let open = t.state.sys.list_open_invites(now()).unwrap();
    assert_eq!(open.len(), 2);
    let prefix = open[0].0.clone();
    let resp = t
        .post_form(&format!("/admin/invites/{prefix}/revoke"), &[], &admin)
        .await;
    assert_eq!(resp.status(), 303);
    assert_eq!(t.state.sys.list_open_invites(now()).unwrap().len(), 1);
    let resp = t.post_form("/admin/invites/zz/revoke", &[], &admin).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(t.state.sys.list_open_invites(now()).unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn disable_and_delete_kill_sessions_and_tokens() {
    let t = TestApp::new();
    let admin = t.admin_session_for("root");
    let b = t.session_for("bob");
    let id = user_id(&t, "bob");
    let unlocked = t.state.sessions.get(&b.cookie).unwrap().unlocked;
    let scope = TokenScope {
        access: Access::Read,
        content: Content::FullText,
        tags: None,
    };
    create_token(&t.state.sys, &unlocked, "hermes", scope, now()).unwrap();
    let token_id = t.state.sys.token_ids_for_user(&id).unwrap().remove(0);
    assert_eq!(t.get("/documents", &b).await.status(), 200);

    let resp = t
        .post_form(&format!("/admin/users/{id}/disable"), &[], &admin)
        .await;
    assert_eq!(resp.status(), 303);
    assert!(t.state.sys.user_by_id(&id).unwrap().unwrap().disabled);
    let resp = t.get("/documents", &b).await;
    assert_eq!(resp.status(), 303);
    assert_eq!(header_str(&resp, "location"), "/login");
    // Task 14 extends this to a `/mcp` request with B's token returning 401.

    let resp = t
        .post_form(&format!("/admin/users/{id}/enable"), &[], &admin)
        .await;
    assert_eq!(resp.status(), 303);
    assert!(!t.state.sys.user_by_id(&id).unwrap().unwrap().disabled);

    let b2 = t.session_for("carol");
    let cid = user_id(&t, "carol");
    let dir = t.dir.path().join("users").join(&id);
    assert!(dir.exists());
    let resp = t
        .post_form(
            &format!("/admin/users/{id}/delete"),
            &[("confirm_username", "bob")],
            &admin,
        )
        .await;
    assert_eq!(resp.status(), 303);
    assert!(!dir.exists());
    assert!(t.state.sys.user_by_id(&id).unwrap().is_none());
    // Task 14 extends this to a `/mcp` 401; for now the token row is gone.
    assert!(t.state.sys.token(&token_id).unwrap().is_none());
    assert_eq!(
        header_str(&t.get("/documents", &b).await, "location"),
        "/login"
    );
    // Other users are untouched.
    assert_eq!(t.get("/documents", &b2).await.status(), 200);
    assert!(t.state.sys.user_by_id(&cid).unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_cannot_delete_self() {
    let t = TestApp::new();
    let admin = t.admin_session_for("root");
    let id = user_id(&t, "root");
    let resp = t
        .post_form(
            &format!("/admin/users/{id}/delete"),
            &[("confirm_username", "root")],
            &admin,
        )
        .await;
    assert_eq!(resp.status(), 400);
    let resp = t
        .post_form(&format!("/admin/users/{id}/disable"), &[], &admin)
        .await;
    assert_eq!(resp.status(), 400);
    let row = t.state.sys.user_by_id(&id).unwrap().unwrap();
    assert!(!row.disabled);
    assert_eq!(t.get("/admin", &admin).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_requires_username_confirmation() {
    let t = TestApp::new();
    let admin = t.admin_session_for("root");
    t.session_for("bob");
    let id = user_id(&t, "bob");
    let path = format!("/admin/users/{id}/delete");
    for fields in [
        vec![],
        vec![("confirm_username", "Bob")],
        vec![("confirm_username", "alice")],
    ] {
        let resp = t.post_form(&path, &fields, &admin).await;
        assert_eq!(resp.status(), 400);
    }
    assert!(t.state.sys.user_by_id(&id).unwrap().is_some());
    assert!(t.dir.path().join("users").join(&id).exists());
    // Unknown and malformed ids.
    let resp = t
        .post_form(
            "/admin/users/not-a-uuid/delete",
            &[("confirm_username", "x")],
            &admin,
        )
        .await;
    assert_eq!(resp.status(), 404);
}
