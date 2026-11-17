//! Remembered-device tokens: storage, resume, expiry, eviction, revocation.

mod common;

use std::sync::Arc;

use common::*;
use personal_media::devices::{
    DEVICE_TTL_SECS, MAX_DEVICES, create_device, device_label, resume_device, revoke_all_devices,
    revoke_device,
};
use personal_media::keyring::Unlocked;
use personal_media::tokens::{authenticate, create_token};
use personal_media::user_db::{Access, Content, TokenScope, list_device_meta};

const NOW: i64 = 1_800_000_000;

fn setup() -> (TestApp, Arc<Unlocked>) {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
    (t, u)
}

fn user_id(t: &TestApp) -> String {
    t.state.sys.user_by_name("alice").unwrap().unwrap().id
}

fn id_of(token: &str) -> &str {
    token
        .strip_prefix("pmd_")
        .unwrap()
        .split('_')
        .next()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn create_then_resume_returns_same_user_and_device_id() {
    let (t, u) = setup();
    let token = create_device(&t.state.sys, &u, "Mac · Safari", NOW).unwrap();
    assert!(token.starts_with("pmd_"));
    let r = resume_device(&t.state, &token, NOW + 10).unwrap();
    assert_eq!(r.user.id, user_id(&t));
    assert_eq!(r.device_id, id_of(&token));
    let metas = r.unlocked.with_db(list_device_meta).unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].label, "Mac · Safari");
    assert_eq!(metas[0].last_used_at, Some(NOW + 10));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_secret_fails_not_genuine() {
    let (t, u) = setup();
    let token = create_device(&t.state.sys, &u, "x", NOW).unwrap();
    let bad = format!("{}{}", &token[..token.len() - 64], "0".repeat(64));
    let e = resume_device(&t.state, &bad, NOW + 1).err().unwrap();
    assert!(!e.genuine);
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_token_fails_genuine() {
    let (t, u) = setup();
    let token = create_device(&t.state.sys, &u, "x", NOW).unwrap();
    let e = resume_device(&t.state, &token, NOW + DEVICE_TTL_SECS + 1)
        .err()
        .unwrap();
    assert!(e.genuine);
    // A wrong secret on an expired row is still not genuine.
    let bad = format!("{}{}", &token[..token.len() - 64], "0".repeat(64));
    let e = resume_device(&t.state, &bad, NOW + DEVICE_TTL_SECS + 1)
        .err()
        .unwrap();
    assert!(!e.genuine);
}

#[tokio::test(flavor = "multi_thread")]
async fn sliding_expiry_extends_at_most_once_a_day() {
    let (t, u) = setup();
    let token = create_device(&t.state.sys, &u, "x", NOW).unwrap();
    let id = id_of(&token).to_owned();
    let exp = || t.state.sys.token_full(&id).unwrap().unwrap().expires_at;
    assert_eq!(exp(), Some(NOW + DEVICE_TTL_SECS));
    resume_device(&t.state, &token, NOW).unwrap();
    resume_device(&t.state, &token, NOW + 3600).unwrap();
    assert_eq!(exp(), Some(NOW + DEVICE_TTL_SECS));
    resume_device(&t.state, &token, NOW + 2 * 86400).unwrap();
    assert_eq!(exp(), Some(NOW + 2 * 86400 + DEVICE_TTL_SECS));
}

#[tokio::test(flavor = "multi_thread")]
async fn twenty_first_device_evicts_least_recently_used() {
    let (t, u) = setup();
    let mut tokens = Vec::new();
    for i in 0..MAX_DEVICES {
        tokens.push(create_device(&t.state.sys, &u, &format!("d{i}"), NOW + i as i64).unwrap());
    }
    // Use the oldest one, so the second-oldest is now the least recent.
    resume_device(&t.state, &tokens[0], NOW + 100).unwrap();
    let new = create_device(&t.state.sys, &u, "new", NOW + 200).unwrap();
    let metas = u.with_db(list_device_meta).unwrap();
    assert_eq!(metas.len(), MAX_DEVICES);
    assert!(resume_device(&t.state, &tokens[1], NOW + 300).is_err());
    assert!(resume_device(&t.state, &tokens[0], NOW + 300).is_ok());
    assert!(resume_device(&t.state, &new, NOW + 300).is_ok());
    assert_eq!(
        t.state.sys.token_ids_for_user(&user_id(&t)).unwrap().len(),
        MAX_DEVICES
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_one_and_foreign_device() {
    let (t, u) = setup();
    let a = create_device(&t.state.sys, &u, "a", NOW).unwrap();
    let b = create_device(&t.state.sys, &u, "b", NOW).unwrap();
    assert!(!revoke_device(&t.state.sys, &u, "nope").unwrap());
    assert!(revoke_device(&t.state.sys, &u, id_of(&a)).unwrap());
    assert!(resume_device(&t.state, &a, NOW + 1).is_err());
    assert!(resume_device(&t.state, &b, NOW + 1).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_all_devices_keeps_mcp_tokens() {
    let (t, u) = setup();
    let scope = TokenScope {
        access: Access::Read,
        content: Content::FullText,
        tags: None,
    };
    let mcp = create_token(&t.state.sys, &u, "bot", scope, NOW).unwrap();
    let d1 = create_device(&t.state.sys, &u, "a", NOW).unwrap();
    let d2 = create_device(&t.state.sys, &u, "b", NOW).unwrap();
    assert_eq!(revoke_all_devices(&t.state.sys, &u).unwrap(), 2);
    assert!(resume_device(&t.state, &d1, NOW + 1).is_err());
    assert!(resume_device(&t.state, &d2, NOW + 1).is_err());
    assert!(u.with_db(list_device_meta).unwrap().is_empty());
    let state = t.state.clone();
    let ok = tokio::task::spawn_blocking(move || authenticate(&state, &mcp).is_ok())
        .await
        .unwrap();
    assert!(ok);
}

#[tokio::test(flavor = "multi_thread")]
async fn device_token_is_not_an_mcp_bearer() {
    let (t, u) = setup();
    let token = create_device(&t.state.sys, &u, "x", NOW).unwrap();
    assert!(authenticate(&t.state, &token).is_err());
    // Same id and secret under the static prefix is no bearer either.
    let as_static = token.replacen("pmd_", "pm_", 1);
    assert!(authenticate(&t.state, &as_static).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_token_does_not_resume() {
    let (t, u) = setup();
    let scope = TokenScope {
        access: Access::Read,
        content: Content::FullText,
        tags: None,
    };
    let mcp = create_token(&t.state.sys, &u, "bot", scope, NOW).unwrap();
    assert!(resume_device(&t.state, &mcp, NOW).is_err());
    let as_device = mcp.replacen("pm_", "pmd_", 1);
    assert!(resume_device(&t.state, &as_device, NOW).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_user_does_not_resume() {
    let (t, u) = setup();
    let token = create_device(&t.state.sys, &u, "x", NOW).unwrap();
    t.state.sys.set_disabled(&user_id(&t), true).unwrap();
    assert!(resume_device(&t.state, &token, NOW + 1).is_err());
}

#[test]
fn device_label_table() {
    let cases = [
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
            "iPhone · Safari",
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            "iPhone · Browser",
        ),
        (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
            "Android · Chrome",
        ),
        (
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Linux · Firefox",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "Mac · Safari",
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36 Edg/124.0",
            "Windows · Edge",
        ),
        ("", "Unknown device · Browser"),
    ];
    for (ua, want) in cases {
        assert_eq!(device_label(ua), want, "{ua}");
    }
    assert_eq!(device_label(&"x".repeat(500)).chars().count(), 24);
    assert!(
        device_label(&format!("Firefox/1 {}", "a".repeat(100)))
            .chars()
            .count()
            <= 60
    );
}
