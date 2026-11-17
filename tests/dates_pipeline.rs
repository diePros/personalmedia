//! Automatic document dates: extraction hook, source rules and the backfill.

mod common;

use common::*;
use personal_media::crypto::Key32;
use personal_media::user_db::{
    DateSource, TextStatus, apply_detected_date, backfill_detected_dates, get_document,
    get_setting, insert_document, open_user_db, set_text, set_transcription,
    update_document_meta_sourced,
};
use rusqlite::Connection;

fn today() -> time::Date {
    time::Date::from_calendar_date(2026, time::Month::November, 17).unwrap()
}

fn db() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_user_db(&dir.path().join("index.db"), &Key32::from_bytes([7; 32])).unwrap();
    (dir, conn)
}

fn doc(conn: &Connection, id: &str, text: Option<&str>) {
    use personal_media::user_db::NewDocument;
    insert_document(
        conn,
        &NewDocument {
            id: id.into(),
            wrapped_dek: vec![1],
            original_filename: format!("{id}.pdf"),
            title: id.into(),
            mime: "application/pdf".into(),
            size: 1,
            sha256: [id.as_bytes()[0]; 32],
            document_date: None,
            tags: vec![],
            created_at: 100,
        },
    )
    .unwrap();
    if let Some(t) = text {
        set_text(conn, id, TextStatus::Done, Some(t), Some(1), 100).unwrap();
    }
}

const TEXT: &str = "Rechnungsdatum 05.10.2026\nBetrag 12,00 EUR";

#[tokio::test(flavor = "multi_thread")]
async fn detected_date_fills_empty_date() {
    let t = TestApp::new();
    let c = t.session_for("alice");
    let resp = t
        .post_multipart(
            "/api/upload",
            &[],
            &[("file", "r.txt", "text/plain", TEXT.as_bytes())],
            &c,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let id = v["id"].as_str().unwrap().to_owned();
    let u = t.state.sessions.get(&c.cookie).unwrap().unlocked;
    for _ in 0..200 {
        let d = u.with_db(|c| get_document(c, &id)).unwrap().unwrap();
        if d.document_date.is_some() {
            assert_eq!(d.document_date.as_deref(), Some("2026-10-05"));
            assert_eq!(d.date_source, Some(DateSource::Detected));
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no date detected");
}

#[test]
fn detection_never_overwrites_user_or_ai_date() {
    let (_d, conn) = db();
    for id in ["user", "ai", "legacy", "cleared"] {
        doc(&conn, id, Some(TEXT));
    }
    update_document_meta_sourced(
        &conn,
        "user",
        None,
        Some(Some("2020-01-01")),
        None,
        None,
        DateSource::User,
        1,
    )
    .unwrap();
    update_document_meta_sourced(
        &conn,
        "ai",
        None,
        Some(Some("2021-02-02")),
        None,
        None,
        DateSource::Ai,
        1,
    )
    .unwrap();
    conn.execute(
        "UPDATE documents SET document_date = '2019-03-03' WHERE id = 'legacy'",
        [],
    )
    .unwrap();
    // A real clear: the document had a date, the user removes it.
    update_document_meta_sourced(
        &conn,
        "cleared",
        None,
        Some(Some("2018-01-01")),
        None,
        None,
        DateSource::Detected,
        1,
    )
    .unwrap();
    update_document_meta_sourced(
        &conn,
        "cleared",
        None,
        Some(None),
        None,
        None,
        DateSource::User,
        1,
    )
    .unwrap();
    for id in ["user", "ai", "legacy", "cleared"] {
        assert!(
            !apply_detected_date(&conn, id, TEXT, today(), 5).unwrap(),
            "{id}"
        );
    }
    let get = |id: &str| get_document(&conn, id).unwrap().unwrap();
    assert_eq!(get("user").document_date.as_deref(), Some("2020-01-01"));
    assert_eq!(get("user").date_source, Some(DateSource::User));
    assert_eq!(get("ai").document_date.as_deref(), Some("2021-02-02"));
    assert_eq!(get("ai").date_source, Some(DateSource::Ai));
    assert_eq!(get("legacy").document_date.as_deref(), Some("2019-03-03"));
    assert_eq!(get("legacy").date_source, None);
    assert_eq!(get("cleared").document_date, None);
    assert_eq!(get("cleared").date_source, Some(DateSource::User));
    // An empty, unsourced document is filled; a detected one is not refilled.
    doc(&conn, "fresh", Some(TEXT));
    assert!(apply_detected_date(&conn, "fresh", TEXT, today(), 5).unwrap());
    assert_eq!(get("fresh").document_date.as_deref(), Some("2026-10-05"));
    assert_eq!(get("fresh").date_source, Some(DateSource::Detected));
    assert!(!apply_detected_date(&conn, "fresh", "Datum 01.01.2020", today(), 6).unwrap());
    assert_eq!(get("fresh").document_date.as_deref(), Some("2026-10-05"));
    // Text without a date changes nothing.
    doc(&conn, "nodate", Some("hello"));
    assert!(!apply_detected_date(&conn, "nodate", "hello", today(), 5).unwrap());
    assert_eq!(get("nodate").date_source, None);
}

#[test]
fn backfill_runs_once() {
    let (_d, conn) = db();
    doc(&conn, "a", Some(TEXT));
    doc(&conn, "b", Some("Brief vom 3. März 2025"));
    doc(&conn, "c", None);
    // A transcription is left to the AI: no detection, even with a date in it.
    doc(&conn, "t", Some(TEXT));
    set_transcription(&conn, "t", TEXT, 100).unwrap();
    let n = backfill_detected_dates(&conn, today(), 9).unwrap();
    assert_eq!(n, 2);
    let get = |id: &str| get_document(&conn, id).unwrap().unwrap();
    assert_eq!(get("a").document_date.as_deref(), Some("2026-10-05"));
    assert_eq!(get("b").document_date.as_deref(), Some("2025-03-03"));
    assert_eq!(get("b").date_source, Some(DateSource::Detected));
    assert_eq!(get("c").document_date, None);
    assert_eq!(get("t").document_date, None);
    assert_eq!(
        get_setting(&conn, "date_backfill").unwrap().as_deref(),
        Some("v1")
    );
    // A second run touches nothing, even for newly dateless documents.
    doc(&conn, "d", Some(TEXT));
    assert_eq!(backfill_detected_dates(&conn, today(), 10).unwrap(), 0);
    assert_eq!(get("d").document_date, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_runs_the_backfill_once_in_the_background() {
    use personal_media::accounts::Accounts;
    use personal_media::config::Config;
    use personal_media::extract::ExtractQueue;
    use personal_media::keyring::Keyring;
    use personal_media::system_db::{Role, SYSTEM_DB_FILE, SystemDb};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_tests(dir.path().to_path_buf());
    let sys = Arc::new(SystemDb::open(&dir.path().join(SYSTEM_DB_FILE)).unwrap());
    let (queue, _rx) = ExtractQueue::channel();
    let keyring = Arc::new(Keyring::new(dir.path().to_path_buf(), Arc::new(queue)));
    let accounts = Accounts::new(&cfg, sys, keyring.clone());
    let url = accounts.create_invite(Role::User, 1_000).unwrap();
    let token = url.rsplit('/').next().unwrap().to_string();
    let (u, _, _) = accounts
        .signup(&token, "sebi", "correct horse battery", 1_000)
        .unwrap();
    let marker = |u: &personal_media::keyring::Unlocked| {
        u.with_db(|c| get_setting(c, "date_backfill")).unwrap()
    };
    let wait = |u: std::sync::Arc<personal_media::keyring::Unlocked>| async move {
        for _ in 0..200 {
            if marker(&u).as_deref() == Some("v1") {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("backfill did not finish");
    };
    // The signup unlock backfilled the empty index; reset it and add data.
    wait(u.clone()).await;
    u.with_db(|c| {
        c.execute("DELETE FROM settings WHERE key = 'date_backfill'", [])?;
        doc(c, "a", Some(TEXT));
        Ok::<_, anyhow::Error>(())
    })
    .unwrap();
    let uid = u.user_id.clone();
    drop(u);
    // A still-running backfill must not keep the old Unlocked alive.
    wait_locked(&keyring, &uid).await;
    let (u, _) = accounts
        .login("sebi", "correct horse battery", None)
        .unwrap();
    wait(u.clone()).await;
    let d = u.with_db(|c| get_document(c, "a")).unwrap().unwrap();
    assert_eq!(d.document_date.as_deref(), Some("2026-10-05"));
    assert_eq!(d.date_source, Some(DateSource::Detected));
}
