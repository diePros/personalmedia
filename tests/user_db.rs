use personal_media::crypto::Key32;
use personal_media::user_db::*;
use rusqlite::Connection;

fn db() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_user_db(&dir.path().join("index.db"), &Key32::from_bytes([7; 32])).unwrap();
    (dir, conn)
}

fn nd(id: &str, title: &str, filename: &str, tags: &[&str], created_at: i64) -> NewDocument {
    NewDocument {
        id: id.into(),
        wrapped_dek: vec![1, 2, 3],
        original_filename: filename.into(),
        title: title.into(),
        mime: "application/pdf".into(),
        size: 42,
        sha256: [id.as_bytes()[0]; 32],
        document_date: None,
        tags: tags.iter().map(|s| s.to_string()).collect(),
        created_at,
    }
}

fn add(conn: &Connection, id: &str, title: &str, tags: &[&str], content: &str) {
    insert_document(conn, &nd(id, title, &format!("{id}.pdf"), tags, 100)).unwrap();
    set_text(conn, id, TextStatus::Done, Some(content), Some(1), 7).unwrap();
}

fn web() -> ListFilter {
    ListFilter {
        access: Some(AccessFilter {
            channel: Channel::Web,
            cap: Level::Full,
        }),
        ..Default::default()
    }
}

fn mcp(cap: Level) -> ListFilter {
    ListFilter {
        access: Some(AccessFilter {
            channel: Channel::Mcp,
            cap,
        }),
        ..Default::default()
    }
}

fn ids(h: &[SearchHit]) -> Vec<&str> {
    h.iter().map(|h| h.doc.id.as_str()).collect()
}

#[test]
fn insert_get_list_roundtrip() {
    let (_d, conn) = db();
    let mut a = nd("a1", "Mietvertrag", "miete.pdf", &["wohnen", "vertrag"], 10);
    a.document_date = Some("2025-01-02".into());
    insert_document(&conn, &a).unwrap();
    insert_document(&conn, &nd("b1", "Zweites", "z.pdf", &[], 20)).unwrap();
    let got = get_document(&conn, "a1").unwrap().unwrap();
    assert_eq!(got.title, "Mietvertrag");
    assert_eq!(got.size, 42);
    assert_eq!(got.wrapped_dek, vec![1, 2, 3]);
    assert_eq!(got.sha256_hex, hex::encode([b'a'; 32]));
    assert_eq!(got.text_status, TextStatus::Pending);
    assert_eq!(got.tags, vec!["vertrag", "wohnen"]);
    assert_eq!(got.document_date.as_deref(), Some("2025-01-02"));
    assert!(get_document(&conn, "nope").unwrap().is_none());
    assert_eq!(
        find_by_sha256(&conn, &[b'b'; 32]).unwrap().unwrap().id,
        "b1"
    );
    let list = list_documents(&conn, &ListFilter::default()).unwrap();
    assert_eq!(
        list.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
        ["b1", "a1"]
    );
    assert_eq!(pending_document_ids(&conn).unwrap().len(), 2);
    set_text(&conn, "a1", TextStatus::Done, Some("x"), Some(3), 7).unwrap();
    assert_eq!(pending_document_ids(&conn).unwrap(), vec!["b1"]);
    assert_eq!(
        get_document(&conn, "a1").unwrap().unwrap().page_count,
        Some(3)
    );
}

#[test]
fn search_finds_content_with_umlaut_folding() {
    let (_d, conn) = db();
    add(&conn, "a1", "Vertrag", &[], "Kündigungsfrist drei Monate");
    let hits = search(&conn, "kundigungsfrist", &web()).unwrap();
    assert_eq!(ids(&hits), ["a1"]);
    assert!(hits[0].snippet.as_ref().unwrap().contains('\u{2}'));
    assert_eq!(hits[0].level, Level::Full);
}

#[test]
fn prefix_search_on_last_term() {
    let (_d, conn) = db();
    add(&conn, "a1", "Vertrag", &[], "Kündigungsfrist drei Monate");
    assert_eq!(search(&conn, "kundig", &web()).unwrap().len(), 1);
    assert_eq!(search(&conn, "drei kundig", &web()).unwrap().len(), 1);
    assert_eq!(search(&conn, "kundig drei", &web()).unwrap().len(), 0);
}

#[test]
fn metadata_only_never_matches_content() {
    let (_d, conn) = db();
    add(&conn, "a1", "Brief", &[], "das ist geheim");
    assert!(
        search(&conn, "geheim", &mcp(Level::Metadata))
            .unwrap()
            .is_empty()
    );
    // default mcp = metadata, so even a Full cap sees no content
    assert!(
        search(&conn, "geheim", &mcp(Level::Full))
            .unwrap()
            .is_empty()
    );
    set_document_access(&conn, "a1", Channel::Mcp, Some(Level::Full)).unwrap();
    let hits = search(&conn, "geheim", &mcp(Level::Full)).unwrap();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].snippet.is_some());
    // cap still limits an overridden-full document
    assert!(
        search(&conn, "geheim", &mcp(Level::Metadata))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn switchboard_off_hides_document() {
    let (_d, conn) = db();
    add(&conn, "a1", "Brief", &[], "geheim");
    add(&conn, "b1", "Zweit", &[], "geheim");
    set_document_access(&conn, "a1", Channel::Web, Some(Level::Off)).unwrap();
    let l = list_documents(&conn, &web()).unwrap();
    assert_eq!(l.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), ["b1"]);
    assert_eq!(ids(&search(&conn, "geheim", &web()).unwrap()), ["b1"]);
    let none = ListFilter::default();
    assert_eq!(list_documents(&conn, &none).unwrap().len(), 2);
    assert_eq!(search(&conn, "geheim", &none).unwrap().len(), 2);
    // cap Off sees nothing
    assert!(list_documents(&conn, &mcp(Level::Off)).unwrap().is_empty());
    assert!(
        search(&conn, "geheim", &mcp(Level::Off))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn switchboard_defaults_and_effective_level() {
    let (_d, conn) = db();
    add(&conn, "a1", "Brief", &[], "x");
    let d = get_access_defaults(&conn).unwrap();
    assert_eq!(d.level(Channel::Web), Level::Full);
    assert_eq!(d.level(Channel::Mcp), Level::Metadata);
    assert_eq!(d.level(Channel::SemanticIndex), Level::Off);
    assert!(Level::Off < Level::Metadata && Level::Metadata < Level::Full);
    let eff = |c, cap| effective_level(&conn, "a1", c, cap).unwrap();
    assert_eq!(eff(Channel::Mcp, Level::Full), Level::Metadata);
    let mut nd_ = d.clone();
    nd_.0.insert(Channel::Mcp, Level::Full);
    set_access_defaults(&conn, &nd_).unwrap();
    assert_eq!(get_access_defaults(&conn).unwrap(), nd_);
    assert_eq!(eff(Channel::Mcp, Level::Full), Level::Full);
    assert_eq!(eff(Channel::Mcp, Level::Metadata), Level::Metadata);
    set_document_access(&conn, "a1", Channel::Mcp, Some(Level::Off)).unwrap();
    assert_eq!(eff(Channel::Mcp, Level::Full), Level::Off);
    assert_eq!(
        document_overrides(&conn, "a1").unwrap().get(&Channel::Mcp),
        Some(&Level::Off)
    );
    set_document_access(&conn, "a1", Channel::Mcp, None).unwrap();
    assert!(document_overrides(&conn, "a1").unwrap().is_empty());
    assert_eq!(eff(Channel::Mcp, Level::Full), Level::Full);
    assert_eq!(
        serde_json::to_string(&Channel::SemanticIndex).unwrap(),
        "\"semantic_index\""
    );
}

#[test]
fn metadata_level_hit_has_no_snippet() {
    let (_d, conn) = db();
    add(&conn, "a1", "Steuerbescheid", &[], "inhalt");
    let hits = search(&conn, "steuer", &mcp(Level::Full)).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].level, Level::Metadata);
    assert!(hits[0].snippet.is_none());
}

#[test]
fn mixed_levels_merge_and_paginate() {
    let (_d, conn) = db();
    add(&conn, "a1", "alpha", &[], "alpha");
    add(&conn, "b1", "alpha", &[], "beta");
    set_document_access(&conn, "a1", Channel::Mcp, Some(Level::Full)).unwrap();
    let mut f = mcp(Level::Full);
    let hits = search(&conn, "alpha", &f).unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits.iter().filter(|h| h.level == Level::Full).count(), 1);
    f.limit = 1;
    f.offset = 1;
    assert_eq!(search(&conn, "alpha", &f).unwrap().len(), 1);
}

#[test]
fn search_input_is_literal_and_cannot_escape_columns() {
    let (_d, conn) = db();
    add(&conn, "a1", "Brief", &[], "geheim");
    let inputs = [
        "geheim\" OR content:geheim",
        "content: geheim",
        "NEAR(geheim",
        "*",
        "-geheim",
        "\"",
        "\"\"",
        "(",
        "title:x OR content:geheim",
    ];
    set_document_access(&conn, "a1", Channel::Mcp, Some(Level::Full)).unwrap();
    for q in inputs {
        let hits = search(&conn, q, &mcp(Level::Metadata)).unwrap();
        assert!(hits.is_empty(), "leaked for {q:?}");
        search(&conn, q, &mcp(Level::Full)).unwrap();
    }
}

#[test]
fn tag_filters() {
    let (_d, conn) = db();
    add(&conn, "a1", "t1", &["a", "b"], "x");
    add(&conn, "b1", "t2", &["a"], "x");
    add(&conn, "c1", "t3", &["b"], "x");
    let f = ListFilter {
        tags_all: vec!["a".into(), "b".into()],
        ..Default::default()
    };
    let l = list_documents(&conn, &f).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].id, "a1");
    let id_a = tag_ids(&conn, &["a".to_string()]).unwrap()[0];
    let f = ListFilter {
        tag_allow: Some(vec![id_a]),
        ..Default::default()
    };
    assert_eq!(list_documents(&conn, &f).unwrap().len(), 2);
    assert_eq!(search(&conn, "x", &f).unwrap().len(), 2);
    let f = ListFilter {
        tag_allow: Some(vec![]),
        ..Default::default()
    };
    assert!(list_documents(&conn, &f).unwrap().is_empty());
    assert_eq!(list_tags(&conn).unwrap().len(), 2);
}

#[test]
fn date_filters_inclusive() {
    let (_d, conn) = db();
    for (id, date) in [
        ("a1", Some("2025-01-01")),
        ("b1", Some("2025-06-01")),
        ("c1", None),
    ] {
        let mut n = nd(id, "t", "f.pdf", &[], 1);
        n.document_date = date.map(String::from);
        insert_document(&conn, &n).unwrap();
    }
    let f = ListFilter {
        date_from: Some("2025-01-01".into()),
        date_to: Some("2025-06-01".into()),
        ..Default::default()
    };
    assert_eq!(list_documents(&conn, &f).unwrap().len(), 2);
    let f = ListFilter {
        date_from: Some("2025-02-01".into()),
        ..Default::default()
    };
    let l = list_documents(&conn, &f).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].id, "b1");
}

#[test]
fn update_meta_reindexes() {
    let (_d, conn) = db();
    add(&conn, "a1", "Altertitel", &["old"], "x");
    update_document_meta(
        &conn,
        "a1",
        Some("Neuertitel"),
        Some(Some("2025-03-03")),
        Some(&["fresh".to_string()]),
        500,
    )
    .unwrap();
    assert_eq!(search(&conn, "neuertitel", &web()).unwrap().len(), 1);
    assert!(search(&conn, "altertitel", &web()).unwrap().is_empty());
    assert_eq!(search(&conn, "fresh", &web()).unwrap().len(), 1);
    assert!(search(&conn, "old", &web()).unwrap().is_empty());
    let d = get_document(&conn, "a1").unwrap().unwrap();
    assert_eq!(d.updated_at, 500);
    assert_eq!(d.document_date.as_deref(), Some("2025-03-03"));
    update_document_meta(&conn, "a1", None, Some(None), None, 501).unwrap();
    assert!(
        get_document(&conn, "a1")
            .unwrap()
            .unwrap()
            .document_date
            .is_none()
    );
}

#[test]
fn delete_removes_from_fts() {
    let (_d, conn) = db();
    add(&conn, "a1", "Brief", &["t"], "geheim");
    set_document_access(&conn, "a1", Channel::Web, Some(Level::Off)).unwrap();
    delete_document(&conn, "a1").unwrap();
    assert!(
        search(&conn, "geheim", &ListFilter::default())
            .unwrap()
            .is_empty()
    );
    assert!(get_document(&conn, "a1").unwrap().is_none());
    let n: i64 = conn
        .query_row("SELECT count(*) FROM document_access", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn token_meta_roundtrip() {
    let (_d, conn) = db();
    let t = TokenMeta {
        id: "tok1".into(),
        name: "claude".into(),
        scope: TokenScope {
            access: Access::ReadWrite,
            content: Content::MetadataOnly,
            tags: Some(vec![1, 2]),
        },
        created_at: 5,
        last_used_at: None,
    };
    insert_token_meta(&conn, &t).unwrap();
    let got = get_token_meta(&conn, "tok1").unwrap().unwrap();
    assert_eq!(got.scope, t.scope);
    assert_eq!(got.name, "claude");
    touch_token(&conn, "tok1", 99).unwrap();
    assert_eq!(list_token_meta(&conn).unwrap()[0].last_used_at, Some(99));
    delete_token_meta(&conn, "tok1").unwrap();
    assert!(get_token_meta(&conn, "tok1").unwrap().is_none());
    assert_eq!(get_setting(&conn, "k").unwrap(), None);
    set_setting(&conn, "k", "v").unwrap();
    set_setting(&conn, "k", "w").unwrap();
    assert_eq!(get_setting(&conn, "k").unwrap().as_deref(), Some("w"));
    assert_eq!(
        serde_json::to_string(&t.scope).unwrap(),
        r#"{"access":"read_write","content":"metadata_only","tags":[1,2]}"#
    );
}

#[test]
fn wrong_key_fails_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("index.db");
    drop(open_user_db(&p, &Key32::from_bytes([1; 32])).unwrap());
    assert!(open_user_db(&p, &Key32::from_bytes([2; 32])).is_err());
    assert!(open_user_db(&p, &Key32::from_bytes([1; 32])).is_ok());
}

#[test]
fn db_file_has_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    {
        let conn = open_user_db(&dir.path().join("index.db"), &Key32::from_bytes([9; 32])).unwrap();
        let mut n = nd(
            "a1",
            "Bescheid",
            "Steuerbescheid_2025.pdf",
            &["finanzamt"],
            1,
        );
        n.title = "Bescheid".into();
        insert_document(&conn, &n).unwrap();
        set_text(
            &conn,
            "a1",
            TextStatus::Done,
            Some("Einkommensteuer"),
            Some(1),
            7,
        )
        .unwrap();
    }
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let raw = std::fs::read(entry.unwrap().path()).unwrap();
        for needle in [
            "Steuerbescheid_2025.pdf",
            "finanzamt",
            "Einkommensteuer",
            "Bescheid",
        ] {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{needle}"
            );
        }
    }
}

#[test]
fn temp_store_is_memory_and_set_text_bumps_updated_at() {
    let (_d, conn) = db();
    let ts: i64 = conn
        .query_row("PRAGMA temp_store", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ts, 2);
    insert_document(&conn, &nd("a1", "t", "f.pdf", &[], 1)).unwrap();
    set_text(&conn, "a1", TextStatus::Done, Some("x"), None, 777).unwrap();
    assert_eq!(get_document(&conn, "a1").unwrap().unwrap().updated_at, 777);
}

fn mcp_full() -> ListFilter {
    mcp(Level::Full)
}

#[test]
fn list_tags_visible_hides_tags_only_on_hidden_documents() {
    let (_d, conn) = db();
    add(&conn, "a1", "Shown", &["steuer"], "x");
    add(&conn, "b1", "Hidden", &["geheim", "steuer"], "x");
    add(&conn, "c1", "Hidden2", &["nur-hidden"], "x");
    set_document_access(&conn, "a1", Channel::Mcp, Some(Level::Full)).unwrap();
    set_document_access(&conn, "b1", Channel::Mcp, Some(Level::Off)).unwrap();
    set_document_access(&conn, "c1", Channel::Mcp, Some(Level::Off)).unwrap();
    // Orphan tag: attached to a document that was then deleted.
    add(&conn, "d1", "Gone", &["orphan"], "x");
    delete_document(&conn, "d1").unwrap();

    let names = |f: &ListFilter| -> Vec<String> {
        list_tags_visible(&conn, f)
            .unwrap()
            .into_iter()
            .map(|(_, n)| n)
            .collect()
    };
    assert_eq!(names(&mcp_full()), ["steuer"]);
    // Unfiltered owner/admin view still sees everything.
    assert_eq!(list_tags(&conn).unwrap().len(), 4);
    assert_eq!(names(&ListFilter::default()).len(), 3); // orphan still absent
    // cap Off sees no tags.
    assert!(names(&mcp(Level::Off)).is_empty());
}

#[test]
fn list_tags_visible_respects_tag_allow() {
    let (_d, conn) = db();
    add(&conn, "a1", "A", &["steuer", "miete"], "x");
    add(&conn, "b1", "B", &["bank"], "x");
    for id in ["a1", "b1"] {
        set_document_access(&conn, id, Channel::Mcp, Some(Level::Full)).unwrap();
    }
    let steuer = tag_ids(&conn, &["steuer".to_string()]).unwrap()[0];
    let f = ListFilter {
        tag_allow: Some(vec![steuer]),
        ..mcp_full()
    };
    let names: Vec<String> = list_tags_visible(&conn, &f)
        .unwrap()
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    // Ruling N: only allowed tags are listed, never a visible document's other tags.
    assert_eq!(names, ["steuer"]);
    let none = ListFilter {
        tag_allow: Some(vec![]),
        ..mcp_full()
    };
    assert!(list_tags_visible(&conn, &none).unwrap().is_empty());
}

#[test]
fn find_by_sha256_visible_ignores_hidden_documents() {
    let (_d, conn) = db();
    add(&conn, "a1", "A", &[], "x");
    set_document_access(&conn, "a1", Channel::Mcp, Some(Level::Off)).unwrap();
    let sha = [b'a'; 32];
    assert!(
        find_by_sha256_visible(&conn, &sha, &mcp_full())
            .unwrap()
            .is_none()
    );
    assert!(
        find_by_sha256_visible(&conn, &sha, &web())
            .unwrap()
            .is_some()
    );
    assert!(
        find_by_sha256_visible(&conn, &sha, &ListFilter::default())
            .unwrap()
            .is_some()
    );
}

#[test]
fn deleted_tag_ids_are_never_reused() {
    let (_d, conn) = db();
    let a = tag_ids(&conn, &["a".to_string(), "b".to_string()]).unwrap();
    conn.execute("DELETE FROM tags WHERE id = ?1", [a[1]])
        .unwrap();
    let c = tag_ids(&conn, &["c".to_string()]).unwrap();
    assert!(
        c[0] > a[1],
        "tag id {} reused after delete of {}",
        c[0],
        a[1]
    );
}

#[test]
fn hidden_from_lists_documents_whose_effective_level_is_off() {
    let (_d, conn) = db();
    for (id, created) in [("a1", 10), ("b1", 20), ("c1", 30), ("d1", 40)] {
        insert_document(&conn, &nd(id, id, &format!("{id}.pdf"), &["t"], created)).unwrap();
    }
    set_document_access(&conn, "a1", Channel::Web, Some(Level::Off)).unwrap();
    set_document_access(&conn, "b1", Channel::Web, Some(Level::Metadata)).unwrap();
    set_document_access(&conn, "c1", Channel::Mcp, Some(Level::Off)).unwrap();
    set_document_access(&conn, "d1", Channel::Web, Some(Level::Off)).unwrap();
    let ids = |ch| -> Vec<String> {
        hidden_from(&conn, ch)
            .unwrap()
            .into_iter()
            .map(|d| d.id)
            .collect()
    };
    // Newest first; only an effective level of off counts.
    assert_eq!(ids(Channel::Web), ["d1", "a1"]);
    assert_eq!(ids(Channel::Mcp), ["c1"]);
    assert_eq!(hidden_from(&conn, Channel::Web).unwrap()[0].tags, ["t"]);

    // Documents without an override follow the channel default.
    let mut defaults = get_access_defaults(&conn).unwrap();
    defaults.0.insert(Channel::Web, Level::Off);
    set_access_defaults(&conn, &defaults).unwrap();
    assert_eq!(ids(Channel::Web), ["d1", "c1", "a1"]);
}
