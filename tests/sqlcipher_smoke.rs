use rusqlite::Connection;

const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn open(path: &std::path::Path, key: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!("PRAGMA key = \"x'{key}'\";"))?;
    Ok(conn)
}

#[test]
fn sqlcipher_encrypts_and_supports_fts5() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.db");
    {
        let conn = open(&path, KEY).unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE f USING fts5(a, tokenize='unicode61 remove_diacritics 2');
             INSERT INTO f(a) VALUES ('Kündigung Mietvertrag');",
        )
        .unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM f WHERE f MATCH 'kundigung'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }
    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(b"Mietvertrag".len())
            .any(|w| w == b"Mietvertrag")
    );
    assert!(!raw.starts_with(b"SQLite format 3"));

    let other = "f".repeat(64);
    let conn = open(&path, &other).unwrap();
    let r: rusqlite::Result<i64> =
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0));
    assert!(r.is_err());
}
