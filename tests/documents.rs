use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use personal_media::accounts::Accounts;
use personal_media::config::Config;
use personal_media::documents::{
    DocError, Documents, Enqueue, OnDuplicate, StoreOutcome, UploadMeta, blob_path,
};
use personal_media::keyring::{Keyring, OnUnlock, Unlocked, user_dir};
use personal_media::system_db::{Role, SYSTEM_DB_FILE, SystemDb};
use personal_media::user_db::{TextStatus, get_document};

const NOW: i64 = 1_800_000_000;

struct NoUnlock;
impl OnUnlock for NoUnlock {
    fn unlocked(&self, _u: &Arc<Unlocked>) {}
}

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);
impl Enqueue for Recorder {
    fn enqueue(&self, _u: Arc<Unlocked>, doc_id: String) {
        self.0.lock().unwrap().push(doc_id);
    }
}

struct Env {
    dir: tempfile::TempDir,
    u: Arc<Unlocked>,
    rec: Arc<Recorder>,
    docs: Documents,
}

fn env(max: u64) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_tests(dir.path().to_path_buf());
    let sys = Arc::new(SystemDb::open(&dir.path().join(SYSTEM_DB_FILE)).unwrap());
    let keyring = Arc::new(Keyring::new(dir.path().to_path_buf(), Arc::new(NoUnlock)));
    let accounts = Accounts::new(&cfg, sys, keyring);
    let url = accounts.create_invite(Role::User, NOW).unwrap();
    let token = url.rsplit('/').next().unwrap().to_string();
    let (u, _, _) = accounts
        .signup(&token, "sebi", "correct horse battery", NOW)
        .unwrap();
    let rec = Arc::new(Recorder::default());
    let docs = Documents::new(dir.path().to_path_buf(), max, rec.clone());
    Env { dir, u, rec, docs }
}

fn meta(name: &str) -> UploadMeta {
    UploadMeta {
        filename: name.into(),
        mime: None,
        title: None,
        tags: vec![],
        document_date: None,
    }
}

fn body(data: &[u8]) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Unpin {
    let chunks: Vec<_> = data
        .chunks(10_000)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    futures_util::stream::iter(chunks)
}

fn stored_id(o: StoreOutcome) -> String {
    match o {
        StoreOutcome::Stored { id } => id,
        other => panic!("expected Stored, got {other:?}"),
    }
}

fn blob_files(e: &Env) -> Vec<String> {
    let dir = user_dir(e.dir.path(), &e.u.user_id).join("blobs");
    std::fs::read_dir(dir)
        .unwrap()
        .map(|f| f.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

fn random_bytes(n: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(n + 32);
    let mut h = Sha256::digest(b"seed").to_vec();
    while out.len() < n {
        out.extend_from_slice(&h);
        h = Sha256::digest(&h).to_vec();
    }
    out.truncate(n);
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn store_and_read_back_identical() {
    let e = env(10_000_000);
    let data = random_bytes(300_000);
    let id = stored_id(
        e.docs
            .store(
                &e.u,
                meta("scan.pdf"),
                body(&data),
                OnDuplicate::Skip,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    let (doc, mut r) = e.docs.open_plaintext(&e.u, &id).unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, data);
    assert_eq!(doc.size, 300_000);
    assert_eq!(doc.title, "scan");
    assert_eq!(doc.mime, "application/pdf");
    assert_eq!(
        e.rec.0.lock().unwrap().as_slice(),
        std::slice::from_ref(&id)
    );
    assert!(blob_path(e.dir.path(), &e.u.user_id, &id).is_file());
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_skip_and_keep() {
    let e = env(10_000_000);
    let data = random_bytes(5000);
    let first = stored_id(
        e.docs
            .store(
                &e.u,
                meta("a.pdf"),
                body(&data),
                OnDuplicate::Skip,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    match e
        .docs
        .store(
            &e.u,
            meta("b.pdf"),
            body(&data),
            OnDuplicate::Skip,
            None,
            NOW,
        )
        .await
        .unwrap()
    {
        StoreOutcome::Duplicate {
            existing_id,
            existing_title,
        } => {
            assert_eq!(existing_id, first);
            assert_eq!(existing_title, "a");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(blob_files(&e).len(), 1);
    let second = stored_id(
        e.docs
            .store(
                &e.u,
                meta("b.pdf"),
                body(&data),
                OnDuplicate::Keep,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    assert_ne!(first, second);
    assert_eq!(blob_files(&e).len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn too_large_rejected_and_no_part_file_left() {
    let e = env(1000);
    let err = e
        .docs
        .store(
            &e.u,
            meta("big.pdf"),
            body(&random_bytes(50_000)),
            OnDuplicate::Skip,
            None,
            NOW,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DocError::TooLarge));
    assert!(blob_files(&e).is_empty());
    assert!(e.rec.0.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_error_leaves_no_part_file() {
    let e = env(1_000_000);
    let s = futures_util::stream::iter(vec![
        Ok(Bytes::from_static(b"abc")),
        Err(std::io::Error::other("boom")),
    ]);
    let err = e
        .docs
        .store(&e.u, meta("x.pdf"), s, OnDuplicate::Skip, None, NOW)
        .await
        .unwrap_err();
    assert!(matches!(err, DocError::Internal(_)));
    assert!(blob_files(&e).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_type_not_enqueued() {
    let e = env(1_000_000);
    let id = stored_id(
        e.docs
            .store(
                &e.u,
                meta("a.zip"),
                body(b"PK"),
                OnDuplicate::Skip,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    assert!(e.rec.0.lock().unwrap().is_empty());
    let doc = e.u.with_db(|c| get_document(c, &id)).unwrap().unwrap();
    assert_eq!(doc.text_status, TextStatus::Unsupported);
}

#[tokio::test(flavor = "multi_thread")]
async fn pdf_enqueued() {
    let e = env(1_000_000);
    let id = stored_id(
        e.docs
            .store(
                &e.u,
                meta("a.PDF"),
                body(b"%PDF-1.4"),
                OnDuplicate::Skip,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        e.rec.0.lock().unwrap().as_slice(),
        std::slice::from_ref(&id)
    );
    let doc = e.u.with_db(|c| get_document(c, &id)).unwrap().unwrap();
    assert_eq!(doc.text_status, TextStatus::Pending);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_removes_blob_and_row() {
    let e = env(1_000_000);
    let id = stored_id(
        e.docs
            .store(
                &e.u,
                meta("a.txt"),
                body(b"hello"),
                OnDuplicate::Skip,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    e.docs.delete(&e.u, &id).unwrap();
    assert!(!blob_path(e.dir.path(), &e.u.user_id, &id).exists());
    assert!(e.u.with_db(|c| get_document(c, &id)).unwrap().is_none());
    assert!(matches!(
        e.docs.open_plaintext(&e.u, &id),
        Err(DocError::NotFound)
    ));
    assert!(matches!(e.docs.delete(&e.u, &id), Err(DocError::NotFound)));
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_date_rejected() {
    let e = env(1_000_000);
    for bad in [
        "2024-13-01",
        "2024-02-30",
        "24-01-01",
        "2024/01/01",
        "abcd-ef-gh",
    ] {
        let mut m = meta("a.txt");
        m.document_date = Some(bad.into());
        let err = e
            .docs
            .store(&e.u, m, body(b"x"), OnDuplicate::Keep, None, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, DocError::InvalidDate), "{bad}");
    }
    let mut m = meta("a.txt");
    m.document_date = Some("2024-02-29".into());
    let id = stored_id(
        e.docs
            .store(&e.u, m, body(b"x"), OnDuplicate::Keep, None, NOW)
            .await
            .unwrap(),
    );
    assert!(matches!(
        e.docs
            .update(&e.u, &id, None, Some(Some("2023-02-29")), None, NOW),
        Err(DocError::InvalidDate)
    ));
    e.docs
        .update(&e.u, &id, Some("T"), Some(None), None, NOW + 1)
        .unwrap();
    let doc = e.u.with_db(|c| get_document(c, &id)).unwrap().unwrap();
    assert_eq!(doc.title, "T");
    assert_eq!(doc.document_date, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_extraction_sets_pending_and_enqueues() {
    let e = env(1_000_000);
    let id = stored_id(
        e.docs
            .store(
                &e.u,
                meta("a.zip"),
                body(b"PK"),
                OnDuplicate::Skip,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    e.docs.retry_extraction(&e.u, &id).unwrap();
    let doc = e.u.with_db(|c| get_document(c, &id)).unwrap().unwrap();
    assert_eq!(doc.text_status, TextStatus::Pending);
    assert_eq!(e.rec.0.lock().unwrap().len(), 1);
}

fn scan(dir: &Path, needles: &[&str], hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            scan(&p, needles, hits);
        } else {
            let bytes = std::fs::read(&p).unwrap();
            let name = p.to_string_lossy().into_owned();
            for n in needles {
                if bytes.windows(n.len()).any(|w| w == n.as_bytes()) || name.contains(n) {
                    hits.push(format!("{name}: {n}"));
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_plaintext_at_rest() {
    let e = env(1_000_000);
    let mut m = meta("Arztbrief_Mueller.txt");
    m.tags = vec!["gesundheit".into()];
    let dir = e.dir.path().to_path_buf();
    let id = stored_id(
        e.docs
            .store(
                &e.u,
                m,
                body(b"Diagnose vertraulich"),
                OnDuplicate::Skip,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    // Simulate extraction finishing so extracted text is on disk too.
    e.u.with_db(|c| {
        personal_media::user_db::set_text(
            c,
            &id,
            TextStatus::Done,
            Some("Diagnose vertraulich"),
            Some(1),
            NOW,
        )
    })
    .unwrap();
    let Env {
        u,
        docs,
        rec,
        dir: td,
    } = e;
    drop(docs);
    drop(rec);
    drop(u);
    let mut hits = vec![];
    scan(
        &dir,
        &[
            "Arztbrief",
            "Mueller",
            "Diagnose",
            "vertraulich",
            "gesundheit",
        ],
        &mut hits,
    );
    drop(td);
    assert!(hits.is_empty(), "{hits:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_check_ignores_documents_hidden_from_the_caller() {
    use personal_media::user_db::{AccessFilter, Channel, Level, ListFilter, set_document_access};
    let e = env(10_000_000);
    let data = random_bytes(5000);
    let mcp = ListFilter {
        access: Some(AccessFilter {
            channel: Channel::Mcp,
            cap: Level::Full,
        }),
        ..Default::default()
    };
    let hidden = stored_id(
        e.docs
            .store(
                &e.u,
                meta("secret-name.pdf"),
                body(&data),
                OnDuplicate::Skip,
                None,
                NOW,
            )
            .await
            .unwrap(),
    );
    e.u.with_db(|c| set_document_access(c, &hidden, Channel::Mcp, Some(Level::Off)))
        .unwrap();

    // Hidden from MCP: behaves like Keep, and reveals nothing about the hidden doc.
    let out = e
        .docs
        .store(
            &e.u,
            meta("other.pdf"),
            body(&data),
            OnDuplicate::Skip,
            Some(&mcp),
            NOW,
        )
        .await
        .unwrap();
    let json = serde_json::to_string(&out).unwrap();
    let second = stored_id(out);
    assert!(!json.contains(&hidden) && !json.contains("secret-name"));
    assert_ne!(second, hidden);

    // Now a visible copy exists, so the MCP caller does get a Duplicate for it.
    e.u.with_db(|c| set_document_access(c, &second, Channel::Mcp, Some(Level::Full)))
        .unwrap();
    match e
        .docs
        .store(
            &e.u,
            meta("third.pdf"),
            body(&data),
            OnDuplicate::Skip,
            Some(&mcp),
            NOW,
        )
        .await
        .unwrap()
    {
        StoreOutcome::Duplicate { existing_id, .. } => assert_eq!(existing_id, second),
        other => panic!("{other:?}"),
    }
    // None = all documents (owner upload) considers every copy.
    match e
        .docs
        .store(
            &e.u,
            meta("fourth.pdf"),
            body(&data),
            OnDuplicate::Skip,
            None,
            NOW,
        )
        .await
        .unwrap()
    {
        StoreOutcome::Duplicate { existing_id, .. } => {
            assert!(existing_id == hidden || existing_id == second)
        }
        other => panic!("{other:?}"),
    }
}
