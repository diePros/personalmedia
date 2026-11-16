use std::path::Path;
use std::sync::Arc;

use assert_cmd::Command;
use bytes::Bytes;
use personal_media::accounts::Accounts;
use personal_media::config::Config;
use personal_media::documents::{Documents, Enqueue, OnDuplicate, StoreOutcome, UploadMeta};
use personal_media::keyring::{Keyring, OnUnlock, Unlocked};
use personal_media::system_db::{Role, SYSTEM_DB_FILE, SystemDb};

const NOW: i64 = 1_800_000_000;
const PASSWORD: &str = "correct horse battery";

struct NoUnlock;
impl OnUnlock for NoUnlock {
    fn unlocked(&self, _u: &Arc<Unlocked>) {}
}

struct NoQueue;
impl Enqueue for NoQueue {
    fn enqueue(&self, _u: Arc<Unlocked>, _doc_id: String) {}
}

const FILES: [(&str, &[u8]); 3] = [
    ("a.txt", b"first document"),
    ("a.txt", b"second, same name"),
    ("b.bin", &[0, 1, 2, 3, 255, 254]),
];

/// A data dir with user `sebi` holding three documents; returns the recovery key.
async fn setup(dir: &Path) -> String {
    let cfg = Config::for_tests(dir.to_path_buf());
    let sys = Arc::new(SystemDb::open(&dir.join(SYSTEM_DB_FILE)).unwrap());
    let keyring = Arc::new(Keyring::new(dir.to_path_buf(), Arc::new(NoUnlock)));
    let accounts = Accounts::new(&cfg, sys, keyring);
    let url = accounts.create_invite(Role::User, NOW).unwrap();
    let token = url.rsplit('/').next().unwrap().to_string();
    let (u, _, rk) = accounts.signup(&token, "sebi", PASSWORD, NOW).unwrap();
    let docs = Documents::new(dir.to_path_buf(), 10_000_000, Arc::new(NoQueue));
    for (i, (name, data)) in FILES.iter().enumerate() {
        let body =
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::copy_from_slice(data))]);
        let meta = UploadMeta {
            filename: (*name).into(),
            mime: None,
            title: None,
            tags: vec!["t".into()],
            document_date: None,
        };
        let out = docs
            .store(&u, meta, body, OnDuplicate::Keep, None, NOW + i as i64)
            .await
            .unwrap();
        assert!(matches!(out, StoreOutcome::Stored { .. }));
    }
    rk.to_display()
}

fn recover(data: &Path, out: &Path, secret: &str, extra: &[&str]) -> assert_cmd::assert::Assert {
    Command::cargo_bin("personal-media")
        .unwrap()
        .args(["recover", "--user", "sebi", "--data"])
        .arg(data)
        .arg("--out")
        .arg(out)
        .args(extra)
        .env("PM_RECOVER_SECRET", secret)
        .assert()
}

fn stderr(a: &assert_cmd::assert::Assert) -> String {
    String::from_utf8(a.get_output().stderr.clone()).unwrap()
}

fn check_output(out: &Path) {
    assert_eq!(std::fs::read(out.join("files/a.txt")).unwrap(), FILES[0].1);
    assert_eq!(
        std::fs::read(out.join("files/a (2).txt")).unwrap(),
        FILES[1].1
    );
    assert_eq!(std::fs::read(out.join("files/b.bin")).unwrap(), FILES[2].1);
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(meta.as_array().unwrap().len(), 3);
    assert_eq!(meta[0]["zip_path"], "files/a.txt");
}

#[tokio::test(flavor = "multi_thread")]
async fn recover_with_password_writes_all_files() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path()).await;
    let out = dir.path().join("out");
    let a = recover(dir.path(), &out, PASSWORD, &[]).success();
    let stdout = String::from_utf8(a.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains(&format!("Recovered 3 documents to {}", out.display())));
    check_output(&out);
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&out).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[tokio::test(flavor = "multi_thread")]
async fn recover_with_recovery_key() {
    let dir = tempfile::tempdir().unwrap();
    let rk = setup(dir.path()).await;
    let out = dir.path().join("out");
    recover(dir.path(), &out, &rk, &["--recovery-key"]).success();
    check_output(&out);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_secret_exits_nonzero_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let rk = setup(dir.path()).await;
    let out = dir.path().join("out");
    let a = recover(dir.path(), &out, "wrong password here", &[]).code(1);
    assert!(stderr(&a).contains("could not unlock"));
    assert!(!out.exists());
    // A recovery key given as a password, and a password given as a key, also fail.
    recover(dir.path(), &out, &rk, &[]).code(1);
    recover(dir.path(), &out, PASSWORD, &["--recovery-key"]).code(1);
    assert!(!out.exists());
    // Unknown user.
    let a = Command::cargo_bin("personal-media")
        .unwrap()
        .args(["recover", "--user", "nobody", "--data"])
        .arg(dir.path())
        .arg("--out")
        .arg(&out)
        .env("PM_RECOVER_SECRET", PASSWORD)
        .assert()
        .code(1);
    assert!(stderr(&a).contains("could not unlock"));
    assert!(!out.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_non_empty_out_dir() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path()).await;
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("keep.txt"), b"x").unwrap();
    recover(dir.path(), &out, PASSWORD, &[]).code(2);
    assert_eq!(std::fs::read(out.join("keep.txt")).unwrap(), b"x");
    assert!(!out.join("files").exists());
    // An existing empty directory is fine.
    std::fs::remove_file(out.join("keep.txt")).unwrap();
    recover(dir.path(), &out, PASSWORD, &[]).success();
    check_output(&out);
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), &dest).unwrap();
        }
    }
}

fn set_tree_mode(path: &Path, dir_mode: u32, file_mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).unwrap();
    if meta.is_dir() {
        // Make the directory traversable before touching what is inside.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        for e in std::fs::read_dir(path).unwrap() {
            set_tree_mode(&e.unwrap().path(), dir_mode, file_mode);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(dir_mode)).unwrap();
    } else {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(file_mode)).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn recover_works_on_read_only_copy() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    setup(&data).await;
    let backup = dir.path().join("backup");
    copy_tree(&data, &backup);
    set_tree_mode(&backup, 0o555, 0o444);
    let out = dir.path().join("out");
    let before = std::fs::read(backup.join(SYSTEM_DB_FILE)).unwrap();
    let a = recover(&backup, &out, PASSWORD, &[]);
    // Restore write access so the tempdir can be removed, then assert.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        a.success();
        check_output(&out);
        assert_eq!(std::fs::read(backup.join(SYSTEM_DB_FILE)).unwrap(), before);
        // Nothing (journal, shm, wal) was added to the backup.
        assert_eq!(std::fs::read_dir(&backup).unwrap().count(), 2);
    }));
    set_tree_mode(&backup, 0o755, 0o644);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
