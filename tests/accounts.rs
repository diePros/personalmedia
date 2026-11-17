use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use personal_media::accounts::{AccountError, Accounts};
use personal_media::config::Config;
use personal_media::keyring::{Keyring, OnUnlock, Unlocked, index_db_path, user_dir};
use personal_media::system_db::{InviteError, Role, SYSTEM_DB_FILE, SystemDb};
use personal_media::user_db::{NewDocument, get_document, insert_document};

const PW: &str = "correct horse battery";
const PW2: &str = "another long password";
const NOW: i64 = 1_800_000_000;

#[derive(Default)]
struct Counter(AtomicUsize);

impl OnUnlock for Counter {
    fn unlocked(&self, _u: &Arc<Unlocked>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Env {
    dir: tempfile::TempDir,
    sys: Arc<SystemDb>,
    keyring: Arc<Keyring>,
    accounts: Accounts,
    unlocks: Arc<Counter>,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::for_tests(dir.path().to_path_buf());
        let sys = Arc::new(SystemDb::open(&dir.path().join(SYSTEM_DB_FILE)).unwrap());
        let unlocks = Arc::new(Counter::default());
        let keyring = Arc::new(Keyring::new(dir.path().to_path_buf(), unlocks.clone()));
        let accounts = Accounts::new(&cfg, sys.clone(), keyring.clone());
        Env {
            dir,
            sys,
            keyring,
            accounts,
            unlocks,
        }
    }

    /// A fresh invite token (the last path segment of the invite URL).
    fn invite(&self, role: Role) -> String {
        let url = self.accounts.create_invite(role, NOW).unwrap();
        url.rsplit('/').next().unwrap().to_string()
    }

    fn unlock_count(&self) -> usize {
        self.unlocks.0.load(Ordering::SeqCst)
    }
}

fn doc(id: &str) -> NewDocument {
    NewDocument {
        id: id.into(),
        wrapped_dek: vec![1, 2, 3],
        original_filename: "a.pdf".into(),
        title: "A".into(),
        mime: "application/pdf".into(),
        size: 1,
        sha256: [9; 32],
        document_date: None,
        tags: vec![],
        created_at: NOW,
    }
}

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

/// Enable TOTP for an unlocked user and return the base32 secret.
fn enable_totp(env: &Env, u: &Unlocked, username: &str) -> String {
    let setup = env.accounts.totp_begin(username);
    env.accounts
        .totp_enable(u, &setup.secret_b32, &totp_code(&setup.secret_b32))
        .unwrap();
    setup.secret_b32
}

#[test]
fn invite_url_format() {
    let env = Env::new();
    let url = env.accounts.create_invite(Role::User, NOW).unwrap();
    let token = url.strip_prefix("https://test.example/invite/").unwrap();
    assert_eq!(token.len(), 64);
    assert!(token.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
}

#[test]
fn signup_then_login() {
    let env = Env::new();
    let (u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::Admin), "sebi", PW, NOW)
        .unwrap();
    assert_eq!(row.username, "sebi");
    assert_eq!(row.role, Role::Admin);
    assert_eq!(row.created_at, NOW);
    assert_eq!(u.user_id, row.id);
    assert!(user_dir(env.dir.path(), &row.id).join("blobs").is_dir());
    assert!(index_db_path(env.dir.path(), &row.id).is_file());

    let (u2, row2) = env.accounts.login("sebi", PW, None).unwrap();
    assert_eq!(row2.id, row.id);
    assert_eq!(u2.umk().as_bytes(), u.umk().as_bytes());
    let n: i64 = u2.with_db(|c| {
        c.query_row("SELECT count(*) FROM documents", [], |r| r.get(0))
            .unwrap()
    });
    assert_eq!(n, 0);
}

#[test]
fn wrong_password_and_unknown_user_are_same_error() {
    let env = Env::new();
    env.accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    let wrong = env
        .accounts
        .login("sebi", "not the password", None)
        .unwrap_err();
    let unknown = env.accounts.login("nobody", PW, None).unwrap_err();
    assert!(matches!(wrong, AccountError::InvalidCredentials));
    assert!(matches!(unknown, AccountError::InvalidCredentials));
    assert_eq!(wrong.to_string(), unknown.to_string());
}

#[test]
fn invite_reuse_rejected() {
    let env = Env::new();
    let token = env.invite(Role::User);
    env.accounts.signup(&token, "first", PW, NOW).unwrap();
    let err = env.accounts.signup(&token, "second", PW, NOW).unwrap_err();
    assert!(matches!(err, AccountError::Invite(InviteError::Used)));
    assert!(env.sys.user_by_name("second").unwrap().is_none());
}

#[test]
fn bad_and_expired_invites_rejected() {
    let env = Env::new();
    for bad in ["", "zz", "abcd", &"0".repeat(64)] {
        let err = env.accounts.signup(bad, "sebi", PW, NOW).unwrap_err();
        assert!(
            matches!(err, AccountError::Invite(InviteError::NotFound)),
            "{bad:?}"
        );
    }
    let token = env.invite(Role::User);
    let late = NOW + 7 * 86400 + 1;
    let err = env.accounts.signup(&token, "sebi", PW, late).unwrap_err();
    assert!(matches!(err, AccountError::Invite(InviteError::Expired)));
    // Still valid at the last second.
    env.accounts
        .signup(&token, "sebi", PW, NOW + 7 * 86400)
        .unwrap();
    // No stray user directories from the failed attempts.
    assert_eq!(
        std::fs::read_dir(env.dir.path().join("users"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn username_rules() {
    let env = Env::new();
    let token = env.invite(Role::User);
    let too_long = "a".repeat(33);
    for bad in ["AB", "ab", "has space", "ümlaut", "a/b", too_long.as_str()] {
        let err = env.accounts.signup(&token, bad, PW, NOW).unwrap_err();
        assert!(matches!(err, AccountError::InvalidUsername), "{bad:?}");
    }
    // The rejected attempts did not burn the invite.
    let (_u, row, _rk) = env.accounts.signup(&token, "Sebi", PW, NOW).unwrap();
    assert_eq!(row.username, "sebi");
    assert!(env.sys.user_by_name("sebi").unwrap().is_some());
    // Login is case-insensitive too.
    env.accounts.login("SEBI", PW, None).unwrap();
}

#[test]
fn duplicate_username_rejected_without_burning_invite() {
    let env = Env::new();
    env.accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    let token = env.invite(Role::User);
    let err = env.accounts.signup(&token, "Sebi", PW, NOW).unwrap_err();
    assert!(matches!(err, AccountError::UsernameTaken));
    env.accounts.signup(&token, "other", PW, NOW).unwrap();
}

#[test]
fn signup_without_valid_invite_never_reveals_username_taken() {
    let env = Env::new();
    env.accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    let bogus = "ab".repeat(32);
    let taken = env.accounts.signup(&bogus, "sebi", PW, NOW).unwrap_err();
    let free = env.accounts.signup(&bogus, "nobody", PW, NOW).unwrap_err();
    assert!(matches!(taken, AccountError::Invite(InviteError::NotFound)));
    assert!(matches!(free, AccountError::Invite(InviteError::NotFound)));
}

#[test]
fn weak_password_rejected() {
    let env = Env::new();
    let token = env.invite(Role::User);
    let err = env
        .accounts
        .signup(&token, "sebi", "123456789", NOW)
        .unwrap_err();
    assert!(matches!(err, AccountError::WeakPassword));
    // Exactly 10 characters is fine, and the invite was not burned.
    env.accounts
        .signup(&token, "sebi", "1234567890", NOW)
        .unwrap();
}

#[test]
fn password_change_keeps_data() {
    let env = Env::new();
    let (u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    u.with_db(|c| insert_document(c, &doc("d1"))).unwrap();

    let err = env
        .accounts
        .change_password(&row.id, "wrong current", PW2)
        .unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    let err = env
        .accounts
        .change_password(&row.id, PW, "short")
        .unwrap_err();
    assert!(matches!(err, AccountError::WeakPassword));

    env.accounts.change_password(&row.id, PW, PW2).unwrap();
    let after = env.sys.user_by_id(&row.id).unwrap().unwrap();
    assert_ne!(after.salt, row.salt);
    assert_ne!(after.umk_by_password, row.umk_by_password);

    drop(u);
    assert!(env.keyring.get(&row.id).is_none());

    let (u, _) = env.accounts.login("sebi", PW2, None).unwrap();
    let found = u.with_db(|c| get_document(c, "d1")).unwrap();
    assert!(found.is_some());
    let err = env.accounts.login("sebi", PW, None).unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
}

#[test]
fn recover_sets_new_password_and_rotates_recovery_key() {
    let env = Env::new();
    let (u, row, rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    u.with_db(|c| insert_document(c, &doc("d1"))).unwrap();
    drop(u);
    let old_key = rk.to_display();

    let err = env
        .accounts
        .recover("sebi", "not a recovery key", PW2)
        .unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    let err = env.accounts.recover("nobody", &old_key, PW2).unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    let err = env.accounts.recover("sebi", &old_key, "short").unwrap_err();
    assert!(matches!(err, AccountError::WeakPassword));

    let (u, row2, new_rk) = env.accounts.recover("sebi", &old_key, PW2).unwrap();
    assert_eq!(row2.id, row.id);
    assert_ne!(row2.umk_by_recovery, row.umk_by_recovery);
    assert_ne!(new_rk.to_display(), old_key);
    assert!(u.with_db(|c| get_document(c, "d1")).unwrap().is_some());
    drop(u);

    env.accounts.login("sebi", PW2, None).unwrap();
    let err = env.accounts.login("sebi", PW, None).unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));

    let err = env.accounts.recover("sebi", &old_key, PW).unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    env.accounts
        .recover("sebi", &new_rk.to_display(), PW)
        .unwrap();
    env.accounts.login("sebi", PW, None).unwrap();
}

#[test]
fn regenerate_recovery_replaces_key() {
    let env = Env::new();
    let (u, _row, rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    let new_rk = env.accounts.regenerate_recovery(&u).unwrap();
    let err = env
        .accounts
        .recover("sebi", &rk.to_display(), PW2)
        .unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    env.accounts
        .recover("sebi", &new_rk.to_display(), PW2)
        .unwrap();
}

#[test]
fn recover_clears_totp() {
    let env = Env::new();
    let (u, row, rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    enable_totp(&env, &u, "sebi");
    drop(u);

    let (u, _row, _new_rk) = env.accounts.recover("sebi", &rk.to_display(), PW2).unwrap();
    assert_eq!(u.user_id, row.id);
    drop(u);

    // Recovery clears TOTP: the authenticator may be lost.
    assert!(!env.accounts.totp_enabled(&row.id));
    env.accounts.login("sebi", PW2, None).unwrap();
}

#[test]
fn totp_enable_refuses_when_already_enabled() {
    let env = Env::new();
    let (u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    enable_totp(&env, &u, "sebi");
    let setup = env.accounts.totp_begin("sebi");
    let err = env
        .accounts
        .totp_enable(&u, &setup.secret_b32, &totp_code(&setup.secret_b32))
        .unwrap_err();
    assert!(matches!(err, AccountError::TotpAlreadyEnabled));
    assert!(env.accounts.totp_enabled(&row.id));
}

#[test]
fn totp_setup_shape() {
    let env = Env::new();
    let setup = env.accounts.totp_begin("sebi");
    assert_eq!(setup.secret_b32.len(), 32); // 20 bytes
    assert!(setup.otpauth_url.starts_with("otpauth://totp/"));
    assert!(setup.otpauth_url.contains("PMS"));
    assert!(setup.otpauth_url.contains("sebi"));
    assert!(setup.otpauth_url.contains(&setup.secret_b32));
    // Base64 of the PNG magic bytes.
    assert!(setup.qr_png_base64.starts_with("iVBORw0KGgo"));
    assert_ne!(env.accounts.totp_begin("sebi").secret_b32, setup.secret_b32);
}

#[test]
fn totp_required_when_enabled() {
    let env = Env::new();
    let (u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    assert!(!env.accounts.totp_enabled(&row.id));

    let setup = env.accounts.totp_begin("sebi");
    let good = totp_code(&setup.secret_b32);
    let bad = if good == "000000" { "000001" } else { "000000" };
    let err = env
        .accounts
        .totp_enable(&u, &setup.secret_b32, bad)
        .unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    assert!(!env.accounts.totp_enabled(&row.id));
    env.accounts
        .totp_enable(&u, &setup.secret_b32, &good)
        .unwrap();
    assert!(env.accounts.totp_enabled(&row.id));

    // The stored secret is sealed, not the raw bytes.
    let sealed = env
        .sys
        .user_by_id(&row.id)
        .unwrap()
        .unwrap()
        .totp_sealed
        .unwrap();
    assert_eq!(sealed.len(), 1 + 24 + 20 + 16);

    let err = env.accounts.login("sebi", PW, None).unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    let err = env.accounts.login("sebi", PW, Some(bad)).unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    let err = env
        .accounts
        .login(
            "sebi",
            "wrong password",
            Some(&totp_code(&setup.secret_b32)),
        )
        .unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    env.accounts
        .login("sebi", PW, Some(&totp_code(&setup.secret_b32)))
        .unwrap();

    let err = env.accounts.totp_disable(&u, bad).unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    assert!(env.accounts.totp_enabled(&row.id));
    env.accounts
        .totp_disable(&u, &totp_code(&setup.secret_b32))
        .unwrap();
    assert!(!env.accounts.totp_enabled(&row.id));
    env.accounts.login("sebi", PW, None).unwrap();
}

#[test]
fn disabled_user_cannot_login() {
    let env = Env::new();
    let (u, row, rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    drop(u);
    env.accounts.set_disabled(&row.id, true).unwrap();

    let err = env.accounts.login("sebi", PW, None).unwrap_err();
    assert!(matches!(err, AccountError::Disabled));
    // Without the right password the disabled state is not revealed.
    let err = env
        .accounts
        .login("sebi", "wrong password", None)
        .unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
    let err = env
        .accounts
        .recover("sebi", &rk.to_display(), PW2)
        .unwrap_err();
    assert!(matches!(err, AccountError::Disabled));
    assert!(env.keyring.get(&row.id).is_none());

    env.accounts.set_disabled(&row.id, false).unwrap();
    env.accounts.login("sebi", PW, None).unwrap();
}

#[test]
fn two_sessions_share_unlocked_and_survive_one_logout() {
    let env = Env::new();
    let (u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    drop(u);
    assert!(env.keyring.get(&row.id).is_none());

    let (a, _) = env.accounts.login("sebi", PW, None).unwrap();
    let (b, _) = env.accounts.login("sebi", PW, None).unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    assert!(Arc::ptr_eq(&a, &env.keyring.get(&row.id).unwrap()));

    drop(a);
    b.with_db(|c| insert_document(c, &doc("d1"))).unwrap();
    assert!(b.with_db(|c| get_document(c, "d1")).unwrap().is_some());

    drop(b);
    assert!(env.keyring.get(&row.id).is_none());
}

#[test]
fn concurrent_logins_share_one_unlocked() {
    let env = Env::new();
    let (u, _row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    drop(u);
    let before = env.unlock_count();

    let arcs: Vec<Arc<Unlocked>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| s.spawn(|| env.accounts.login("sebi", PW, None).unwrap().0))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(arcs.iter().all(|a| Arc::ptr_eq(a, &arcs[0])));
    assert_eq!(env.unlock_count(), before + 1);
}

#[test]
fn on_unlock_called_once_per_fresh_unlock() {
    let env = Env::new();
    assert_eq!(env.unlock_count(), 0);
    let (u, _row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    assert_eq!(env.unlock_count(), 1);

    let (u2, _) = env.accounts.login("sebi", PW, None).unwrap();
    assert_eq!(env.unlock_count(), 1);

    drop(u);
    drop(u2);
    let (_u3, _) = env.accounts.login("sebi", PW, None).unwrap();
    assert_eq!(env.unlock_count(), 2);

    // Failed logins never unlock.
    env.accounts
        .login("sebi", "wrong password", None)
        .unwrap_err();
    assert_eq!(env.unlock_count(), 2);
}

#[test]
fn delete_user_removes_directory() {
    let env = Env::new();
    let (u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    drop(u);
    let dir = user_dir(env.dir.path(), &row.id);
    assert!(dir.is_dir());

    env.accounts.delete_user(&row.id).unwrap();
    assert!(!dir.exists());
    assert!(env.sys.user_by_id(&row.id).unwrap().is_none());
    let err = env.accounts.login("sebi", PW, None).unwrap_err();
    assert!(matches!(err, AccountError::InvalidCredentials));
}

#[test]
fn unlocked_debug_does_not_leak_key() {
    let env = Env::new();
    let (u, _row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    let dbg = format!("{u:?}");
    assert!(!dbg.contains(&hex::encode(u.umk().as_bytes())));
    assert!(!dbg.contains(&format!("{:?}", u.umk().as_bytes())));
}

#[test]
fn verify_password_checks_without_changing_anything() {
    let env = Env::new();
    let (_u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "sebi", PW, NOW)
        .unwrap();
    env.accounts.verify_password(&row.id, PW).unwrap();
    assert!(matches!(
        env.accounts.verify_password(&row.id, PW2).unwrap_err(),
        AccountError::InvalidCredentials
    ));
    assert!(matches!(
        env.accounts.verify_password("nobody", PW).unwrap_err(),
        AccountError::InvalidCredentials
    ));
    // Still logs in with the original password.
    env.accounts.login("sebi", PW, None).unwrap();
}

#[test]
fn totp_resume_rebuilds_the_same_setup() {
    let env = Env::new();
    let setup = env.accounts.totp_begin("sebi");
    let again = env.accounts.totp_resume("sebi", &setup.secret_b32).unwrap();
    assert_eq!(again.secret_b32, setup.secret_b32);
    assert_eq!(again.otpauth_url, setup.otpauth_url);
    assert!(again.qr_png_base64.starts_with("iVBORw0KGgo"));
    assert!(env.accounts.totp_resume("sebi", "not base32 !").is_err());
}

fn forge_password_wrap(env: &Env, user_id: &str, attacker_pw: &str) {
    use personal_media::crypto::{Key32, aad, password_kek, wrap_key};
    let row = env.sys.user_by_id(user_id).unwrap().unwrap();
    let salt = [5u8; 16];
    let kek = password_kek(attacker_pw, &salt, &row.argon2).unwrap();
    let forged = wrap_key(
        &kek,
        &Key32::from_bytes([9u8; 32]),
        aad::umk_password(user_id).as_bytes(),
    );
    rusqlite::Connection::open(env.dir.path().join(SYSTEM_DB_FILE))
        .unwrap()
        .execute(
            "UPDATE users SET salt=?1, umk_by_password=?2 WHERE id=?3",
            rusqlite::params![salt.to_vec(), forged, user_id],
        )
        .unwrap();
}

#[test]
fn forged_password_wrap_rejected_while_user_unlocked() {
    let env = Env::new();
    let (u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "victim", PW, NOW)
        .unwrap();
    // `u` keeps the keyring entry live.
    forge_password_wrap(&env, &row.id, "attacker chosen pw");
    let r = env.accounts.login("victim", "attacker chosen pw", None);
    assert!(matches!(r, Err(AccountError::InvalidCredentials)));
    drop(u);
}

#[test]
fn forged_password_wrap_rejected_while_user_locked() {
    let env = Env::new();
    let (u, row, _rk) = env
        .accounts
        .signup(&env.invite(Role::User), "victim", PW, NOW)
        .unwrap();
    drop(u);
    forge_password_wrap(&env, &row.id, "attacker chosen pw");
    assert!(
        env.accounts
            .login("victim", "attacker chosen pw", None)
            .is_err()
    );
}

#[test]
fn swapped_index_key_wraps_rejected() {
    let env = Env::new();
    let (ua, a, _) = env
        .accounts
        .signup(&env.invite(Role::User), "alice", PW, NOW)
        .unwrap();
    let (ub, b, _) = env
        .accounts
        .signup(&env.invite(Role::User), "bobby", PW, NOW)
        .unwrap();
    let ra = env.sys.user_by_id(&a.id).unwrap().unwrap();
    let rb = env.sys.user_by_id(&b.id).unwrap().unwrap();
    let conn = rusqlite::Connection::open(env.dir.path().join(SYSTEM_DB_FILE)).unwrap();
    for (id, w) in [
        (&a.id, &rb.index_key_wrapped),
        (&b.id, &ra.index_key_wrapped),
    ] {
        conn.execute(
            "UPDATE users SET index_key_wrapped=?1 WHERE id=?2",
            rusqlite::params![w, id],
        )
        .unwrap();
    }
    drop((ua, ub));
    // Locked: the swapped index key cannot be unwrapped.
    assert!(env.accounts.login("alice", PW, None).is_err());
    assert!(env.accounts.login("bobby", PW, None).is_err());
}
