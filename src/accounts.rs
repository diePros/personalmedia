//! Account lifecycle: invites, signup, login, recovery, password change, TOTP
//! and admin operations.
//!
//! All methods are synchronous. Several run Argon2, so the web layer calls
//! them inside `spawn_blocking`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Builder, Secret, Totp, TotpError};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::crypto::{
    Argon2Params, CryptoError, INFO_RECOVERY, Key32, RecoveryKey, aad, fill_random, open,
    password_kek, seal, secret_kek, unwrap_key, wrap_key,
};
use crate::keyring::{Keyring, Unlocked, index_db_path, user_dir};
use crate::system_db::{InviteError, Role, SysError, SystemDb, UserRow};
use crate::user_db::open_user_db;

const INVITE_TTL_SECS: i64 = 7 * 86400;
const MIN_PASSWORD_CHARS: usize = 10;
const TOTP_ISSUER: &str = "Personal Media";
const TOTP_SECRET_LEN: usize = 20;

#[derive(thiserror::Error, Debug)]
pub enum AccountError {
    /// Wrong password, unknown user, wrong recovery key, or wrong/missing TOTP code.
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("account disabled")]
    Disabled,
    #[error("username already taken")]
    UsernameTaken,
    #[error("invalid username")]
    InvalidUsername,
    #[error("password too short")]
    WeakPassword,
    /// TOTP is already enabled; disable it (with a current code) first.
    #[error("TOTP is already enabled")]
    TotpAlreadyEnabled,
    #[error("invite: {0}")]
    Invite(#[from] InviteError),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

pub struct TotpSetup {
    pub secret_b32: String,
    pub otpauth_url: String,
    pub qr_png_base64: String,
}

pub struct Accounts {
    sys: Arc<SystemDb>,
    keyring: Arc<Keyring>,
    data_dir: PathBuf,
    argon2: Argon2Params,
    public_url: String,
}

/// Lowercase and validate against `^[a-z0-9_.-]{3,32}$`.
fn normalize_username(input: &str) -> Result<String, AccountError> {
    let name = input.to_lowercase();
    let ok = (3..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'));
    if ok {
        Ok(name)
    } else {
        Err(AccountError::InvalidUsername)
    }
}

fn check_password_strength(password: &str) -> Result<(), AccountError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AccountError::WeakPassword);
    }
    Ok(())
}

/// A failed authenticated decryption means the credential was wrong; anything
/// else is corrupt stored data.
fn credential_error(e: CryptoError) -> AccountError {
    match e {
        CryptoError::Decrypt => AccountError::InvalidCredentials,
        e => AccountError::Internal(anyhow!("stored key wrap unusable: {e}")),
    }
}

fn kdf_error(e: CryptoError) -> AccountError {
    AccountError::Internal(anyhow!("password key derivation: {e}"))
}

fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    fill_random(&mut salt);
    salt
}

fn build_totp(secret: Secret, account_name: &str) -> Result<Totp, TotpError> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(TOTP_ISSUER))
        .with_account_name(account_name)
        .build()
}

fn totp_setup(secret: Secret, username: &str) -> Result<TotpSetup, TotpError> {
    // ':' separates issuer and account in the otpauth label and is rejected there.
    let account = username.replace(':', "_");
    let totp = build_totp(secret, &account)?;
    Ok(TotpSetup {
        secret_b32: totp.secret().to_base32(),
        otpauth_url: totp.to_url().unwrap_or_default(),
        qr_png_base64: totp.to_qr_base64().unwrap_or_default(),
    })
}

/// Check a user-typed code (whitespace is ignored) against the current time.
fn totp_code_valid(secret: Secret, code: &str) -> bool {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    match build_totp(secret, "") {
        Ok(totp) => totp.check_current(&code).is_some(),
        Err(_) => false,
    }
}

impl Accounts {
    pub fn new(cfg: &Config, sys: Arc<SystemDb>, keyring: Arc<Keyring>) -> Accounts {
        Accounts {
            sys,
            keyring,
            data_dir: cfg.data_dir.clone(),
            argon2: cfg.argon2,
            public_url: cfg.public_url.trim_end_matches('/').to_string(),
        }
    }

    /// Create a single-use invite valid for 7 days and return its full URL.
    /// Only the SHA-256 of the token is stored.
    pub fn create_invite(&self, role: Role, now: i64) -> anyhow::Result<String> {
        let mut raw = Zeroizing::new([0u8; 32]);
        fill_random(raw.as_mut());
        let hash: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        self.sys
            .create_invite(hash, role, now, now + INVITE_TTL_SECS)?;
        Ok(format!(
            "{}/invite/{}",
            self.public_url,
            hex::encode(raw.as_slice())
        ))
    }

    /// Wrap `umk` under a fresh salt and the current default Argon2 parameters.
    fn new_password_wrap(
        &self,
        user_id: &str,
        password: &str,
        umk: &Key32,
    ) -> Result<([u8; 16], Vec<u8>), AccountError> {
        let salt = random_salt();
        let kek = password_kek(password, &salt, &self.argon2).map_err(kdf_error)?;
        let wrapped = wrap_key(&kek, umk, aad::umk_password(user_id).as_bytes());
        Ok((salt, wrapped))
    }

    /// A new recovery key with its wrap and its pending copy (the key sealed
    /// under the UMK, kept until the user confirms having saved it).
    fn new_recovery_wrap(user_id: &str, umk: &Key32) -> (RecoveryKey, Vec<u8>, Vec<u8>) {
        let rk = RecoveryKey::generate();
        let kek = secret_kek(rk.secret(), INFO_RECOVERY);
        let wrapped = wrap_key(&kek, umk, aad::umk_recovery(user_id).as_bytes());
        let pending = seal(umk, rk.secret(), aad::pending_recovery(user_id).as_bytes());
        (rk, wrapped, pending)
    }

    fn unwrap_with_password(&self, row: &UserRow, password: &str) -> Result<Key32, AccountError> {
        let kek = password_kek(password, &row.salt, &row.argon2).map_err(kdf_error)?;
        unwrap_key(
            &kek,
            &row.umk_by_password,
            aad::umk_password(&row.id).as_bytes(),
        )
        .map_err(credential_error)
    }

    pub fn signup(
        &self,
        invite_token: &str,
        username: &str,
        password: &str,
        now: i64,
    ) -> Result<(Arc<Unlocked>, UserRow, RecoveryKey), AccountError> {
        // Validate the invite first (read-only) so that an unauthenticated
        // caller can never learn whether a username exists.
        let mut raw = Zeroizing::new([0u8; 32]);
        if invite_token.len() != 64 || hex::decode_to_slice(invite_token, raw.as_mut()).is_err() {
            return Err(InviteError::NotFound.into());
        }
        let hash: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        self.sys.invite_status(hash, now)?;

        let username = normalize_username(username)?;
        check_password_strength(password)?;
        if self.sys.user_by_name(&username)?.is_some() {
            return Err(AccountError::UsernameTaken);
        }
        let role = self.sys.consume_invite(hash, now)?;

        let id = uuid::Uuid::new_v4().to_string();
        let umk = Key32::random();
        let dir = user_dir(&self.data_dir, &id);
        let created = self.create_user(&id, &username, role, password, &umk, now);
        let (row, recovery) = match created {
            Ok(v) => v,
            Err(e) => {
                // The invite stays consumed; only the half-created directory is removed.
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let unlocked = self.keyring.unlock(&id, umk, &row.index_key_wrapped)?;
        Ok((unlocked, row, recovery))
    }

    /// Create the key wraps, `users/{id}/blobs/`, the index DB and the user row.
    fn create_user(
        &self,
        id: &str,
        username: &str,
        role: Role,
        password: &str,
        umk: &Key32,
        now: i64,
    ) -> Result<(UserRow, RecoveryKey), AccountError> {
        let (salt, umk_by_password) = self.new_password_wrap(id, password, umk)?;
        let (recovery, umk_by_recovery, pending) = Self::new_recovery_wrap(id, umk);
        let index_key = Key32::random();
        let index_key_wrapped = wrap_key(umk, &index_key, aad::index_key(id).as_bytes());

        std::fs::create_dir_all(user_dir(&self.data_dir, id).join("blobs"))
            .context("creating user directory")?;
        // Create and migrate the index DB now; the keyring reopens it on unlock.
        drop(open_user_db(
            &index_db_path(&self.data_dir, id),
            &index_key,
        )?);

        let row = UserRow {
            id: id.to_string(),
            username: username.to_string(),
            role,
            disabled: false,
            created_at: now,
            salt,
            argon2: self.argon2,
            umk_by_password,
            umk_by_recovery,
            index_key_wrapped,
            totp_sealed: None,
            pending_recovery_sealed: Some(pending),
        };
        match self.sys.insert_user(&row) {
            Ok(()) => Ok((row, recovery)),
            Err(SysError::UsernameTaken) => Err(AccountError::UsernameTaken),
            Err(e) => Err(AccountError::Internal(e.into())),
        }
    }

    pub fn login(
        &self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<(Arc<Unlocked>, UserRow), AccountError> {
        let Some(row) = self.sys.user_by_name(&username.to_lowercase())? else {
            // Spend about as long as a real attempt so unknown usernames are
            // not distinguishable by timing.
            let _ = password_kek(password, &[0u8; 16], &self.argon2);
            return Err(AccountError::InvalidCredentials);
        };
        let umk = self.unwrap_with_password(&row, password)?;
        // Only someone who knows the password learns that the account is disabled.
        if row.disabled {
            return Err(AccountError::Disabled);
        }
        if let Some(sealed) = &row.totp_sealed {
            let secret = open(&umk, sealed, aad::totp(&row.id).as_bytes())
                .map_err(|e| anyhow!("stored TOTP secret unusable: {e}"))?;
            let code = totp_code.ok_or(AccountError::InvalidCredentials)?;
            if !totp_code_valid(Secret::from(secret.as_slice()), code) {
                return Err(AccountError::InvalidCredentials);
            }
        }
        let unlocked = self.keyring.unlock(&row.id, umk, &row.index_key_wrapped)?;
        Ok((unlocked, row))
    }

    /// Recovery-key login: skips TOTP, sets a new password, rotates the
    /// recovery key and clears TOTP (the authenticator may be lost).
    /// Returns the new recovery key.
    pub fn recover(
        &self,
        username: &str,
        recovery_key: &str,
        new_password: &str,
    ) -> Result<(Arc<Unlocked>, UserRow, RecoveryKey), AccountError> {
        let row = self
            .sys
            .user_by_name(&username.to_lowercase())?
            .ok_or(AccountError::InvalidCredentials)?;
        let old = RecoveryKey::parse(recovery_key).map_err(|_| AccountError::InvalidCredentials)?;
        let umk = unwrap_key(
            &secret_kek(old.secret(), INFO_RECOVERY),
            &row.umk_by_recovery,
            aad::umk_recovery(&row.id).as_bytes(),
        )
        .map_err(credential_error)?;
        if row.disabled {
            return Err(AccountError::Disabled);
        }
        check_password_strength(new_password)?;

        let (salt, by_password) = self.new_password_wrap(&row.id, new_password, &umk)?;
        let (new_recovery, by_recovery, pending) = Self::new_recovery_wrap(&row.id, &umk);
        self.sys
            .set_password_wrap(&row.id, salt, self.argon2, &by_password)?;
        self.sys.replace_recovery(&row.id, &by_recovery, &pending)?;
        // The authenticator may be lost; the user re-enables TOTP afterwards.
        self.sys.set_totp(&row.id, None)?;

        let row = UserRow {
            salt,
            argon2: self.argon2,
            umk_by_password: by_password,
            umk_by_recovery: by_recovery,
            totp_sealed: None,
            pending_recovery_sealed: Some(pending),
            ..row
        };
        let unlocked = self.keyring.unlock(&row.id, umk, &row.index_key_wrapped)?;
        Ok((unlocked, row, new_recovery))
    }

    /// Verify `current` by unwrapping the UMK, then re-wrap it under `new` with
    /// a fresh salt and the current default Argon2 parameters.
    pub fn change_password(
        &self,
        user_id: &str,
        current: &str,
        new: &str,
    ) -> Result<(), AccountError> {
        let row = self
            .sys
            .user_by_id(user_id)?
            .ok_or(AccountError::InvalidCredentials)?;
        let umk = self.unwrap_with_password(&row, current)?;
        check_password_strength(new)?;
        let (salt, wrapped) = self.new_password_wrap(&row.id, new, &umk)?;
        self.sys
            .set_password_wrap(&row.id, salt, self.argon2, &wrapped)?;
        Ok(())
    }

    /// Replace the recovery wrap with one for a newly generated recovery key.
    pub fn regenerate_recovery(&self, u: &Unlocked) -> Result<RecoveryKey, AccountError> {
        let (recovery, wrapped, pending) = Self::new_recovery_wrap(&u.user_id, u.umk());
        self.sys.replace_recovery(&u.user_id, &wrapped, &pending)?;
        Ok(recovery)
    }

    /// The recovery key the user has not confirmed saving yet, if any.
    pub fn pending_recovery(&self, u: &Unlocked) -> Result<Option<RecoveryKey>, AccountError> {
        let Some(row) = self.sys.user_by_id(&u.user_id)? else {
            return Err(AccountError::InvalidCredentials);
        };
        let Some(sealed) = row.pending_recovery_sealed else {
            return Ok(None);
        };
        let bytes = open(
            u.umk(),
            &sealed,
            aad::pending_recovery(&u.user_id).as_bytes(),
        )
        .map_err(|e| anyhow!("stored pending recovery key unusable: {e}"))?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("stored pending recovery key has the wrong length"))?;
        Ok(Some(RecoveryKey::from_secret(key)))
    }

    /// The user confirmed saving the recovery key: forget the pending copy.
    pub fn confirm_recovery(&self, user_id: &str) -> anyhow::Result<()> {
        self.sys.clear_pending_recovery(user_id)
    }

    /// Check `password` against the stored password wrap without changing anything.
    pub fn verify_password(&self, user_id: &str, password: &str) -> Result<(), AccountError> {
        let row = self
            .sys
            .user_by_id(user_id)?
            .ok_or(AccountError::InvalidCredentials)?;
        self.unwrap_with_password(&row, password).map(|_| ())
    }

    /// Generate a new TOTP secret for the user to scan. Nothing is stored until
    /// [`Accounts::totp_enable`] confirms a code.
    pub fn totp_begin(&self, username: &str) -> TotpSetup {
        let mut bytes = Zeroizing::new([0u8; TOTP_SECRET_LEN]);
        fill_random(bytes.as_mut());
        totp_setup(Secret::from(*bytes), username)
            .expect("fixed TOTP parameters and a 20-byte secret are valid")
    }

    /// Rebuild the setup data (QR code, URL) for a secret from
    /// [`Accounts::totp_begin`], for example after a wrong confirmation code.
    pub fn totp_resume(&self, username: &str, secret_b32: &str) -> Result<TotpSetup, AccountError> {
        let secret =
            Secret::try_from_base32(secret_b32).map_err(|_| AccountError::InvalidCredentials)?;
        totp_setup(secret, username).map_err(|_| AccountError::InvalidCredentials)
    }

    /// Confirm `code` against the secret from [`Accounts::totp_begin`] and store
    /// the secret sealed under the UMK. Refuses if TOTP is already enabled.
    pub fn totp_enable(
        &self,
        u: &Unlocked,
        secret_b32: &str,
        code: &str,
    ) -> Result<(), AccountError> {
        let row = self
            .sys
            .user_by_id(&u.user_id)?
            .ok_or(AccountError::InvalidCredentials)?;
        if row.totp_sealed.is_some() {
            return Err(AccountError::TotpAlreadyEnabled);
        }
        let secret =
            Secret::try_from_base32(secret_b32).map_err(|_| AccountError::InvalidCredentials)?;
        if !totp_code_valid(secret.clone(), code) {
            return Err(AccountError::InvalidCredentials);
        }
        let sealed = seal(u.umk(), secret.as_bytes(), aad::totp(&u.user_id).as_bytes());
        self.sys.set_totp(&u.user_id, Some(&sealed))?;
        Ok(())
    }

    /// Turn TOTP off after verifying a current code. A no-op if it is not enabled.
    pub fn totp_disable(&self, u: &Unlocked, code: &str) -> Result<(), AccountError> {
        let row = self
            .sys
            .user_by_id(&u.user_id)?
            .ok_or(AccountError::InvalidCredentials)?;
        let Some(sealed) = &row.totp_sealed else {
            return Ok(());
        };
        let secret = open(u.umk(), sealed, aad::totp(&u.user_id).as_bytes())
            .map_err(|e| anyhow!("stored TOTP secret unusable: {e}"))?;
        if !totp_code_valid(Secret::from(secret.as_slice()), code) {
            return Err(AccountError::InvalidCredentials);
        }
        self.sys.set_totp(&u.user_id, None)?;
        Ok(())
    }

    /// False for unknown users and when the system DB cannot be read.
    pub fn totp_enabled(&self, user_id: &str) -> bool {
        matches!(self.sys.user_by_id(user_id), Ok(Some(row)) if row.totp_sealed.is_some())
    }

    pub fn set_disabled(&self, user_id: &str, disabled: bool) -> anyhow::Result<()> {
        self.sys.set_disabled(user_id, disabled)
    }

    /// Remove the user's system rows (tokens cascade) and `users/{id}` recursively.
    pub fn delete_user(&self, user_id: &str) -> anyhow::Result<()> {
        // User IDs are server-generated UUIDs; refuse anything else so a bad
        // caller can never make this remove a path outside `users/`.
        anyhow::ensure!(
            uuid::Uuid::try_parse(user_id).is_ok(),
            "invalid user id for deletion"
        );
        self.sys.delete_user(user_id)?;
        match std::fs::remove_dir_all(user_dir(&self.data_dir, user_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("removing user directory"),
        }
    }
}
