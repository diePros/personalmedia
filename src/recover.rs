//! Offline recovery: decrypt a user's documents straight from the data
//! directory with their password or recovery key. No server, no `Accounts`,
//! no rate limiting: whoever can read the data directory and knows the secret
//! can already do this.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use zeroize::Zeroizing;

use crate::crypto::{INFO_RECOVERY, Key32, RecoveryKey, aad, password_kek, secret_kek, unwrap_key};
use crate::documents::{Documents, Enqueue};
use crate::export::{all_documents, metadata_json, plan_entries};
use crate::keyring::Unlocked;
use crate::system_db::{SYSTEM_DB_FILE, SystemDb, UserRow};

/// The secret a user proves themselves with.
pub enum Secret {
    Password(Zeroizing<String>),
    RecoveryKey(Zeroizing<String>),
}

/// Why a recovery did not run to completion.
#[derive(Debug)]
pub enum RecoverError {
    /// `--out` exists and is not an empty directory. Nothing was touched.
    OutNotEmpty(PathBuf),
    /// Unknown user or wrong secret. Deliberately indistinguishable.
    CouldNotUnlock,
    Other(anyhow::Error),
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoverError::OutNotEmpty(p) => write!(
                f,
                "output directory {} exists and is not empty; choose a new or empty directory",
                p.display()
            ),
            RecoverError::CouldNotUnlock => {
                write!(f, "could not unlock: unknown user or wrong secret")
            }
            RecoverError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl From<anyhow::Error> for RecoverError {
    fn from(e: anyhow::Error) -> Self {
        RecoverError::Other(e)
    }
}

/// Nothing is ever extracted offline.
struct NoQueue;

impl Enqueue for NoQueue {
    fn enqueue(&self, _: Arc<Unlocked>, _: String) {}
}

fn unwrap_umk(row: &UserRow, secret: &Secret) -> Option<Key32> {
    match secret {
        Secret::Password(pw) => {
            let kek = password_kek(pw, &row.salt, &row.argon2).ok()?;
            unwrap_key(
                &kek,
                &row.umk_by_password,
                aad::umk_password(&row.id).as_bytes(),
            )
            .ok()
        }
        Secret::RecoveryKey(rk) => {
            let rk = RecoveryKey::parse(rk).ok()?;
            let kek = secret_kek(rk.secret(), INFO_RECOVERY);
            unwrap_key(
                &kek,
                &row.umk_by_recovery,
                aad::umk_recovery(&row.id).as_bytes(),
            )
            .ok()
        }
    }
}

/// `out` must not exist, or be an empty directory.
fn check_out(out: &Path) -> Result<(), RecoverError> {
    match fs::read_dir(out) {
        Ok(mut it) => {
            if it.next().is_some() {
                return Err(RecoverError::OutNotEmpty(out.to_path_buf()));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        // Exists but is not a readable directory (e.g. a file).
        Err(_) => Err(RecoverError::OutNotEmpty(out.to_path_buf())),
    }
}

fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
    {
        Ok(()) => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
    }
    // An existing empty directory keeps its mode otherwise.
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting permissions on {}", path.display()))?;
    Ok(())
}

/// Decrypt every document of `username` into `out/files/…` plus
/// `out/metadata.json`, and return how many were written.
pub fn recover(
    data_dir: &Path,
    username: &str,
    secret: &Secret,
    out: &Path,
) -> Result<usize, RecoverError> {
    check_out(out)?;
    let sys_path = data_dir.join(SYSTEM_DB_FILE);
    if !sys_path.exists() {
        return Err(anyhow::anyhow!("no {SYSTEM_DB_FILE} in {}", data_dir.display()).into());
    }
    let sys = SystemDb::open_readonly(&sys_path)?;
    let row = sys
        .user_by_name(&username.to_lowercase())?
        .ok_or(RecoverError::CouldNotUnlock)?;
    let umk = unwrap_umk(&row, secret).ok_or(RecoverError::CouldNotUnlock)?;
    let u = Unlocked::open_readonly(data_dir, &row.id, umk, &row.index_key_wrapped)?;

    let all = all_documents(&u)?;
    let plan = plan_entries(&all);
    let docs = Documents::new(data_dir.to_path_buf(), 0, Arc::new(NoQueue));

    create_private_dir(out)?;
    create_private_dir(&out.join("files"))?;
    for (id, rel) in &plan {
        let (_, mut reader) = docs
            .open_plaintext(&u, id)
            .map_err(|e| anyhow::anyhow!("opening a document: {e}"))?;
        let mut f = fs::File::create(out.join(rel)).context("creating output file")?;
        io::copy(&mut reader, &mut f).context("decrypting a document")?;
        f.flush().context("writing output file")?;
    }
    fs::write(out.join("metadata.json"), metadata_json(&all, &plan)?)
        .context("writing metadata.json")?;
    Ok(all.len())
}
