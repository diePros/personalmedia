//! MCP access tokens: creation and revocation (Task 12). Authentication comes
//! in Task 14.
//!
//! A token is `pm_{id: 32 hex}_{secret: 64 hex}`. The system DB row holds the
//! user's UMK wrapped under a key derived from the secret, so the server can
//! only unlock the user while a token is presented. The name and scope live in
//! the user's encrypted index DB, never in the system DB.

use anyhow::{Context, bail};
use zeroize::Zeroizing;

use crate::crypto::{INFO_TOKEN, aad, fill_random, secret_kek, wrap_key};
use crate::keyring::Unlocked;
use crate::system_db::SystemDb;
use crate::user_db::{TokenMeta, TokenScope, delete_token_meta, get_token_meta, insert_token_meta};

/// Cache of unlocked state for recently used MCP tokens.
#[derive(Default)]
pub struct TokenCache {}

impl TokenCache {
    /// Drop the cached unlock for one token (after it is revoked).
    pub fn evict(&self, _token_id: &str) {}

    /// Drop every cached unlock of a user (disable, delete, password change).
    pub fn evict_user(&self, _user_id: &str) {}
}

/// Create a token for `u`. Returns the full token string; it cannot be
/// recovered later. The system row is written first; if the metadata insert
/// fails the system row is removed again.
pub fn create_token(
    sys: &SystemDb,
    u: &Unlocked,
    name: &str,
    scope: TokenScope,
    now: i64,
) -> anyhow::Result<String> {
    let mut id_bytes = [0u8; 16];
    fill_random(&mut id_bytes);
    let id = hex::encode(id_bytes);
    let mut secret = Zeroizing::new([0u8; 32]);
    fill_random(secret.as_mut());
    let secret_hex = Zeroizing::new(hex::encode(secret.as_slice()));

    let kek = secret_kek(&secret, INFO_TOKEN);
    let wrapped = wrap_key(&kek, u.umk(), aad::umk_token(&id).as_bytes());
    sys.insert_token(&id, &u.user_id, &wrapped)
        .context("storing token")?;

    let meta = TokenMeta {
        id: id.clone(),
        name: name.to_owned(),
        scope,
        created_at: now,
        last_used_at: None,
    };
    if let Err(e) = u.with_db(|c| insert_token_meta(c, &meta)) {
        if let Err(e2) = sys.delete_token(&id) {
            tracing::error!(error = %e2, "could not roll back token row");
        }
        return Err(e.context("storing token metadata"));
    }
    Ok(format!("pm_{id}_{}", secret_hex.as_str()))
}

/// Delete both rows of one of `u`'s tokens and evict it from the cache.
/// Fails if `token_id` is not one of `u`'s tokens.
pub fn revoke_token(
    sys: &SystemDb,
    u: &Unlocked,
    token_id: &str,
    cache: &TokenCache,
) -> anyhow::Result<()> {
    if u.with_db(|c| get_token_meta(c, token_id))?.is_none() {
        bail!("unknown token");
    }
    // The system row is what grants access, so it goes first.
    sys.delete_token(token_id)?;
    u.with_db(|c| delete_token_meta(c, token_id))?;
    cache.evict(token_id);
    Ok(())
}
