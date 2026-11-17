//! Remembered devices: a `pmd_{id}_{secret}` token kept in a cookie lets a
//! browser resume without the password. Like MCP tokens, the system row holds
//! the UMK wrapped under a key derived from the secret; label and last use
//! live in the user's index DB. Device tokens expire (sliding) and are never
//! valid MCP bearers.

use std::sync::Arc;

use anyhow::Context;
use zeroize::Zeroizing;

use crate::crypto::{INFO_DEVICE, Key32, aad, fill_random, secret_kek, unwrap_key, wrap_key};
use crate::keyring::Unlocked;
use crate::system_db::{SystemDb, UserRow};
use crate::tokens::split_token;
use crate::user_db::{
    DeviceMeta, delete_all_device_meta, delete_device_meta, insert_device_meta, list_device_meta,
    touch_device_meta,
};
use crate::web::AppState;

/// `tokens.kind` of a device row.
const KIND_DEVICE: &str = "device";
const PREFIX: &str = "pmd_";
/// Lifetime of a device token, renewed on use.
pub const DEVICE_TTL_SECS: i64 = 90 * 24 * 3600;
/// Remembered devices per user; the least recently used one is evicted.
pub const MAX_DEVICES: usize = 20;
/// The expiry is pushed out at most this often.
const SLIDE_EVERY_SECS: i64 = 24 * 3600;

/// Creates a device token for `u`. Returns the full `pmd_…` token; it cannot
/// be recovered later. The system row is written first and removed again if
/// the metadata insert fails.
pub fn create_device(
    sys: &SystemDb,
    u: &Unlocked,
    label: &str,
    now: i64,
) -> anyhow::Result<String> {
    let mut id_bytes = [0u8; 16];
    fill_random(&mut id_bytes);
    let id = hex::encode(id_bytes);
    let mut secret = Zeroizing::new([0u8; 32]);
    fill_random(secret.as_mut());
    let secret_hex = Zeroizing::new(hex::encode(secret.as_slice()));

    let kek = secret_kek(&secret, INFO_DEVICE);
    let wrapped = wrap_key(&kek, u.umk(), aad::umk_device(&id).as_bytes());
    sys.insert_device_token(&id, &u.user_id, &wrapped, now + DEVICE_TTL_SECS)
        .context("storing device token")?;

    let meta = DeviceMeta {
        id: id.clone(),
        label: label.to_owned(),
        created_at: now,
        last_used_at: None,
    };
    if let Err(e) = u.with_db(|c| insert_device_meta(c, &meta)) {
        if let Err(e2) = sys.delete_token(&id) {
            tracing::error!(error = %e2, "could not roll back device row");
        }
        return Err(e.context("storing device metadata"));
    }

    // Over the cap: evict the least recently used (the list is newest first),
    // never the device just created. A failure here must not lose the token.
    if let Err(e) = evict_over_cap(sys, u, &id) {
        tracing::error!(error = %e, "could not evict old devices");
    }
    Ok(format!("{PREFIX}{id}_{}", secret_hex.as_str()))
}

fn evict_over_cap(sys: &SystemDb, u: &Unlocked, keep: &str) -> anyhow::Result<()> {
    let all = u.with_db(list_device_meta)?;
    for old in all.iter().skip(MAX_DEVICES).filter(|d| d.id != keep) {
        sys.delete_token(&old.id)?;
        u.with_db(|c| delete_device_meta(c, &old.id))?;
    }
    Ok(())
}

/// A successfully resumed device login.
pub struct Resumed {
    pub user: UserRow,
    pub unlocked: Arc<Unlocked>,
    pub device_id: String,
}

/// Why a resume failed. `genuine`: the secret was right but the row had
/// expired (the normal end of a device's life, not a guess).
#[derive(Debug)]
pub struct ResumeFail {
    pub genuine: bool,
}

impl ResumeFail {
    const BAD: ResumeFail = ResumeFail { genuine: false };
}

fn unwrap_with_secret(id: &str, secret_hex: &str, wrapped: &[u8]) -> Option<Key32> {
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(secret_hex, secret.as_mut()).ok()?;
    let kek = secret_kek(&secret, INFO_DEVICE);
    unwrap_key(&kek, wrapped, aad::umk_device(id).as_bytes()).ok()
}

/// Resumes a login from a `pmd_` token. Blocking (SQLite).
pub fn resume_device(state: &AppState, token: &str, now: i64) -> Result<Resumed, ResumeFail> {
    let (id, secret_hex) = split_token(token, PREFIX).ok_or(ResumeFail::BAD)?;
    let row = state
        .sys
        .token_full(id)
        .map_err(|e| {
            tracing::error!(error = %e, "device lookup failed");
            ResumeFail::BAD
        })?
        .ok_or(ResumeFail::BAD)?;
    if row.kind != KIND_DEVICE {
        return Err(ResumeFail::BAD);
    }
    let Some(expires_at) = row.expires_at else {
        return Err(ResumeFail::BAD);
    };
    let umk = unwrap_with_secret(id, secret_hex, &row.wrapped);
    if expires_at <= now {
        return Err(ResumeFail {
            genuine: umk.is_some(),
        });
    }
    let umk = umk.ok_or(ResumeFail::BAD)?;
    let user = state
        .sys
        .user_by_id(&row.user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "user lookup failed");
            ResumeFail::BAD
        })?
        .ok_or(ResumeFail::BAD)?;
    if user.disabled {
        return Err(ResumeFail::BAD);
    }
    let unlocked = state
        .keyring
        .unlock(&row.user_id, umk, &user.index_key_wrapped)
        .map_err(|e| {
            tracing::error!(error = %e, "device unlock failed");
            ResumeFail::BAD
        })?;

    // Sliding expiry, written at most once a day.
    if expires_at < now + DEVICE_TTL_SECS - SLIDE_EVERY_SECS
        && let Err(e) = state.sys.set_token_expiry(id, now + DEVICE_TTL_SECS)
    {
        tracing::warn!(error = %e, "could not extend device expiry");
    }
    if let Err(e) = unlocked.with_db(|c| touch_device_meta(c, id, now)) {
        tracing::warn!(error = %e, "could not update device last_used_at");
    }
    Ok(Resumed {
        user,
        unlocked,
        device_id: id.to_owned(),
    })
}

/// Revokes one of `u`'s devices. False if it is not one of theirs.
pub fn revoke_device(sys: &SystemDb, u: &Unlocked, device_id: &str) -> anyhow::Result<bool> {
    let mine = u
        .with_db(list_device_meta)?
        .iter()
        .any(|d| d.id == device_id);
    if !mine {
        return Ok(false);
    }
    // The system row is what grants access, so it goes first.
    sys.delete_token(device_id)?;
    u.with_db(|c| delete_device_meta(c, device_id))?;
    Ok(true)
}

/// Revokes every device of `u` (MCP tokens are untouched). Returns how many.
pub fn revoke_all_devices(sys: &SystemDb, u: &Unlocked) -> anyhow::Result<usize> {
    let ids = sys.delete_device_tokens(&u.user_id)?;
    u.with_db(delete_all_device_meta)?;
    Ok(ids.len())
}

/// A short "{platform} · {browser}" label from a User-Agent.
pub fn device_label(user_agent: &str) -> String {
    let ua = user_agent;
    let has = |s: &str| ua.contains(s);
    // iOS UAs say "like Mac OS X" and Android ones "Linux", so order matters.
    let platform = if has("iPhone") {
        "iPhone"
    } else if has("iPad") {
        "iPad"
    } else if has("Android") {
        "Android"
    } else if has("Mac") {
        "Mac"
    } else if has("Windows") {
        "Windows"
    } else if has("Linux") {
        "Linux"
    } else {
        "Unknown device"
    };
    // Chrome-based UAs also say "Safari", Edge also "Chrome".
    let browser = if has("Firefox/") || has("FxiOS") {
        "Firefox"
    } else if has("Edg/") {
        "Edge"
    } else if has("Chrome/") || has("CriOS") {
        "Chrome"
    } else if has("Safari")
        || ((has("iPhone") || has("iPad"))
            && has("AppleWebKit")
            && !has("CriOS")
            && !has("FxiOS")
            && !has("EdgiOS"))
    {
        // An installed iOS web app sends no "Safari/" token.
        "Safari"
    } else {
        "Browser"
    };
    format!("{platform} · {browser}").chars().take(60).collect()
}
