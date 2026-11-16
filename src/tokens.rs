//! MCP access tokens: creation, revocation and bearer authentication.
//!
//! A token is `pm_{id: 32 hex}_{secret: 64 hex}`. The system DB row holds the
//! user's UMK wrapped under a key derived from the secret, so the server can
//! only unlock the user while a token is presented. The name and scope live in
//! the user's encrypted index DB, never in the system DB.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{INFO_TOKEN, aad, fill_random, secret_kek, unwrap_key, wrap_key};
use crate::keyring::Unlocked;
use crate::system_db::SystemDb;
use crate::user_db::{
    Access, AccessFilter, Channel, Content, Level, ListFilter, TokenMeta, TokenScope,
    delete_token_meta, get_token_meta, insert_token_meta, list_tags, touch_token,
};
use crate::web::AppState;

/// How long an unused cache entry survives.
pub const CACHE_IDLE: Duration = Duration::from_secs(5 * 60);
/// `last_used_at` is written at most this often per token.
const TOUCH_EVERY: Duration = Duration::from_secs(60);

struct CacheEntry {
    unlocked: Arc<Unlocked>,
    scope: TokenScope,
    /// SHA-256 of the full token string, compared in constant time on a hit.
    token_hash: [u8; 32],
    last_used: Instant,
    last_touch: Instant,
}

/// Cache of unlocked state for recently used MCP tokens, keyed by token id.
#[derive(Default)]
pub struct TokenCache {
    map: Mutex<HashMap<String, CacheEntry>>,
}

impl TokenCache {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, CacheEntry>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop the cached unlock for one token (after it is revoked).
    pub fn evict(&self, token_id: &str) {
        self.lock().remove(token_id);
    }

    /// Drop every cached unlock of a user (disable, delete, password change).
    pub fn evict_user(&self, user_id: &str) {
        self.lock().retain(|_, e| e.unlocked.user_id != user_id);
    }

    /// Drop entries idle for [`CACHE_IDLE`].
    pub fn sweep(&self) {
        self.lock()
            .retain(|_, e| e.last_used.elapsed() < CACHE_IDLE);
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An authenticated MCP/API caller.
#[derive(Clone)]
pub struct Principal {
    pub unlocked: Arc<Unlocked>,
    pub token_id: String,
    pub scope: TokenScope,
}

impl Principal {
    /// The content level this token may read.
    pub fn cap(&self) -> Level {
        match self.scope.content {
            Content::MetadataOnly => Level::Metadata,
            Content::FullText => Level::Full,
        }
    }

    pub fn can_write(&self) -> bool {
        self.scope.access == Access::ReadWrite
    }

    /// The filter every read of this token starts from: switchboard channel
    /// `Mcp` capped by the token, plus the tag allow-list.
    pub fn filter(&self) -> ListFilter {
        ListFilter {
            access: Some(AccessFilter {
                channel: Channel::Mcp,
                cap: self.cap(),
            }),
            tag_allow: self.scope.tags.clone(),
            ..ListFilter::default()
        }
    }

    /// Names of the allowed tags in scope order (`None` = no restriction).
    pub fn allowed_tag_names(
        &self,
        conn: &rusqlite::Connection,
    ) -> anyhow::Result<Option<Vec<String>>> {
        let Some(ids) = &self.scope.tags else {
            return Ok(None);
        };
        let all = list_tags(conn)?;
        Ok(Some(
            ids.iter()
                .filter_map(|id| all.iter().find(|(i, _)| i == id).map(|(_, n)| n.clone()))
                .collect(),
        ))
    }

    /// For a token with a tag allow-list: `tags` with the first allowed tag
    /// added when none of them is allowed. Fails when no allowed tag exists.
    pub fn tags_for_upload(
        &self,
        conn: &rusqlite::Connection,
        tags: Vec<String>,
    ) -> anyhow::Result<Vec<String>> {
        let Some(allowed) = self.allowed_tag_names(conn)? else {
            return Ok(tags);
        };
        if tags.iter().any(|t| allowed.iter().any(|a| a == t.trim())) {
            return Ok(tags);
        }
        let first = allowed
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("token has no usable tag"))?;
        let mut tags = tags;
        tags.push(first);
        Ok(tags)
    }
}

/// Authentication failed. Carries no detail on purpose.
#[derive(Debug)]
pub struct AuthFail;

pub(crate) fn parse_bearer(bearer: &str) -> Option<&str> {
    let rest = bearer.strip_prefix("pm_")?;
    let (id, secret) = rest.split_once('_')?;
    let hex_ok = |s: &str, n: usize| {
        s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    (hex_ok(id, 32) && hex_ok(secret, 64)).then_some(id)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Authenticate a bearer token. Blocking (SQLite); call from a blocking context.
///
/// The system rows (token and user) are read on every call, cache hit or not,
/// so a revoked token, a disabled user or a deleted user fails at once.
pub fn authenticate(state: &AppState, bearer: &str) -> Result<Principal, AuthFail> {
    let id = parse_bearer(bearer).ok_or(AuthFail)?;
    let hash: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();

    let (user_id, wrapped) = state
        .sys
        .token(id)
        .map_err(|e| {
            tracing::error!(error = %e, "token lookup failed");
            AuthFail
        })?
        .ok_or(AuthFail)?;
    let user = state
        .sys
        .user_by_id(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "user lookup failed");
            AuthFail
        })?
        .ok_or(AuthFail)?;
    if user.disabled {
        return Err(AuthFail);
    }

    // Cache hit.
    let hit = {
        let mut map = state.tokens.lock();
        match map.get_mut(id) {
            Some(e) if e.last_used.elapsed() >= CACHE_IDLE => {
                map.remove(id);
                None
            }
            Some(e) => {
                if e.unlocked.user_id != user_id || !ct_eq(&e.token_hash, &hash) {
                    return Err(AuthFail);
                }
                e.last_used = Instant::now();
                let touch = e.last_touch.elapsed() >= TOUCH_EVERY;
                if touch {
                    e.last_touch = Instant::now();
                }
                Some((e.unlocked.clone(), e.scope.clone(), touch))
            }
            None => None,
        }
    };
    if let Some((unlocked, scope, touch)) = hit {
        if touch {
            touch_meta(&unlocked, id);
        }
        return Ok(Principal {
            unlocked,
            token_id: id.to_owned(),
            scope,
        });
    }

    // Miss: unwrap the UMK with the secret and unlock.
    let secret_hex = &bearer[bearer.len() - 64..];
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(secret_hex, secret.as_mut()).map_err(|_| AuthFail)?;
    let kek = secret_kek(&secret, INFO_TOKEN);
    let umk = unwrap_key(&kek, &wrapped, aad::umk_token(id).as_bytes()).map_err(|_| AuthFail)?;
    let unlocked = state
        .keyring
        .unlock(&user_id, umk, &user.index_key_wrapped)
        .map_err(|e| {
            tracing::error!(error = %e, "token unlock failed");
            AuthFail
        })?;
    let meta = unlocked
        .with_db(|c| get_token_meta(c, id))
        .map_err(|e| {
            tracing::error!(error = %e, "token meta lookup failed");
            AuthFail
        })?
        .ok_or(AuthFail)?;
    touch_meta(&unlocked, id);
    let now = Instant::now();
    state.tokens.lock().insert(
        id.to_owned(),
        CacheEntry {
            unlocked: unlocked.clone(),
            scope: meta.scope.clone(),
            token_hash: hash,
            last_used: now,
            last_touch: now,
        },
    );
    Ok(Principal {
        unlocked,
        token_id: id.to_owned(),
        scope: meta.scope,
    })
}

fn touch_meta(u: &Unlocked, id: &str) {
    if let Err(e) = u.with_db(|c| touch_token(c, id, now_secs())) {
        tracing::warn!(error = %e, "could not update token last_used_at");
    }
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
