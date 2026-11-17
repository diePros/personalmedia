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

use crate::crypto::{INFO_TOKEN, Key32, aad, fill_random, secret_kek, unwrap_key, wrap_key};
use crate::keyring::Unlocked;
use crate::system_db::{OauthTokenRow, SystemDb};
use crate::user_db::{
    Access, AccessFilter, Channel, Content, GrantInfo, Level, ListFilter, TokenMeta, TokenScope,
    delete_token_meta, get_token_meta, insert_token_meta, list_tags, touch_token,
};
use crate::web::AppState;

/// `tokens.kind` values.
const KIND_STATIC: &str = "static";
const KIND_ACCESS: &str = "oauth_access";
const KIND_REFRESH: &str = "oauth_refresh";
/// OAuth access tokens are `pma_{id}_{secret}`, refresh tokens `pmr_{id}_{secret}`.
const ACCESS_PREFIX: &str = "pma_";
const REFRESH_PREFIX: &str = "pmr_";
/// Lifetime of an OAuth access token.
pub const ACCESS_TTL_SECS: i64 = 3600;
/// Lifetime of an OAuth refresh token.
pub const REFRESH_TTL_SECS: i64 = 30 * 24 * 3600;

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

/// Authentication failed. Carries no detail on purpose, except whether the
/// failure was a correctly signed but expired token (the normal hourly
/// lifecycle of an access token, which must not count as a guess).
#[derive(Debug)]
pub struct AuthFail {
    pub expired: bool,
}

impl AuthFail {
    const BAD: AuthFail = AuthFail { expired: false };
}

/// Splits `{prefix}{id: 32 hex}_{secret: 64 hex}` into `(id, secret)`.
fn split_token<'a>(token: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let rest = token.strip_prefix(prefix)?;
    let (id, secret) = rest.split_once('_')?;
    let hex_ok = |s: &str, n: usize| {
        s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    (hex_ok(id, 32) && hex_ok(secret, 64)).then_some((id, secret))
}

/// The token id of a well-formed bearer: a static `pm_` or an OAuth access
/// `pma_` token.
pub(crate) fn parse_bearer(bearer: &str) -> Option<&str> {
    split_token(bearer, "pm_")
        .or_else(|| split_token(bearer, ACCESS_PREFIX))
        .map(|(id, _)| id)
}

/// Unwraps the UMK of a token row with the secret in `token`.
fn unwrap_with_secret(token_id: &str, secret_hex: &str, wrapped: &[u8]) -> Option<Key32> {
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(secret_hex, secret.as_mut()).ok()?;
    let kek = secret_kek(&secret, INFO_TOKEN);
    unwrap_key(&kek, wrapped, aad::umk_token(token_id).as_bytes()).ok()
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
    let id = parse_bearer(bearer).ok_or(AuthFail::BAD)?;
    let is_access = bearer.starts_with(ACCESS_PREFIX);
    let hash: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();

    let row = state
        .sys
        .token_full(id)
        .map_err(|e| {
            tracing::error!(error = %e, "token lookup failed");
            AuthFail::BAD
        })?
        .ok_or(AuthFail::BAD)?;
    // The prefix must match the row's kind: a refresh token is never a bearer.
    let kind_ok = if is_access {
        row.kind == KIND_ACCESS
    } else {
        row.kind == KIND_STATIC
    };
    if !kind_ok {
        return Err(AuthFail::BAD);
    }
    if row.expires_at.is_some_and(|exp| exp <= now_secs()) {
        // Verify the secret before reporting expiry: only a token whose secret
        // is right is "expired" (not counted as a guess by the caller). The
        // row stays for the sweeper, so a client retrying with it is not
        // counted either.
        state.tokens.evict(id);
        let genuine = unwrap_with_secret(id, &bearer[bearer.len() - 64..], &row.wrapped).is_some();
        return Err(AuthFail { expired: genuine });
    }
    let user_id = row.user_id.clone();
    // Static tokens keep their metadata under the token id, grants under the
    // grant id.
    let meta_id = row.grant_id.clone().unwrap_or_else(|| id.to_owned());
    let user = state
        .sys
        .user_by_id(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "user lookup failed");
            AuthFail::BAD
        })?
        .ok_or(AuthFail::BAD)?;
    if user.disabled {
        return Err(AuthFail::BAD);
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
                    return Err(AuthFail::BAD);
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
            touch_meta(&unlocked, &meta_id);
        }
        return Ok(Principal {
            unlocked,
            token_id: id.to_owned(),
            scope,
        });
    }

    // Miss: unwrap the UMK with the secret and unlock.
    let umk =
        unwrap_with_secret(id, &bearer[bearer.len() - 64..], &row.wrapped).ok_or(AuthFail::BAD)?;
    let unlocked = state
        .keyring
        .unlock(&user_id, umk, &user.index_key_wrapped)
        .map_err(|e| {
            tracing::error!(error = %e, "token unlock failed");
            AuthFail::BAD
        })?;
    let meta = unlocked
        .with_db(|c| get_token_meta(c, &meta_id))
        .map_err(|e| {
            tracing::error!(error = %e, "token meta lookup failed");
            AuthFail::BAD
        })?
        .ok_or(AuthFail::BAD)?;
    touch_meta(&unlocked, &meta_id);
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
        grant: None,
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
    let Some(meta) = u.with_db(|c| get_token_meta(c, token_id))? else {
        bail!("unknown token");
    };
    if meta.grant.is_some() {
        return revoke_grant(sys, Some(u), token_id, cache);
    }
    // The system row is what grants access, so it goes first.
    sys.delete_token(token_id)?;
    u.with_db(|c| delete_token_meta(c, token_id))?;
    cache.evict(token_id);
    Ok(())
}

// ---------------------------------------------------------------------------
// OAuth grants
// ---------------------------------------------------------------------------

/// A freshly minted access/refresh pair. The strings exist only here and in
/// the in-memory authorization-code entry until the client has them.
pub struct IssuedPair {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    rows: Vec<OauthTokenRow>,
}

fn random_hex<const N: usize>() -> Zeroizing<String> {
    let mut b = Zeroizing::new([0u8; N]);
    fill_random(b.as_mut());
    Zeroizing::new(hex::encode(b.as_slice()))
}

/// Mints one token string and its wrapped row for `umk`.
fn mint_token(
    umk: &Key32,
    user_id: &str,
    grant_id: &str,
    prefix: &str,
    kind: &'static str,
    expires_at: i64,
) -> (Zeroizing<String>, OauthTokenRow) {
    let id = random_hex::<16>();
    let secret_hex = random_hex::<32>();
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(secret_hex.as_str(), secret.as_mut()).expect("hex we just made");
    let kek = secret_kek(&secret, INFO_TOKEN);
    let wrapped = wrap_key(&kek, umk, aad::umk_token(&id).as_bytes());
    let token = Zeroizing::new(format!("{prefix}{}_{}", id.as_str(), secret_hex.as_str()));
    (
        token,
        OauthTokenRow {
            token_id: id.to_string(),
            user_id: user_id.to_owned(),
            wrapped,
            kind,
            expires_at,
            grant_id: grant_id.to_owned(),
        },
    )
}

fn mint_pair(umk: &Key32, user_id: &str, grant_id: &str, now: i64) -> IssuedPair {
    let (access, a_row) = mint_token(
        umk,
        user_id,
        grant_id,
        ACCESS_PREFIX,
        KIND_ACCESS,
        now + ACCESS_TTL_SECS,
    );
    let (refresh, r_row) = mint_token(
        umk,
        user_id,
        grant_id,
        REFRESH_PREFIX,
        KIND_REFRESH,
        now + REFRESH_TTL_SECS,
    );
    IssuedPair {
        access,
        refresh,
        rows: vec![a_row, r_row],
    }
}

/// The OAuth scope string echoed in token responses.
pub fn scope_string(scope: &TokenScope) -> String {
    let mut out = String::from(match scope.access {
        Access::Read => "mcp:read",
        Access::ReadWrite => "mcp:write",
    });
    if scope.content == Content::FullText {
        out.push_str(" content:full");
    }
    out.push_str(" offline_access");
    out
}

/// Creates a grant for `u`: two wrapped system rows (access, refresh) under a
/// fresh `grant_id` plus the grant metadata in the user's index DB. Returns
/// the grant id and the plaintext pair. Rows are removed again if the metadata
/// insert fails.
pub fn create_grant(
    sys: &SystemDb,
    u: &Unlocked,
    scope: TokenScope,
    grant: GrantInfo,
    now: i64,
) -> anyhow::Result<(String, IssuedPair)> {
    let grant_id = random_hex::<16>().to_string();
    let pair = mint_pair(u.umk(), &u.user_id, &grant_id, now);
    sys.insert_oauth_pair(&pair.rows)
        .context("storing grant tokens")?;
    let meta = TokenMeta {
        id: grant_id.clone(),
        name: grant.client_name.clone(),
        scope,
        created_at: now,
        last_used_at: None,
        grant: Some(grant),
    };
    if let Err(e) = u.with_db(|c| insert_token_meta(c, &meta)) {
        if let Err(e2) = sys.delete_grant_tokens(&grant_id) {
            tracing::error!(error = %e2, "could not roll back grant rows");
        }
        return Err(e.context("storing grant metadata"));
    }
    Ok((grant_id, pair))
}

/// Deletes every token row of `grant_id`, evicts their cache entries and, when
/// `u` is given, the grant metadata. The system rows go first: they are what
/// grants access.
pub fn revoke_grant(
    sys: &SystemDb,
    u: Option<&Unlocked>,
    grant_id: &str,
    cache: &TokenCache,
) -> anyhow::Result<()> {
    let ids = sys.delete_grant_tokens(grant_id)?;
    for id in &ids {
        cache.evict(id);
    }
    if let Some(u) = u {
        u.with_db(|c| delete_token_meta(c, grant_id))?;
    }
    Ok(())
}

/// Removes grant metadata whose token rows no longer exist, e.g. a grant that
/// was revoked (or whose code expired unused) while the user was locked and
/// so could not be cleaned up then. Returns how many were removed. Static
/// tokens are never touched. Grant rows are inserted before their metadata, so
/// a grant being created right now is not an orphan.
pub fn prune_orphan_grants(sys: &SystemDb, u: &Unlocked) -> anyhow::Result<usize> {
    let metas = u.with_db(crate::user_db::list_token_meta)?;
    let mut removed = 0;
    for m in metas.iter().filter(|m| m.grant.is_some()) {
        if sys.token_ids_for_grant(&m.id)?.is_empty() {
            u.with_db(|c| delete_token_meta(c, &m.id))?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Why a refresh failed.
#[derive(Debug)]
pub enum RefreshError {
    /// The token is unknown, expired, consumed, for another client, or wrong.
    InvalidGrant,
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for RefreshError {
    fn from(e: anyhow::Error) -> Self {
        RefreshError::Internal(e)
    }
}

/// Result of a successful refresh.
pub struct Refreshed {
    pub pair: IssuedPair,
    pub scope: String,
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Exchanges a `pmr_` refresh token for a new pair under the same grant.
/// Blocking.
///
/// The old refresh and access rows are deleted and the new rows inserted in
/// one system-DB transaction, so a crash cannot leave two live refresh
/// tokens. The consumed id is remembered (memory only, see
/// `OAuthState::consumed_refresh`); presenting it again revokes the grant unless that happens within
/// `REFRESH_GRACE` of the rotation.
pub fn refresh_grant(
    state: &AppState,
    refresh_token: &str,
    client_id: &str,
) -> Result<Refreshed, RefreshError> {
    let (id, secret_hex) =
        split_token(refresh_token, REFRESH_PREFIX).ok_or(RefreshError::InvalidGrant)?;
    let hash = token_hash(refresh_token);
    let now = now_secs();

    let Some(row) = state.sys.token_full(id)? else {
        // Gone: either never existed or already used. A replay of a consumed
        // token (same full string) kills the whole grant, unless it comes
        // within the grace window of the rotation (a retry after a lost
        // response, or a parallel refresh): that only fails (ruling AF).
        if let Some((user_id, grant_id, in_grace)) = state.oauth.consumed_refresh(id, &hash)
            && !in_grace
        {
            tracing::warn!(grant = %grant_id, "refresh token reuse; revoking grant");
            let unlocked = state.keyring.get(&user_id);
            revoke_grant(&state.sys, unlocked.as_deref(), &grant_id, &state.tokens)?;
        }
        return Err(RefreshError::InvalidGrant);
    };
    if row.kind != KIND_REFRESH {
        return Err(RefreshError::InvalidGrant);
    }
    let grant_id = row.grant_id.clone().ok_or(RefreshError::InvalidGrant)?;
    if row.expires_at.is_none_or(|exp| exp <= now) {
        revoke_grant(
            &state.sys,
            state.keyring.get(&row.user_id).as_deref(),
            &grant_id,
            &state.tokens,
        )?;
        return Err(RefreshError::InvalidGrant);
    }
    let umk = unwrap_with_secret(id, secret_hex, &row.wrapped).ok_or(RefreshError::InvalidGrant)?;
    let user = state
        .sys
        .user_by_id(&row.user_id)?
        .ok_or(RefreshError::InvalidGrant)?;
    if user.disabled {
        return Err(RefreshError::InvalidGrant);
    }
    let unlocked = state
        .keyring
        .unlock(&row.user_id, umk, &user.index_key_wrapped)
        .map_err(|_| RefreshError::InvalidGrant)?;
    let Some(meta) = unlocked.with_db(|c| get_token_meta(c, &grant_id))? else {
        // The grant was revoked but rows survived: finish the job.
        revoke_grant(&state.sys, None, &grant_id, &state.tokens)?;
        return Err(RefreshError::InvalidGrant);
    };
    if meta.grant.as_ref().map(|g| g.client_id.as_str()) != Some(client_id) {
        return Err(RefreshError::InvalidGrant);
    }

    let pair = mint_pair(unlocked.umk(), &row.user_id, &grant_id, now);
    let old_ids = state.sys.token_ids_for_grant(&grant_id)?;
    if !state.sys.rotate_grant_tokens(id, &grant_id, &pair.rows)? {
        // A concurrent use of the same refresh token won the race.
        return Err(RefreshError::InvalidGrant);
    }
    state
        .oauth
        .note_consumed_refresh(id, hash, &row.user_id, &grant_id);
    for t in old_ids {
        state.tokens.evict(&t);
    }
    // A refresh counts as activity, so a client in use is never pruned.
    if let Err(e) = state.sys.touch_oauth_client_grant(client_id, now) {
        tracing::warn!(error = %e, "could not record oauth client activity");
    }
    Ok(Refreshed {
        scope: scope_string(&meta.scope),
        pair,
    })
}

/// RFC 7009 revocation of `token` (`pma_` or `pmr_`). Only a holder of the
/// full token (secret included) can revoke it. A refresh token takes its
/// whole grant with it; an access token only itself. Anything else is
/// ignored. Blocking.
pub fn revoke_presented(state: &AppState, token: &str) -> anyhow::Result<()> {
    let refresh = split_token(token, REFRESH_PREFIX);
    let Some((id, secret_hex)) = refresh.or_else(|| split_token(token, ACCESS_PREFIX)) else {
        return Ok(());
    };
    let Some(row) = state.sys.token_full(id)? else {
        return Ok(());
    };
    let expected = if refresh.is_some() {
        KIND_REFRESH
    } else {
        KIND_ACCESS
    };
    if row.kind != expected {
        return Ok(());
    }
    let Some(umk) = unwrap_with_secret(id, secret_hex, &row.wrapped) else {
        return Ok(());
    };
    match (refresh.is_some(), row.grant_id) {
        (true, Some(grant_id)) => {
            // Unlock with the UMK we just proved we hold, so the metadata can go too.
            let unlocked = state.sys.user_by_id(&row.user_id)?.and_then(|u| {
                state
                    .keyring
                    .unlock(&row.user_id, umk, &u.index_key_wrapped)
                    .ok()
            });
            revoke_grant(&state.sys, unlocked.as_deref(), &grant_id, &state.tokens)?;
        }
        _ => {
            state.sys.delete_token(id)?;
            state.tokens.evict(id);
        }
    }
    Ok(())
}
