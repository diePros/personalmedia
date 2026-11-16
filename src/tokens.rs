//! MCP access tokens. Task 14 fills this in; for now only the cache handle
//! that `AppState` carries exists.

/// Cache of unlocked state for recently used MCP tokens.
#[derive(Default)]
pub struct TokenCache {}

impl TokenCache {
    /// Drop the cached unlock for one token (after it is revoked).
    pub fn evict(&self, _token_id: &str) {}

    /// Drop every cached unlock of a user (disable, delete, password change).
    pub fn evict_user(&self, _user_id: &str) {}
}
