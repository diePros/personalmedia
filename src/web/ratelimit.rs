//! Failure-based rate limiting and client IP detection.
//!
//! Usage on a login-like route:
//!
//! ```ignore
//! let keys = [ip_key(ip), user_key(&username)];
//! if let Err(retry) = state.limiter.check(&keys) {
//!     return too_many_requests(retry);
//! }
//! match attempt {
//!     Ok(_) => state.limiter.record_success(&keys[1]),
//!     Err(_) => state.limiter.record_failure(&keys),
//! }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Failures within [`WINDOW`] that lock a key.
pub const MAX_FAILURES: usize = 10;
/// How far back failures count.
pub const WINDOW: Duration = Duration::from_secs(15 * 60);
/// How long a key stays locked.
pub const LOCK: Duration = Duration::from_secs(15 * 60);

pub fn ip_key(ip: IpAddr) -> String {
    format!("ip:{ip}")
}

/// `username` is lowercased so case variants share one key.
pub fn user_key(username: &str) -> String {
    format!("user:{}", username.to_lowercase())
}

pub fn mcp_ip_key(ip: IpAddr) -> String {
    format!("mcp-ip:{ip}")
}

/// The address rate limiting should attribute a request to.
///
/// `X-Forwarded-For` is honoured only when the TCP peer is the trusted proxy;
/// from anyone else the header is attacker-controlled and ignored. The proxy
/// is expected to send a single address. Should it append to a client-supplied
/// list instead, only the last entry (the one the proxy itself wrote) is used.
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trusted: IpAddr) -> IpAddr {
    let peer_ip = peer.ip().to_canonical();
    if peer_ip != trusted.to_canonical() {
        return peer_ip;
    }
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .unwrap_or(peer_ip)
}

/// A `429 Too Many Requests` with `Retry-After` (whole seconds, rounded up).
pub fn too_many_requests(retry_after: Duration) -> Response {
    let secs = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, HeaderValue::from(secs.max(1)))],
        "Too many attempts. Try again later.",
    )
        .into_response()
}

#[derive(Default)]
struct Entry {
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
}

/// Counts failures per key: [`MAX_FAILURES`] within [`WINDOW`] lock the key
/// for [`LOCK`]. Keys are built with [`ip_key`], [`user_key`] and [`mcp_ip_key`].
#[derive(Default)]
pub struct RateLimiter {
    entries: Mutex<HashMap<String, Entry>>,
}

impl RateLimiter {
    pub fn new() -> RateLimiter {
        RateLimiter::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // A poisoned lock only means another thread panicked; the map is still usable.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `Err(retry_after)` if any of `keys` is locked (the longest remaining lock).
    pub fn check(&self, keys: &[String]) -> Result<(), Duration> {
        let now = Instant::now();
        let entries = self.lock();
        let remaining = keys
            .iter()
            .filter_map(|k| entries.get(k)?.locked_until)
            .filter_map(|until| until.checked_duration_since(now))
            .filter(|d| !d.is_zero())
            .max();
        match remaining {
            Some(d) => Err(d),
            None => Ok(()),
        }
    }

    /// Count one failure against each of `keys`, locking those that reach the limit.
    pub fn record_failure(&self, keys: &[String]) {
        let now = Instant::now();
        let mut entries = self.lock();
        for key in keys {
            let e = entries.entry(key.clone()).or_default();
            e.failures.retain(|t| now.duration_since(*t) < WINDOW);
            e.failures.push(now);
            if e.failures.len() >= MAX_FAILURES {
                e.failures.clear();
                e.locked_until = Some(now + LOCK);
            }
        }
    }

    /// Forget `key` (used for the `user:` key after a successful login).
    pub fn record_success(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Drop entries with no active lock and no recent failure. Called
    /// periodically so the map cannot grow without bound.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.lock().retain(|_, e| {
            e.failures.retain(|t| now.duration_since(*t) < WINDOW);
            let locked = e.locked_until.is_some_and(|until| until > now);
            locked || !e.failures.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_keeps_live_entries_and_drops_dead_ones() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        {
            let mut entries = limiter.lock();
            entries.insert(
                "ip:recent".into(),
                Entry {
                    failures: vec![now],
                    locked_until: None,
                },
            );
            entries.insert(
                "ip:locked".into(),
                Entry {
                    failures: vec![],
                    locked_until: Some(now + LOCK),
                },
            );
            entries.insert("ip:idle".into(), Entry::default());
            if let Some(past) = now.checked_sub(Duration::from_secs(1)) {
                entries.insert(
                    "ip:expired-lock".into(),
                    Entry {
                        failures: vec![],
                        locked_until: Some(past),
                    },
                );
            }
        }
        limiter.sweep();
        let entries = limiter.lock();
        assert!(entries.contains_key("ip:recent"));
        assert!(entries.contains_key("ip:locked"));
        assert!(!entries.contains_key("ip:idle"));
        assert!(!entries.contains_key("ip:expired-lock"));
    }

    #[test]
    fn an_expired_lock_no_longer_blocks() {
        let limiter = RateLimiter::new();
        let Some(past) = Instant::now().checked_sub(Duration::from_secs(1)) else {
            return;
        };
        limiter.lock().insert(
            "user:a".into(),
            Entry {
                failures: vec![],
                locked_until: Some(past),
            },
        );
        assert!(limiter.check(&["user:a".to_string()]).is_ok());
    }
}
