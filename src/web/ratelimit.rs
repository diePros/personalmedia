//! Failure-based rate limiting and client IP detection.
//!
//! Usage on a login-like route:
//!
//! ```ignore
//! let keys = [ip_key(ip), user_key(&username)];
//! let attempt = match state.limiter.begin(&keys) {
//!     Ok(a) => a,
//!     Err(retry) => return too_many_requests(retry),
//! };
//! match check_credentials() {
//!     Ok(_) => attempt.success(),
//!     Err(_) => attempt.failure(), // also what dropping the attempt does
//! }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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

/// Longest username that still makes a distinct key. Longer input is cut so
/// one request cannot park megabytes in the limiter map.
const USER_KEY_MAX_CHARS: usize = 64;

/// IPv4 addresses are keyed as they are. An IPv6 client usually owns a whole
/// /64, so those are keyed by their /64 prefix (`ip:2001:db8:1:2::/64`).
fn ip_part(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{}/64", Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

pub fn ip_key(ip: IpAddr) -> String {
    format!("ip:{}", ip_part(ip))
}

/// `username` is lowercased (so case variants share one key) and cut to 64 characters.
pub fn user_key(username: &str) -> String {
    let name: String = username
        .to_lowercase()
        .chars()
        .take(USER_KEY_MAX_CHARS)
        .collect();
    format!("user:{name}")
}

pub fn mcp_ip_key(ip: IpAddr) -> String {
    format!("mcp-ip:{}", ip_part(ip))
}

/// `/oauth/token` failures of a registered client. Codes and refresh tokens
/// carry 256 bits, so this guards nothing worth an IP lock; keying it by
/// client keeps one party from locking out a shared egress IP (ruling AH).
pub fn oauth_client_key(client_id: &str) -> String {
    format!("oauth-client:{client_id}")
}

/// `/oauth/token` failures without a known client id. Separate from
/// [`mcp_ip_key`] and [`ip_key`] so it shares state with neither `/mcp` nor logins.
pub fn oauth_ip_key(ip: IpAddr) -> String {
    format!("oauth-ip:{}", ip_part(ip))
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
    /// Attempts begun but not settled yet. They count like failures, so a
    /// burst of parallel requests cannot all pass before the first one fails.
    in_flight: usize,
    locked_until: Option<Instant>,
}

/// Counts failures per key: [`MAX_FAILURES`] within [`WINDOW`] lock the key
/// for [`LOCK`]. Keys are built with [`ip_key`], [`user_key`] and [`mcp_ip_key`].
///
/// Attempts are reserved up front with [`RateLimiter::begin`] and settled with
/// [`Attempt::success`] or [`Attempt::failure`] (reserve-then-settle).
#[derive(Default)]
pub struct RateLimiter {
    entries: Mutex<HashMap<String, Entry>>,
}

/// A reserved slot on a set of keys. Dropping it unsettled counts as a failure.
#[must_use = "settle the attempt with success() or failure()"]
pub struct Attempt<'a> {
    limiter: &'a RateLimiter,
    keys: Vec<String>,
    settled: bool,
}

impl Attempt<'_> {
    /// The credentials were right: release the slot and forget the `user:`
    /// keys' failures. `ip:` failures stay.
    pub fn success(mut self) {
        self.settled = true;
        self.limiter.settle(&self.keys, true);
    }

    /// The credentials were wrong: the reserved slot becomes a failure.
    pub fn failure(mut self) {
        self.settled = true;
        self.limiter.settle(&self.keys, false);
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.limiter.settle(&self.keys, false);
        }
    }
}

/// Retry hint when the limit is reached only by attempts still in flight.
const IN_FLIGHT_RETRY: Duration = Duration::from_secs(5);

impl RateLimiter {
    pub fn new() -> RateLimiter {
        RateLimiter::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // A poisoned lock only means another thread panicked; the map is still usable.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserve one attempt on every key, or `Err(retry_after)` if any key is
    /// locked or has [`MAX_FAILURES`] failures plus attempts in flight. All
    /// keys are checked and counted under one lock.
    pub fn begin(&self, keys: &[String]) -> Result<Attempt<'_>, Duration> {
        let now = Instant::now();
        let mut entries = self.lock();
        let mut retry: Option<Duration> = None;
        for key in keys {
            let Some(e) = entries.get_mut(key) else {
                continue;
            };
            e.failures.retain(|t| now.duration_since(*t) < WINDOW);
            let wait = match e.locked_until.and_then(|u| u.checked_duration_since(now)) {
                Some(d) if !d.is_zero() => Some(d),
                _ if e.failures.len() + e.in_flight >= MAX_FAILURES => Some(IN_FLIGHT_RETRY),
                _ => None,
            };
            if let Some(d) = wait {
                retry = Some(retry.map_or(d, |r| r.max(d)));
            }
        }
        if let Some(d) = retry {
            return Err(d);
        }
        for key in keys {
            entries.entry(key.clone()).or_default().in_flight += 1;
        }
        Ok(Attempt {
            limiter: self,
            keys: keys.to_vec(),
            settled: false,
        })
    }

    /// `Err(retry_after)` if any key is locked. Reserves nothing: for callers
    /// that only record failures ([`RateLimiter::record_failure`]) and so never
    /// count attempts in flight.
    pub fn check(&self, keys: &[String]) -> Result<(), Duration> {
        let now = Instant::now();
        let entries = self.lock();
        let wait = keys
            .iter()
            .filter_map(|k| entries.get(k))
            .filter_map(|e| e.locked_until.and_then(|u| u.checked_duration_since(now)))
            .filter(|d| !d.is_zero())
            .max();
        wait.map_or(Ok(()), Err)
    }

    /// Count one failure on every key without having reserved an attempt.
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

    /// Forget the failures (and any lock) of every key.
    pub fn clear(&self, keys: &[String]) {
        let mut entries = self.lock();
        for key in keys {
            if let Some(e) = entries.get_mut(key) {
                e.failures.clear();
                e.locked_until = None;
            }
        }
    }

    fn settle(&self, keys: &[String], success: bool) {
        let now = Instant::now();
        let mut entries = self.lock();
        for key in keys {
            let Some(e) = entries.get_mut(key) else {
                continue;
            };
            e.in_flight = e.in_flight.saturating_sub(1);
            if success {
                if key.starts_with("user:") {
                    e.failures.clear();
                    e.locked_until = None;
                }
                continue;
            }
            e.failures.retain(|t| now.duration_since(*t) < WINDOW);
            e.failures.push(now);
            if e.failures.len() >= MAX_FAILURES {
                e.failures.clear();
                e.locked_until = Some(now + LOCK);
            }
        }
    }

    /// Drop entries with no active lock, no recent failure and nothing in
    /// flight. Called periodically so the map cannot grow without bound.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.lock().retain(|_, e| {
            e.failures.retain(|t| now.duration_since(*t) < WINDOW);
            let locked = e.locked_until.is_some_and(|until| until > now);
            locked || !e.failures.is_empty() || e.in_flight > 0
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
                    ..Entry::default()
                },
            );
            entries.insert(
                "ip:locked".into(),
                Entry {
                    failures: vec![],
                    locked_until: Some(now + LOCK),
                    ..Entry::default()
                },
            );
            entries.insert("ip:idle".into(), Entry::default());
            if let Some(past) = now.checked_sub(Duration::from_secs(1)) {
                entries.insert(
                    "ip:expired-lock".into(),
                    Entry {
                        failures: vec![],
                        locked_until: Some(past),
                        ..Entry::default()
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
                ..Entry::default()
            },
        );
        assert!(limiter.begin(&["user:a".to_string()]).is_ok());
    }
}
