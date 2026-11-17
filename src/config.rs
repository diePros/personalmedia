use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::crypto::kdf::Argon2Params;

/// Default lifetime of a staged share (spec: 15 minutes).
pub const DEFAULT_SHARE_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    /// `{data_dir}/models`: downloaded embedding model files.
    pub models_dir: PathBuf,
    pub bind: SocketAddr,
    pub public_url: String,
    pub max_upload_bytes: u64,
    pub session_idle: Duration,
    pub session_max: Duration,
    /// How long shared files wait for review in memory (`/share`).
    pub share_ttl: Duration,
    pub trusted_proxy: IpAddr,
    pub ocr_workers: usize,
    pub argon2: Argon2Params,
    /// Extra hosts (lowercase) whose `https://` redirect URIs OAuth clients may
    /// register (`PM_OAUTH_EXTRA_REDIRECT_HOSTS`, comma separated).
    pub oauth_extra_redirect_hosts: Vec<String>,
    /// The owner's shared iCloud link to the PMS iOS Shortcut
    /// (`PM_IOS_SHORTCUT_URL`); `None` when unset or not a valid link.
    pub ios_shortcut_url: Option<String>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn parse_var<T>(name: &str, default: &str) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = var(name).unwrap_or_else(|| default.to_string());
    raw.parse::<T>()
        .with_context(|| format!("invalid value for {name}"))
}

/// `https://host[:port]` (a trailing `/` is fine). For local development
/// `http://localhost[:port]` and `http://127.0.0.1[:port]` are accepted too.
/// No path, query, user info or placeholder characters.
pub fn validate_public_url(url: &str) -> Result<()> {
    let bad = || {
        anyhow::anyhow!(
            "PM_PUBLIC_URL must be an https://host[:port] URL such as \
             https://node.tailnet.ts.net (got {url:?})"
        )
    };
    let url = url.strip_suffix('/').unwrap_or(url);
    let (https, rest) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("http://").ok_or_else(bad)?),
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if let Some(p) = port
        && (p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err())
    {
        return Err(bad());
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if host.is_empty() || !host.split('.').all(label_ok) {
        return Err(bad());
    }
    if !https && host != "localhost" && host != "127.0.0.1" {
        return Err(bad());
    }
    Ok(())
}

/// Accepts only `https://www.icloud.com/shortcuts/<32 hex chars>`, with an
/// optional trailing `/`.
pub fn validate_ios_shortcut_url(url: &str) -> bool {
    let Some(id) = url.strip_prefix("https://www.icloud.com/shortcuts/") else {
        return false;
    };
    let id = id.strip_suffix('/').unwrap_or(id);
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Config {
    /// Build the configuration from `PM_*` environment variables.
    /// `PM_PUBLIC_URL` is not required here; commands that need it use
    /// [`Config::require_public_url`].
    pub fn from_env() -> Result<Config> {
        let idle_min: u64 = parse_var("PM_SESSION_IDLE_MINUTES", "30")?;
        let max_hours: u64 = parse_var("PM_SESSION_MAX_HOURS", "12")?;
        let max_upload_mb: u64 = parse_var("PM_MAX_UPLOAD_MB", "100")?;
        let data_dir = PathBuf::from(var("PM_DATA_DIR").unwrap_or_else(|| "/data".into()));
        Ok(Config {
            models_dir: data_dir.join("models"),
            data_dir,
            bind: parse_var("PM_BIND", "127.0.0.1:8080")?,
            public_url: var("PM_PUBLIC_URL")
                .map(|u| u.trim_end_matches('/').to_ascii_lowercase())
                .unwrap_or_default(),
            max_upload_bytes: max_upload_mb * 1024 * 1024,
            session_idle: Duration::from_secs(idle_min * 60),
            session_max: Duration::from_secs(max_hours * 3600),
            share_ttl: DEFAULT_SHARE_TTL,
            trusted_proxy: parse_var("PM_TRUSTED_PROXY", "127.0.0.1")?,
            ocr_workers: parse_var("PM_OCR_WORKERS", "1")?,
            argon2: Argon2Params::default(),
            oauth_extra_redirect_hosts: var("PM_OAUTH_EXTRA_REDIRECT_HOSTS")
                .map(|v| {
                    v.split(',')
                        .map(|h| h.trim().to_ascii_lowercase())
                        .filter(|h| !h.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            ios_shortcut_url: var("PM_IOS_SHORTCUT_URL").and_then(|u| {
                let u = u.trim().to_owned();
                if validate_ios_shortcut_url(&u) {
                    Some(u)
                } else {
                    tracing::warn!(
                        "ignoring PM_IOS_SHORTCUT_URL: expected \
                         https://www.icloud.com/shortcuts/<32 hex characters>"
                    );
                    None
                }
            }),
        })
    }

    /// Fails if `PM_PUBLIC_URL` is unset or not a plain `https://host[:port]`
    /// origin (required for `serve` and `invite`).
    pub fn require_public_url(&self) -> Result<&str> {
        anyhow::ensure!(!self.public_url.is_empty(), "PM_PUBLIC_URL is required");
        validate_public_url(&self.public_url)?;
        Ok(&self.public_url)
    }

    pub fn for_tests(data_dir: PathBuf) -> Config {
        Config {
            models_dir: data_dir.join("models"),
            data_dir,
            bind: "127.0.0.1:0".parse().unwrap(),
            public_url: "https://test.example".into(),
            max_upload_bytes: 100 * 1024 * 1024,
            session_idle: Duration::from_secs(30 * 60),
            session_max: Duration::from_secs(12 * 3600),
            share_ttl: DEFAULT_SHARE_TTL,
            trusted_proxy: "127.0.0.1".parse().unwrap(),
            ocr_workers: 1,
            argon2: Argon2Params {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
            oauth_extra_redirect_hosts: Vec::new(),
            ios_shortcut_url: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_tests_values() {
        let c = Config::for_tests("/tmp/x".into());
        assert_eq!(c.public_url, "https://test.example");
        assert_eq!(c.argon2.m_kib, 1024);
    }
}
