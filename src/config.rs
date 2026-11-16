use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::crypto::kdf::Argon2Params;

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub bind: SocketAddr,
    pub public_url: String,
    pub max_upload_bytes: u64,
    pub session_idle: Duration,
    pub session_max: Duration,
    pub trusted_proxy: IpAddr,
    pub ocr_workers: usize,
    pub argon2: Argon2Params,
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

impl Config {
    /// Build the configuration from `PM_*` environment variables.
    /// `PM_PUBLIC_URL` is not required here; commands that need it use
    /// [`Config::require_public_url`].
    pub fn from_env() -> Result<Config> {
        let idle_min: u64 = parse_var("PM_SESSION_IDLE_MINUTES", "30")?;
        let max_hours: u64 = parse_var("PM_SESSION_MAX_HOURS", "12")?;
        let max_upload_mb: u64 = parse_var("PM_MAX_UPLOAD_MB", "100")?;
        Ok(Config {
            data_dir: PathBuf::from(var("PM_DATA_DIR").unwrap_or_else(|| "/data".into())),
            bind: parse_var("PM_BIND", "127.0.0.1:8080")?,
            public_url: var("PM_PUBLIC_URL")
                .map(|u| u.trim_end_matches('/').to_string())
                .unwrap_or_default(),
            max_upload_bytes: max_upload_mb * 1024 * 1024,
            session_idle: Duration::from_secs(idle_min * 60),
            session_max: Duration::from_secs(max_hours * 3600),
            trusted_proxy: parse_var("PM_TRUSTED_PROXY", "127.0.0.1")?,
            ocr_workers: parse_var("PM_OCR_WORKERS", "1")?,
            argon2: Argon2Params::default(),
        })
    }

    /// Fails if `PM_PUBLIC_URL` is unset (required for `serve` and `invite`).
    pub fn require_public_url(&self) -> Result<&str> {
        anyhow::ensure!(!self.public_url.is_empty(), "PM_PUBLIC_URL is required");
        Ok(&self.public_url)
    }

    pub fn for_tests(data_dir: PathBuf) -> Config {
        Config {
            data_dir,
            bind: "127.0.0.1:0".parse().unwrap(),
            public_url: "https://test.example".into(),
            max_upload_bytes: 100 * 1024 * 1024,
            session_idle: Duration::from_secs(30 * 60),
            session_max: Duration::from_secs(12 * 3600),
            trusted_proxy: "127.0.0.1".parse().unwrap(),
            ocr_workers: 1,
            argon2: Argon2Params {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
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
