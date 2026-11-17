use std::path::PathBuf;

use std::sync::Arc;

use clap::{Parser, Subcommand};
use personal_media::accounts::Accounts;
use personal_media::config::Config;
use personal_media::keyring::{Keyring, OnUnlock, Unlocked};
use personal_media::recover::{RecoverError, Secret};
use personal_media::system_db::{Role, SYSTEM_DB_FILE, SystemDb};
use personal_media::web::AppState;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "personal-media", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the web server (default)
    Serve,
    /// Probe `GET /login` on `PM_BIND`; exit 0 on HTTP 200, else 1 (Docker HEALTHCHECK)
    Healthcheck,
    /// Create an invite link
    Invite {
        #[arg(long)]
        admin: bool,
    },
    /// Download and verify the embedding model into `<data>/models` (idempotent)
    FetchModel {
        /// Data directory (default: `PM_DATA_DIR`, else `/data`)
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Check the embedding model on this machine (downloads it if missing): ranking
    /// quality, speed and peak memory. Exit 0 if at least 3 of 4 queries pass.
    EmbedSelftest {
        /// Data directory (default: `PM_DATA_DIR`, else `/data`)
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Offline recovery export for a user
    Recover {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        out: PathBuf,
        /// Unlock with the recovery key instead of the password
        #[arg(long)]
        recovery_key: bool,
    },
}

/// Log to stderr; `RUST_LOG` overrides the default level `info`.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// No-op: the invite command never unlocks a user.
struct NoUnlock;

impl OnUnlock for NoUnlock {
    fn unlocked(&self, _: &Arc<Unlocked>) {}
}

/// Creates an invite straight in the system DB: no workers, no server.
fn create_invite(config: &Config, admin: bool) -> anyhow::Result<String> {
    std::fs::create_dir_all(&config.data_dir)?;
    let sys = Arc::new(SystemDb::open(&config.data_dir.join(SYSTEM_DB_FILE))?);
    let keyring = Arc::new(Keyring::new(config.data_dir.clone(), Arc::new(NoUnlock)));
    let accounts = Accounts::new(config, sys, keyring);
    let role = if admin { Role::Admin } else { Role::User };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    accounts.create_invite(role, now)
}

/// Where the recovery secret comes from. `PM_RECOVER_SECRET` exists in debug
/// builds only (tests): in a production binary an environment variable would
/// show up in `docker inspect` and `/proc/<pid>/environ`. Otherwise one line
/// from stdin when stdin is not a terminal, else a prompt on the TTY.
fn read_secret(recovery_key: bool) -> anyhow::Result<Secret> {
    use std::io::IsTerminal;
    #[cfg(debug_assertions)]
    let from_env = std::env::var("PM_RECOVER_SECRET").ok().map(Zeroizing::new);
    #[cfg(not(debug_assertions))]
    let from_env: Option<Zeroizing<String>> = {
        if std::env::var_os("PM_RECOVER_SECRET").is_some() {
            eprintln!(
                "warning: PM_RECOVER_SECRET is ignored; the secret is read from stdin or a prompt"
            );
        }
        None
    };
    let value = match from_env {
        Some(v) => v,
        None if !std::io::stdin().is_terminal() => {
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().read_line(&mut line)?;
            let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
            anyhow::ensure!(!trimmed.is_empty(), "no secret on stdin");
            Zeroizing::new(trimmed)
        }
        None => {
            let prompt = if recovery_key {
                "Recovery key: "
            } else {
                "Password: "
            };
            Zeroizing::new(rpassword::prompt_password(prompt)?)
        }
    };
    Ok(if recovery_key {
        Secret::RecoveryKey(value)
    } else {
        Secret::Password(value)
    })
}

/// True if `GET /healthz` on the bind address answers `204`. Std sockets only: the
/// runtime image has no curl.
fn healthcheck() -> bool {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let bind = std::env::var("PM_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let Ok(mut addr) = bind.parse::<SocketAddr>() else {
        return false;
    };
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let t = Duration::from_secs(3);
    let Ok(mut s) = TcpStream::connect_timeout(&addr, t) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(t));
    let _ = s.set_write_timeout(Some(t));
    let req = format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 12];
    s.read_exact(&mut head).is_ok() && head.starts_with(b"HTTP/1.1 204")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            init_tracing();
            personal_media::harden::harden_process();
            let config = Config::from_env()?;
            config.require_public_url()?;
            // Wipes OCR scratch and starts the extraction workers.
            let state = AppState::build(config)?;
            personal_media::web::serve(state).await?;
        }
        Command::Healthcheck => {
            std::process::exit(if healthcheck() { 0 } else { 1 });
        }
        Command::Invite { admin } => {
            let config = Config::from_env()?;
            config.require_public_url()?;
            println!("{}", create_invite(&config, admin)?);
        }
        Command::FetchModel { data } => {
            let data = match data {
                Some(d) => d,
                None => Config::from_env()?.data_dir,
            };
            let dir = personal_media::embed::model::ensure_model_with_progress(
                &data.join("models"),
                &personal_media::embed::MODEL,
                &mut |line| println!("{line}"),
            )?;
            println!("Model ready: {}", dir.display());
        }
        Command::EmbedSelftest { data } => {
            let data = match data {
                Some(d) => d,
                None => Config::from_env()?.data_dir,
            };
            let models = data.join("models");
            personal_media::embed::model::ensure_model_with_progress(
                &models,
                &personal_media::embed::MODEL,
                &mut |line| println!("{line}"),
            )?;
            let engine =
                personal_media::embed::Engine::new(models, std::time::Duration::from_secs(600));
            let report = personal_media::embed::selftest::run(&engine)?;
            let hits = report.queries.iter().filter(|q| q.ok()).count();
            for q in &report.queries {
                println!(
                    "{} query {:?} ({}): expected passage {}, top {}",
                    if q.ok() { "PASS" } else { "FAIL" },
                    q.query,
                    if q.cross_language {
                        "cross-language"
                    } else {
                        "same language"
                    },
                    q.expected,
                    q.top
                );
            }
            println!(
                "speed: {:.1} ms per passage (first {}-token chunk, mean of 10 runs)",
                report.ms_per_passage, report.chunk_tokens_run
            );
            match report.peak_rss_mb {
                Some(mb) => println!("peak RSS: {mb:.0} MB"),
                None => println!("peak RSS: unavailable"),
            }
            let total = report.queries.len();
            if report.passed() {
                println!("embed-selftest OK: {hits} of {total} queries ranked correctly");
            } else {
                eprintln!(
                    "embed-selftest FAILED: only {hits} of {total} queries ranked correctly; the quantized model may not suit this CPU"
                );
                std::process::exit(1);
            }
        }
        Command::Recover {
            data,
            user,
            out,
            recovery_key,
        } => {
            let secret = read_secret(recovery_key)?;
            match personal_media::recover::recover(&data, &user, &secret, &out) {
                Ok(n) => println!("Recovered {n} documents to {}", out.display()),
                Err(e) => {
                    eprintln!("error: {e}");
                    let code = match e {
                        RecoverError::OutNotEmpty(_) => 2,
                        _ => 1,
                    };
                    std::process::exit(code);
                }
            }
        }
    }
    Ok(())
}
