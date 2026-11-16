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
    /// Create an invite link
    Invite {
        #[arg(long)]
        admin: bool,
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

/// `PM_RECOVER_SECRET` if set (tests), otherwise a prompt on the TTY.
fn read_secret(recovery_key: bool) -> anyhow::Result<Secret> {
    let value = match std::env::var("PM_RECOVER_SECRET") {
        Ok(v) => Zeroizing::new(v),
        Err(_) => {
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
        Command::Invite { admin } => {
            let config = Config::from_env()?;
            config.require_public_url()?;
            println!("{}", create_invite(&config, admin)?);
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
