use std::path::PathBuf;

use clap::{Parser, Subcommand};
use personal_media::config::Config;
use personal_media::web::AppState;
use tracing_subscriber::EnvFilter;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            personal_media::harden::harden_process();
            init_tracing();
            let config = Config::from_env()?;
            config.require_public_url()?;
            // Wipes OCR scratch and starts the extraction workers.
            let state = AppState::build(config)?;
            personal_media::web::serve(state).await?;
        }
        Command::Invite { admin: _ } => {
            let config = Config::from_env()?;
            config.require_public_url()?;
            println!("not implemented");
        }
        Command::Recover { .. } => println!("not implemented"),
    }
    Ok(())
}
