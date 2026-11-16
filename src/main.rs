use std::path::PathBuf;

use clap::{Parser, Subcommand};
use personal_media::config::Config;

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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            personal_media::harden::harden_process();
            let config = Config::from_env()?;
            config.require_public_url()?;
            println!("not implemented");
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
