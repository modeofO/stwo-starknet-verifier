mod crypto;
mod tree;
mod args;
mod pack;
mod chain;
mod pipeline;
mod state;
mod config;
mod inbox;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

fn default_home() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".zkmsg")
}

#[derive(Parser)]
#[command(name = "zkmsg", about = "zkmsg CLI")]
struct Cli {
    /// zkmsg home directory (config, keys, state).
    #[arg(long, global = true)]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn home_dir(&self) -> PathBuf {
        self.home.clone().unwrap_or_else(default_home)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new zkmsg home directory and keypair.
    Init,
    /// Register a handle on-chain.
    Register { handle: String },
    /// Send a message to a handle.
    Send {
        handle: String,
        text: String,
        #[arg(long)]
        resume: Option<String>,
    },
    /// List received messages.
    Inbox,
    /// Show current status.
    Status,
    /// Internal: dump dev args for debugging.
    #[command(hide = true, name = "dev-args")]
    DevArgs { out: PathBuf },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let home = cli.home_dir();

    match cli.command {
        Command::Init => cmd_init(&home),
        Command::Register { handle } => cmd_register(&home, &handle),
        Command::Send { handle, text, resume } => cmd_send(&home, &handle, &text, resume),
        Command::Inbox => cmd_inbox(&home),
        Command::Status => cmd_status(&home),
        Command::DevArgs { out } => cmd_dev_args(&home, &out),
    }
}

fn cmd_init(_home: &PathBuf) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}

fn cmd_register(_home: &PathBuf, _handle: &str) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}

fn cmd_send(
    _home: &PathBuf,
    _handle: &str,
    _text: &str,
    _resume: Option<String>,
) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}

fn cmd_inbox(_home: &PathBuf) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}

fn cmd_status(_home: &PathBuf) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}

fn cmd_dev_args(_home: &PathBuf, _out: &PathBuf) -> anyhow::Result<()> {
    anyhow::bail!("not implemented")
}
