//! zkmsg — private messages on Starknet, proven on your own machine. A send
//! is one transaction: the zkmsg statement (sender membership in the
//! registered-user tree, plus the hybrid ML-KEM + ECDH envelope) runs in
//! StarkWare's virtual Starknet OS here, and the S-two proof of that run
//! rides in the invoke for the sequencer to verify (SNIP-36,
//! core/src/virtual_send.rs).
//!
//! Specs: docs/superpowers/specs/2026-10-01-zkmsg-desktop-snip36-pq-design.md
//! and 2026-10-01-zkmsg-pq-hybrid-kem-design.md.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};

use zkmsg_core::app;
use zkmsg_core::chain::{Chain, felt_hex};
use zkmsg_core::config::{Home, StoreKind, store_kind};
use zkmsg_core::inbox;
use zkmsg_core::state::SendState;

fn default_home() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".zkmsg")
}

/// The repo this binary was built from — the default prover binary path.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
    })
}

#[derive(Parser)]
#[command(name = "zkmsg", about = "Private messages on Starknet, proven on your machine")]
struct Cli {
    /// zkmsg home directory (config, keys, send state).
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
    /// Generate the scan keypair, the ML-KEM seed and a default config
    /// (refuses to overwrite).
    Init {
        /// sncast account name to send transactions from.
        #[arg(long, default_value = "funded-deployer")]
        account: String,
        /// MessageStore address (defaults to the v2 store).
        #[arg(long)]
        store: Option<String>,
    },
    /// Register a handle on-chain (one tx).
    Register { handle: String },
    /// Prove + publish a private message: one transaction, ~1.6 STRK (the
    /// account must hold ~4 STRK of fee ceiling).
    Send { handle: String, text: String },
    /// Resume an interrupted send (its proof is saved; Publish is retried).
    Resume { id: String },
    /// Scan MessageSent events and decrypt the ones addressed to you.
    Inbox {
        /// Also scan the legacy MessageStore v3 (read-only history).
        #[arg(long)]
        legacy: bool,
    },
    /// Config, balance, deployed addresses.
    Status,
    /// Point a profile at the v2 (post-quantum) store. Registration is per
    /// store: the handle is cleared and you register again. The scan key is
    /// kept; an ML-KEM key is added if the profile predates v2.
    MigrateStore {
        /// Profile name under the profile root (default: the current one).
        profile: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::MigrateStore { profile: Some(name) } = &cli.command {
        let dir = cli.home_dir().join(format!("{}{name}", zkmsg_core::profiles::PROFILE_PREFIX));
        ensure!(dir.join("config.json").exists(), "no profile '{name}' at {}", dir.display());
        return cmd_migrate_store(&Home::new(dir));
    }
    let dir = zkmsg_core::profiles::resolve_cli_home(&cli.home_dir())?;
    let home = Home::new(dir);

    match cli.command {
        Command::Init { account, store } => cmd_init(&home, account, store),
        Command::Register { handle } => cmd_register(&home, &handle),
        Command::Send { handle, text } => cmd_send(&home, &handle, &text),
        Command::Resume { id } => cmd_resume(&home, &id),
        Command::Inbox { legacy } => cmd_inbox(&home, legacy),
        Command::Status => cmd_status(&home),
        Command::MigrateStore { .. } => cmd_migrate_store(&home),
    }
}

fn cmd_init(home: &Home, account: String, store: Option<String>) -> Result<()> {
    let scan_pub = app::init_identity(home, &account, store, &repo_root())?;
    let config = home.load_config()?;

    println!("zkmsg home: {}", home.dir.display());
    println!("scan pubkey: {}", zkmsg_core::chain::felt_hex_grouped(&felt_hex(&scan_pub)));
    println!("account: {}", config.account);
    if config.store.is_empty() {
        println!("NOTE: no MessageStore address configured yet (set it in config.json)");
    }
    Ok(())
}

fn cmd_register(home: &Home, handle: &str) -> Result<()> {
    let leaf_index = match app::register(home, handle)? {
        app::RegisterOutcome::Registered { tx_hash, leaf_index } => {
            println!("register tx {tx_hash}");
            leaf_index
        }
        app::RegisterOutcome::AlreadyRegistered { leaf_index } => {
            println!("handle already registered to this scan key — syncing local state");
            leaf_index
        }
    };
    println!("registered '{handle}' at leaf {leaf_index}");
    Ok(())
}

fn cmd_send(home: &Home, handle: &str, text: &str) -> Result<()> {
    let config = home.load_config()?;
    let keys = home.load_keys()?;
    ensure!(!config.store.is_empty(), "no store address in config.json");
    ensure!(
        app::uses_virtual_route(&config),
        "{} is not a store this client sends to — `zkmsg migrate-store` moves the profile to v2",
        config.store,
    );
    keys.leaf_index.context("not registered — run `zkmsg register`")?;
    // The fee-ceiling check runs inside, against live prices, before proving.
    let state = app::send_virtual(home, &config, &keys, handle, text, &mut sink())?;
    println!("send '{}' -> {handle} published", state.id);
    Ok(())
}

fn cmd_resume(home: &Home, id: &str) -> Result<()> {
    let config = home.load_config()?;
    let mut send_state = SendState::load(home, id)?;
    app::resume_send(home, &config, &mut send_state, &mut sink())
}

/// Progress lines. The send id is only known once Prepare has built the
/// commitment, so lines are keyed by step, and the publish hash is printed
/// the moment the gateway takes it.
fn sink() -> impl FnMut(zkmsg_core::pipeline::PipelineEvent) {
    use zkmsg_core::pipeline::PipelineEvent as E;
    move |event| match event {
        E::StepStarted { index, total, kind } => println!("[send] step {}/{total}: {kind:?}", index + 1),
        E::StepCompleted { kind, .. } => println!("[send] {kind:?} done"),
        E::Checkpointed { id } => println!("[send] proof saved — resumable as `zkmsg resume {id}`"),
        E::TxSubmitted { tx_hash, .. } => println!("[send] submitted {tx_hash}"),
        E::Completed => {}
    }
}

fn cmd_inbox(home: &Home, legacy: bool) -> Result<()> {
    use zkmsg_core::config::{SEPOLIA_STORE_V3, same_address};
    let config = home.load_config()?;
    let keys = home.load_keys()?;
    ensure!(!config.store.is_empty(), "no store address in config.json");
    let chain = Chain::new(&config.rpc_url, &config.account);
    let scan_priv = keys.scan_priv_felt()?;

    let mut messages = vec![];
    if legacy && !same_address(&config.store, SEPOLIA_STORE_V3) {
        let history = inbox::scan(&chain, SEPOLIA_STORE_V3, &scan_priv)?;
        if !history.is_empty() {
            println!("-- legacy v3 store ({} message(s)) --", history.len());
            for m in &history {
                println!("#{:<4} {}  {}", m.nonce, &m.commitment[..18], m.text);
            }
            println!("-- home store --");
        }
    }
    messages.extend(inbox::scan_with_keys(&chain, &config.store, &keys)?);
    if messages.is_empty() {
        println!("inbox empty (no envelopes match your scan key)");
        return Ok(());
    }
    for m in &messages {
        println!("#{:<4} {}  {}", m.nonce, &m.commitment[..18], m.text);
    }
    std::fs::write(home.inbox_cache_path(), serde_json::to_string_pretty(&messages)?)?;
    Ok(())
}

fn cmd_migrate_store(home: &Home) -> Result<()> {
    let m = app::migrate_store(home)?;
    println!(
        "{}: store {} -> {}",
        home.dir.display(),
        m.previous_store,
        zkmsg_core::config::SEPOLIA_STORE_V2
    );
    match m.previous_handle {
        Some(h) => println!("registration is per store — run `zkmsg register {h}` to register again"),
        None => println!("registration is per store — run `zkmsg register <handle>`"),
    }
    Ok(())
}

fn cmd_status(home: &Home) -> Result<()> {
    let report = app::status(home)?;

    println!("rpc      : {}", report.rpc);
    println!("account  : {}", report.account);
    let route = match store_kind(&report.store) {
        _ if report.store.is_empty() => "",
        Some(StoreKind::V2) => " (v2: hybrid ML-KEM + ECDH)",
        Some(StoreKind::Snip36V1) => " (SNIP-36 v1 — `zkmsg migrate-store` moves to v2)",
        Some(StoreKind::V3) => " (legacy v3, read-only — `zkmsg migrate-store` moves to v2)",
        None => "",
    };
    println!(
        "store    : {}{route}",
        if report.store.is_empty() { "(not deployed)" } else { &report.store },
    );
    if let Some(scan_pub) = &report.scan_pub {
        println!("scan pub : {}", zkmsg_core::chain::felt_hex_grouped(scan_pub));
        match (&report.handle, report.leaf_index) {
            (Some(h), Some(i)) => println!("handle   : {h} (leaf {i})"),
            _ => println!("handle   : (not registered)"),
        }
    }
    if let Some(n) = &report.n_messages {
        println!("messages : {n}");
    }
    match report.balance_strk {
        Some(strk) => println!("balance  : ~{strk} STRK (a send costs ~1.6; needs ~4 of fee ceiling)"),
        None => {
            let e = report.balance_error.as_deref().unwrap_or("?");
            println!("balance  : unavailable ({e})");
        }
    }
    Ok(())
}
