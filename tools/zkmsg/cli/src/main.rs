//! zkmsg — private messages on Starknet, proven on your own machine. A send
//! is one transaction: the zkmsg statement (sender membership in the
//! registered-user tree, a per-epoch quota nullifier, a spent fee ticket,
//! plus the hybrid ML-KEM + ECDH envelope) runs in StarkWare's virtual
//! Starknet OS here, and the S-two proof of that run rides in an invoke that
//! the v4 POOL publishes and pays for — never your own account (SNIP-36,
//! core/src/virtual_send.rs).
//!
//! Specs: docs/superpowers/specs/2026-10-07-zkmsg-v4-pool-tickets-design.md,
//! 2026-10-01-zkmsg-desktop-snip36-pq-design.md and
//! 2026-10-01-zkmsg-pq-hybrid-kem-design.md.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};

use zkmsg_core::app;
use zkmsg_core::chain::{Chain, felt_hex};
use zkmsg_core::config::{Home, is_current_store};
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
    /// Generate the scan keypair, the ML-KEM seed, the membership secret and
    /// a default config
    /// (refuses to overwrite).
    Init {
        /// sncast account name to send transactions from.
        #[arg(long, default_value = "funded-deployer")]
        account: String,
        /// Store address (defaults to the v4 pool).
        #[arg(long)]
        store: Option<String>,
    },
    /// Register a handle on-chain (one tx, from the profile's account).
    Register { handle: String },
    /// Prove + publish a private message: one transaction, published and
    /// paid by the pool, spending one of your tickets. Your account is not
    /// involved.
    Send { handle: String, text: String },
    /// Buy single-send tickets (3 STRK each, at most 8 per purchase) from
    /// the profile's account, in one transaction.
    /// The secrets are saved to tickets.json (0600) before anything is sent.
    BuyTickets {
        #[arg(default_value_t = 1)]
        count: usize,
    },
    /// The ticket wallet: unspent / reserved / spent / pending tickets.
    Tickets,
    /// Resume an interrupted send (its proof is saved; Publish is retried).
    Resume { id: String },
    /// Scan MessageSent events and decrypt the ones addressed to you.
    Inbox,
    /// Config, balance, deployed addresses.
    Status,
    /// Point a profile at the v4 pool (accountless, ticket-paid sends).
    /// Registration is per store: the handle is cleared and you register
    /// again, with a FRESH scan key, ML-KEM seed and membership secret (the
    /// old keys are overwritten — back the profile up first).
    MigrateStore {
        /// Profile name under the profile root (default: the current one).
        profile: Option<String>,
        /// sncast account to register and buy tickets from (default: keep).
        #[arg(long)]
        account: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::MigrateStore { profile: Some(name), account } = &cli.command {
        let dir = cli.home_dir().join(format!("{}{name}", zkmsg_core::profiles::PROFILE_PREFIX));
        ensure!(dir.join("config.json").exists(), "no profile '{name}' at {}", dir.display());
        return cmd_migrate_store(&Home::new(dir), account.as_deref());
    }
    let dir = zkmsg_core::profiles::resolve_cli_home(&cli.home_dir())?;
    let home = Home::new(dir);

    match cli.command {
        Command::Init { account, store } => cmd_init(&home, account, store),
        Command::Register { handle } => cmd_register(&home, &handle),
        Command::Send { handle, text } => cmd_send(&home, &handle, &text),
        Command::Resume { id } => cmd_resume(&home, &id),
        Command::BuyTickets { count } => cmd_buy_tickets(&home, count),
        Command::Tickets => cmd_tickets(&home),
        Command::Inbox => cmd_inbox(&home),
        Command::Status => cmd_status(&home),
        Command::MigrateStore { account, .. } => cmd_migrate_store(&home, account.as_deref()),
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
        app::on_current_store(&config),
        "{} is not the v4 pool — `zkmsg migrate-store` moves the profile",
        config.store,
    );
    keys.leaf_index.context("not registered — run `zkmsg register`")?;
    // The ticket and the pool's fee policy are checked inside, before proving.
    let state = app::send_virtual(home, &config, &keys, handle, text, &mut sink())?;
    println!("send '{}' -> {handle} published by the pool", state.id);
    Ok(())
}

fn cmd_buy_tickets(home: &Home, count: usize) -> Result<()> {
    println!("buying {count} ticket(s) — the secrets are saved before anything is sent");
    let p = app::buy_tickets(home, count)?;
    println!("approve + buy tx {}", p.buy_tx);
    println!(
        "bought {} x {} STRK; wallet: {}",
        p.bought,
        p.price_fri as f64 / 1e18,
        tickets_line(&p.counts)
    );
    Ok(())
}

fn cmd_tickets(home: &Home) -> Result<()> {
    println!("tickets  : {}", tickets_line(&app::sync_tickets(home)?));
    Ok(())
}

fn tickets_line(c: &zkmsg_core::tickets::TicketCounts) -> String {
    let mut line = format!("{} unspent", c.unspent);
    for (n, what) in [(c.reserved, "reserved by a pending send"), (c.pending, "purchase pending"), (c.spent, "spent")] {
        if n > 0 {
            line.push_str(&format!(", {n} {what}"));
        }
    }
    line
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
        E::Waiting { until_block, blocks_left } => println!(
            "[send] proof ready — publishing in {} (at block {until_block}, the shared schedule)",
            zkmsg_core::txpolicy::wait_label(blocks_left)
        ),
        E::Completed => {}
    }
}

fn cmd_inbox(home: &Home) -> Result<()> {
    let config = home.load_config()?;
    let keys = home.load_keys()?;
    ensure!(!config.store.is_empty(), "no store address in config.json");
    let chain = Chain::new(&config.rpc_url, &config.account);
    let messages = inbox::scan_with_keys(&chain, &config.store, &keys)?;
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

fn cmd_migrate_store(home: &Home, account: Option<&str>) -> Result<()> {
    let m = app::migrate_store(home, account)?;
    println!(
        "{}: store {} -> {} (fresh scan key, ML-KEM seed and membership secret)",
        home.dir.display(),
        m.previous_store,
        zkmsg_core::config::SEPOLIA_POOL_V4
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
    println!(
        "address  : {}",
        report.account_address.as_deref().unwrap_or("(not in sncast accounts file)"),
    );
    let route = if report.store.is_empty() {
        ""
    } else if is_current_store(&report.store) {
        " (v4 pool: accountless ticket-paid sends, PQ membership, hybrid ML-KEM/ECDH)"
    } else {
        " (not read any more — `zkmsg migrate-store` moves to v4)"
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
    if let Some(c) = &report.tickets {
        println!("tickets  : {} (a send spends one)", tickets_line(c));
    }
    match report.balance_strk {
        Some(strk) => println!("balance  : ~{strk} STRK (pays registration and tickets, never a send)"),
        None => {
            let e = report.balance_error.as_deref().unwrap_or("?");
            println!("balance  : unavailable ({e})");
        }
    }
    Ok(())
}
