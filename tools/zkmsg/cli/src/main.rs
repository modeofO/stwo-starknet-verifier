//! zkmsg — messagezk on lane 1, natively. A private message costs one
//! locally-proven ZK statement (sender+recipient membership, ephemeral
//! ECDH, commitment), verified on Starknet Sepolia through the live
//! `StwoFactRegistry`, then published to MessageStore v3. Fresh profiles
//! default to the SNIP-36 store, where a send is one transaction carrying a
//! virtual-OS proof (core/src/virtual_send.rs).
//!
//! Spec: docs/superpowers/specs/2026-07-05-zkmsg-lane1-port-design.md.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use starknet_types_core::felt::Felt;

use zkmsg_core::app;
use zkmsg_core::args::{CircuitInputs, args_to_json, build_circuit_args};
use zkmsg_core::chain::{Chain, felt_hex};
use zkmsg_core::config::{Config, Home};
use zkmsg_core::crypto::ec_mul_gen_x;
use zkmsg_core::pipeline::Pipeline;
use zkmsg_core::state::SendState;
use zkmsg_core::{inbox, tree};

/// Rough per-send ceiling at spiky Sepolia prices (runbook: the fixture
/// fact cost ~49 STRK; refuse to start below this unless --force).
const MIN_BALANCE_STRK: u128 = 60;

fn default_home() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".zkmsg")
}

/// The repo this binary was built from — bridge + circuit artifact paths.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
    })
}

#[derive(Parser)]
#[command(name = "zkmsg", about = "Private messages on Starknet, proven natively (lane 1)")]
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
    /// Generate the scan keypair + default config (refuses to overwrite).
    Init {
        /// sncast account name to send transactions from.
        #[arg(long, default_value = "funded-deployer")]
        account: String,
        /// MessageStore address (defaults to the SNIP-36 store; pass the v3
        /// address to keep sending on the legacy lane-1 route).
        #[arg(long)]
        store: Option<String>,
    },
    /// Register a handle on-chain (one tx).
    Register { handle: String },
    /// Prove + publish a private message. SNIP-36 store: one transaction
    /// (~1.6 STRK; the account must hold ~4 STRK of fee ceiling). Legacy v3
    /// store: the lane-1 pipeline (~50 STRK).
    Send {
        handle: String,
        text: String,
        /// Skip the balance pre-check.
        #[arg(long)]
        force: bool,
    },
    /// Resume an interrupted send at its first incomplete step.
    Resume { id: String },
    /// Scan MessageSent events and decrypt the ones addressed to you.
    Inbox {
        /// Also scan the legacy MessageStore v3 (read-only history).
        #[arg(long)]
        legacy: bool,
    },
    /// Config, balance, projected cost, deployed addresses.
    Status,
    /// Internal: write the milestone-1 synthetic-tree args file.
    #[command(hide = true, name = "dev-args")]
    DevArgs { out: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = zkmsg_core::profiles::resolve_cli_home(&cli.home_dir())?;
    let home = Home::new(dir);

    match cli.command {
        Command::Init { account, store } => cmd_init(&home, account, store),
        Command::Register { handle } => cmd_register(&home, &handle),
        Command::Send { handle, text, force } => cmd_send(&home, &handle, &text, force),
        Command::Resume { id } => cmd_resume(&home, &id),
        Command::Inbox { legacy } => cmd_inbox(&home, legacy),
        Command::Status => cmd_status(&home),
        Command::DevArgs { out } => cmd_dev_args(&out),
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

fn cmd_send(home: &Home, handle: &str, text: &str, force: bool) -> Result<()> {
    let config = home.load_config()?;
    let keys = home.load_keys()?;
    ensure!(!config.store.is_empty(), "no store address in config.json");
    let sender_leaf = keys.leaf_index.context("not registered — run `zkmsg register`")?;

    if app::uses_virtual_route(&config) {
        // The fee-ceiling check runs inside, against live prices, before
        // proving; `--force` has nothing to skip here.
        let state = app::send_virtual(home, &config, &keys, handle, text, &mut virtual_sink())?;
        println!("send '{}' -> {handle} published", state.id);
        return Ok(());
    }

    if !force {
        let chain = Chain::new(&config.rpc_url, &config.account);
        check_balance(&chain, &config)?;
    }

    let mut send_state = app::prepare_send(home, &config, &keys, sender_leaf, handle, text)?;
    let ciphertext_len = send_state.ciphertext_hex.len() / 2;
    println!("send '{}' -> {handle} ({ciphertext_len} bytes ciphertext)", send_state.id);

    let id = send_state.id.clone();
    let result = Pipeline::new(home, &config).run(&mut send_state, &mut cli_sink(&id));
    result
}

fn cmd_resume(home: &Home, id: &str) -> Result<()> {
    let config = home.load_config()?;
    let mut send_state = SendState::load(home, id)?;
    let id = send_state.id.clone();
    if send_state.is_virtual() {
        return app::resume_send(home, &config, &mut send_state, &mut virtual_sink());
    }
    let result = Pipeline::new(home, &config).run(&mut send_state, &mut cli_sink(&id));
    result
}

/// SNIP-36 progress: the send id is only known once Prepare has built the
/// commitment, so lines are keyed by step, and the publish hash is printed
/// the moment the gateway takes it.
fn virtual_sink() -> impl FnMut(zkmsg_core::pipeline::PipelineEvent) {
    use zkmsg_core::pipeline::PipelineEvent as E;
    move |event| match event {
        E::StepStarted { index, total, kind } => println!("[snip36] step {}/{total}: {kind:?}", index + 1),
        E::StepCompleted { kind, .. } => println!("[snip36] {kind:?} done"),
        E::Checkpointed { id } => println!("[snip36] proof saved — resumable as `zkmsg resume {id}`"),
        E::TxSubmitted { tx_hash, .. } => println!("[snip36] submitted {tx_hash}"),
        E::Completed { .. } => {}
    }
}

fn format_step_line(id: &str, index: usize, total: usize, kind: &zkmsg_core::state::StepKind) -> String {
    format!("[{id}] step {}/{}: {kind:?}", index + 1, total)
}

fn format_complete_line(id: &str, fact: Option<&str>) -> String {
    format!("[{id}] complete — fact {}", fact.unwrap_or("(recorded on-chain)"))
}

/// Reproduces the pre-refactor CLI's live progress output exactly:
/// a "step N/M: Kind" line per step start, and a "complete — fact …" line
/// at the end. Tx submissions and step completions print nothing, as
/// before — the runbook was narrated by step, not by transaction.
fn cli_sink(id: &str) -> impl FnMut(zkmsg_core::pipeline::PipelineEvent) + '_ {
    use zkmsg_core::pipeline::PipelineEvent as E;
    move |event| match event {
        E::StepStarted { index, total, kind } => {
            println!("{}", format_step_line(id, index, total, &kind));
        }
        E::TxSubmitted { .. } => {}
        E::StepCompleted { .. } => {}
        E::Checkpointed { .. } => {}
        E::Completed { fact } => {
            println!("{}", format_complete_line(id, fact.as_deref()));
        }
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
    messages.extend(inbox::scan(&chain, &config.store, &scan_priv)?);
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

fn cmd_status(home: &Home) -> Result<()> {
    let report = app::status(home)?;

    println!("rpc      : {}", report.rpc);
    println!("account  : {}", report.account);
    println!("registry : {} (live lane-1)", report.registry);
    let route = if report.store.is_empty() {
        ""
    } else if zkmsg_core::config::is_snip36_store(&report.store) {
        " (SNIP-36, one-transaction sends)"
    } else if zkmsg_core::config::same_address(&report.store, zkmsg_core::config::SEPOLIA_STORE_V3) {
        " (legacy v3, lane-1)"
    } else {
        ""
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
        Some(strk) if zkmsg_core::config::is_snip36_store(&report.store) => {
            println!("balance  : ~{strk} STRK (a send costs ~1.6; needs ~4 of fee ceiling)")
        }
        Some(strk) => println!("balance  : ~{strk} STRK (a send costs ~50 at spiky prices)"),
        None => {
            let e = report.balance_error.as_deref().unwrap_or("?");
            println!("balance  : unavailable ({e})");
        }
    }
    Ok(())
}

fn cmd_dev_args(out: &Path) -> Result<()> {
    // The milestone-1 synthetic 2-user tree (scan privs 5/7, ephemeral 6).
    let mut tree = tree::MerkleTree::new();
    tree.insert(ec_mul_gen_x(&Felt::from(5u32)));
    let recipient_pub = ec_mul_gen_x(&Felt::from(7u32));
    tree.insert(recipient_pub);
    let (args, tuple) = build_circuit_args(&CircuitInputs {
        merkle_root: tree.root(),
        sender_scan_priv: Felt::from(5u32),
        recipient_scan_pub: recipient_pub,
        ephemeral_priv: Felt::from(6u32),
        sender_leaf_index: 0,
        recipient_leaf_index: 1,
        sender_path: &tree.path(0),
        recipient_path: &tree.path(1),
    })?;
    std::fs::write(out, args_to_json(&args))?;
    println!("wrote {} (commitment {})", out.display(), felt_hex(&tuple.commitment));
    Ok(())
}

// --- helpers ----------------------------------------------------------------

fn check_balance(chain: &Chain, config: &Config) -> Result<()> {
    let strk = zkmsg_core::app::account_balance_strk(chain, config)
        .context("balance check failed (use --force to skip)")?;
    ensure!(
        strk >= MIN_BALANCE_STRK,
        "balance ~{strk} STRK < {MIN_BALANCE_STRK} projected send ceiling — top up or --force",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_sink_line_formats() {
        use zkmsg_core::state::StepKind;

        // Plain kind.
        assert_eq!(
            format_step_line("6d3671ecef", 0, 6, &StepKind::Prove),
            "[6d3671ecef] step 1/6: Prove",
        );
        // Kind with a field.
        assert_eq!(
            format_step_line("6d3671ecef", 2, 6, &StepKind::Stage { offset: 0 }),
            "[6d3671ecef] step 3/6: Stage { offset: 0 }",
        );
        // Completed with a fact.
        assert_eq!(
            format_complete_line(
                "6d3671ecef",
                Some("0x2dc0a3703c2703c471591c64307ebb8a50f8c4eae35f0c916d6fca56014145f"),
            ),
            "[6d3671ecef] complete — fact 0x2dc0a3703c2703c471591c64307ebb8a50f8c4eae35f0c916d6fca56014145f",
        );
        // Completed without a fact falls back to the placeholder.
        assert_eq!(
            format_complete_line("6d3671ecef", None),
            "[6d3671ecef] complete — fact (recorded on-chain)",
        );
    }
}
