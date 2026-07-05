//! zkmsg — messagezk on lane 1, natively. A private message costs one
//! locally-proven ZK statement (sender+recipient membership, ephemeral
//! ECDH, commitment), verified on Starknet Sepolia through the live
//! `StwoFactRegistry`, then published to MessageStore v3.
//!
//! Spec: docs/superpowers/specs/2026-07-05-zkmsg-lane1-port-design.md.

mod args;
mod chain;
mod config;
mod crypto;
mod inbox;
mod pack;
mod pipeline;
mod state;
mod tree;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use starknet_types_core::felt::Felt;

use crate::args::{CircuitInputs, args_to_json, build_circuit_args};
use crate::chain::{Chain, felt_hex, felt_to_u64};
use crate::config::{Config, Home, Keys};
use crate::crypto::{ec_mul_gen_x, ecdh_shared_x, encrypt, poseidon2, scan_keygen};
use crate::pipeline::Pipeline;
use crate::state::SendState;

/// STRK token (same address on Sepolia and mainnet).
const STRK: &str = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
/// Rough per-send ceiling at spiky Sepolia prices (runbook: the fixture
/// fact cost ~49 STRK; refuse to start below this unless --force).
const MIN_BALANCE_STRK: u128 = 60;

fn default_home() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".zkmsg")
}

/// The repo this binary was built from — bridge + circuit artifact paths.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
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
        /// MessageStore v3 address (defaults to the baked-in deployment).
        #[arg(long)]
        store: Option<String>,
    },
    /// Register a handle on-chain (one tx).
    Register { handle: String },
    /// Prove + verify + publish a private message (~50 STRK on Sepolia).
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
    Inbox,
    /// Config, balance, projected cost, deployed addresses.
    Status,
    /// Internal: write the milestone-1 synthetic-tree args file.
    #[command(hide = true, name = "dev-args")]
    DevArgs { out: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let home = Home::new(cli.home_dir());

    match cli.command {
        Command::Init { account, store } => cmd_init(&home, account, store),
        Command::Register { handle } => cmd_register(&home, &handle),
        Command::Send { handle, text, force } => cmd_send(&home, &handle, &text, force),
        Command::Resume { id } => cmd_resume(&home, &id),
        Command::Inbox => cmd_inbox(&home),
        Command::Status => cmd_status(&home),
        Command::DevArgs { out } => cmd_dev_args(&out),
    }
}

fn cmd_init(home: &Home, account: String, store: Option<String>) -> Result<()> {
    let (scan_priv, scan_pub) = scan_keygen();
    home.save_new_keys(&Keys {
        scan_priv: felt_hex(&scan_priv),
        scan_pub: felt_hex(&scan_pub),
        handle: None,
        leaf_index: None,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home.dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let mut config = Config::default_sepolia(&repo_root());
    config.account = account;
    if let Some(store) = store {
        config.store = store;
    }
    home.save_config(&config)?;

    println!("zkmsg home: {}", home.dir.display());
    println!("scan pubkey: {}", felt_hex(&scan_pub));
    println!("account: {}", config.account);
    if config.store.is_empty() {
        println!("NOTE: no MessageStore address configured yet (set it in config.json)");
    }
    Ok(())
}

fn cmd_register(home: &Home, handle: &str) -> Result<()> {
    let config = home.load_config()?;
    let mut keys = home.load_keys()?;
    ensure!(!config.store.is_empty(), "no store address in config.json");
    if let Some(existing) = &keys.handle {
        bail!("already registered as '{existing}'");
    }

    let chain = Chain::new(&config.rpc_url, &config.account);
    let handle_felt = short_string_felt(handle)?;
    let tx = chain.invoke(
        &config.store,
        "register",
        &[felt_hex(&handle_felt), keys.scan_pub.clone()],
        &Default::default(),
    )?;
    println!("register tx {tx}");
    chain.wait_receipt(&tx, std::time::Duration::from_secs(600))?;

    let user = chain.call(&config.store, "get_user", &[felt_hex(&handle_felt)])?;
    ensure!(user.len() == 3, "get_user shape: {user:?}");
    let leaf_index = felt_to_u64(&Felt::from_hex(&user[2])?)? as u32;
    keys.handle = Some(handle.to_string());
    keys.leaf_index = Some(leaf_index);
    home.update_keys(&keys)?;
    println!("registered '{handle}' at leaf {leaf_index}");
    Ok(())
}

fn cmd_send(home: &Home, handle: &str, text: &str, force: bool) -> Result<()> {
    let config = home.load_config()?;
    let keys = home.load_keys()?;
    ensure!(!config.store.is_empty(), "no store address in config.json");
    let sender_leaf = keys.leaf_index.context("not registered — run `zkmsg register`")?;
    let chain = Chain::new(&config.rpc_url, &config.account);

    if !force {
        check_balance(&chain, &config)?;
    }

    // Resolve the recipient and pull both membership paths + the root.
    let handle_felt = short_string_felt(handle)?;
    let user = chain.call(&config.store, "get_user", &[felt_hex(&handle_felt)])?;
    ensure!(user.len() == 3, "get_user shape: {user:?}");
    let recipient_pub = Felt::from_hex(&user[1])?;
    let recipient_leaf = felt_to_u64(&Felt::from_hex(&user[2])?)? as u32;

    let root = Felt::from_hex(
        chain.call(&config.store, "get_merkle_root", &[])?.first().context("root")?,
    )?;
    let sender_path = call_path(&chain, &config, sender_leaf)?;
    let recipient_path = call_path(&chain, &config, recipient_leaf)?;

    // Fresh ephemeral key; args + the tuple the proof must produce.
    let (eph_priv, _) = scan_keygen();
    let (circuit_args, tuple) = build_circuit_args(&CircuitInputs {
        merkle_root: root,
        sender_scan_priv: keys.scan_priv_felt()?,
        recipient_scan_pub: recipient_pub,
        ephemeral_priv: eph_priv,
        sender_leaf_index: sender_leaf,
        recipient_leaf_index: recipient_leaf,
        sender_path: &sender_path,
        recipient_path: &recipient_path,
    })?;

    let shared = ecdh_shared_x(&eph_priv, &recipient_pub)?;
    let ciphertext = encrypt(&shared, text.as_bytes());

    let id = format!("{:.10}", felt_hex(&tuple.commitment).trim_start_matches("0x"));
    let proof_id = poseidon2(&tuple.commitment, &short_string_felt("zkmsg")?);
    let args_hex: Vec<String> =
        serde_json::from_str(&args_to_json(&circuit_args)).expect("round trip");

    let mut send_state = SendState::new_plan(
        id.clone(),
        handle.to_string(),
        hex::encode(&ciphertext),
        args_hex,
        (
            felt_hex(&tuple.commitment),
            felt_hex(&tuple.ephemeral_pubkey),
            felt_hex(&tuple.merkle_root),
        ),
        felt_hex(&proof_id),
    );
    send_state.save(home)?;
    println!("send '{id}' -> {handle} ({} bytes ciphertext)", ciphertext.len());

    Pipeline::new(home, &config).run(&mut send_state)
}

fn cmd_resume(home: &Home, id: &str) -> Result<()> {
    let config = home.load_config()?;
    let mut send_state = SendState::load(home, id)?;
    Pipeline::new(home, &config).run(&mut send_state)
}

fn cmd_inbox(home: &Home) -> Result<()> {
    let config = home.load_config()?;
    let keys = home.load_keys()?;
    ensure!(!config.store.is_empty(), "no store address in config.json");
    let chain = Chain::new(&config.rpc_url, &config.account);

    let messages = inbox::scan(&chain, &config.store, &keys.scan_priv_felt()?)?;
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
    let config = home.load_config()?;
    let keys = home.load_keys().ok();
    let chain = Chain::new(&config.rpc_url, &config.account);

    println!("rpc      : {}", config.rpc_url);
    println!("account  : {}", config.account);
    println!("registry : {} (live lane-1)", config.registry);
    println!(
        "store    : {}",
        if config.store.is_empty() { "(not deployed)" } else { &config.store },
    );
    if let Some(keys) = &keys {
        println!("scan pub : {}", keys.scan_pub);
        match (&keys.handle, keys.leaf_index) {
            (Some(h), Some(i)) => println!("handle   : {h} (leaf {i})"),
            _ => println!("handle   : (not registered)"),
        }
    }
    if !config.store.is_empty() {
        if let Ok(n) = chain.call(&config.store, "n_messages", &[]) {
            println!("messages : {}", n.first().map(String::as_str).unwrap_or("?"));
        }
    }
    match account_balance_strk(&chain, &config) {
        Ok(strk) => println!("balance  : ~{strk} STRK (a send costs ~50 at spiky prices)"),
        Err(e) => println!("balance  : unavailable ({e})"),
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

fn short_string_felt(s: &str) -> Result<Felt> {
    ensure!(s.len() <= 31 && s.is_ascii(), "handle must be ASCII, <= 31 chars");
    let mut buf = [0u8; 32];
    buf[32 - s.len()..].copy_from_slice(s.as_bytes());
    Ok(Felt::from_bytes_be(&buf))
}

fn call_path(chain: &Chain, config: &Config, leaf_index: u32) -> Result<Vec<Felt>> {
    let raw = chain.call(&config.store, "get_merkle_path", &[format!("{leaf_index:#x}")])?;
    // Array<felt252> response: length prefix + 20 siblings.
    ensure!(raw.len() == 21, "get_merkle_path shape: {} felts", raw.len());
    raw[1..].iter().map(|s| Felt::from_hex(s).context("path felt")).collect()
}

/// The account's STRK balance in whole tokens (floor).
fn account_balance_strk(chain: &Chain, config: &Config) -> Result<u128> {
    let address = account_address(&config.account)?;
    let out = chain.call(STRK, "balance_of", &[address])?;
    let low = u128::from_str_radix(
        out.first().context("balance_of shape")?.trim_start_matches("0x"),
        16,
    )?;
    Ok(low / 1_000_000_000_000_000_000)
}

fn check_balance(chain: &Chain, config: &Config) -> Result<()> {
    let strk = account_balance_strk(chain, config)
        .context("balance check failed (use --force to skip)")?;
    ensure!(
        strk >= MIN_BALANCE_STRK,
        "balance ~{strk} STRK < {MIN_BALANCE_STRK} projected send ceiling — top up or --force",
    );
    Ok(())
}

/// The account's address from sncast's OZ accounts file.
fn account_address(account: &str) -> Result<String> {
    let path = PathBuf::from(std::env::var("HOME")?)
        .join(".starknet_accounts/starknet_open_zeppelin_accounts.json");
    let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let address = raw["alpha-sepolia"][account]["address"]
        .as_str()
        .with_context(|| format!("account '{account}' not in {}", path.display()))?;
    Ok(address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_strings_encode_like_cairo() {
        // 'zkmsg' == 0x7a6b6d7367 (Cairo short-string literal).
        assert_eq!(short_string_felt("zkmsg").unwrap(), Felt::from_hex("0x7a6b6d7367").unwrap());
        assert!(short_string_felt("this-is-way-too-long-for-a-short-string").is_err());
    }
}
