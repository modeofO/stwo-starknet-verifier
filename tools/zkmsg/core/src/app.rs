//! Shared UX actions behind `status`, `init`, `register`, `send` — the
//! non-pipeline logic that both the CLI and the GUI drive identically.
//! Nothing here prints; callers own presentation.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use starknet_types_core::felt::Felt;

use crate::args::{CircuitInputs, args_to_json, build_circuit_args};
use crate::chain::{Chain, account_address, felt_hex, felt_to_u64};
use crate::config::{Config, Home, Keys, STRK_TOKEN};
use crate::crypto::{ecdh_shared_x, encrypt, poseidon2, scan_keygen};
use crate::state::{SendState, StepKind};

pub struct StatusReport {
    pub rpc: String,
    pub account: String,
    pub registry: String,
    pub store: String,
    pub scan_pub: Option<String>,
    pub handle: Option<String>,
    pub leaf_index: Option<u32>,
    pub n_messages: Option<String>,
    pub balance_strk: Option<u128>,
    /// Set (and `balance_strk` left `None`) when the balance read fails,
    /// so callers can reproduce the CLI's "unavailable ({e})" message.
    pub balance_error: Option<String>,
}

/// Snapshots config, keys and live chain reads (message count, balance)
/// into one report; callers render it however they like.
pub fn status(home: &Home) -> Result<StatusReport> {
    let config = home.load_config()?;
    let keys = home.load_keys().ok();
    let chain = Chain::new(&config.rpc_url, &config.account);

    let n_messages = if !config.store.is_empty() {
        chain
            .call(&config.store, "n_messages", &[])
            .ok()
            .map(|n| n.first().cloned().unwrap_or_else(|| "?".into()))
    } else {
        None
    };
    let (balance_strk, balance_error) = match account_balance_strk(&chain, &config) {
        Ok(strk) => (Some(strk), None),
        Err(e) => (None, Some(e.to_string())),
    };

    Ok(StatusReport {
        rpc: config.rpc_url.clone(),
        account: config.account.clone(),
        registry: config.registry.clone(),
        store: config.store.clone(),
        scan_pub: keys.as_ref().map(|k| k.scan_pub.clone()),
        handle: keys.as_ref().and_then(|k| k.handle.clone()),
        leaf_index: keys.as_ref().and_then(|k| k.leaf_index),
        n_messages,
        balance_strk,
        balance_error,
    })
}

/// Generates the scan keypair, writes `keys.json` (mode 0600, refuses to
/// overwrite) and a default Sepolia `config.json`. Returns the scan
/// pubkey.
pub fn init_identity(
    home: &Home,
    account: &str,
    store: Option<String>,
    repo_root: &Path,
) -> Result<Felt> {
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

    let mut config = Config::default_sepolia(repo_root);
    config.account = account.to_string();
    if let Some(store) = store {
        config.store = store;
    }
    home.save_config(&config)?;

    Ok(scan_pub)
}

/// Which branch `register` took — lets a caller reproduce the CLI's
/// distinct progress lines for a fresh registration vs. a local-state
/// sync (both end at the same final "registered at leaf N" outcome).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// The handle already resolved to our scan key; only local state
    /// (`keys.json`) was updated, no transaction was sent.
    AlreadyRegistered { leaf_index: u32 },
    /// A fresh `register` transaction landed.
    Registered { tx_hash: String, leaf_index: u32 },
}

/// Registers `handle` on-chain against our scan key and records the
/// leaf index locally. Idempotent: if the handle already resolves to our
/// scan key (e.g. a prior run died between invoke and local record), it
/// just syncs local state instead of re-registering.
pub fn register(home: &Home, handle: &str) -> Result<RegisterOutcome> {
    let config = home.load_config()?;
    let mut keys = home.load_keys()?;
    ensure!(!config.store.is_empty(), "no store address in config.json");
    if let Some(existing) = &keys.handle {
        bail!("already registered as '{existing}'");
    }

    let chain = Chain::new(&config.rpc_url, &config.account);
    let handle_felt = short_string_felt(handle)?;
    let already = chain
        .call(&config.store, "get_user", &[felt_hex(&handle_felt)])
        .ok()
        .filter(|u| u.len() == 3 && Felt::from_hex(&u[1]).ok() == keys.scan_pub_felt().ok());
    let tx_hash = if already.is_none() {
        let tx = chain.invoke(
            &config.store,
            "register",
            &[felt_hex(&handle_felt), keys.scan_pub.clone()],
            &Default::default(),
        )?;
        chain.wait_receipt(&tx, std::time::Duration::from_secs(600))?;
        Some(tx)
    } else {
        None
    };

    let user = chain.call(&config.store, "get_user", &[felt_hex(&handle_felt)])?;
    ensure!(user.len() == 3, "get_user shape: {user:?}");
    let leaf_index = felt_to_u64(&Felt::from_hex(&user[2])?)? as u32;
    keys.handle = Some(handle.to_string());
    keys.leaf_index = Some(leaf_index);
    home.update_keys(&keys)?;

    Ok(match tx_hash {
        Some(tx_hash) => RegisterOutcome::Registered { tx_hash, leaf_index },
        None => RegisterOutcome::AlreadyRegistered { leaf_index },
    })
}

/// Looks up a handle's scan pubkey + leaf index in the store.
pub fn resolve_recipient(chain: &Chain, store: &str, handle: &str) -> Result<(Felt, u32)> {
    let handle_felt = short_string_felt(handle)?;
    let user = chain.call(store, "get_user", &[felt_hex(&handle_felt)])?;
    ensure!(user.len() == 3, "get_user shape: {user:?}");
    let recipient_pub = Felt::from_hex(&user[1])?;
    let recipient_leaf = felt_to_u64(&Felt::from_hex(&user[2])?)? as u32;
    Ok((recipient_pub, recipient_leaf))
}

/// Everything a send needs before the paid pipeline runs: resolve the
/// recipient, pull the current root + both membership paths, mint a
/// fresh ephemeral key, build the circuit args + expected tuple, encrypt
/// the message, and persist the resulting `SendState` so a crash before
/// `Pipeline::run` still leaves a resumable checkpoint.
pub fn prepare_send(
    home: &Home,
    config: &Config,
    keys: &Keys,
    sender_leaf: u32,
    handle: &str,
    text: &str,
) -> Result<SendState> {
    let chain = Chain::new(&config.rpc_url, &config.account);
    let (recipient_pub, recipient_leaf) = resolve_recipient(&chain, &config.store, handle)?;

    let root = Felt::from_hex(
        chain.call(&config.store, "get_merkle_root", &[])?.first().context("root")?,
    )?;
    let sender_path = call_path(&chain, config, sender_leaf)?;
    let recipient_path = call_path(&chain, config, recipient_leaf)?;

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

    let send_state = SendState::new_plan(
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
    Ok(send_state)
}

/// Incomplete sends under `home` — id + the kind of their next pending
/// step, for a resume banner / list.
pub fn pending_sends(home: &Home) -> Result<Vec<(String, StepKind)>> {
    let dir = home.sends_dir();
    let mut out = vec![];
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        let state = SendState::load(home, id)?;
        if let Some(index) = state.next_pending() {
            out.push((id.to_string(), state.steps[index].kind.clone()));
        }
    }
    Ok(out)
}

/// Cairo short-string encoding: ASCII bytes right-aligned into a felt.
pub fn short_string_felt(s: &str) -> Result<Felt> {
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
pub fn account_balance_strk(chain: &Chain, config: &Config) -> Result<u128> {
    let address = account_address(&config.account)?;
    let out = chain.call(STRK_TOKEN, "balance_of", &[address])?;
    let low = u128::from_str_radix(
        out.first().context("balance_of shape")?.trim_start_matches("0x"),
        16,
    )?;
    Ok(low / 1_000_000_000_000_000_000)
}

/// Fri retained on a swept account to cover the transfer's own fee
/// (measured transfers cost ~0.05 STRK; 0.2 is generous, and the dust
/// left behind is the price of never under-providing the fee).
pub const SWEEP_HEADROOM_FRI: u128 = 200_000_000_000_000_000;

/// How much a sweep can move: balance minus headroom, `None` when the
/// balance doesn't exceed the headroom (nothing worth sweeping).
pub fn sweep_amount_fri(balance_fri: u128, headroom_fri: u128) -> Option<u128> {
    (balance_fri > headroom_fri).then(|| balance_fri - headroom_fri)
}

/// Sweeps (balance - headroom) STRK from `config.account` (the burner)
/// to `to_address`, waiting for the receipt. Returns (tx_hash, swept
/// fri). Blocking (invoke + receipt wait) — worker threads only.
///
/// The caller's UI must have shown the linking warning: this transfer
/// is a public on-chain edge from the burner to the target.
pub fn sweep_strk(config: &Config, to_address: &str) -> Result<(String, u128)> {
    let chain = Chain::new(&config.rpc_url, &config.account);
    let own_address = account_address(&config.account)?;
    let balance = crate::setup::read_balance_fri(&chain, &own_address)?;
    let amount = sweep_amount_fri(balance, SWEEP_HEADROOM_FRI)
        .with_context(|| format!("balance {balance} fri does not exceed the fee headroom"))?;
    let tx = chain.invoke(
        STRK_TOKEN,
        "transfer",
        &[to_address.to_string(), format!("{amount:#x}"), "0x0".into()],
        &Default::default(),
    )?;
    chain.wait_receipt(&tx, std::time::Duration::from_secs(600))?;
    Ok((tx, amount))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_string_matches_cairo() {
        assert_eq!(short_string_felt("zkmsg").unwrap(),
            starknet_types_core::felt::Felt::from_hex("0x7a6b6d7367").unwrap());
        assert!(short_string_felt("x".repeat(40).as_str()).is_err());
    }
    #[test]
    fn sweep_amount_leaves_headroom() {
        let one = 1_000_000_000_000_000_000u128;
        assert_eq!(sweep_amount_fri(10 * one, one / 5), Some(10 * one - one / 5));
        assert_eq!(sweep_amount_fri(one / 5, one / 5), None); // exactly headroom: nothing to sweep
        assert_eq!(sweep_amount_fri(0, one / 5), None);
    }
    #[test]
    fn pending_sends_reads_incomplete_only() {
        let dir = std::env::temp_dir().join(format!("zkmsg-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = crate::config::Home::new(dir.clone());
        let mut s = crate::state::SendState::new_plan("s1".into(), "bob".into(),
            "00".into(), vec!["0x1".into()],
            ("0xa".into(),"0xb".into(),"0xc".into()), "0xd".into());
        s.mark_done(0, None, None);
        s.save(&home).unwrap();
        let pending = pending_sends(&home).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "s1");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
