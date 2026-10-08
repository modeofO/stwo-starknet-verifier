//! Shared UX actions behind `status`, `init`, `register`, `send` — the
//! non-pipeline logic that both the CLI and the GUI drive identically.
//! Nothing here prints; callers own presentation.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use starknet_types_core::felt::Felt;

use crate::chain::{Chain, account_address, bytearray_calldata, felt_hex, felt_to_u64};
use crate::config::{Config, Home, Keys, STRK_TOKEN, is_current_store};
use crate::crypto::{kem_digest, member_commit, scan_keygen};
use crate::state::{SendState, StepKind};
use crate::tickets::{TicketCounts, TicketTree, Wallet};

pub struct StatusReport {
    pub rpc: String,
    pub account: String,
    /// The account's on-chain address from sncast's accounts file; `None`
    /// when the named account is missing from it (the name alone is
    /// ambiguous — profiles can share one funding account).
    pub account_address: Option<String>,
    pub store: String,
    pub scan_pub: Option<String>,
    pub handle: Option<String>,
    pub leaf_index: Option<u32>,
    pub n_messages: Option<String>,
    pub balance_strk: Option<u128>,
    /// Set (and `balance_strk` left `None`) when the balance read fails,
    /// so callers can reproduce the CLI's "unavailable ({e})" message.
    pub balance_error: Option<String>,
    /// The local ticket wallet on the current store (no network read).
    pub tickets: Option<TicketCounts>,
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
        account_address: account_address(&config.account).ok(),
        store: config.store.clone(),
        scan_pub: keys.as_ref().map(|k| k.scan_pub.clone()),
        handle: keys.as_ref().and_then(|k| k.handle.clone()),
        leaf_index: keys.as_ref().and_then(|k| k.leaf_index),
        n_messages,
        balance_strk,
        balance_error,
        tickets: is_current_store(&config.store)
            .then(|| Wallet::load(home, &config.store).ok().map(|w| w.counts()))
            .flatten(),
    })
}

/// Generates the scan keypair, the ML-KEM seed and the membership secret,
/// writes `keys.json` (mode 0600, refuses to overwrite) and a default Sepolia `config.json`. Returns the scan
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
        kem_seed: Some(crate::config::kem_seed_hex(&crate::crypto::kem_seed_gen())),
        member_secret: Some(crate::config::member_secret_hex(&crate::crypto::member_secret_gen())),
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
    ensure!(
        is_current_store(&config.store),
        "{} is not the v4 pool — `zkmsg migrate-store` first",
        config.store
    );
    if let Some(existing) = &home.load_keys()?.handle {
        bail!("already registered as '{existing}'");
    }
    // Registration publishes the ML-KEM key and the membership commitment;
    // an older profile gets its seed and secret now, written to keys.json
    // before anything reaches the chain.
    let mut keys = home.ensure_register_keys()?;
    let ek = keys.kem_keypair()?.1;
    let digest = kem_digest(&ek);
    let m_commit = member_commit(&keys.member_secret_felt()?);

    let chain = Chain::new(&config.rpc_url, &config.account);
    let handle_felt = short_string_felt(handle)?;
    let ours = |user: &Member| {
        Some(user.scan_pub) == keys.scan_pub_felt().ok()
            && user.kem_digest == digest
            && user.m_commit == m_commit
    };
    // Only the store's own "unknown handle" means unregistered; any other
    // failure (RPC down, timeout) stops here rather than paying for a
    // register that may already have landed.
    let already = match chain.call(&config.store, "get_user", &[felt_hex(&handle_felt)]) {
        Ok(u) => Some(Member::parse(&u)?).filter(|u| ours(u)),
        Err(e) if is_unknown_handle(&format!("{e:#}")) => None,
        Err(e) => return Err(e.context("checking whether the handle is registered")),
    };
    let tx_hash = if already.is_none() {
        let mut calldata = vec![handle_felt, keys.scan_pub_felt()?];
        for word in bytearray_calldata(&ek) {
            calldata.push(Felt::from_hex(&word)?);
        }
        calldata.push(m_commit);
        let call = crate::invoke_v3::Call::new(Felt::from_hex(&config.store)?, "register", calldata);
        // Signed natively under the shared policy, like every client's.
        Some(crate::account_tx::send(&chain, &config.account, &[call], crate::txpolicy::TxKind::Register)?)
    } else {
        None
    };

    let user = Member::parse(&chain.call(&config.store, "get_user", &[felt_hex(&handle_felt)])?)?;
    ensure!(ours(&user), "'{handle}' is registered, but not to this profile's keys");
    let leaf_index = user.leaf_index;
    keys.handle = Some(handle.to_string());
    keys.leaf_index = Some(leaf_index);
    home.update_keys(&keys)?;

    Ok(match tx_hash {
        Some(tx_hash) => RegisterOutcome::Registered { tx_hash, leaf_index },
        None => RegisterOutcome::AlreadyRegistered { leaf_index },
    })
}

/// The store's `get_user` revert for an unregistered handle. sncast reports
/// the reason hex-encoded (`0x756e6b…` = 'unknown handle'); match both forms.
fn is_unknown_handle(error: &str) -> bool {
    error.contains("unknown handle") || error.contains(&format!("0x{}", hex::encode("unknown handle")))
}

/// A registered member as `get_user` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub scan_pub: Felt,
    /// Poseidon over the registered ML-KEM key's ByteArray.
    pub kem_digest: Felt,
    /// poseidon(MEMBER_V3, m): the membership secret's commitment.
    pub m_commit: Felt,
    pub leaf_index: u32,
}

impl Member {
    /// `get_user` returns `(owner, scan_pubkey, kem_digest, m_commit,
    /// leaf_index)`.
    pub fn parse(user: &[String]) -> Result<Self> {
        let felts: Vec<Felt> =
            user.iter().map(|s| Felt::from_hex(s).context("get_user felt")).collect::<Result<_>>()?;
        Self::from_felts(&felts)
    }

    pub fn from_felts(user: &[Felt]) -> Result<Self> {
        ensure!(user.len() == 5, "get_user returned {} felts, expected 5", user.len());
        Ok(Self {
            scan_pub: user[1],
            kem_digest: user[2],
            m_commit: user[3],
            leaf_index: u32::try_from(felt_to_u64(&user[4])?).context("leaf index")?,
        })
    }
}

/// Looks up a handle's scan pubkey + leaf index among the store's
/// registrations. All of them are read and the match is made locally: a
/// `get_user(handle)` would tell the RPC whom this profile is about to
/// write to.
pub fn resolve_recipient(chain: &Chain, store: &str, handle: &str) -> Result<(Felt, u32)> {
    let registry = crate::registry::Registry::fetch(chain, store, None)?;
    let user = registry.get(handle)?;
    Ok((user.scan_pub, user.leaf_index))
}

/// What `migrate_store` changed, so a caller can tell the user what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreMigration {
    pub previous_store: String,
    /// The handle the profile had on the previous store — the obvious one to
    /// register again (registration is per store).
    pub previous_handle: Option<String>,
}

/// Points a profile at the v4 pool. Registration is per store, so the
/// handle and leaf index are cleared and the user registers again, with a
/// FRESH identity: a new scan key, ML-KEM seed and membership secret. Keys
/// reused across stores would link the identities (red team 2026-10); the
/// old ones stay in whatever backup was taken first — this overwrites them.
/// `account` replaces the profile's account (the one that registers and buys
/// tickets); an empty RPC URL is reset to the Sepolia default.
/// Refused while a send is incomplete: its proof is bound to the old store.
pub fn migrate_store(home: &Home, account: Option<&str>) -> Result<StoreMigration> {
    let mut config = home.load_config()?;
    ensure!(!is_current_store(&config.store), "this profile already uses the v4 pool");
    let pending = pending_sends(home)?;
    ensure!(
        pending.is_empty(),
        "{} incomplete send(s) on the current store ({}); resume or discard them first",
        pending.len(),
        pending.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>().join(", "),
    );
    if let Some(account) = account {
        account_address(account).with_context(|| format!("account '{account}'"))?;
    }

    // One write: the old store's registration out, a fresh identity in.
    let mut keys = home.load_keys()?;
    let migration = StoreMigration {
        previous_store: config.store.clone(),
        previous_handle: keys.handle.take(),
    };
    let (scan_priv, scan_pub) = scan_keygen();
    keys.scan_priv = felt_hex(&scan_priv);
    keys.scan_pub = felt_hex(&scan_pub);
    keys.leaf_index = None;
    keys.kem_seed = Some(crate::config::kem_seed_hex(&crate::crypto::kem_seed_gen()));
    keys.member_secret = Some(crate::config::member_secret_hex(&crate::crypto::member_secret_gen()));
    home.update_keys(&keys)?;
    config.store = crate::config::SEPOLIA_POOL_V4.to_string();
    if let Some(account) = account {
        config.account = account.to_string();
    }
    if config.rpc_url.is_empty() {
        config.rpc_url = crate::config::SEPOLIA_RPC_DEFAULT.into();
    }
    home.save_config(&config)?;
    // The cached inbox and the quota log belong to the old store.
    let _ = std::fs::remove_file(home.inbox_cache_path());
    let _ = std::fs::remove_file(home.quota_path());
    Ok(migration)
}

/// Whether `config` points at the store this client reads and writes (v4).
/// Anything else needs `migrate_store` first.
pub fn on_current_store(config: &Config) -> bool {
    is_current_store(&config.store)
}

/// A fresh send, end to end: prepare, prove and publish in one call,
/// because the witness Prepare builds is never written down.
pub fn send_virtual(
    home: &Home,
    config: &Config,
    keys: &Keys,
    handle: &str,
    text: &str,
    sink: &mut dyn FnMut(crate::pipeline::PipelineEvent),
) -> Result<SendState> {
    crate::virtual_send::VirtualSender::new(home, config)?.send(keys, handle, text, sink)
}

/// Resumes a saved send (only its Publish can be pending).
pub fn resume_send(
    home: &Home,
    config: &Config,
    state: &mut SendState,
    sink: &mut dyn FnMut(crate::pipeline::PipelineEvent),
) -> Result<()> {
    crate::virtual_send::VirtualSender::new(home, config)?.resume(state, sink)
}

/// What `buy_tickets` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPurchase {
    /// The one `[approve, buy_tickets]` transaction.
    pub buy_tx: String,
    pub bought: usize,
    pub price_fri: u128,
    /// Wallet counts after settling against the chain (a purchase the RPC
    /// has not indexed yet still reads as pending).
    pub counts: TicketCounts,
}

/// Buys `n` single-send tickets from the pool with the profile's account:
/// fresh secrets are written to `tickets.json` (0600) first, then ONE
/// natively signed `[approve, buy_tickets(leaves)]` transaction under the
/// shared policy. The purchase shows the account bought tickets; nothing
/// on chain ties a later send to them.
pub fn buy_tickets(home: &Home, n: usize) -> Result<TicketPurchase> {
    let config = home.load_config()?;
    ensure!(is_current_store(&config.store), "{} is not the v4 pool — `zkmsg migrate-store` first", config.store);
    let max = crate::txpolicy::MAX_TICKETS_PER_PURCHASE;
    ensure!((1..=max).contains(&n), "buy 1..={max} tickets at a time");
    let chain = Chain::new(&config.rpc_url, &config.account);
    let price_fri = {
        let out = chain.call(&config.store, "ticket_price", &[])?;
        u128::from_str_radix(out.first().context("ticket_price shape")?.trim_start_matches("0x"), 16)?
    };
    let total = price_fri.checked_mul(n as u128).context("ticket total overflows")?;

    let mut wallet = Wallet::load(home, &config.store)?;
    let first = wallet.tickets.len();
    let leaves = wallet.mint(n)?;
    // Bearer value: on disk before any transaction can make it real.
    wallet.save(home)?;

    let pool = Felt::from_hex(&config.store)?;
    let approve = crate::invoke_v3::Call::new(Felt::from_hex(STRK_TOKEN)?, "approve", vec![pool, Felt::from(total), Felt::ZERO]);
    let mut leaves_calldata = vec![Felt::from(n as u64)];
    leaves_calldata.extend_from_slice(&leaves);
    let buy = crate::invoke_v3::Call::new(pool, "buy_tickets", leaves_calldata);
    let buy_tx = crate::account_tx::send(&chain, &config.account, &[approve, buy], crate::txpolicy::TxKind::BuyTickets)?;
    for t in &mut wallet.tickets[first..] {
        t.buy_tx = Some(buy_tx.clone());
    }
    wallet.save(home)?;

    let tree = TicketTree::fetch(&chain, &config.store, None)?;
    wallet.settle(&tree)?;
    wallet.save(home)?;
    Ok(TicketPurchase { buy_tx, bought: n, price_fri, counts: wallet.counts() })
}

/// Settles pending purchases against ALL of the pool's ticket purchases
/// (the request names no ticket) and returns the wallet's counts.
pub fn sync_tickets(home: &Home) -> Result<TicketCounts> {
    let config = home.load_config()?;
    ensure!(is_current_store(&config.store), "{} is not the v4 pool — `zkmsg migrate-store` first", config.store);
    let mut wallet = Wallet::load(home, &config.store)?;
    if wallet.counts().pending > 0 {
        let chain = Chain::new(&config.rpc_url, &config.account);
        if wallet.settle(&TicketTree::fetch(&chain, &config.store, None)?)? > 0 {
            wallet.save(home)?;
        }
    }
    Ok(wallet.counts())
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
        // States from the removed lane-1 pipeline no longer parse: skip
        // them rather than hide every other pending send behind the error.
        let Ok(state) = SendState::load(home, id) else { continue };
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recognises_the_unknown_handle_revert() {
        // Verbatim from sncast 0.61 against the v3 store, 2026-10-01.
        assert!(is_unknown_handle(
            r#"sncast error: "An error occurred in the called contract = ContractErrorData { revert_error: Message(\"0x756e6b6e6f776e2068616e646c65\") }""#
        ));
        assert!(!is_unknown_handle("rpc starknet_call: connection refused"));
    }

    #[test]
    fn short_string_matches_cairo() {
        assert_eq!(short_string_felt("zkmsg").unwrap(),
            starknet_types_core::felt::Felt::from_hex("0x7a6b6d7367").unwrap());
        assert!(short_string_felt("x".repeat(40).as_str()).is_err());
    }
    /// The retired SNIP-36 v1 store.
    const OLD_STORE: &str = "0x002b9c6f617b3197dfed76401c32aa3b4b597ebdd01a7eba4b5657236bc8084f";

    #[test]
    fn migrate_store_moves_to_v4_with_a_fresh_identity() {
        let dir = std::env::temp_dir().join(format!("zkmsg-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Home::new(dir.clone());
        let mut config = Config::default_sepolia(Path::new("/r"));
        config.store = OLD_STORE.into();
        home.save_config(&config).unwrap();
        home.save_new_keys(&Keys {
            scan_priv: "0x5".into(),
            scan_pub: "0x6".into(),
            handle: Some("carol".into()),
            leaf_index: Some(0),
            kem_seed: None,
            member_secret: None,
        })
        .unwrap();

        std::fs::write(home.quota_path(), "{}").unwrap();
        let m = migrate_store(&home, None).unwrap();
        assert_eq!(m.previous_handle.as_deref(), Some("carol"));
        assert_eq!(m.previous_store, OLD_STORE);
        let keys = home.load_keys().unwrap();
        assert_eq!((keys.handle.as_deref(), keys.leaf_index), (None, None));
        assert_ne!(keys.scan_priv, "0x5", "a fresh scan key: none is reused across stores");
        assert_eq!(keys.scan_pub_felt().unwrap(), crate::crypto::ec_mul_gen_x(&keys.scan_priv_felt().unwrap()));
        assert!(keys.kem_seed_bytes().is_ok());
        assert!(keys.member_secret_felt().is_ok(), "a fresh membership secret for the new store");
        assert!(is_current_store(&home.load_config().unwrap().store));
        assert!(!home.quota_path().exists(), "the old store's quota log is dropped");
        // Twice is refused.
        assert!(migrate_store(&home, None).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn migrate_store_refuses_with_pending_sends() {
        let dir = std::env::temp_dir().join(format!("zkmsg-migrate-p-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Home::new(dir.clone());
        let mut config = Config::default_sepolia(Path::new("/r"));
        config.store = OLD_STORE.into();
        home.save_config(&config).unwrap();
        let s = SendState::new_virtual_plan(
            "p1".into(), "mode2".into(), "00".into(), ("0xa".into(), "0xb".into(), "0xc".into()), 1,
        );
        s.save(&home).unwrap();
        assert!(migrate_store(&home, None).unwrap_err().to_string().contains("p1"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pending_sends_reads_incomplete_only() {
        let dir = std::env::temp_dir().join(format!("zkmsg-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = crate::config::Home::new(dir.clone());
        let mut s = crate::state::SendState::new_virtual_plan("s1".into(), "bob".into(),
            "00".into(), ("0xa".into(),"0xb".into(),"0xc".into()), 1);
        s.mark_done(0, None, None);
        s.save(&home).unwrap();
        // A lane-1 state left over from before 2026-10-01 is skipped.
        std::fs::write(home.sends_dir().join("old.json"), r#"{"id":"old","steps":[{"kind":"Wrap"}]}"#)
            .unwrap();
        let pending = pending_sends(&home).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "s1");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
