//! v4 fee tickets and quota slots — the two pieces of per-profile state a
//! pool send spends.
//!
//! A TICKET is a single-send bearer note bought from the pool
//! (`buy_tickets`, `ticket_price` STRK each): the buyer picks a secret t and
//! publishes only its leaf poseidon([TICKET_V4, t]). A send proves knowledge
//! of some ticket's t under a ticket root and reveals its ticket nullifier;
//! the pool's `__validate__` burns that nullifier and pays the send's fee
//! from the STRK the ticket brought in. Nothing ties the spend to the leaf
//! or to the account that bought it.
//!
//! Rules this module keeps:
//!
//!   * Secrets are written (0600, atomically) BEFORE the purchase is sent: a
//!     purchase that lands is never one whose secrets only lived in memory.
//!   * The ticket tree is rebuilt locally from ALL `TicketBought` events,
//!     like the member tree (`registry`): no request names a ticket, its
//!     leaf or its index. The pool's `get_ticket_path` is never called.
//!   * A ticket is reserved for a send while its proof exists, spent once
//!     the publish is accepted, and released if the proof is retired unsent.
//!   * Quota slots (`slot < quota` per epoch) are tracked locally and taken
//!     before proving, so a slot that may have reached the chain is never
//!     used twice. The store would refuse the second use anyway (in
//!     validate, unpaid), but only after minutes of proving.
//!
//! Event (contracts/zkmsg_pool_v4/src/pool.cairo `TicketBought`):
//!   keys = [sn_keccak("TicketBought")], data = [leaf, index]

use std::fs;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use crate::chain::{Chain, felt_hex, felt_to_u64, snkeccak};
use crate::config::{Home, same_address, store_deploy_block, write_atomic};
use crate::crypto::{member_secret_felt, ticket_leaf, ticket_nullifier, ticket_secret_gen};
use crate::tree::MerkleTree;

/// Tickets per `buy_tickets` call (`pool::MAX_TICKETS_PER_BUY`).
pub const MAX_TICKETS_PER_BUY: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TicketState {
    /// Secret saved; the purchase has not been seen on chain (yet).
    Pending,
    /// In the pool's ticket tree, never spent.
    Unspent,
    /// A send's proof spends it; settled when that send publishes or is
    /// retired.
    Reserved { send_id: String },
    /// Burnt by an accepted publish (or found burnt by the pool).
    Spent { tx: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    /// t: `0x` + 64 lowercase hex (< 2^251, nonzero). Bearer value.
    pub secret: String,
    /// The leaf index once the purchase is in the tree.
    #[serde(default)]
    pub index: Option<u32>,
    /// The `buy_tickets` transaction, once submitted.
    #[serde(default)]
    pub buy_tx: Option<String>,
    #[serde(flatten)]
    pub state: TicketState,
}

impl Ticket {
    pub fn secret_felt(&self) -> Result<Felt> {
        let bytes = hex::decode(self.secret.trim_start_matches("0x")).context("ticket secret hex")?;
        member_secret_felt(&bytes).context("ticket secret")
    }

    pub fn leaf(&self) -> Result<Felt> {
        Ok(ticket_leaf(&self.secret_felt()?))
    }

    pub fn nullifier(&self, store: &Felt) -> Result<Felt> {
        Ok(ticket_nullifier(store, &self.secret_felt()?))
    }
}

/// `tickets.json`: one profile's tickets on one store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Wallet {
    pub store: String,
    pub tickets: Vec<Ticket>,
}

/// Counts by state, for status lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TicketCounts {
    pub unspent: usize,
    pub reserved: usize,
    pub spent: usize,
    pub pending: usize,
}

impl Wallet {
    /// The wallet for `store`; empty if there is none yet. A wallet kept for
    /// another store is refused rather than mixed in.
    pub fn load(home: &Home, store: &str) -> Result<Self> {
        let path = home.tickets_path();
        if !path.exists() {
            return Ok(Self { store: store.to_string(), tickets: vec![] });
        }
        let wallet: Self = serde_json::from_str(&fs::read_to_string(&path)?)
            .with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            same_address(&wallet.store, store),
            "{} holds tickets for store {}, not {store}",
            path.display(),
            wallet.store
        );
        Ok(wallet)
    }

    /// Atomic and owner-only: the secrets are bearer value.
    pub fn save(&self, home: &Home) -> Result<()> {
        fs::create_dir_all(&home.dir)?;
        write_atomic(&home.tickets_path(), serde_json::to_string_pretty(self)?.as_bytes(), 0o600)
    }

    pub fn counts(&self) -> TicketCounts {
        let mut c = TicketCounts::default();
        for t in &self.tickets {
            match t.state {
                TicketState::Pending => c.pending += 1,
                TicketState::Unspent => c.unspent += 1,
                TicketState::Reserved { .. } => c.reserved += 1,
                TicketState::Spent { .. } => c.spent += 1,
            }
        }
        c
    }

    /// Mints `n` fresh secrets as Pending tickets and returns their leaves.
    /// The caller saves the wallet before sending the purchase.
    pub fn mint(&mut self, n: usize) -> Result<Vec<Felt>> {
        let mut leaves = vec![];
        for _ in 0..n {
            let ticket = Ticket {
                secret: crate::config::member_secret_hex(&ticket_secret_gen()),
                index: None,
                buy_tx: None,
                state: TicketState::Pending,
            };
            leaves.push(ticket.leaf()?);
            self.tickets.push(ticket);
        }
        Ok(leaves)
    }

    /// Settles Pending tickets against the tree: a leaf found there is
    /// bought (Unspent, with its index). Returns how many were settled.
    pub fn settle(&mut self, tree: &TicketTree) -> Result<usize> {
        let mut settled = 0;
        for t in self.tickets.iter_mut() {
            if t.state != TicketState::Pending {
                continue;
            }
            if let Some(index) = tree.index_of(&t.leaf()?) {
                t.index = Some(index);
                t.state = TicketState::Unspent;
                settled += 1;
            }
        }
        Ok(settled)
    }

    /// An Unspent ticket whose leaf the tree holds at its index.
    pub fn pick(&self, tree: &TicketTree) -> Result<usize> {
        for (i, t) in self.tickets.iter().enumerate() {
            if t.state != TicketState::Unspent {
                continue;
            }
            let Some(index) = t.index else { continue };
            if tree.leaf(index) == Some(t.leaf()?) {
                return Ok(i);
            }
        }
        let c = self.counts();
        if c.unspent > 0 {
            return Err(TicketNotInTreeYet { unspent: c.unspent }.into());
        }
        bail!(
            "no unspent ticket ({} reserved, {} pending, {} spent) — buy one with `zkmsg buy-tickets`",
            c.reserved,
            c.pending,
            c.spent
        )
    }

    /// The wallet entry whose ticket nullifier on `store` is `nullifier`.
    pub fn position_by_nullifier(&self, store: &Felt, nullifier: &Felt) -> Option<usize> {
        self.tickets.iter().position(|t| t.nullifier(store).ok().as_ref() == Some(nullifier))
    }

    /// Marks the ticket with this nullifier spent (by `tx`, if known).
    pub fn mark_spent(&mut self, store: &Felt, nullifier: &Felt, tx: Option<String>) -> bool {
        match self.position_by_nullifier(store, nullifier) {
            Some(i) => {
                self.tickets[i].state = TicketState::Spent { tx };
                true
            }
            None => false,
        }
    }

    /// Back to Unspent: the send that reserved it will never publish.
    pub fn release(&mut self, store: &Felt, nullifier: &Felt) -> bool {
        match self.position_by_nullifier(store, nullifier) {
            Some(i) if matches!(self.tickets[i].state, TicketState::Reserved { .. }) => {
                self.tickets[i].state = TicketState::Unspent;
                true
            }
            _ => false,
        }
    }
}

/// Every unspent ticket was bought after the block the send proves on (the
/// schedule's base trails the head by 10–41 blocks): a fresh purchase is
/// usable a minute later. The sender waits on this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketNotInTreeYet {
    pub unspent: usize,
}

impl std::fmt::Display for TicketNotInTreeYet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} unspent ticket(s), but none is in the ticket tree at the proof's base block yet \
             (the base trails the head by 10–41 blocks) — try again in a minute",
            self.unspent
        )
    }
}

impl std::error::Error for TicketNotInTreeYet {}

/// The pool's ticket tree, rebuilt from its `TicketBought` events.
pub struct TicketTree {
    leaves: Vec<Felt>,
    tree: MerkleTree,
}

impl TicketTree {
    /// `(keys, data)` pairs as `Chain::events_through` returns them; any
    /// order. Indices must be 0, 1, 2, … with no gap or duplicate.
    pub fn from_events(events: &[(Vec<String>, Vec<String>)]) -> Result<Self> {
        let mut bought: Vec<(u32, Felt)> = events
            .iter()
            .map(|(keys, data)| {
                ensure!(keys.len() == 1, "TicketBought has {} keys, expected 1", keys.len());
                ensure!(data.len() == 2, "TicketBought has {} data felts, expected 2", data.len());
                let leaf = Felt::from_hex(&data[0]).context("ticket leaf")?;
                let index = u32::try_from(felt_to_u64(&Felt::from_hex(&data[1]).context("ticket index")?)?)?;
                Ok((index, leaf))
            })
            .collect::<Result<_>>()?;
        bought.sort_by_key(|(index, _)| *index);
        let mut tree = MerkleTree::new();
        let mut leaves = vec![];
        for (i, (index, leaf)) in bought.into_iter().enumerate() {
            ensure!(
                index as usize == i,
                "ticket events are not contiguous: index {index} where {i} was expected"
            );
            tree.insert(leaf);
            leaves.push(leaf);
        }
        Ok(Self { leaves, tree })
    }

    /// Every ticket bought from `store` up to and including `to_block`
    /// (`None`: latest). The request names no ticket.
    pub fn fetch(chain: &Chain, store: &str, to_block: Option<u64>) -> Result<Self> {
        let key0 = felt_hex(&snkeccak("TicketBought"));
        let events = chain
            .events_through(store, &key0, store_deploy_block(store), to_block)
            .context("reading the pool's ticket purchases")?;
        Self::from_events(&events)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn root(&self) -> Felt {
        self.tree.root()
    }

    pub fn leaf(&self, index: u32) -> Option<Felt> {
        self.leaves.get(index as usize).copied()
    }

    pub fn index_of(&self, leaf: &Felt) -> Option<u32> {
        self.leaves.iter().position(|l| l == leaf).map(|i| i as u32)
    }

    /// The 20 siblings bottom-up.
    pub fn path(&self, index: u32) -> Result<Vec<Felt>> {
        ensure!((index as usize) < self.len(), "ticket {index} is not in the tree");
        Ok(self.tree.path(index))
    }
}

/// `quota.json`: the slots this profile took in one epoch of one store.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotaLog {
    pub store: String,
    pub epoch: u64,
    /// Slots taken this epoch: the next free one is `used`.
    pub used: u32,
}

impl QuotaLog {
    pub fn load(home: &Home) -> Result<Option<Self>> {
        let path = home.quota_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&fs::read_to_string(&path)?).context("reading quota.json")?))
    }

    /// Takes the next free slot of `epoch` (refusing past `quota`) and
    /// records it before returning it.
    pub fn take_slot(home: &Home, store: &str, epoch: u64, quota: u32) -> Result<u32> {
        let mut log = match Self::load(home)? {
            Some(log) if same_address(&log.store, store) && log.epoch == epoch => log,
            Some(log) if same_address(&log.store, store) && log.epoch > epoch => {
                bail!("quota.json is at epoch {}, ahead of this send's {epoch}", log.epoch)
            }
            _ => Self { store: store.to_string(), epoch, used: 0 },
        };
        ensure!(
            log.used < quota,
            "all {quota} sends of epoch {epoch} are used — the next epoch refills the quota"
        );
        let slot = log.used;
        log.used += 1;
        write_atomic(&home.quota_path(), serde_json::to_string_pretty(&log)?.as_bytes(), 0o600)?;
        Ok(slot)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A `TicketBought` event as the RPC returns it.
    pub(crate) fn event(leaf: Felt, index: u32) -> (Vec<String>, Vec<String>) {
        (vec![felt_hex(&snkeccak("TicketBought"))], vec![felt_hex(&leaf), felt_hex(&Felt::from(index))])
    }

    fn home(tag: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("zkmsg-tickets-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Home::new(dir)
    }

    #[test]
    fn tree_rebuilds_from_events_in_any_order() {
        let leaves: Vec<Felt> = (1..=5u64).map(|i| ticket_leaf(&Felt::from(i))).collect();
        let mut events: Vec<_> = leaves.iter().enumerate().map(|(i, l)| event(*l, i as u32)).collect();
        events.reverse();
        let tree = TicketTree::from_events(&events).unwrap();
        assert_eq!(tree.len(), 5);
        let mut direct = MerkleTree::new();
        for l in &leaves {
            direct.insert(*l);
        }
        assert_eq!(tree.root(), direct.root());
        assert_eq!(tree.index_of(&leaves[3]), Some(3));
        assert_eq!(
            crate::tree::fold_path(&leaves[3], 3, &tree.path(3).unwrap()),
            tree.root()
        );
        assert!(tree.path(5).is_err());

        events.remove(2);
        assert!(TicketTree::from_events(&events).err().unwrap().to_string().contains("contiguous"));
    }

    #[test]
    fn wallet_lifecycle_and_file_mode() {
        let home = home("wallet");
        let store = Felt::from_hex("0x5704e").unwrap();
        let mut wallet = Wallet::load(&home, "0x5704e").unwrap();
        let leaves = wallet.mint(3).unwrap();
        wallet.save(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(home.tickets_path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "ticket secrets are owner-only");
        }
        assert_eq!(wallet.counts().pending, 3);
        assert!(wallet.pick(&TicketTree::from_events(&[]).unwrap()).is_err());

        // Someone else's ticket at 0, ours at 1 and 2; the third never landed.
        let events = vec![event(Felt::from(77u64), 0), event(leaves[0], 1), event(leaves[1], 2)];
        let tree = TicketTree::from_events(&events).unwrap();
        assert_eq!(wallet.settle(&tree).unwrap(), 2);
        assert_eq!(wallet.tickets[0].index, Some(1));
        assert_eq!(wallet.counts(), TicketCounts { unspent: 2, reserved: 0, spent: 0, pending: 1 });

        let i = wallet.pick(&tree).unwrap();
        assert_eq!(i, 0);
        let nullifier = wallet.tickets[i].nullifier(&store).unwrap();
        wallet.tickets[i].state = TicketState::Reserved { send_id: "s1".into() };
        assert_eq!(wallet.pick(&tree).unwrap(), 1, "a reserved ticket is not picked again");
        assert!(wallet.release(&store, &nullifier));
        assert_eq!(wallet.tickets[0].state, TicketState::Unspent);
        assert!(wallet.mark_spent(&store, &nullifier, Some("0xabc".into())));
        assert_eq!(wallet.pick(&tree).unwrap(), 1);

        wallet.save(&home).unwrap();
        let back = Wallet::load(&home, "0x05704e").unwrap();
        assert_eq!(back.counts(), TicketCounts { unspent: 1, reserved: 0, spent: 1, pending: 1 });
        assert!(Wallet::load(&home, "0x1").is_err(), "another store's wallet is refused");
        fs::remove_dir_all(&home.dir).unwrap();
    }

    /// A ticket settled against the latest tree but younger than the
    /// (older) tree a send proves on is "not yet", which the sender waits on.
    #[test]
    fn a_ticket_newer_than_the_base_tree_is_not_yet() {
        let mut wallet = Wallet::default();
        let leaves = wallet.mint(1).unwrap();
        wallet.settle(&TicketTree::from_events(&[event(leaves[0], 0)]).unwrap()).unwrap();
        let base_tree = TicketTree::from_events(&[]).unwrap();
        let err = wallet.pick(&base_tree).unwrap_err();
        assert_eq!(err.downcast_ref::<TicketNotInTreeYet>(), Some(&TicketNotInTreeYet { unspent: 1 }));
    }

    #[test]
    fn quota_slots_are_taken_once_per_epoch() {
        let home = home("quota");
        fs::create_dir_all(&home.dir).unwrap();
        assert_eq!(QuotaLog::take_slot(&home, "0x1", 7, 2).unwrap(), 0);
        assert_eq!(QuotaLog::take_slot(&home, "0x1", 7, 2).unwrap(), 1);
        assert!(QuotaLog::take_slot(&home, "0x1", 7, 2).unwrap_err().to_string().contains("used"));
        assert_eq!(QuotaLog::take_slot(&home, "0x1", 8, 2).unwrap(), 0, "a new epoch refills");
        assert!(QuotaLog::take_slot(&home, "0x1", 7, 2).is_err(), "never back to an older epoch");
        assert_eq!(QuotaLog::take_slot(&home, "0x2", 7, 2).unwrap(), 0, "another store starts fresh");
        fs::remove_dir_all(&home.dir).unwrap();
    }
}
