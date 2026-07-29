//! A self-serving Starknet client for networks that expose only a feeder
//! gateway — sepolia-integration in particular, where qm31 is enabled but no
//! JSON-RPC provider exists (public or paid) and every state-read endpoint has
//! been deprecated since 0.12.3.
//!
//! The insight is that zkmsg never actually needs general state reads. Its five
//! queries — resolve a handle, fetch the membership root, fetch a Merkle path,
//! scan the inbox, learn a nonce — are all answerable from the event stream
//! plus locally replayed contract logic:
//!
//! * `get_block` still serves full receipts and events (verified against
//!   integration block 13,888,040, the qm31 campaign's `mul_qm31` block), so
//!   events are readable even though `call_contract` and `get_nonce` are not.
//! * The registration tree is fully determined by `UserRegistered` events, and
//!   the tree is an ordinary depth-20 incremental Poseidon tree already
//!   implemented and golden-vector-pinned in `zkmsg_core::tree`. Replaying the
//!   events locally reproduces the root and every path — no view call needed.
//! * The inbox is `MessageSent` events, which the scanner already trial-decrypts
//!   locally; only its source changes.
//!
//! What this buys beyond integration access: on any network it removes the
//! trusted-RPC dependency the threat model flags. An RPC provider sees your IP
//! alongside the exact events you ask for; a client that syncs whole blocks
//! reveals nothing about which of them it cares about.
//!
//! Trust is relocated, not eliminated: block data comes from StarkWare's feeder
//! rather than an RPC provider — the same operator that runs the sequencer.
//! Cryptographic verification of block headers against L1 is out of scope here
//! (that is a light client, a much larger build).

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use zkmsg_core::tree::MerkleTree;

pub mod feeder;

/// A decoded event, in the shape the zkmsg scanners already consume
/// (hex strings, matching `zkmsg_core::chain::events`). Serializable because
/// an `Index` persists its events between syncs — see `Index::save_cache`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub from_address: String,
    pub keys: Vec<String>,
    pub data: Vec<String>,
    pub block_number: u64,
}

/// Raw feeder shapes. Only the fields we consume are modelled; the feeder
/// sends a great deal more per block.
#[derive(Debug, Deserialize)]
pub struct Block {
    pub block_number: u64,
    pub block_hash: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub transaction_receipts: Vec<Receipt>,
    #[serde(default)]
    pub l1_gas_price: GasPrice,
    #[serde(default)]
    pub l2_gas_price: GasPrice,
    #[serde(default)]
    pub l1_data_gas_price: GasPrice,
}

#[derive(Debug, Deserialize, Default)]
pub struct GasPrice {
    #[serde(default)]
    pub price_in_fri: String,
}

#[derive(Debug, Deserialize)]
pub struct Receipt {
    #[serde(default)]
    pub events: Vec<RawEvent>,
}

#[derive(Debug, Deserialize)]
pub struct RawEvent {
    pub from_address: String,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub data: Vec<String>,
}

impl Block {
    /// Events emitted by `address` (case-insensitive, zero-padding-insensitive
    /// — the feeder does not normalise felt hex).
    pub fn events_from(&self, address: &str) -> Vec<Event> {
        let want = normalize_felt(address);
        self.transaction_receipts
            .iter()
            .flat_map(|r| r.events.iter())
            .filter(|e| normalize_felt(&e.from_address) == want)
            .map(|e| Event {
                from_address: e.from_address.clone(),
                keys: e.keys.clone(),
                data: e.data.clone(),
                block_number: self.block_number,
            })
            .collect()
    }
}

/// Decodes a Cairo short string (ASCII packed into one felt) back to text —
/// how handles travel on the wire.
pub fn short_string(hex: &str) -> Result<String> {
    let bytes = hex_to_bytes(hex)?;
    let text: Vec<u8> = bytes.into_iter().skip_while(|b| *b == 0).collect();
    String::from_utf8(text).map_err(|e| anyhow!("handle is not utf-8: {e}"))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let t = hex.trim_start_matches("0x");
    let padded = if t.len() % 2 == 1 { format!("0{t}") } else { t.to_string() };
    (0..padded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).context("handle hex"))
        .collect()
}

/// Canonical form of a felt hex string, so `0x0ae4…` and `0xae4…` compare equal.
pub fn normalize_felt(s: &str) -> String {
    let t = s.trim_start_matches("0x").trim_start_matches('0').to_lowercase();
    if t.is_empty() { "0".into() } else { t }
}

/// An append-only event index over one contract, plus the derived state zkmsg
/// needs. Sync is block-by-block because the feeder offers no event filter:
/// the cost of not depending on an indexing provider.
pub struct Index {
    pub address: String,
    /// Where this index started; a cache is only reusable by a caller asking
    /// for the same starting point, or events before it would be missing.
    pub first_block: u64,
    pub next_block: u64,
    pub events: Vec<Event>,
}

/// On-disk form of an `Index`. What turns the one growing cost of a feeder-only
/// network — replaying the whole event history every time — into a one-time
/// cost: a synced index is saved, and the next sync pays only for the delta.
#[derive(Serialize, Deserialize)]
struct IndexCache {
    address: String,
    first_block: u64,
    next_block: u64,
    events: Vec<Event>,
}

impl Index {
    pub fn new(address: &str, from_block: u64) -> Self {
        Self {
            address: address.to_string(),
            first_block: from_block,
            next_block: from_block,
            events: Vec::new(),
        }
    }

    /// Ingests one block's events for this contract.
    pub fn absorb(&mut self, block: &Block) {
        self.events.extend(block.events_from(&self.address));
        self.next_block = block.block_number + 1;
    }

    /// A previously saved index, if one exists at `path` and covers the same
    /// contract from the same starting block. Anything else — no file, another
    /// contract, another starting point, an unreadable cache — returns None
    /// and the caller syncs from scratch: a cache must never be able to make
    /// a sync wrong, only cheaper.
    pub fn load_cache(path: &Path, address: &str, from_block: u64) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        let cache: IndexCache = serde_json::from_slice(&data).ok()?;
        if normalize_felt(&cache.address) != normalize_felt(address)
            || cache.first_block != from_block
        {
            return None;
        }
        Some(Self {
            address: cache.address,
            first_block: cache.first_block,
            next_block: cache.next_block,
            events: cache.events,
        })
    }

    /// Persists the index for `load_cache`, atomically: a torn write must not
    /// be able to replace a good cache with a corrupt one.
    pub fn save_cache(&self, path: &Path) -> Result<()> {
        let cache = IndexCache {
            address: self.address.clone(),
            first_block: self.first_block,
            next_block: self.next_block,
            events: self.events.clone(),
        };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&cache)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))
    }

    /// Syncs `[next_block, to)` in windows, calling `checkpoint` after each so
    /// an interrupted sync resumes from its last window rather than from
    /// `first_block`. On a phone syncing thousands of blocks through a
    /// rate-limited feeder, this is the difference between a failure costing
    /// seconds and costing the whole sync.
    pub fn sync(
        &mut self,
        feeder: &feeder::Feeder,
        to: u64,
        workers: usize,
        mut checkpoint: impl FnMut(&Index) -> Result<()>,
    ) -> Result<()> {
        const WINDOW: u64 = 256;
        while self.next_block < to {
            let end = (self.next_block + WINDOW).min(to);
            for block in feeder.blocks(self.next_block, end, workers)? {
                self.absorb(&block);
            }
            checkpoint(self)?;
        }
        Ok(())
    }

    pub fn with_key0(&self, selector: Felt) -> impl Iterator<Item = &Event> {
        let want = normalize_felt(&format!("{selector:#x}"));
        self.events.iter().filter(move |e| {
            e.keys.first().map(|k| normalize_felt(k) == want).unwrap_or(false)
        })
    }
}

/// The membership tree, rebuilt from `UserRegistered` events rather than read
/// from the contract — the substitute for `get_merkle_root` / `get_merkle_path`.
///
/// Event shape (messagezk_store::UserRegistered) — verified live on
/// sepolia-integration, since only `owner` carries `#[key]`:
///   keys = [sn_keccak("UserRegistered"), owner]
///   data = [handle, scan_pubkey, leaf_index]
/// Leaves are inserted in `leaf_index` order, which the contract assigns
/// sequentially; we sort explicitly rather than trusting block ordering.
pub struct Registry {
    pub tree: MerkleTree,
    pub handles: HashMap<String, u32>,
    pub scan_keys: HashMap<u32, Felt>,
}

impl Registry {
    pub fn rebuild(index: &Index) -> Result<Self> {
        let selector = zkmsg_core::chain::snkeccak("UserRegistered");
        let mut rows: Vec<(u32, String, Felt)> = Vec::new();
        for e in index.with_key0(selector) {
            let handle = e.data.first().ok_or_else(|| anyhow!("UserRegistered without handle"))?;
            let scan = e.data.get(1).ok_or_else(|| anyhow!("UserRegistered without scan key"))?;
            let leaf_index = e
                .data
                .get(2)
                .ok_or_else(|| anyhow!("UserRegistered without leaf index"))?;
            rows.push((
                u32::from_str_radix(leaf_index.trim_start_matches("0x"), 16)
                    .context("leaf index")?,
                short_string(handle)?,
                Felt::from_hex(scan).map_err(|e| anyhow!("scan key: {e}"))?,
            ));
        }
        rows.sort_by_key(|(i, _, _)| *i);

        let mut tree = MerkleTree::new();
        let mut handles = HashMap::new();
        let mut scan_keys = HashMap::new();
        for (expected_index, handle, scan) in rows {
            // The tree's own counter must agree with the contract's assignment;
            // a gap would mean we missed a block, and silently producing a wrong
            // root would burn a send's fee at verification time.
            let got = tree.insert(scan);
            if got != expected_index {
                return Err(anyhow!(
                    "leaf index mismatch: contract said {expected_index}, local tree assigned \
                     {got} — the event index has a gap"
                ));
            }
            handles.insert(handle, got);
            scan_keys.insert(got, scan);
        }
        Ok(Self { tree, handles, scan_keys })
    }

    pub fn root(&self) -> Felt {
        self.tree.root()
    }

    pub fn resolve(&self, handle: &str) -> Option<(u32, Felt)> {
        let idx = *self.handles.get(handle)?;
        Some((idx, *self.scan_keys.get(&idx)?))
    }

    pub fn path(&self, leaf_index: u32) -> Vec<Felt> {
        self.tree.path(leaf_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_with_event() -> Index {
        let mut index = Index::new("0x0abc", 100);
        index.events.push(Event {
            from_address: "0xabc".into(),
            keys: vec!["0x1".into()],
            data: vec!["0x2".into(), "0x3".into(), "0x0".into()],
            block_number: 150,
        });
        index.next_block = 200;
        index
    }

    #[test]
    fn cache_round_trips() {
        let dir = std::env::temp_dir().join(format!("zkmsg-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("round-trip.json");

        let index = index_with_event();
        index.save_cache(&path).unwrap();

        // Address comparison is normalized: 0x0abc and 0xABC are the same felt.
        let loaded = Index::load_cache(&path, "0xABC", 100).expect("cache should load");
        assert_eq!(loaded.next_block, 200);
        assert_eq!(loaded.first_block, 100);
        assert_eq!(loaded.events.len(), 1);
        assert_eq!(loaded.events[0].block_number, 150);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_is_rejected_unless_it_matches_exactly() {
        let dir = std::env::temp_dir().join(format!("zkmsg-cache-rej-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");
        index_with_event().save_cache(&path).unwrap();

        // A different contract or starting block would mean missing events —
        // the cache must be ignored, not adapted.
        assert!(Index::load_cache(&path, "0xdef", 100).is_none());
        assert!(Index::load_cache(&path, "0xabc", 99).is_none());
        // Corruption degrades to a fresh sync, never an error.
        std::fs::write(&path, b"not json").unwrap();
        assert!(Index::load_cache(&path, "0xabc", 100).is_none());
        // As does absence.
        assert!(Index::load_cache(&dir.join("missing.json"), "0xabc", 100).is_none());

        std::fs::remove_dir_all(&dir).ok();
    }
}
