//! The store's registrations (the v4 pool's are v3's), rebuilt locally from
//! its `UserRegistered` events: handle lookups, the membership tree and
//! Merkle paths.
//!
//! Why not `get_user(handle)` / `get_merkle_path(leaf)`: those reads tell the
//! RPC provider which handles a client cares about — while preparing a send,
//! "this IP is about to send to B, as A", where the chain itself never shows
//! the recipient. Every request made here is identical for every client:
//! all of the store's registrations (up to a block), and the root at that
//! block, compared against the rebuilt tree by the caller.
//!
//! Event (contracts/messagezk_store_v3/src/store.cairo `UserRegistered`):
//!   keys = [sn_keccak("UserRegistered"), owner]
//!   data = [handle, scan_pubkey, leaf_index, m_commit, kem_pubkey ByteArray…]
//! The contract assigns leaf indices 0, 1, 2, … in registration order; the
//! rebuild sorts by index and refuses a gap or a duplicate, since a tree with
//! a missing leaf would only surface as a root mismatch.

use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use starknet_types_core::felt::Felt;

use crate::app::{Member, short_string_felt};
use crate::chain::{Chain, bytearray_decode, felt_hex, felt_to_u64, snkeccak};
use crate::config::store_deploy_block;
use crate::crypto::{kem_digest, leaf_v3};
use crate::tree::MerkleTree;

/// One `UserRegistered` event, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub owner: Felt,
    /// The handle as a Cairo short string.
    pub handle: Felt,
    pub scan_pub: Felt,
    pub leaf_index: u32,
    pub m_commit: Felt,
    /// The 1184-byte ML-KEM encapsulation key.
    pub kem_pubkey: Vec<u8>,
    /// `kem_digest(kem_pubkey)` — what the store keeps and the leaf binds.
    pub kem_digest: Felt,
}

impl Registration {
    pub fn from_event(keys: &[String], data: &[String]) -> Result<Self> {
        let felt = |s: &String| Felt::from_hex(s).context("UserRegistered felt");
        ensure!(keys.len() == 2, "UserRegistered has {} keys, expected 2", keys.len());
        ensure!(data.len() > 4, "UserRegistered has {} data felts", data.len());
        let data: Vec<Felt> = data.iter().map(felt).collect::<Result<_>>()?;
        let (kem_pubkey, used) = bytearray_decode(&data[4..])?;
        ensure!(4 + used == data.len(), "UserRegistered has trailing data");
        Ok(Self {
            owner: felt(&keys[1])?,
            handle: data[0],
            scan_pub: data[1],
            leaf_index: u32::try_from(felt_to_u64(&data[2])?).context("leaf index")?,
            m_commit: data[3],
            kem_digest: kem_digest(&kem_pubkey),
            kem_pubkey,
        })
    }

    /// The tree leaf the store inserted for this registration.
    pub fn leaf(&self) -> Felt {
        leaf_v3(&self.scan_pub, &self.kem_digest, &self.m_commit)
    }

    /// The `get_user` view of this registration.
    pub fn member(&self) -> Member {
        Member {
            scan_pub: self.scan_pub,
            kem_digest: self.kem_digest,
            m_commit: self.m_commit,
            leaf_index: self.leaf_index,
        }
    }
}

pub struct Registry {
    /// Indexed by leaf index.
    registrations: Vec<Registration>,
    by_handle: HashMap<Felt, usize>,
    tree: MerkleTree,
}

impl Registry {
    pub fn from_registrations(mut registrations: Vec<Registration>) -> Result<Self> {
        registrations.sort_by_key(|r| r.leaf_index);
        let mut tree = MerkleTree::new();
        let mut by_handle = HashMap::new();
        for (i, r) in registrations.iter().enumerate() {
            ensure!(
                r.leaf_index as usize == i,
                "registration events are not contiguous: leaf {} where {i} was expected",
                r.leaf_index
            );
            ensure!(by_handle.insert(r.handle, i).is_none(), "handle {} registered twice", felt_hex(&r.handle));
            tree.insert(r.leaf());
        }
        Ok(Self { registrations, by_handle, tree })
    }

    pub fn from_events(events: &[(Vec<String>, Vec<String>)]) -> Result<Self> {
        let registrations = events
            .iter()
            .map(|(keys, data)| Registration::from_event(keys, data))
            .collect::<Result<_>>()?;
        Self::from_registrations(registrations)
    }

    /// Every `UserRegistered` event of `store`, from its deploy block up to
    /// and including `to_block` (`None`: latest). The request names no user.
    pub fn fetch(chain: &Chain, store: &str, to_block: Option<u64>) -> Result<Self> {
        let key0 = felt_hex(&snkeccak("UserRegistered"));
        let events = chain
            .events_through(store, &key0, store_deploy_block(store), to_block)
            .context("reading the store's registrations")?;
        Self::from_events(&events)
    }

    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    pub fn get(&self, handle: &str) -> Result<&Registration> {
        let i = self
            .by_handle
            .get(&short_string_felt(handle)?)
            .with_context(|| format!("'{handle}' is not registered in this store"))?;
        Ok(&self.registrations[*i])
    }

    pub fn root(&self) -> Felt {
        self.tree.root()
    }

    /// The 20 siblings bottom-up — what `get_merkle_path(leaf)` returns.
    pub fn path(&self, leaf_index: u32) -> Result<Vec<Felt>> {
        ensure!((leaf_index as usize) < self.len(), "leaf {leaf_index} is not in the tree");
        Ok(self.tree.path(leaf_index))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain::bytearray_calldata;
    use crate::tree::fold_path;

    fn f(hex: &str) -> Felt {
        Felt::from_hex(hex).unwrap()
    }

    /// A `UserRegistered` event as the RPC returns it.
    pub(crate) fn event(
        owner: Felt, handle: &str, scan_pub: Felt, leaf_index: u32, m_commit: Felt, ek: &[u8],
    ) -> (Vec<String>, Vec<String>) {
        let mut data = vec![
            felt_hex(&short_string_felt(handle).unwrap()),
            felt_hex(&scan_pub),
            felt_hex(&Felt::from(leaf_index)),
            felt_hex(&m_commit),
        ];
        data.extend(bytearray_calldata(ek));
        (vec![felt_hex(&snkeccak("UserRegistered")), felt_hex(&owner)], data)
    }

    // contracts/messagezk_store_v3/tests/vector.cairo: alice (leaf 0) and bob
    // (leaf 1); `registration_reproduces_the_client_tree` pins the same root
    // against the contract's own insert.
    const ALICE_LEAF: &str = "0x6d11002f3f123d05bf349faeeb9da3f065afdf5834ff31529fe1468cd8c78e0";
    const BOB_LEAF: &str = "0x454b085c23b1c5faf05a41eafa5a26a14bd24b35fa940c72a8dada733a4ac8d";
    const ROOT: &str = "0x3e26f6fd13c9bfab343294ed95f2afc0182559d4d15778c13223197fe7e3580";
    const ALICE_PATH: [&str; 20] = [
        "0x454b085c23b1c5faf05a41eafa5a26a14bd24b35fa940c72a8dada733a4ac8d",
        "0x1fb7169b936dd880cb7ebc50e932a495a60e0084cdab94a681040cb4006e1a0",
        "0x17b96a8cee53f9566e4a318ccfe4bd54669d13d4e0ad518ce2905ac58ab6fcd",
        "0x4268c203f18d361afc33a2d15356a4e64f2ca1f507bcefaf6e0daa5a2c4c4b8",
        "0x31f82f7b110cf0fedec4381eb2b4ef7bbfb6241276ad81e99f23e64ea3457d2",
        "0x55ce2b27b18dc167740cea55bfba4c920bf41455caf86c7ea4b9f7a614b3ac",
        "0x1d2fd418edbc17be7e37a4d07fb3f910801b4a469fdcb6ba2ee6156294668",
        "0x4f9b1a51a3ec0964b97c108efe065f54e6edd63cf2ef40dfc93f590437cae58",
        "0x11d6400cced0057f253dd0f4906d202daec97295c251c1eb3a3ae13bf4442c5",
        "0x2828ea3570ae2642abdf689ca78220d7dc45b7be0cc1ae97089a8fe89c739e1",
        "0x54355cfccf17e98bf076e119955b58d531ab864c4f8b9606779ec0117ef3fac",
        "0x3e170baf04d290e76759a1e2b67fa63739578d9883b7bdc6ba98afffc8992c5",
        "0xce682ba73ca032d5dd0f2ccb29a1834b51d4dc850486cf08fdce6969203917",
        "0x36480f71ded7948935f02b3755f9c79c3419476c69dfbe5ff9dc742b7136623",
        "0x27a7269fa0c704fb77ff85b9579c7b81591a63ac1a68f5763e972d2941b10d1",
        "0x1efdc54c79b7b0830cf54eaf000851aea6c543f7d12a193d4e2d596e905a7d8",
        "0x3378095e3b6b35069a13555a585e41a8497cacf482520ed422d8a6addf0115a",
        "0x1b31d8bdb4b4ca31bbf3902884c8be863315e8433a22e4aa2090c55f236b9a1",
        "0x20a0570911d8a00c74573184ac517730de6f8cc0ca547f3449865eeb62b5b45",
        "0x57ae865f1792ab222addcd9174fa8ef11d8d4e70149324ec901f7674a18d575",
    ];

    #[test]
    fn local_tree_matches_the_cairo_vector() {
        let mut tree = MerkleTree::new();
        assert_eq!(tree.insert(f(ALICE_LEAF)), 0);
        assert_eq!(tree.insert(f(BOB_LEAF)), 1);
        assert_eq!(tree.root(), f(ROOT));
        let path: Vec<Felt> = ALICE_PATH.iter().map(|h| f(h)).collect();
        assert_eq!(tree.path(0), path);
        assert_eq!(fold_path(&f(ALICE_LEAF), 0, &path), f(ROOT));
        assert_eq!(fold_path(&f(BOB_LEAF), 1, &tree.path(1)), f(ROOT));
    }

    /// The vector's alice and bob as registrations (their recorded scan
    /// key, kem_digest and m_commit): the registry's leaf formula and tree
    /// reproduce the vector's leaves, root and alice's path.
    #[test]
    fn registry_reproduces_the_cairo_vector() {
        let reg = |owner: u64, handle: &str, leaf_index, scan, digest, m_commit| Registration {
            owner: Felt::from(owner),
            handle: short_string_felt(handle).unwrap(),
            scan_pub: f(scan),
            leaf_index,
            m_commit: f(m_commit),
            kem_pubkey: vec![],
            kem_digest: f(digest),
        };
        let registry = Registry::from_registrations(vec![
            reg(
                2, "bob", 1,
                "0x7c4179ae1f3635d460a48af1ddaf3bf76150511dcf96f0d6d6ac3f2e375a15d",
                "0x2f6a9e2f5b43b7591ae35a57cf0238f7c33cce5a83d65cfb765a16e457f70ef",
                "0xeb5212b823ebe5394db58d185934436f253380a9b82f202d6239b581940a8a",
            ),
            reg(
                1, "alice", 0,
                "0x3948102149cf2d831e1a91e9014fd63216b6b83cdbbbba17fe82ccddf2df054",
                "0x3d9aebb2f9823b47e55d0a962f225afa89da234c4ec60e3e8a366f079775f2e",
                "0x1d2bb94133d344fecabb7ecefd0f0c18479ef5b48cd23b90ce0a8076d2dcbf6",
            ),
        ])
        .unwrap();
        assert_eq!(registry.get("alice").unwrap().leaf(), f(ALICE_LEAF));
        assert_eq!(registry.get("bob").unwrap().leaf(), f(BOB_LEAF));
        assert_eq!(registry.root(), f(ROOT));
        let path: Vec<Felt> = ALICE_PATH.iter().map(|h| f(h)).collect();
        assert_eq!(registry.path(0).unwrap(), path);
    }

    fn sample(n: u32) -> Vec<(Vec<String>, Vec<String>)> {
        (0..n)
            .map(|i| {
                let (_, ek) = crate::crypto::kem_keygen_from_seed(&[i as u8 + 1; 64]);
                event(
                    Felt::from(0x1000 + i as u64),
                    &format!("user{i}"),
                    crate::crypto::ec_mul_gen_x(&Felt::from(i as u64 + 2)),
                    i,
                    crate::crypto::member_commit(&Felt::from(i as u64 + 7)),
                    &ek,
                )
            })
            .collect()
    }

    #[test]
    fn registry_rebuilds_tree_and_paths() {
        let mut events = sample(5);
        events.reverse(); // order on the wire must not matter
        let reg = Registry::from_events(&events).unwrap();
        assert_eq!(reg.len(), 5);
        let user3 = reg.get("user3").unwrap();
        assert_eq!(user3.leaf_index, 3);
        assert_eq!(user3.kem_digest, kem_digest(&user3.kem_pubkey));
        assert_eq!(user3.member().leaf_index, 3);
        for i in 0..5u32 {
            let r = &reg.registrations[i as usize];
            assert_eq!(fold_path(&r.leaf(), i, &reg.path(i).unwrap()), reg.root());
        }
        assert!(reg.path(5).is_err());
        assert!(reg.get("nobody").unwrap_err().to_string().contains("not registered"));

        // The same leaves inserted directly give the same root.
        let mut tree = MerkleTree::new();
        for r in &reg.registrations {
            tree.insert(r.leaf());
        }
        assert_eq!(tree.root(), reg.root());
    }

    #[test]
    fn registry_refuses_gaps_and_duplicates() {
        let mut events = sample(3);
        events.remove(1);
        assert!(Registry::from_events(&events).err().unwrap().to_string().contains("contiguous"));

        let mut events = sample(2);
        let (_, ek) = crate::crypto::kem_keygen_from_seed(&[9; 64]);
        events.push(event(Felt::from(9u64), "user0", Felt::from(5u64), 2, Felt::from(6u64), &ek));
        assert!(Registry::from_events(&events).err().unwrap().to_string().contains("twice"));
    }

    /// Live, read-only: the tree rebuilt from the real v3 store's events
    /// equals `get_merkle_root` at the same block (the current store).
    /// `cargo test -p zkmsg-core live_registry -- --ignored`
    #[test]
    #[ignore = "network: reads Sepolia"]
    fn live_registry_root_matches_the_store() {
        use crate::config::{SEPOLIA_POOL_V4 as SEPOLIA_STORE, SEPOLIA_PROVER_RPC};
        use serde_json::json;
        let rpc = std::env::var("ZKMSG_RPC").unwrap_or_else(|_| SEPOLIA_PROVER_RPC.into());
        let chain = Chain::new(&rpc, "unused");
        let block = chain.rpc("starknet_blockNumber", json!([])).unwrap().as_u64().unwrap();
        let reg = Registry::fetch(&chain, SEPOLIA_STORE, Some(block)).unwrap();
        let root = chain
            .rpc(
                "starknet_call",
                json!([
                    {
                        "contract_address": SEPOLIA_STORE,
                        "entry_point_selector": felt_hex(&snkeccak("get_merkle_root")),
                        "calldata": [],
                    },
                    {"block_number": block},
                ]),
            )
            .unwrap();
        let root = f(root[0].as_str().unwrap());
        eprintln!("block {block}: {} registrations, root {}", reg.len(), felt_hex(&root));
        assert!(!reg.is_empty());
        assert_eq!(reg.root(), root);
        // And each local path is the store's `get_merkle_path` (a test-only
        // read; the send path never makes it).
        for leaf in 0..reg.len() as u32 {
            let raw = chain
                .rpc(
                    "starknet_call",
                    json!([
                        {
                            "contract_address": SEPOLIA_STORE,
                            "entry_point_selector": felt_hex(&snkeccak("get_merkle_path")),
                            "calldata": [felt_hex(&Felt::from(leaf))],
                        },
                        {"block_number": block},
                    ]),
                )
                .unwrap();
            let path: Vec<Felt> = raw.as_array().unwrap()[1..].iter().map(|x| f(x.as_str().unwrap())).collect();
            assert_eq!(reg.path(leaf).unwrap(), path, "leaf {leaf}");
        }
    }
}
