//! `~/.zkmsg` home layout: `config.json` (network + addresses + tool
//! paths), `keys.json` (scan keypair, mode 0600 — the app's only
//! long-lived secret), `sends/<id>.json` (pipeline checkpoints).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

/// Live lane-1 registry on Sepolia (docs/lane1-results.md) — the one
/// production address that is NOT ours to change.
pub const SEPOLIA_REGISTRY: &str =
    "0x0194f44002b4af71e58ba7d30667ed565f1d420d3fb1e7c578de35170309c6aa";
/// MessageStore v3 — deployed 2026-07-05 (docs/zkmsg-deployment.md),
/// class 0x04dc67c0…5745, pinned to the live registry + the
/// messagezk_scan circuit route. Legacy: kept read-only for inbox history
/// (`zkmsg inbox --legacy`), and still the store the lane-1 send pipeline
/// targets.
pub const SEPOLIA_STORE_V3: &str =
    "0x02d66a02b2efdddb5282bf7d7931cbb7a724f191478843b1fccbf3b9729e91b7";
pub const SEPOLIA_STORE_V3_DEPLOY_BLOCK: u64 = 11_624_399;

/// MessageStoreSnip36 (contracts/messagezk_store_snip36) — the home store.
/// Same registration/tree/event interface as v3, but `send_message` takes
/// no fact: the tx must carry SNIP-36 proof_facts from ZkmsgSendProver.
pub const SEPOLIA_STORE_SNIP36: &str =
    "0x002b9c6f617b3197dfed76401c32aa3b4b597ebdd01a7eba4b5657236bc8084f";
pub const SEPOLIA_STORE_SNIP36_DEPLOY_BLOCK: u64 = 15_850_710;
/// ZkmsgSendProver — the contract proven in the virtual OS for a SNIP-36 send.
pub const SEPOLIA_SNIP36_SEND_PROVER: &str =
    "0x012b85a4b5e6918eb6f18a07fddc1667d67beaac0ab647928105b8ccf7ee5346";

/// MessageStoreV2PQ (contracts/messagezk_store_pq), deployed 2026-10-01
/// (docs/zkmsg-deployment.md): hybrid ML-KEM-768 + ECDH, recipient check out
/// of the zk statement, leaf = poseidon(LEAF_V2, scan_pub, kem_digest).
/// Registration carries the 1184-byte ML-KEM encapsulation key.
pub const SEPOLIA_STORE_V2: &str =
    "0x04dc92ef9a90d336a79188c5408cdf9ce480f3ecd5b1ce55ef2ca207f2c3afe8";
pub const SEPOLIA_STORE_V2_DEPLOY_BLOCK: u64 = 15_947_092;
/// ZkmsgSendProverV2 — the v2 store's pinned virtual-OS prover contract.
pub const SEPOLIA_V2_SEND_PROVER: &str =
    "0x02d993bd9e1229367fe9643151fdb7b2fb9fe06b28e6ff0d2f1d451894182d79";

/// The store a fresh profile is configured with.
pub const SEPOLIA_STORE_DEFAULT: &str = SEPOLIA_STORE_V2;

/// What a store address is, as far as this client knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// MessageStore v3: lane-1 fact registry.
    V3,
    /// MessageStoreSnip36: SNIP-36, ECDH only.
    Snip36V1,
    /// MessageStoreV2PQ: SNIP-36, hybrid ML-KEM + ECDH.
    V2,
}

pub fn store_kind(store: &str) -> Option<StoreKind> {
    if same_address(store, SEPOLIA_STORE_V2) {
        Some(StoreKind::V2)
    } else if same_address(store, SEPOLIA_STORE_SNIP36) {
        Some(StoreKind::Snip36V1)
    } else if same_address(store, SEPOLIA_STORE_V3) {
        Some(StoreKind::V3)
    } else {
        None
    }
}

/// Address equality as felts (tolerates leading zeros / case).
pub fn same_address(a: &str, b: &str) -> bool {
    match (Felt::from_hex(a), Felt::from_hex(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// First block worth scanning for `store`'s events: the deploy block of a
/// known store, else 0. From-genesis getEvents 500s on publicnode.
pub fn store_deploy_block(store: &str) -> u64 {
    match store_kind(store) {
        Some(StoreKind::V2) => SEPOLIA_STORE_V2_DEPLOY_BLOCK,
        Some(StoreKind::Snip36V1) => SEPOLIA_STORE_SNIP36_DEPLOY_BLOCK,
        Some(StoreKind::V3) => SEPOLIA_STORE_V3_DEPLOY_BLOCK,
        None => 0,
    }
}

/// Whether `store` is a SNIP-36 store (its `send_message` needs
/// proof_facts the lane-1 pipeline cannot produce).
pub fn is_snip36_store(store: &str) -> bool {
    matches!(store_kind(store), Some(StoreKind::Snip36V1 | StoreKind::V2))
}

/// Refuses a desktop send against the SNIP-36 store with a pointer to the
/// route that can do it.
pub fn ensure_lane1_send_store(store: &str) -> Result<()> {
    if is_snip36_store(store) {
        bail!(
            "sending to the SNIP-36 store ({store}) is not supported from desktop yet: its \
             send_message needs SNIP-36 proof_facts (virtual-OS proof of ZkmsgSendProver), \
             which the lane-1 fact-registry pipeline cannot produce. Send from the iOS app \
             (phone-only SNIP-36 route) or the `snip36` CLI in snip-36-prover-backend. To send \
             on the legacy v3 store instead, set \"store\" in config.json to {SEPOLIA_STORE_V3} \
             (requires a v3 registration)."
        );
    }
    Ok(())
}
pub const SEPOLIA_RPC_DEFAULT: &str = "https://starknet-sepolia-rpc.publicnode.com";
/// Serves `starknet_getStorageProof` for recent blocks (refuses blocks older
/// than ~6 minutes), which the virtual-OS prover needs.
pub const SEPOLIA_PROVER_RPC: &str = "https://api.zan.top/public/starknet-sepolia/rpc/v0_10";

/// STRK token (same address on Sepolia and mainnet) — the fee/transfer
/// token used by the setup wizard's fund step and the status balance read.
pub const STRK_TOKEN: &str =
    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

/// The messagezk_scan circuit route, pinned at milestone 1
/// (docs/superpowers/specs/2026-07-05-zkmsg-milestone1-addendum.md).
pub const PROGRAM_HASH: &str =
    "0x250cb04a129e5259221ad4635950ac983bccf1de574893a2fae75c3c64385c";
pub const INNER_ROOT: [u32; 8] = [
    2674953418, 3988685724, 1385424428, 1661362028, 3534442848, 356489633, 2101289576,
    2757001180,
];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub rpc_url: String,
    pub account: String,
    pub registry: String,
    pub store: String,
    /// The bridge binary (prove/wrap legs).
    pub bridge_bin: PathBuf,
    /// The built circuit executable.
    pub circuit_executable: PathBuf,
    /// This profile is a throwaway sender created by the burner wizard.
    /// Local-only; nothing on-chain marks a burner.
    #[serde(default)]
    pub burner: bool,
    /// SNIP-36 route: the `snip36-prove` binary (tools/snip36-phone-ffi,
    /// built from the sequencer workspace). Absent in configs older than the
    /// route; `virtual_prover_bin()` names the default then.
    #[serde(default)]
    pub virtual_prover_bin: Option<PathBuf>,
    /// SNIP-36 route: the RPC every read of a virtual send goes through, and
    /// the one the prover fetches state from. It must serve
    /// `starknet_getStorageProof` for recent blocks (zan does, publicnode
    /// doesn't). Absent: `SEPOLIA_PROVER_RPC`.
    #[serde(default)]
    pub prover_rpc_url: Option<String>,
}

impl Config {
    pub fn default_sepolia(repo_root: &Path) -> Self {
        Self {
            rpc_url: SEPOLIA_RPC_DEFAULT.into(),
            account: "funded-deployer".into(),
            registry: SEPOLIA_REGISTRY.into(),
            store: SEPOLIA_STORE_DEFAULT.into(),
            bridge_bin: repo_root
                .join(".prover/proving-utils/target/release/privacy_prove_cairo_bridge"),
            circuit_executable: repo_root
                .join("fixtures/target/dev/messagezk_scan.executable.json"),
            burner: false,
            virtual_prover_bin: Some(default_virtual_prover_bin(repo_root)),
            prover_rpc_url: None,
        }
    }

    /// The `snip36-prove` binary: the configured one, else the default build
    /// location beside the lane-1 bridge (both live under the repo's
    /// gitignored `.prover/`).
    pub fn virtual_prover_bin(&self) -> PathBuf {
        if let Some(bin) = &self.virtual_prover_bin {
            return bin.clone();
        }
        // bridge_bin = <repo>/.prover/proving-utils/target/release/<bin>
        let repo_root = self.bridge_bin.ancestors().nth(5).unwrap_or(Path::new("."));
        default_virtual_prover_bin(repo_root)
    }

    pub fn prover_rpc_url(&self) -> &str {
        self.prover_rpc_url.as_deref().unwrap_or(SEPOLIA_PROVER_RPC)
    }
}

fn default_virtual_prover_bin(repo_root: &Path) -> PathBuf {
    repo_root.join(".prover/sequencer/target/release/snip36-prove")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Keys {
    pub scan_priv: String,
    pub scan_pub: String,
    pub handle: Option<String>,
    pub leaf_index: Option<u32>,
    /// ML-KEM-768 seed `d ‖ z`, 64 bytes as `0x` + 128 hex digits (the
    /// scan key's style; zkmsg-ios `zkmsgtool` reads it, with or without the
    /// prefix, to carry it into a phone backup) — the v2 store's second
    /// recipient key. Generated on `init`, and added to older profiles the
    /// first time a v2 operation needs it (`Home::ensure_kem_seed`). Like the
    /// scan key, losing it loses the v2 inbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem_seed: Option<String>,
}

impl Keys {
    pub fn kem_seed_bytes(&self) -> Result<[u8; crate::crypto::KEM_SEED_LEN]> {
        let hex = self.kem_seed.as_deref().context("keys.json has no kem_seed")?;
        hex::decode(hex.trim_start_matches("0x"))
            .context("keys.json kem_seed hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("keys.json kem_seed is not 64 bytes"))
    }

    /// `(dk, ek)` from the stored seed.
    pub fn kem_keypair(&self) -> Result<(ml_kem::DecapsulationKey768, Vec<u8>)> {
        Ok(crate::crypto::kem_keygen_from_seed(&self.kem_seed_bytes()?))
    }

    pub fn scan_priv_felt(&self) -> Result<Felt> {
        Felt::from_hex(&self.scan_priv).context("keys.json scan_priv")
    }

    pub fn scan_pub_felt(&self) -> Result<Felt> {
        Felt::from_hex(&self.scan_pub).context("keys.json scan_pub")
    }
}

/// The keys.json form of a KEM seed: `0x` + 128 lowercase hex digits.
pub fn kem_seed_hex(seed: &[u8; crate::crypto::KEM_SEED_LEN]) -> String {
    format!("0x{}", hex::encode(seed))
}

pub struct Home {
    pub dir: PathBuf,
}

impl Home {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    pub fn keys_path(&self) -> PathBuf {
        self.dir.join("keys.json")
    }

    pub fn sends_dir(&self) -> PathBuf {
        self.dir.join("sends")
    }

    pub fn inbox_cache_path(&self) -> PathBuf {
        self.dir.join("inbox.json")
    }

    pub fn load_config(&self) -> Result<Config> {
        let raw = fs::read_to_string(self.config_path())
            .with_context(|| format!("no config at {} — run `zkmsg init`", self.dir.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        fs::write(self.config_path(), serde_json::to_string_pretty(config)?)?;
        Ok(())
    }

    pub fn load_keys(&self) -> Result<Keys> {
        let raw = fs::read_to_string(self.keys_path())
            .with_context(|| format!("no keys at {} — run `zkmsg init`", self.dir.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }

    /// Writes keys with owner-only permissions. Refuses to overwrite —
    /// losing a scan key means losing the inbox.
    pub fn save_new_keys(&self, keys: &Keys) -> Result<()> {
        if self.keys_path().exists() {
            bail!("{} already exists; refusing to overwrite scan keys", self.keys_path().display());
        }
        fs::create_dir_all(&self.dir)?;
        fs::write(self.keys_path(), serde_json::to_string_pretty(keys)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.keys_path(), fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Updates mutable key metadata (handle/leaf index after registration).
    pub fn update_keys(&self, keys: &Keys) -> Result<()> {
        fs::write(self.keys_path(), serde_json::to_string_pretty(keys)?)?;
        Ok(())
    }

    /// Loads keys, adding a fresh ML-KEM seed first if the profile predates
    /// v2. The seed is written before it is returned, so a key the chain
    /// might learn (via `register`) is never one that only lived in memory.
    pub fn ensure_kem_seed(&self) -> Result<Keys> {
        let mut keys = self.load_keys()?;
        if keys.kem_seed.is_none() {
            keys.kem_seed = Some(kem_seed_hex(&crate::crypto::kem_seed_gen()));
            self.update_keys(&keys)?;
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_refuse_overwrite() {
        let dir = std::env::temp_dir().join(format!("zkmsg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let home = Home::new(dir.clone());
        let keys = Keys {
            scan_priv: "0x5".into(),
            scan_pub: "0x6".into(),
            handle: None,
            leaf_index: None,
            kem_seed: None,
        };
        home.save_new_keys(&keys).unwrap();
        assert!(home.save_new_keys(&keys).is_err());
        let loaded = home.load_keys().unwrap();
        assert_eq!(loaded.scan_priv, "0x5");

        // An older profile gains a KEM seed once, and keeps it.
        assert!(loaded.kem_seed.is_none());
        let seeded = home.ensure_kem_seed().unwrap();
        assert_eq!(seeded.kem_seed_bytes().unwrap().len(), 64);
        let stored = seeded.kem_seed.as_deref().unwrap();
        assert!(stored.starts_with("0x") && stored.len() == 130, "pinned format: {stored}");
        // Read with or without the prefix.
        let bare = Keys { kem_seed: Some(stored[2..].to_string()), ..home.load_keys().unwrap() };
        assert_eq!(bare.kem_seed_bytes().unwrap(), seeded.kem_seed_bytes().unwrap());
        assert_eq!(home.ensure_kem_seed().unwrap().kem_seed, seeded.kem_seed);
        assert_eq!(home.load_keys().unwrap().kem_seed, seeded.kem_seed);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(home.keys_path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "rewriting keys.json keeps it owner-only");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_serde_defaults_burner_fields() {
        // A pre-burner config.json (alice/bob/carol era): no burner fields.
        let old = r#"{
            "rpc_url": "https://x", "account": "funded-deployer",
            "registry": "0x1", "store": "0x2",
            "bridge_bin": "/b", "circuit_executable": "/c"
        }"#;
        let c: Config = serde_json::from_str(old).unwrap();
        assert!(!c.burner);
    }

    #[test]
    fn config_ignores_retired_reply_handle() {
        // A burner config written before the from-line was retired still
        // loads: serde skips the unknown `reply_handle` field.
        let old = r#"{
            "rpc_url": "https://x", "account": "zkmsg-burner-ab12cd",
            "registry": "0x1", "store": "0x2",
            "bridge_bin": "/b", "circuit_executable": "/c",
            "burner": true, "reply_handle": "alice"
        }"#;
        let c: Config = serde_json::from_str(old).unwrap();
        assert!(c.burner);
    }

    #[test]
    fn prover_bin_defaults_beside_the_bridge() {
        let c = Config::default_sepolia(Path::new("/repo"));
        assert_eq!(
            c.virtual_prover_bin(),
            PathBuf::from("/repo/.prover/sequencer/target/release/snip36-prove")
        );
        // An older config without the key derives the same path.
        let old = Config { virtual_prover_bin: None, ..c };
        assert_eq!(
            old.virtual_prover_bin(),
            PathBuf::from("/repo/.prover/sequencer/target/release/snip36-prove")
        );
        assert_eq!(old.prover_rpc_url(), SEPOLIA_PROVER_RPC);
    }

    #[test]
    fn store_routing() {
        assert_eq!(Config::default_sepolia(Path::new("/r")).store, SEPOLIA_STORE_V2);
        assert_eq!(store_kind(SEPOLIA_STORE_V2), Some(StoreKind::V2));
        assert_eq!(store_deploy_block(SEPOLIA_STORE_V2), SEPOLIA_STORE_V2_DEPLOY_BLOCK);
        assert!(is_snip36_store(SEPOLIA_STORE_V2));
        // Leading-zero / case differences still match.
        assert_eq!(
            store_deploy_block("0x2B9C6F617B3197DFED76401C32AA3B4B597EBDD01A7EBA4B5657236BC8084F"),
            SEPOLIA_STORE_SNIP36_DEPLOY_BLOCK,
        );
        assert_eq!(store_deploy_block(SEPOLIA_STORE_V3), SEPOLIA_STORE_V3_DEPLOY_BLOCK);
        assert_eq!(store_deploy_block("0x123"), 0);
        assert!(ensure_lane1_send_store(SEPOLIA_STORE_SNIP36).is_err());
        assert!(ensure_lane1_send_store(SEPOLIA_STORE_V3).is_ok());
    }
}
