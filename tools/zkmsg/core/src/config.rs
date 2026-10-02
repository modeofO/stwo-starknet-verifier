//! `~/.zkmsg` home layout: `config.json` (network + addresses + tool
//! paths), `keys.json` (scan keypair, mode 0600 — the app's only
//! long-lived secret), `sends/<id>.json` (pipeline checkpoints).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

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

/// The store a fresh profile is configured with — and the only one this
/// client reads or writes (owner decision 2026-10-01: MessageStore v3 and the
/// SNIP-36 v1 store are no longer read; `zkmsg migrate-store` moves a
/// profile still pointing at one of them).
pub const SEPOLIA_STORE_DEFAULT: &str = SEPOLIA_STORE_V2;

/// Whether `store` is the v2 store.
pub fn is_v2_store(store: &str) -> bool {
    same_address(store, SEPOLIA_STORE_V2)
}

/// Address equality as felts (tolerates leading zeros / case).
pub fn same_address(a: &str, b: &str) -> bool {
    match (Felt::from_hex(a), Felt::from_hex(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// First block worth scanning for `store`'s events: the v2 store's deploy
/// block, else 0. From-genesis getEvents 500s on publicnode.
pub fn store_deploy_block(store: &str) -> u64 {
    if is_v2_store(store) { SEPOLIA_STORE_V2_DEPLOY_BLOCK } else { 0 }
}

pub const SEPOLIA_RPC_DEFAULT: &str = "https://starknet-sepolia-rpc.publicnode.com";
/// Serves `starknet_getStorageProof` for recent blocks (refuses blocks older
/// than ~6 minutes), which the virtual-OS prover needs.
pub const SEPOLIA_PROVER_RPC: &str = "https://api.zan.top/public/starknet-sepolia/rpc/v0_10";

/// STRK token (same address on Sepolia and mainnet) — the fee/transfer
/// token used by the setup wizard's fund step and the status balance read.
pub const STRK_TOKEN: &str =
    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub rpc_url: String,
    pub account: String,
    pub store: String,
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
            store: SEPOLIA_STORE_DEFAULT.into(),
            burner: false,
            virtual_prover_bin: Some(default_virtual_prover_bin(repo_root)),
            prover_rpc_url: None,
        }
    }

    /// The `snip36-prove` binary: the configured one, else the default build
    /// location in the repo this binary was built from (the gitignored
    /// `.prover/` checkout).
    pub fn virtual_prover_bin(&self) -> PathBuf {
        if let Some(bin) = &self.virtual_prover_bin {
            return bin.clone();
        }
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        default_virtual_prover_bin(&repo_root.canonicalize().unwrap_or(repo_root))
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
        // A pre-burner config.json (alice/bob/carol era): no burner fields,
        // and the lane-1 keys (registry, bridge_bin, circuit_executable)
        // removed 2026-10-01 — ignored.
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
    fn prover_bin_default_location() {
        let c = Config::default_sepolia(Path::new("/repo"));
        assert_eq!(
            c.virtual_prover_bin(),
            PathBuf::from("/repo/.prover/sequencer/target/release/snip36-prove")
        );
        // An older config without the key falls back to this build's repo.
        let old = Config { virtual_prover_bin: None, ..c };
        assert!(old.virtual_prover_bin().ends_with(".prover/sequencer/target/release/snip36-prove"));
        assert_eq!(old.prover_rpc_url(), SEPOLIA_PROVER_RPC);
    }

    #[test]
    fn store_routing() {
        assert_eq!(Config::default_sepolia(Path::new("/r")).store, SEPOLIA_STORE_V2);
        // Leading-zero / case differences still match.
        assert!(is_v2_store("0x4DC92EF9A90D336A79188C5408CDF9CE480F3ECD5B1CE55EF2CA207F2C3AFE8"));
        assert_eq!(store_deploy_block(SEPOLIA_STORE_V2), SEPOLIA_STORE_V2_DEPLOY_BLOCK);
        // The retired stores are just unknown addresses now.
        let snip36_v1 = "0x002b9c6f617b3197dfed76401c32aa3b4b597ebdd01a7eba4b5657236bc8084f";
        assert!(!is_v2_store(snip36_v1));
        assert_eq!(store_deploy_block(snip36_v1), 0);
    }
}
