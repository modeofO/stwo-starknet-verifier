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

/// The store a fresh profile is configured with.
pub const SEPOLIA_STORE_DEFAULT: &str = SEPOLIA_STORE_SNIP36;

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
    if same_address(store, SEPOLIA_STORE_SNIP36) {
        SEPOLIA_STORE_SNIP36_DEPLOY_BLOCK
    } else if same_address(store, SEPOLIA_STORE_V3) {
        SEPOLIA_STORE_V3_DEPLOY_BLOCK
    } else {
        0
    }
}

/// Whether `store` is the SNIP-36 store (its `send_message` needs
/// proof_facts the lane-1 pipeline cannot produce).
pub fn is_snip36_store(store: &str) -> bool {
    same_address(store, SEPOLIA_STORE_SNIP36)
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
    /// The creating profile's registered handle, for the compose
    /// from-line. Local-only.
    #[serde(default)]
    pub reply_handle: Option<String>,
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
            reply_handle: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Keys {
    pub scan_priv: String,
    pub scan_pub: String,
    pub handle: Option<String>,
    pub leaf_index: Option<u32>,
}

impl Keys {
    pub fn scan_priv_felt(&self) -> Result<Felt> {
        Felt::from_hex(&self.scan_priv).context("keys.json scan_priv")
    }

    pub fn scan_pub_felt(&self) -> Result<Felt> {
        Felt::from_hex(&self.scan_pub).context("keys.json scan_pub")
    }
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
        };
        home.save_new_keys(&keys).unwrap();
        assert!(home.save_new_keys(&keys).is_err());
        let loaded = home.load_keys().unwrap();
        assert_eq!(loaded.scan_priv, "0x5");
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
        assert!(c.reply_handle.is_none());
    }

    #[test]
    fn store_routing() {
        assert_eq!(Config::default_sepolia(Path::new("/r")).store, SEPOLIA_STORE_SNIP36);
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
