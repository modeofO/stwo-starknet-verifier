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
/// messagezk_scan circuit route.
pub const SEPOLIA_STORE_DEFAULT: &str =
    "0x02d66a02b2efdddb5282bf7d7931cbb7a724f191478843b1fccbf3b9729e91b7";
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
}
