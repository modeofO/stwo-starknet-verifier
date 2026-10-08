//! `~/.zkmsg` home layout: `config.json` (network + addresses + tool
//! paths), `keys.json` (mode 0600: the scan keypair, the ML-KEM `kem_seed`
//! and the `member_secret` — the app's long-lived secrets),
//! `tickets.json` (mode 0600: the v4 fee tickets, bearer value),
//! `quota.json` (the epoch's used quota slots), `sends/<id>.json` (send
//! checkpoints).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

/// MessageStoreV3 (contracts/messagezk_store_v3), deployed 2026-10-01 —
/// RETIRED 2026-10-07 by the v4 pool: every v3 send was published (and paid)
/// by the sender's own account, the same account that registered the handle.
pub const SEPOLIA_STORE_V3: &str =
    "0x0103de677e966a8a72669551093f0f5342621e635531fec146c4b04c5f5d3d9d";

/// ZkmsgPoolV4 (contracts/zkmsg_pool_v4), deployed 2026-10-07
/// (docs/zkmsg-deployment.md): the message store AND the account that
/// publishes every send. A send carries no signature and names no member's
/// account: the SNIP-36 proof (v3 membership + a per-epoch quota nullifier +
/// a spent single-send ticket) authorizes it, and the ticket, bought earlier
/// at `ticket_price`, pays for it. Registration (leaf, events, ABI) is v3's.
pub const SEPOLIA_POOL_V4: &str =
    "0x050f98ee98a0c1a583529c115f394ad79d18686ff66dc1ee25ba0f7bc53669b9";
pub const SEPOLIA_POOL_V4_DEPLOY_BLOCK: u64 = 16_257_012;
/// The pool's `ticket_price()`: 3 STRK per single-send ticket. Its fee
/// policy caps a publish's worst case at the same 3 STRK (~2x a send's
/// measured cost); what a send does not use stays in the pool.
pub const SEPOLIA_V4_TICKET_PRICE_FRI: u128 = 3_000_000_000_000_000_000;
/// ZkmsgSendProverV4 — the pool's pinned virtual-OS prover contract.
pub const SEPOLIA_V4_SEND_PROVER: &str =
    "0x0496b7e39ea515c48e8f37dd588ed1ff16c86b3ff7619c6a30ae7b473f902973";
/// ZkmsgVirtualSenderV4 — the shared, zero-fee account every member's
/// VIRTUAL `prove_send` runs from (its nonce stays 0 forever), so a member's
/// own account never enters a proof request.
pub const SEPOLIA_V4_VIRTUAL_SENDER: &str =
    "0x01e9fefc5d5848690330af81644736e90cc1e7192357d06fe40080da2ddd94a4";

/// The store a fresh profile is configured with — and the only one this
/// client reads or writes (owner decision 2026-10-01: only the current store
/// is read; `zkmsg migrate-store` moves a profile still pointing at an older
/// one).
pub const SEPOLIA_STORE_DEFAULT: &str = SEPOLIA_POOL_V4;

/// Whether `store` is the current (v4 pool) store.
pub fn is_current_store(store: &str) -> bool {
    same_address(store, SEPOLIA_POOL_V4)
}

/// Address equality as felts (tolerates leading zeros / case).
pub fn same_address(a: &str, b: &str) -> bool {
    match (Felt::from_hex(a), Felt::from_hex(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// First block worth scanning for `store`'s events: the current store's deploy
/// block, else 0. From-genesis getEvents 500s on publicnode.
pub fn store_deploy_block(store: &str) -> u64 {
    if is_current_store(store) { SEPOLIA_POOL_V4_DEPLOY_BLOCK } else { 0 }
}

pub const SEPOLIA_RPC_DEFAULT: &str = "https://starknet-sepolia-rpc.publicnode.com";
/// Serves `starknet_getStorageProof` for recent blocks (refuses blocks older
/// than ~6 minutes), which the virtual-OS prover needs.
pub const SEPOLIA_PROVER_RPC: &str = "https://api.zan.top/public/starknet-sepolia/rpc/v0_10";

/// STRK token (same address on Sepolia and mainnet) — the fee/transfer
/// token used by the setup wizard's fund step, the status balance read and
/// ticket purchases.
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
    /// prefix, to carry it into a phone backup) — the second recipient key
    /// (v2 onwards). Generated on `init`, and added to older profiles the
    /// first time it is needed (`Home::ensure_kem_seed`). Like the scan key,
    /// losing it loses the inbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem_seed: Option<String>,
    /// v3 membership secret m, `0x` + 64 lowercase hex (< 2^251, never 0).
    /// It is the SEND credential: the leaf commits to poseidon(MEMBER_V3, m)
    /// and a send proves knowledge of m. Minted on `init`, and fresh for each
    /// store a profile registers on (`migrate_store`); never re-minted for a
    /// profile that holds a handle on the current store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_secret: Option<String>,
}

impl Keys {
    pub fn kem_seed_bytes(&self) -> Result<[u8; crate::crypto::KEM_SEED_LEN]> {
        let hex = self.kem_seed.as_deref().context("keys.json has no kem_seed")?;
        hex::decode(hex.trim_start_matches("0x"))
            .context("keys.json kem_seed hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("keys.json kem_seed is not 64 bytes"))
    }

    /// The membership secret as a felt, range-checked (< 2^251, nonzero).
    pub fn member_secret_felt(&self) -> Result<Felt> {
        let hex = self.member_secret.as_deref().context("keys.json has no member_secret")?;
        let bytes = hex::decode(hex.trim_start_matches("0x")).context("keys.json member_secret hex")?;
        crate::crypto::member_secret_felt(&bytes).context("keys.json member_secret")
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

/// The keys.json form of a membership secret: `0x` + 64 lowercase hex.
pub fn member_secret_hex(m: &[u8; crate::crypto::MEMBER_SECRET_LEN]) -> String {
    format!("0x{}", hex::encode(m))
}

/// Writes `bytes` to `path` atomically: a temp file in the same directory
/// (created with `mode`, so a secret is never briefly world-readable),
/// fsynced, then renamed over `path`.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().context("path has no parent")?;
    let name = path.file_name().context("path has no file name")?.to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
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

    /// The ticket wallet (mode 0600): ticket secrets are bearer value.
    pub fn tickets_path(&self) -> PathBuf {
        self.dir.join("tickets.json")
    }

    /// The quota slots this profile used in the current epoch.
    pub fn quota_path(&self) -> PathBuf {
        self.dir.join("quota.json")
    }

    pub fn load_config(&self) -> Result<Config> {
        let raw = fs::read_to_string(self.config_path())
            .with_context(|| format!("no config at {} — run `zkmsg init`", self.dir.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        write_atomic(&self.config_path(), serde_json::to_string_pretty(config)?.as_bytes(), 0o644)
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
        write_atomic(&self.keys_path(), serde_json::to_string_pretty(keys)?.as_bytes(), 0o600)
    }

    /// Updates mutable key metadata (handle/leaf index after registration).
    /// Atomic and owner-only: the scan key and KEM seed in this file are
    /// irreplaceable, so it is never left truncated.
    pub fn update_keys(&self, keys: &Keys) -> Result<()> {
        write_atomic(&self.keys_path(), serde_json::to_string_pretty(keys)?.as_bytes(), 0o600)
    }

    /// Loads keys, adding a fresh ML-KEM seed first if the profile predates
    /// v2. The seed is written before it is returned, so a key the chain
    /// might learn (via `register`) is never one that only lived in memory.
    ///
    /// Refused for a profile that holds a handle but no seed: on the v2
    /// store that registration committed to a seed this file has lost (an
    /// older build rewrote keys.json without it), and minting another would
    /// only hide that. `migrate_store` clears the handle first.
    /// Loads keys, adding the KEM seed and the membership secret if missing —
    /// everything a current-store registration publishes a commitment to.
    /// Same rule as `ensure_kem_seed`: never minted for a profile that holds
    /// a handle (its registration committed to the secret it lost).
    pub fn ensure_register_keys(&self) -> Result<Keys> {
        let mut keys = self.ensure_kem_seed()?;
        if keys.member_secret.is_none() {
            if let Some(handle) = &keys.handle {
                bail!(
                    "keys.json holds the handle '{handle}' but no member_secret — refusing to \
                     mint a new one (restore it from a backup, or `zkmsg migrate-store` if \
                     '{handle}' is an older store's registration)"
                );
            }
            keys.member_secret = Some(member_secret_hex(&crate::crypto::member_secret_gen()));
            self.update_keys(&keys)?;
        }
        Ok(keys)
    }

    pub fn ensure_kem_seed(&self) -> Result<Keys> {
        let mut keys = self.load_keys()?;
        if keys.kem_seed.is_none() {
            if let Some(handle) = &keys.handle {
                bail!(
                    "keys.json holds the handle '{handle}' but no kem_seed — refusing to mint a new \
                     one (restore the seed from a backup, or `zkmsg migrate-store` if '{handle}' is \
                     an older store's registration)"
                );
            }
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
            member_secret: None,
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

        // A registered profile whose seed went missing is refused, not re-seeded.
        let lost = Keys { handle: Some("carol".into()), kem_seed: None, ..home.load_keys().unwrap() };
        home.update_keys(&lost).unwrap();
        assert!(home.ensure_kem_seed().is_err());
        assert!(home.load_keys().unwrap().kem_seed.is_none());
        home.update_keys(&seeded).unwrap();

        // The membership secret: minted once, pinned format, range-checked.
        let full = home.ensure_register_keys().unwrap();
        let m = full.member_secret.clone().unwrap();
        assert!(m.starts_with("0x") && m.len() == 66, "pinned format: {m}");
        assert!(full.member_secret_felt().is_ok());
        assert_eq!(home.ensure_register_keys().unwrap().member_secret, Some(m.clone()));
        let too_big = Keys { member_secret: Some(format!("0x08{}", "00".repeat(31))), ..home.load_keys().unwrap() };
        assert!(too_big.member_secret_felt().is_err(), ">= 2^251 is rejected");
        let zero = Keys { member_secret: Some(format!("0x{}", "00".repeat(32))), ..home.load_keys().unwrap() };
        assert!(zero.member_secret_felt().is_err(), "0 is rejected");
        // Never minted for a registered profile that lost it.
        let lost = Keys { handle: Some("carol".into()), member_secret: None, ..home.load_keys().unwrap() };
        home.update_keys(&lost).unwrap();
        assert!(home.ensure_register_keys().is_err());
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
        assert_eq!(Config::default_sepolia(Path::new("/r")).store, SEPOLIA_POOL_V4);
        assert!(is_current_store(SEPOLIA_POOL_V4));
        // Leading-zero / case differences still match.
        let upper = format!("0x{}", SEPOLIA_POOL_V4.trim_start_matches("0x").trim_start_matches('0').to_uppercase());
        assert!(is_current_store(&upper));
        assert_eq!(store_deploy_block(SEPOLIA_POOL_V4), SEPOLIA_POOL_V4_DEPLOY_BLOCK);
        // The retired stores are just unknown addresses now.
        for retired in [
            SEPOLIA_STORE_V3,
            "0x04dc92ef9a90d336a79188c5408cdf9ce480f3ecd5b1ce55ef2ca207f2c3afe8", // v2 PQ
            "0x002b9c6f617b3197dfed76401c32aa3b4b597ebdd01a7eba4b5657236bc8084f", // SNIP-36 v1
        ] {
            assert!(!is_current_store(retired));
            assert_eq!(store_deploy_block(retired), 0);
        }
    }
}
