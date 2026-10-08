//! Per-profile encryption at rest, so that deleting a profile is a
//! crypto-shred rather than a hope.
//!
//! Deleting a plain file on an SSD (APFS is copy-on-write) leaves its
//! blocks readable until something overwrites them. So a profile's secret
//! files — `keys.json`, `tickets*.json`, `quota.json`, `inbox.json`,
//! `sends/*.json` — are sealed with AES-256-GCM under a random per-profile
//! key K that lives in the macOS login Keychain, never on disk beside them.
//! Deleting K makes every sealed byte unreadable, wherever its blocks
//! linger.
//!
//! Layout:
//!
//!   * `vault.json` (plain): `{"id": "<32 hex>"}`, the Keychain account name
//!     of this profile's K. Survives renames (archive moves the dir).
//!   * A sealed file: `MAGIC ‖ nonce(12) ‖ AES-256-GCM(K, plaintext)`, with
//!     the file's path relative to the profile dir as associated data, so a
//!     sealed file cannot be swapped for another's.
//!   * Keychain: generic password, service `zkmsg.profile-key`, account =
//!     the id, password = hex(K).
//!
//! Reads accept plaintext too (profiles written before the vault);
//! `seal_profile` converts them, and every write seals.
//!
//! The Keychain is reached through `/usr/bin/security`: an item it creates
//! trusts that Apple-signed tool, so rebuilding zkmsg (a new code signature
//! each time) never raises an access prompt. `add` takes the secret on
//! stdin (`security -i`), never in argv where `ps` would show it.
//!
//! What this does not cover: the account's private key lives in sncast's
//! accounts file, outside the profile (`wipe` removes its entry, a plain
//! rewrite); and a deleted Keychain item may persist in the keychain
//! database's free pages, encrypted under the login keychain's own key.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, bail, ensure};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::config::{Home, write_atomic};

/// First bytes of every sealed file (no JSON file starts with them).
pub const MAGIC: &[u8; 5] = b"zkv1\0";
const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const KEYCHAIN_SERVICE: &str = "zkmsg.profile-key";
const VAULT_FILE: &str = "vault.json";

/// Where profile keys are kept.
pub trait KeyStore: Send + Sync {
    fn get(&self, id: &str) -> Result<Option<[u8; KEY_LEN]>>;
    fn put(&self, id: &str, key: &[u8; KEY_LEN]) -> Result<()>;
    /// Deleting a key that is not there is not an error.
    fn delete(&self, id: &str) -> Result<()>;
}

/// The macOS login Keychain, via `/usr/bin/security`.
pub struct SecurityCli;

const SECURITY: &str = "/usr/bin/security";
/// `security`'s exit status for "item not found".
const ERR_SEC_ITEM_NOT_FOUND: i32 = 44;

impl KeyStore for SecurityCli {
    fn get(&self, id: &str) -> Result<Option<[u8; KEY_LEN]>> {
        check_id(id)?;
        let out = std::process::Command::new(SECURITY)
            .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", id, "-w"])
            .output()
            .context("running /usr/bin/security")?;
        if out.status.code() == Some(ERR_SEC_ITEM_NOT_FOUND) {
            return Ok(None);
        }
        ensure!(
            out.status.success(),
            "reading profile key {id} from the Keychain: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(Some(parse_key(String::from_utf8_lossy(&out.stdout).trim())?))
    }

    fn put(&self, id: &str, key: &[u8; KEY_LEN]) -> Result<()> {
        use std::io::Write;
        check_id(id)?;
        let mut child = std::process::Command::new(SECURITY)
            .arg("-i")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("running /usr/bin/security")?;
        let line = format!(
            "add-generic-password -U -s {KEYCHAIN_SERVICE} -a {id} -l zkmsg-profile-key -w {}\n",
            hex::encode(key)
        );
        child.stdin.take().context("security stdin")?.write_all(line.as_bytes())?;
        let out = child.wait_with_output()?;
        // `security -i` exits 0 whatever its commands did: read it back.
        ensure!(
            self.get(id)?.as_ref() == Some(key),
            "storing profile key {id} in the Keychain failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<()> {
        check_id(id)?;
        let out = std::process::Command::new(SECURITY)
            .args(["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", id])
            .output()
            .context("running /usr/bin/security")?;
        ensure!(
            out.status.success() || out.status.code() == Some(ERR_SEC_ITEM_NOT_FOUND),
            "deleting profile key {id} from the Keychain: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        ensure!(self.get(id)?.is_none(), "profile key {id} is still in the Keychain after delete");
        Ok(())
    }
}

/// Keys in process memory: tests, and `ZKMSG_KEYSTORE=memory` for other
/// crates' tests. Nothing survives the process.
#[derive(Default)]
pub struct MemoryKeyStore(Mutex<HashMap<String, [u8; KEY_LEN]>>);

impl KeyStore for MemoryKeyStore {
    fn get(&self, id: &str) -> Result<Option<[u8; KEY_LEN]>> {
        Ok(self.0.lock().unwrap().get(id).copied())
    }
    fn put(&self, id: &str, key: &[u8; KEY_LEN]) -> Result<()> {
        self.0.lock().unwrap().insert(id.to_string(), *key);
        Ok(())
    }
    fn delete(&self, id: &str) -> Result<()> {
        self.0.lock().unwrap().remove(id);
        Ok(())
    }
}

/// The process's key store, with a read cache in front (each Keychain read
/// is a subprocess).
struct Cached {
    inner: Box<dyn KeyStore>,
    cache: Mutex<HashMap<String, [u8; KEY_LEN]>>,
}

fn store() -> &'static Cached {
    static STORE: OnceLock<Cached> = OnceLock::new();
    STORE.get_or_init(|| {
        let memory = cfg!(test) || std::env::var("ZKMSG_KEYSTORE").is_ok_and(|v| v == "memory");
        let inner: Box<dyn KeyStore> =
            if memory { Box::<MemoryKeyStore>::default() } else { Box::new(SecurityCli) };
        Cached { inner, cache: Mutex::new(HashMap::new()) }
    })
}

fn key_get(id: &str) -> Result<Option<[u8; KEY_LEN]>> {
    let s = store();
    if let Some(k) = s.cache.lock().unwrap().get(id) {
        return Ok(Some(*k));
    }
    let k = s.inner.get(id)?;
    if let Some(k) = k {
        s.cache.lock().unwrap().insert(id.to_string(), k);
    }
    Ok(k)
}

fn key_put(id: &str, key: &[u8; KEY_LEN]) -> Result<()> {
    store().inner.put(id, key)?;
    store().cache.lock().unwrap().insert(id.to_string(), *key);
    Ok(())
}

fn key_delete(id: &str) -> Result<()> {
    store().cache.lock().unwrap().remove(id);
    store().inner.delete(id)
}

/// Ids are 32 lowercase hex digits: safe as a `security -i` token.
fn check_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "malformed profile key id {id:?}"
    );
    Ok(())
}

fn parse_key(hex_key: &str) -> Result<[u8; KEY_LEN]> {
    hex::decode(hex_key)
        .context("profile key hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("profile key is not {KEY_LEN} bytes"))
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    id: String,
}

/// This profile's key id, if it has a vault.
pub fn profile_key_id(home: &Home) -> Result<Option<String>> {
    let path = home.dir.join(VAULT_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let v: VaultFile = serde_json::from_str(&fs::read_to_string(&path)?)
        .with_context(|| format!("reading {}", path.display()))?;
    check_id(&v.id)?;
    Ok(Some(v.id))
}

/// The profile's key, if it has a vault. An id whose key is gone means the
/// profile was shredded (or its Keychain item removed): its sealed files
/// are unreadable, and that is said plainly.
fn profile_key(home: &Home) -> Result<Option<[u8; KEY_LEN]>> {
    let Some(id) = profile_key_id(home)? else { return Ok(None) };
    match key_get(&id)? {
        Some(k) => Ok(Some(k)),
        None => bail!(
            "the profile key for {} (Keychain service {KEYCHAIN_SERVICE}, account {id}) is gone — \
             this profile was deleted, and its sealed files can no longer be read",
            home.dir.display()
        ),
    }
}

/// The profile's key, creating the vault first if it has none. The key is
/// stored (and read back) before `vault.json` names it, so no file is ever
/// sealed under a key that only lived in memory.
fn profile_key_or_create(home: &Home) -> Result<[u8; KEY_LEN]> {
    if let Some(k) = profile_key(home)? {
        return Ok(k);
    }
    let mut id = [0u8; 16];
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut id);
    rand::rngs::OsRng.fill_bytes(&mut key);
    let id = hex::encode(id);
    key_put(&id, &key)?;
    fs::create_dir_all(&home.dir)?;
    // Published by hard link, which fails if vault.json exists: two processes
    // creating a vault at once (GUI and CLI opening an old profile) cannot
    // both win, so no file is ever sealed under a key vault.json does not
    // name. The loser drops its key and uses the winner's.
    let path = home.dir.join(VAULT_FILE);
    let tmp = home.dir.join(format!(".{VAULT_FILE}.new-{id}"));
    write_atomic(&tmp, serde_json::to_string_pretty(&VaultFile { id: id.clone() })?.as_bytes(), 0o600)?;
    let linked = fs::hard_link(&tmp, &path);
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(key),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            key_delete(&id)?;
            profile_key(home)?.context("vault.json appeared without a key")
        }
        Err(e) => {
            let _ = key_delete(&id);
            Err(e).with_context(|| format!("writing {}", path.display()))
        }
    }
}

/// `path` relative to the profile dir, as the AEAD's associated data.
fn aad(home: &Home, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(&home.dir)
        .with_context(|| format!("{} is outside the profile {}", path.display(), home.dir.display()))?;
    Ok(rel.to_string_lossy().into_owned())
}

pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

fn seal(key: &[u8; KEY_LEN], aad: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = Aes256Gcm::new(key.into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
        .map_err(|_| anyhow::anyhow!("sealing {aad}"))?;
    Ok([MAGIC.as_slice(), &nonce, &ct].concat())
}

fn open(key: &[u8; KEY_LEN], aad: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    ensure!(sealed.len() >= MAGIC.len() + NONCE_LEN + 16, "{aad}: sealed file is truncated");
    let (nonce, ct) = sealed[MAGIC.len()..].split_at(NONCE_LEN);
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: aad.as_bytes() })
        .map_err(|_| anyhow::anyhow!("{aad}: does not decrypt under this profile's key"))
}

/// A profile file's contents: opened if sealed, as-is if plaintext.
pub fn read(home: &Home, path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if !is_sealed(&bytes) {
        return Ok(bytes);
    }
    let key = profile_key(home)?
        .with_context(|| format!("{} is sealed but the profile has no vault.json", path.display()))?;
    open(&key, &aad(home, path)?, &bytes)
}

pub fn read_to_string(home: &Home, path: &Path) -> Result<String> {
    String::from_utf8(read(home, path)?).with_context(|| format!("{} is not UTF-8", path.display()))
}

/// Seals `plaintext` under the profile's key (creating the vault if needed)
/// and writes it atomically, owner-only.
pub fn write(home: &Home, path: &Path, plaintext: &[u8]) -> Result<()> {
    let key = profile_key_or_create(home)?;
    let sealed = seal(&key, &aad(home, path)?, plaintext)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    write_atomic(path, &sealed, 0o600)
}

/// The profile's files that hold secrets or private content: the ones a
/// vault seals. (Proofs under `sends/<id>/` go on chain; config.json and
/// setup.json hold addresses and names, not secrets.)
pub fn secret_files(home: &Home) -> Result<Vec<std::path::PathBuf>> {
    let mut out = vec![];
    if home.dir.is_dir() {
        for entry in fs::read_dir(&home.dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let wanted = matches!(name, "keys.json" | "quota.json" | "inbox.json")
                || (name.starts_with("tickets") && name.ends_with(".json"));
            if wanted && path.is_file() {
                out.push(path);
            }
        }
    }
    let sends = home.sends_dir();
    if sends.is_dir() {
        for entry in fs::read_dir(&sends)? {
            let path = entry?.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Seals every plaintext secret file in place; returns how many. Each one is
/// read back and checked before the next, so a failure leaves at worst a
/// mix of sealed and plaintext files, all readable.
pub fn seal_profile(home: &Home) -> Result<usize> {
    let mut sealed = 0;
    for path in secret_files(home)? {
        let bytes = fs::read(&path)?;
        if is_sealed(&bytes) {
            continue;
        }
        write(home, &path, &bytes)?;
        ensure!(read(home, &path)? == bytes, "{} did not read back after sealing", path.display());
        sealed += 1;
    }
    Ok(sealed)
}

/// Whether the profile has any secret file still in plaintext.
pub fn has_plaintext(home: &Home) -> Result<bool> {
    for path in secret_files(home)? {
        if !is_sealed(&fs::read(&path)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Deletes the profile's key: every sealed file becomes unreadable. Returns
/// whether there was a vault to shred.
pub fn shred(home: &Home) -> Result<bool> {
    let Some(id) = profile_key_id(home)? else { return Ok(false) };
    key_delete(&id)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(tag: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("zkmsg-vault-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Home::new(dir)
    }

    #[test]
    fn seals_reads_back_and_shreds() {
        let h = home("roundtrip");
        let p = h.dir.join("keys.json");
        write(&h, &p, b"{\"scan_priv\":\"0x5\"}").unwrap();
        let raw = fs::read(&p).unwrap();
        assert!(is_sealed(&raw));
        assert!(!raw.windows(9).any(|w| w == b"scan_priv"), "no plaintext on disk");
        assert_eq!(read(&h, &p).unwrap(), b"{\"scan_priv\":\"0x5\"}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // Shredding loses every sealed file, and says why.
        assert!(shred(&h).unwrap());
        let err = format!("{:#}", read(&h, &p).unwrap_err());
        assert!(err.contains("is gone"), "{err}");
        // No new key is minted behind the user's back for a shredded profile.
        assert!(write(&h, &p, b"x").is_err());
        fs::remove_dir_all(&h.dir).unwrap();
    }

    #[test]
    fn plaintext_is_read_and_sealed_in_place() {
        let h = home("seal");
        fs::create_dir_all(h.sends_dir().join("abc")).unwrap();
        fs::write(h.dir.join("keys.json"), "{\"k\":1}").unwrap();
        fs::write(h.dir.join("tickets.json"), "{\"t\":1}").unwrap();
        fs::write(h.dir.join("tickets-050f.json"), "{\"old\":1}").unwrap();
        fs::write(h.sends_dir().join("abc.json"), "{\"s\":1}").unwrap();
        fs::write(h.sends_dir().join("abc/proof.json"), "{\"proof\":1}").unwrap();
        fs::write(h.dir.join("config.json"), "{}").unwrap();

        assert_eq!(read(&h, &h.dir.join("keys.json")).unwrap(), b"{\"k\":1}");
        assert!(has_plaintext(&h).unwrap());
        assert_eq!(seal_profile(&h).unwrap(), 4);
        assert!(!has_plaintext(&h).unwrap());
        assert_eq!(seal_profile(&h).unwrap(), 0, "idempotent");
        assert_eq!(read(&h, &h.dir.join("tickets-050f.json")).unwrap(), b"{\"old\":1}");
        assert_eq!(read(&h, &h.sends_dir().join("abc.json")).unwrap(), b"{\"s\":1}");
        // Not secret: left alone.
        assert_eq!(fs::read(h.dir.join("config.json")).unwrap(), b"{}");
        assert_eq!(fs::read(h.sends_dir().join("abc/proof.json")).unwrap(), b"{\"proof\":1}");
        fs::remove_dir_all(&h.dir).unwrap();
    }

    #[test]
    fn a_sealed_file_is_bound_to_its_path_and_profile() {
        let h = home("aad");
        write(&h, &h.dir.join("keys.json"), b"secret").unwrap();
        fs::copy(h.dir.join("keys.json"), h.dir.join("quota.json")).unwrap();
        assert!(read(&h, &h.dir.join("quota.json")).is_err(), "swapped file refused");

        // Another profile's key does not open it.
        let other = home("aad-other");
        write(&other, &other.dir.join("keys.json"), b"x").unwrap();
        fs::copy(h.dir.join("keys.json"), other.dir.join("keys.json")).unwrap();
        assert!(read(&other, &other.dir.join("keys.json")).is_err());
        fs::remove_dir_all(&h.dir).unwrap();
        fs::remove_dir_all(&other.dir).unwrap();
    }

    #[test]
    fn the_vault_follows_a_renamed_dir() {
        let h = home("rename");
        write(&h, &h.dir.join("keys.json"), b"k").unwrap();
        let moved = h.dir.with_file_name(format!("zkmsg-vault-renamed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&moved);
        fs::rename(&h.dir, &moved).unwrap();
        let h2 = Home::new(moved.clone());
        assert_eq!(read(&h2, &h2.dir.join("keys.json")).unwrap(), b"k");
        fs::remove_dir_all(&moved).unwrap();
    }

    #[test]
    fn ids_are_checked_before_reaching_the_shell() {
        assert!(check_id(&"a".repeat(32)).is_ok());
        assert!(check_id("abc").is_err());
        assert!(check_id(&format!("{} -w x", "a".repeat(26))).is_err());
        assert!(check_id(&"A".repeat(32)).is_err());
    }
}
