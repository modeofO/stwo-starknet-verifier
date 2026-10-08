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
//!     the id, value = K wrapped under the app's master key (`applock`: the
//!     app PIN unlocks it), or bare K for a key stored before the PIN.
//!
//! Reads accept plaintext too (profiles written before the vault);
//! `seal_profile` converts them, and every write seals.
//!
//! The Keychain is reached through `keychain` (`/usr/bin/security`).
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
/// First bytes of a profile key wrapped under the app's master key
/// (`applock`); a bare 32-byte value is a key stored before the app PIN.
const WRAPPED: &[u8; 4] = b"zkk1";

/// The Keychain service profile keys live in.
pub fn keychain_service() -> String {
    crate::keychain::service(KEYCHAIN_SERVICE)
}

/// Unwrapped profile keys this process has read. Cleared by `forget_keys`
/// (the app locking).
fn cache() -> &'static Mutex<HashMap<String, [u8; KEY_LEN]>> {
    static CACHE: OnceLock<Mutex<HashMap<String, [u8; KEY_LEN]>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Drops every unwrapped profile key held in memory.
pub fn forget_keys() {
    cache().lock().unwrap().clear();
}

fn wrap_aad(id: &str) -> String {
    format!("zkmsg.profile-key/{id}")
}

/// A profile key as the Keychain holds it: wrapped under the master key
/// once the app has a PIN, bare before.
fn stored_form(id: &str, key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    match crate::applock::master_key_if_set()? {
        None => Ok(key.to_vec()),
        Some(mk) => Ok([WRAPPED.as_slice(), &seal(&mk, &wrap_aad(id), key)?[MAGIC.len()..]].concat()),
    }
}

fn key_get(id: &str) -> Result<Option<[u8; KEY_LEN]>> {
    check_id(id)?;
    if let Some(k) = cache().lock().unwrap().get(id) {
        return Ok(Some(*k));
    }
    let Some(stored) = crate::keychain::store().get(&keychain_service(), id)? else { return Ok(None) };
    let key: [u8; KEY_LEN] = if let Some(body) = stored.strip_prefix(WRAPPED.as_slice()) {
        let mk = crate::applock::master_key()?;
        let sealed = [MAGIC.as_slice(), body].concat();
        open(&mk, &wrap_aad(id), &sealed)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("profile key {id} is not {KEY_LEN} bytes"))?
    } else {
        let key: [u8; KEY_LEN] =
            stored.try_into().map_err(|_| anyhow::anyhow!("profile key {id} is not {KEY_LEN} bytes"))?;
        // Stored before the app had a PIN: wrap it now that it has one.
        if crate::applock::master_key_if_set()?.is_some() {
            key_put(id, &key)?;
        }
        key
    };
    cache().lock().unwrap().insert(id.to_string(), key);
    Ok(Some(key))
}

fn key_put(id: &str, key: &[u8; KEY_LEN]) -> Result<()> {
    check_id(id)?;
    crate::keychain::store().put(&keychain_service(), id, &stored_form(id, key)?)?;
    cache().lock().unwrap().insert(id.to_string(), *key);
    Ok(())
}

fn key_delete(id: &str) -> Result<()> {
    check_id(id)?;
    cache().lock().unwrap().remove(id);
    crate::keychain::store().delete(&keychain_service(), id)
}

/// Rewraps the profile key `id` under the current master key (after the PIN
/// is set). Returns whether there was one.
pub fn rewrap(id: &str) -> Result<bool> {
    cache().lock().unwrap().remove(id);
    match key_get(id)? {
        Some(k) => {
            key_put(id, &k)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Set by `shred_all`: this process creates no new vault afterwards (until
/// a new app PIN is set).
static WIPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn clear_wiped() {
    WIPED.store(false, std::sync::atomic::Ordering::SeqCst);
}

/// Deletes every profile key in the Keychain, whatever profile it belonged
/// to (the panic wipe). Returns how many.
pub fn shred_all() -> Result<usize> {
    #[cfg(not(test))]
    WIPED.store(true, std::sync::atomic::Ordering::SeqCst);
    forget_keys();
    crate::keychain::store().delete_all(&keychain_service())
}

/// Ids are 32 lowercase hex digits.
fn check_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "malformed profile key id {id:?}"
    );
    Ok(())
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
    // After a panic wipe in this process, a straggling worker must not
    // recreate a profile (under a fresh, unprotected key).
    ensure!(
        !WIPED.load(std::sync::atomic::Ordering::SeqCst),
        "everything was wiped: not creating {}",
        home.dir.display()
    );
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

pub(crate) fn seal(key: &[u8; KEY_LEN], aad: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = Aes256Gcm::new(key.into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
        .map_err(|_| anyhow::anyhow!("sealing {aad}"))?;
    Ok([MAGIC.as_slice(), &nonce, &ct].concat())
}

pub(crate) fn open(key: &[u8; KEY_LEN], aad: &str, sealed: &[u8]) -> Result<Vec<u8>> {
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
