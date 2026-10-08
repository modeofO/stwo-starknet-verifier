//! The app PIN (owner decision 2026-10-08: a separate app PIN, set on
//! first use; not the login password, never biometrics).
//!
//! One random master key MK wraps every profile key (`vault`). MK itself
//! is kept only wrapped:
//!
//!   KEK = Argon2id(PIN, salt; 256 MiB, 3 passes)
//!   stored = AES-256-GCM(KEK, MK), in the login Keychain
//!            (service `zkmsg.app-lock`, account `lock`), with the salt,
//!            the KDF parameters and the failed-attempt counter.
//!
//! So reading any profile needs the PIN, and guessing it offline needs the
//! login Keychain item first (the login password, or the logged-in user's
//! session) and then ~1 s of a 256 MiB computation per guess. That is the
//! honest strength on a Mac, which has no Secure Enclave this unsigned
//! tool can use: a 6-digit PIN against someone holding the unlocked
//! Keychain falls in days. A longer PIN or a passphrase is stronger; the
//! phone binds its PIN to the Secure Enclave instead.
//!
//! Attempts: the counter is raised and saved BEFORE a guess is checked (a
//! killed process still spends the attempt), reset by a correct PIN.
//! From the 5th failure each try waits (30 s, 1 min, 5 min, 15 min, 1 h);
//! the 10th consecutive failure runs the panic wipe (`wipe::panic_wipe`).
//! Someone who can rewrite the Keychain item can reset the counter; the
//! limit stops guessing through the app, not a forensic attack.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, bail, ensure};
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const SERVICE: &str = "zkmsg.app-lock";
const ACCOUNT: &str = "lock";
pub const MAX_ATTEMPTS: u32 = 10;
/// Failures before the first wait.
const FREE_ATTEMPTS: u32 = 4;
const WAITS: [u64; 5] = [30, 60, 300, 900, 3600];
pub const MIN_PIN_LEN: usize = 6;
pub const MAX_PIN_LEN: usize = 64;
const AAD: &[u8] = b"zkmsg app-lock v1";

/// Argon2id cost: 256 MiB, 3 passes, 1 lane (tiny under test).
#[cfg(not(test))]
const KDF: (u32, u32, u32) = (256 * 1024, 3, 1);
#[cfg(test)]
const KDF: (u32, u32, u32) = (64, 1, 1);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LockBlob {
    v: u32,
    salt: String,
    m_kib: u32,
    t: u32,
    p: u32,
    nonce: String,
    wrapped: String,
    /// Consecutive failed attempts.
    fails: u32,
    /// Unix seconds before which no attempt is checked.
    not_before: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// No PIN yet: first use.
    NotSet,
    Locked { fails: u32, wait_secs: u64 },
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlock {
    Unlocked,
    Wrong { attempts_left: u32, wait_secs: u64 },
    /// Too soon after a failure; nothing was checked or counted.
    Wait { secs: u64 },
    /// That was the last attempt: the panic wipe ran. Its errors (if any)
    /// say what it could not do.
    Wiped { errors: Vec<String> },
}

/// MK while unlocked: per process (per thread under test, like the test
/// Keychain).
#[cfg(not(test))]
static MASTER: Mutex<Option<[u8; 32]>> = Mutex::new(None);
#[cfg(test)]
thread_local! {
    static MASTER_T: &'static Mutex<Option<[u8; 32]>> = Box::leak(Box::new(Mutex::new(None)));
}
#[cfg(test)]
fn master_slot() -> &'static Mutex<Option<[u8; 32]>> {
    MASTER_T.with(|m| *m)
}
#[cfg(not(test))]
fn master_slot() -> &'static Mutex<Option<[u8; 32]>> {
    &MASTER
}

fn service() -> String {
    crate::keychain::service(SERVICE)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn load() -> Result<Option<LockBlob>> {
    let Some(raw) = crate::keychain::store().get(&service(), ACCOUNT)? else { return Ok(None) };
    Ok(Some(serde_json::from_slice(&raw).context("reading the app lock")?))
}

fn save(blob: &LockBlob) -> Result<()> {
    crate::keychain::store().put(&service(), ACCOUNT, &serde_json::to_vec(blob)?)
}

fn wait_after(fails: u32) -> u64 {
    if fails <= FREE_ATTEMPTS {
        return 0;
    }
    WAITS[((fails - FREE_ATTEMPTS - 1) as usize).min(WAITS.len() - 1)]
}

pub fn state() -> Result<LockState> {
    if master_slot().lock().unwrap().is_some() {
        return Ok(LockState::Unlocked);
    }
    Ok(match load()? {
        None => LockState::NotSet,
        Some(b) => LockState::Locked { fails: b.fails, wait_secs: b.not_before.saturating_sub(now()) },
    })
}

/// MK, or an error saying the app is locked.
pub fn master_key() -> Result<[u8; 32]> {
    if let Some(mk) = *master_slot().lock().unwrap() {
        return Ok(mk);
    }
    if load()?.is_none() {
        bail!("this profile key is wrapped under an app PIN that no longer exists (the app was wiped)");
    }
    bail!("zkmsg is locked: enter the app PIN")
}

/// MK if a PIN is set (an error if it is set but locked), `None` before the
/// first PIN.
pub fn master_key_if_set() -> Result<Option<[u8; 32]>> {
    if let Some(mk) = *master_slot().lock().unwrap() {
        return Ok(Some(mk));
    }
    match load()? {
        None => Ok(None),
        Some(_) => bail!("zkmsg is locked: enter the app PIN"),
    }
}

pub fn validate_pin(pin: &str) -> Result<()> {
    ensure!(pin.chars().count() >= MIN_PIN_LEN, "the PIN needs at least {MIN_PIN_LEN} characters");
    ensure!(pin.chars().count() <= MAX_PIN_LEN, "the PIN can have at most {MAX_PIN_LEN} characters");
    ensure!(!pin.chars().any(char::is_control), "the PIN cannot contain control characters");
    Ok(())
}

fn kek(pin: &str, salt: &[u8], (m, t, p): (u32, u32, u32)) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m, t, p, Some(32)).map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(out)
}

fn wrap(pin: &str, mk: &[u8; 32]) -> Result<LockBlob> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let k = kek(pin, &salt, KDF)?;
    let wrapped = Aes256Gcm::new((&k).into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: mk, aad: AAD })
        .map_err(|_| anyhow::anyhow!("wrapping the master key"))?;
    Ok(LockBlob {
        v: 1,
        salt: hex::encode(salt),
        m_kib: KDF.0,
        t: KDF.1,
        p: KDF.2,
        nonce: hex::encode(nonce),
        wrapped: hex::encode(wrapped),
        fails: 0,
        not_before: 0,
    })
}

fn unwrap(pin: &str, b: &LockBlob) -> Result<Option<[u8; 32]>> {
    let k = kek(pin, &hex::decode(&b.salt)?, (b.m_kib, b.t, b.p))?;
    let Ok(mk) = Aes256Gcm::new((&k).into()).decrypt(
        Nonce::from_slice(&hex::decode(&b.nonce)?),
        Payload { msg: &hex::decode(&b.wrapped)?, aad: AAD },
    ) else {
        return Ok(None);
    };
    Ok(Some(mk.try_into().map_err(|_| anyhow::anyhow!("master key is not 32 bytes"))?))
}

/// First use: sets the PIN, unlocks, and wraps every profile key under
/// `root` that was stored before the PIN. Refused if a PIN exists.
pub fn set_pin(pin: &str, root: &Path) -> Result<usize> {
    validate_pin(pin)?;
    ensure!(load()?.is_none(), "an app PIN is already set");
    let mut mk = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut mk);
    save(&wrap(pin, &mk)?)?;
    ensure!(unwrap(pin, &load()?.context("the app lock did not save")?)? == Some(mk), "the app lock did not read back");
    *master_slot().lock().unwrap() = Some(mk);
    crate::vault::clear_wiped();
    wrap_profile_keys(root)
}

/// Wraps every bare profile key of the profiles under `root` (live and
/// archived) under MK. Returns how many keys it touched.
pub fn wrap_profile_keys(root: &Path) -> Result<usize> {
    let mut n = 0;
    for dir in crate::wipe::all_profile_dirs(root) {
        if let Some(id) = crate::vault::profile_key_id(&crate::config::Home::new(dir))? {
            if crate::vault::rewrap(&id)? {
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Attempts are serialized across processes by an exclusive lock on this
/// file, held from reading the counter to saving the result: N processes
/// started at once with N guesses spend N attempts, not one.
fn attempt_lock() -> Result<std::fs::File> {
    let path = std::env::temp_dir().join(format!("{}.attempt.lock", service()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.lock().with_context(|| format!("locking {}", path.display()))?;
    Ok(file)
}

/// One attempt. The counter is raised and saved before the PIN is checked;
/// the 10th consecutive failure runs `wipe::panic_wipe(root)`.
pub fn unlock(pin: &str, root: &Path) -> Result<Unlock> {
    let _serial = attempt_lock()?;
    let mut blob = load()?.context("no app PIN is set")?;
    let wait = blob.not_before.saturating_sub(now());
    if wait > 0 {
        return Ok(Unlock::Wait { secs: wait });
    }
    blob.fails += 1;
    blob.not_before = now() + wait_after(blob.fails);
    save(&blob)?;
    if let Some(mk) = unwrap(pin, &blob)? {
        blob.fails = 0;
        blob.not_before = 0;
        save(&blob)?;
        *master_slot().lock().unwrap() = Some(mk);
        return Ok(Unlock::Unlocked);
    }
    if blob.fails >= MAX_ATTEMPTS {
        let report = crate::wipe::panic_wipe(root)?;
        return Ok(Unlock::Wiped { errors: report.errors });
    }
    Ok(Unlock::Wrong { attempts_left: MAX_ATTEMPTS - blob.fails, wait_secs: wait_after(blob.fails) })
}

/// Re-wraps MK under a new PIN. Needs the old one (an attempt like any
/// other: it counts).
pub fn change_pin(old: &str, new: &str, root: &Path) -> Result<Unlock> {
    validate_pin(new)?;
    let outcome = unlock(old, root)?;
    // The new wrap is saved outside the attempt lock: `unlock` released it,
    // and only a process holding MK can get here.
    if outcome != Unlock::Unlocked {
        return Ok(outcome);
    }
    let mk = master_key()?;
    save(&wrap(new, &mk)?)?;
    ensure!(unwrap(new, &load()?.context("the app lock vanished")?)? == Some(mk), "the new PIN did not read back");
    Ok(Unlock::Unlocked)
}

/// Forgets MK and every unwrapped profile key this process holds.
pub fn lock() {
    *master_slot().lock().unwrap() = None;
    crate::vault::forget_keys();
}

/// Deletes the app lock (panic wipe). The next start is a first use.
pub fn destroy() -> Result<()> {
    lock();
    crate::keychain::store().delete(&service(), ACCOUNT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Home, Keys};

    fn root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zkmsg-applock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn profile(root: &Path, name: &str) -> Home {
        let home = Home::new(root.join(format!(".zkmsg-{name}")));
        home.save_config(&crate::config::Config::default_sepolia(Path::new("/r"))).unwrap();
        home.save_new_keys(&Keys {
            scan_priv: "0x5".into(),
            scan_pub: "0x6".into(),
            handle: Some(name.into()),
            leaf_index: Some(0),
            kem_seed: None,
            member_secret: None,
        })
        .unwrap();
        home
    }

    fn reset() {
        let _ = destroy();
    }

    #[test]
    fn first_use_wraps_existing_keys_and_locking_closes_everything() {
        reset();
        let r = root("first");
        let carol = profile(&r, "carol");
        let id = crate::vault::profile_key_id(&carol).unwrap().unwrap();
        let svc = crate::vault::keychain_service();
        assert_eq!(crate::keychain::store().get(&svc, &id).unwrap().unwrap().len(), 32, "bare before the PIN");

        assert_eq!(state().unwrap(), LockState::NotSet);
        assert!(set_pin("12345", &r).is_err(), "too short");
        assert_eq!(set_pin("123456", &r).unwrap(), 1);
        assert!(set_pin("654321", &r).is_err(), "only once");
        let stored = crate::keychain::store().get(&svc, &id).unwrap().unwrap();
        assert!(stored.starts_with(b"zkk1"), "wrapped once the PIN exists");
        assert!(carol.load_keys().is_ok());

        lock();
        assert!(matches!(state().unwrap(), LockState::Locked { fails: 0, .. }));
        let err = format!("{:#}", carol.load_keys().unwrap_err());
        assert!(err.contains("locked"), "{err}");
        assert_eq!(unlock("123456", &r).unwrap(), Unlock::Unlocked);
        assert_eq!(carol.load_keys().unwrap().handle.as_deref(), Some("carol"));

        // A profile made after the PIN is wrapped from the start.
        let mode = profile(&r, "mode");
        let mid = crate::vault::profile_key_id(&mode).unwrap().unwrap();
        assert!(crate::keychain::store().get(&svc, &mid).unwrap().unwrap().starts_with(b"zkk1"));
        reset();
        std::fs::remove_dir_all(&r).unwrap();
    }

    #[test]
    fn wrong_pins_count_wait_and_the_tenth_wipes() {
        reset();
        let r = root("attempts");
        let carol = profile(&r, "carol");
        set_pin("123456", &r).unwrap();
        lock();
        for i in 1..=4 {
            assert_eq!(unlock("000000", &r).unwrap(), Unlock::Wrong { attempts_left: 10 - i, wait_secs: 0 });
        }
        // A correct PIN resets the count.
        assert_eq!(unlock("123456", &r).unwrap(), Unlock::Unlocked);
        lock();
        for _ in 1..=4 {
            unlock("000000", &r).unwrap();
        }
        assert_eq!(unlock("000000", &r).unwrap(), Unlock::Wrong { attempts_left: 5, wait_secs: 30 });
        assert!(matches!(unlock("123456", &r).unwrap(), Unlock::Wait { .. }), "even the right PIN waits");
        assert!(matches!(state().unwrap(), LockState::Locked { fails: 5, wait_secs: 1.. }));

        // Skip the waits (rewrite not_before) to reach the 10th failure.
        for _ in 6..=9 {
            let mut b = load().unwrap().unwrap();
            b.not_before = 0;
            save(&b).unwrap();
            assert!(matches!(unlock("000000", &r).unwrap(), Unlock::Wrong { .. }));
        }
        let mut b = load().unwrap().unwrap();
        b.not_before = 0;
        save(&b).unwrap();
        assert_eq!(unlock("000000", &r).unwrap(), Unlock::Wiped { errors: vec![] });
        assert!(!carol.dir.exists());
        assert_eq!(state().unwrap(), LockState::NotSet);
        std::fs::remove_dir_all(&r).ok();
    }

    #[test]
    fn the_attempt_is_counted_before_the_check() {
        reset();
        let r = root("order");
        set_pin("123456", &r).unwrap();
        lock();
        // What a process killed mid-check leaves: the raised counter.
        let mut b = load().unwrap().unwrap();
        b.fails += 1;
        save(&b).unwrap();
        assert_eq!(unlock("000000", &r).unwrap(), Unlock::Wrong { attempts_left: 8, wait_secs: 0 });
        reset();
        std::fs::remove_dir_all(&r).unwrap();
    }

    #[test]
    fn change_pin_rewraps_and_counts_a_wrong_old_pin() {
        reset();
        let r = root("change");
        let carol = profile(&r, "carol");
        set_pin("123456", &r).unwrap();
        assert!(matches!(change_pin("999999", "abcdefgh", &r).unwrap(), Unlock::Wrong { .. }));
        assert_eq!(change_pin("123456", "abcdefgh", &r).unwrap(), Unlock::Unlocked);
        lock();
        assert!(matches!(unlock("123456", &r).unwrap(), Unlock::Wrong { .. }));
        assert_eq!(unlock("abcdefgh", &r).unwrap(), Unlock::Unlocked);
        assert!(carol.load_keys().is_ok());
        reset();
        std::fs::remove_dir_all(&r).unwrap();
    }

    #[test]
    fn waits_escalate_and_cap() {
        assert_eq!((1..=4).map(wait_after).collect::<Vec<_>>(), vec![0; 4]);
        assert_eq!((5..=11).map(wait_after).collect::<Vec<_>>(), vec![30, 60, 300, 900, 3600, 3600, 3600]);
    }
}
