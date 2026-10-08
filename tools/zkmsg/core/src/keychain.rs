//! The macOS login Keychain, as zkmsg uses it: generic passwords holding
//! small binary values (hex-encoded), by service and account.
//!
//! It is reached through `/usr/bin/security`: an item that tool creates
//! trusts it (an Apple-signed binary), so rebuilding zkmsg (a new code
//! signature each time) never raises an access prompt. Values are added
//! through `security -i` on stdin, never in argv where `ps` would show them.
//!
//! Tests (and `ZKMSG_KEYSTORE=memory`) use an in-process store instead.
//! `ZKMSG_KEYCHAIN_NAMESPACE=<word>` prefixes every service name, so a
//! live end-to-end run can use the real Keychain without touching the
//! user's own items.

use std::collections::HashMap;
use std::sync::Mutex;
#[cfg(not(test))]
use std::sync::OnceLock;

use anyhow::{Context, Result, ensure};

pub trait KeyStore: Send + Sync {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>>;
    /// Creates or replaces, and reads the value back.
    fn put(&self, service: &str, account: &str, value: &[u8]) -> Result<()>;
    /// Deleting an item that is not there is not an error.
    fn delete(&self, service: &str, account: &str) -> Result<()>;
    /// Deletes every item of `service`; returns how many.
    fn delete_all(&self, service: &str) -> Result<usize>;
}

pub struct SecurityCli;

const SECURITY: &str = "/usr/bin/security";
/// `security`'s exit status for "item not found".
const ERR_SEC_ITEM_NOT_FOUND: i32 = 44;
/// `delete_all` stops after this many items (a runaway guard).
const DELETE_ALL_LIMIT: usize = 10_000;

impl KeyStore for SecurityCli {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>> {
        check_token(service)?;
        check_token(account)?;
        let out = std::process::Command::new(SECURITY)
            .args(["find-generic-password", "-s", service, "-a", account, "-w"])
            .output()
            .context("running /usr/bin/security")?;
        if out.status.code() == Some(ERR_SEC_ITEM_NOT_FOUND) {
            return Ok(None);
        }
        ensure!(
            out.status.success(),
            "reading {service}/{account} from the Keychain: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        let value = hex::decode(String::from_utf8_lossy(&out.stdout).trim())
            .with_context(|| format!("{service}/{account} is not hex"))?;
        Ok(Some(value))
    }

    fn put(&self, service: &str, account: &str, value: &[u8]) -> Result<()> {
        use std::io::Write;
        check_token(service)?;
        check_token(account)?;
        // With no default keychain (e.g. HOME pointed elsewhere), `add`
        // raises a system dialog whose "Reset to defaults" button would wipe
        // the real login keychain. Refuse instead.
        let default = std::process::Command::new(SECURITY)
            .arg("default-keychain")
            .output()
            .context("running /usr/bin/security")?;
        ensure!(
            default.status.success(),
            "no default keychain for this user (is HOME set to another directory?): {}",
            String::from_utf8_lossy(&default.stderr).trim()
        );
        let mut child = std::process::Command::new(SECURITY)
            .arg("-i")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("running /usr/bin/security")?;
        let line = format!(
            "add-generic-password -U -s {service} -a {account} -l {service} -w {}\n",
            hex::encode(value)
        );
        child.stdin.take().context("security stdin")?.write_all(line.as_bytes())?;
        let out = child.wait_with_output()?;
        // `security -i` exits 0 whatever its commands did: read it back.
        ensure!(
            self.get(service, account)?.as_deref() == Some(value),
            "storing {service}/{account} in the Keychain failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<()> {
        check_token(service)?;
        check_token(account)?;
        let out = std::process::Command::new(SECURITY)
            .args(["delete-generic-password", "-s", service, "-a", account])
            .output()
            .context("running /usr/bin/security")?;
        ensure!(
            out.status.success() || out.status.code() == Some(ERR_SEC_ITEM_NOT_FOUND),
            "deleting {service}/{account} from the Keychain: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        ensure!(self.get(service, account)?.is_none(), "{service}/{account} is still in the Keychain after delete");
        Ok(())
    }

    fn delete_all(&self, service: &str) -> Result<usize> {
        check_token(service)?;
        // `delete-generic-password -s` removes the first match: repeat
        // until there is none.
        for n in 0..DELETE_ALL_LIMIT {
            let out = std::process::Command::new(SECURITY)
                .args(["delete-generic-password", "-s", service])
                .output()
                .context("running /usr/bin/security")?;
            if out.status.code() == Some(ERR_SEC_ITEM_NOT_FOUND) {
                return Ok(n);
            }
            ensure!(
                out.status.success(),
                "deleting {service} items from the Keychain: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        anyhow::bail!("{service}: more than {DELETE_ALL_LIMIT} Keychain items")
    }
}

/// Items in process memory. Nothing survives the process.
#[derive(Default)]
pub struct MemoryKeyStore(Mutex<HashMap<(String, String), Vec<u8>>>);

impl KeyStore for MemoryKeyStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(&(service.into(), account.into())).cloned())
    }
    fn put(&self, service: &str, account: &str, value: &[u8]) -> Result<()> {
        self.0.lock().unwrap().insert((service.into(), account.into()), value.to_vec());
        Ok(())
    }
    fn delete(&self, service: &str, account: &str) -> Result<()> {
        self.0.lock().unwrap().remove(&(service.to_string(), account.to_string()));
        Ok(())
    }
    fn delete_all(&self, service: &str) -> Result<usize> {
        let mut items = self.0.lock().unwrap();
        let before = items.len();
        items.retain(|(s, _), _| s != service);
        Ok(before - items.len())
    }
}

/// The process's store: memory under test or `ZKMSG_KEYSTORE=memory`, else
/// the login Keychain.
pub fn store() -> &'static dyn KeyStore {
    // Under test each test thread gets its own Keychain, so tests that set
    // an app PIN never lock another test's profiles.
    #[cfg(test)]
    {
        thread_local! {
            static THREAD: &'static MemoryKeyStore = Box::leak(Box::default());
        }
        THREAD.with(|s| *s as &'static dyn KeyStore)
    }
    #[cfg(not(test))]
    store_for_process()
}

#[cfg(not(test))]
fn store_for_process() -> &'static dyn KeyStore {
    static STORE: OnceLock<Box<dyn KeyStore>> = OnceLock::new();
    STORE
        .get_or_init(|| {
            let memory = std::env::var("ZKMSG_KEYSTORE").is_ok_and(|v| v == "memory");
            if memory { Box::<MemoryKeyStore>::default() } else { Box::new(SecurityCli) }
        })
        .as_ref()
}

/// `base` with the `ZKMSG_KEYCHAIN_NAMESPACE` prefix, if one is set.
pub fn service(base: &str) -> String {
    match std::env::var("ZKMSG_KEYCHAIN_NAMESPACE") {
        Ok(ns) if !ns.is_empty() => format!("{ns}.{base}"),
        _ => base.to_string(),
    }
}

/// Services and accounts become `security -i` tokens: letters, digits,
/// `.`, `-` and `_` only, never empty.
pub fn check_token(t: &str) -> Result<()> {
    ensure!(
        !t.is_empty()
            && t.len() <= 128
            && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'),
        "malformed Keychain name {t:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_checked_before_reaching_the_shell() {
        assert!(check_token("zkmsg.profile-key").is_ok());
        assert!(check_token(&"a".repeat(32)).is_ok());
        for bad in ["", "a b", "a\nb", "x -w y", "a\"b", "a;b", &"a".repeat(129)] {
            assert!(check_token(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn memory_store_delete_all_is_per_service() {
        let s = MemoryKeyStore::default();
        s.put("a", "1", b"x").unwrap();
        s.put("a", "2", b"y").unwrap();
        s.put("b", "1", b"z").unwrap();
        assert_eq!(s.delete_all("a").unwrap(), 2);
        assert_eq!(s.get("b", "1").unwrap().as_deref(), Some(&b"z"[..]));
        assert!(s.get("a", "1").unwrap().is_none());
    }
}
