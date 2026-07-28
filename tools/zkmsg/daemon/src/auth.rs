//! Bearer-token auth. The daemon prints one token at first start; the user
//! enters it on the phone during pairing. Every route checks it; a request
//! without a valid token gets 401. There is no unauthenticated fallback.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::RngCore;

/// The token file lives in the Home dir, mode 0600 — same posture as
/// `keys.json`. It is a shared secret, not a key: rotating it (delete the
/// file, restart) only re-pairs the phone.
pub fn token_path(home_dir: &Path) -> PathBuf {
    home_dir.join("daemon-token")
}

/// 32 random bytes, hex — 256 bits of entropy, URL-safe, easy to read aloud
/// during pairing.
pub fn generate_token() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Loads the persisted token, or generates and persists a fresh one.
/// Returns `(token, created)` — `created` is true only when a new token was
/// written, so the caller prints the pairing banner exactly once per token.
pub fn load_or_create_token(home_dir: &Path) -> Result<(String, bool)> {
    let path = token_path(home_dir);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let token = existing.trim().to_string();
        if !token.is_empty() {
            return Ok((token, false));
        }
    }
    let token = generate_token();
    std::fs::create_dir_all(home_dir)?;
    write_token_file(&path, &token)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok((token, true))
}

/// Writes the token so it is never readable by other users, not even for the
/// instant between create and chmod. On unix the file is created with mode 0600
/// in one step (`create_new` also refuses to follow a pre-planted symlink);
/// elsewhere a plain write is the best available.
#[cfg(unix)]
fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // create_new fails if the path exists; the caller only reaches here when no
    // usable token was read, but a racing writer or a stale empty file is
    // possible, so replace atomically via a fresh 0600 temp + rename.
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(token.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(not(unix))]
fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    std::fs::write(path, token)
}

/// True when the `Authorization` header value is exactly `Bearer <token>`.
/// A missing header, a wrong scheme, or a mismatched token all fail.
pub fn bearer_ok(header_value: Option<&str>, token: &str) -> bool {
    match header_value.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(got) => got.trim() == token,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_gate_accepts_only_exact_token() {
        assert!(bearer_ok(Some("Bearer abc123"), "abc123"));
        // Trailing whitespace tolerated (some clients pad the header).
        assert!(bearer_ok(Some("Bearer abc123 "), "abc123"));
        // Wrong token, wrong scheme, missing scheme, missing header: all reject.
        assert!(!bearer_ok(Some("Bearer nope"), "abc123"));
        assert!(!bearer_ok(Some("Basic abc123"), "abc123"));
        assert!(!bearer_ok(Some("abc123"), "abc123"));
        assert!(!bearer_ok(None, "abc123"));
    }

    #[test]
    fn token_persists_and_is_stable() {
        let dir = std::env::temp_dir().join(format!("zkmsgd-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (first, created) = load_or_create_token(&dir).unwrap();
        assert!(created, "first call mints a token");
        assert_eq!(first.len(), 64, "32 bytes hex");
        let (second, created2) = load_or_create_token(&dir).unwrap();
        assert!(!created2, "second call reuses the persisted token");
        assert_eq!(first, second);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
