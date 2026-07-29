//! Pairing emit. The desktop hands the phone a companion base URL and a
//! bearer token without a camera or hand-typing. Both carriers hold the same
//! one-line URI: the copyable `zkmsg://pair` string (printed at startup, or
//! copied from the GUI) and the `.zkmsgpair` file (the user AirDrops it).
//!
//! The phone's client owns the `/v1` prefix, so the base URL in the URI is the
//! host root — `http://<addr>`, NEVER `http://<addr>/v1`. A base URL that
//! already ends in `/v1` would double the prefix on the phone.

use std::path::Path;

/// Percent-encodes `input` for use as a URI query-parameter value. It keeps
/// only the RFC 3986 unreserved characters (`A-Z`, `a-z`, `0-9`, `-`, `.`,
/// `_`, `~`) and encodes every other byte as `%XX` (upper-case hex). So a base
/// URL like `http://192.168.1.196:8787` becomes
/// `http%3A%2F%2F192.168.1.196%3A8787`: the `.` and the digits stay, the `:`
/// and the `/` are encoded.
pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(upper_hex(b >> 4));
            out.push(upper_hex(b & 0x0f));
        }
    }
    out
}

/// One hex digit (0..=15) as an upper-case ASCII char.
fn upper_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

/// Builds the pairing URI `zkmsg://pair?url=<enc>&token=<token>`. `addr` is the
/// daemon's listen address (`host:port`); the base URL is `http://<addr>` — the
/// host root, without the `/v1` prefix the phone adds. The `url` value is
/// percent-encoded; the token is hex from `auth::generate_token`, so it needs
/// no encoding and is appended as is.
pub fn pairing_uri(addr: &str, token: &str) -> String {
    let base = format!("http://{addr}");
    format!("zkmsg://pair?url={}&token={}", percent_encode(&base), token)
}

/// Writes the pairing file at `path`: exactly the pairing URI plus a trailing
/// newline, mode 0600. It carries the bearer token, so it gets the same care
/// as the token file — the atomic 0600 write from `auth`.
pub fn write_pair_file(path: &Path, addr: &str, token: &str) -> std::io::Result<()> {
    let mut contents = pairing_uri(addr, token).into_bytes();
    contents.push(b'\n');
    crate::auth::write_private_file(path, &contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_keeps_unreserved_and_encodes_the_rest() {
        // Unreserved characters pass through untouched.
        assert_eq!(percent_encode("aZ0-._~"), "aZ0-._~");
        // The reserved characters in a base URL are encoded, upper-case hex.
        assert_eq!(percent_encode("http://h:8787"), "http%3A%2F%2Fh%3A8787");
        // A space is %20, not `+`.
        assert_eq!(percent_encode("a b"), "a%20b");
    }

    #[test]
    fn pairing_uri_pins_the_exact_string() {
        // A known addr + token produces this exact URI. The Swift side parses
        // it, so the shape is a contract: `zkmsg://pair?url=<enc>&token=<hex>`,
        // the url value the host root (no `/v1`) with `:` and `/` encoded.
        let uri = pairing_uri("192.168.1.196:8787", "f0a866aa");
        assert_eq!(
            uri,
            "zkmsg://pair?url=http%3A%2F%2F192.168.1.196%3A8787&token=f0a866aa"
        );
    }

    #[test]
    fn pairing_uri_base_is_host_root_not_v1() {
        let uri = pairing_uri("127.0.0.1:8787", "deadbeef");
        assert!(uri.contains("url=http%3A%2F%2F127.0.0.1%3A8787&"));
        // The daemon listens on /v1, but the paired base URL must NOT carry it.
        assert!(!uri.contains("v1"));
    }

    #[test]
    fn write_pair_file_round_trips_the_uri_with_newline() {
        let dir = std::env::temp_dir().join(format!("zkmsgd-pair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.zkmsgpair");

        write_pair_file(&path, "10.0.0.5:8787", "abcd1234").unwrap();

        let got = std::fs::read_to_string(&path).unwrap();
        let want = format!("{}\n", pairing_uri("10.0.0.5:8787", "abcd1234"));
        assert_eq!(got, want, "file is the URI plus one trailing newline");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "pairing file must be 0600 — it holds the token");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
