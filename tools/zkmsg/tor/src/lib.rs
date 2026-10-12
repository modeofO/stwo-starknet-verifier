//! Tor for zkmsg, embedded (Arti), behind a local HTTP CONNECT proxy.
//!
//! Why a proxy and not a Rust API: three different HTTP stacks must use Tor
//! — zkmsg's own `ureq` calls, the prover (`snip36-prove`, reqwest, a
//! subprocess) and sncast (a subprocess) — and every one of them speaks to
//! an HTTP CONNECT proxy without extra features (`ureq::Proxy`, and
//! reqwest's `HTTPS_PROXY` environment variable). The iPhone's URLSession
//! does too (`ProxyConfiguration(httpCONNECTProxy:)`).
//!
//! The proxy:
//!   * listens on 127.0.0.1 on a random port, and answers only requests that
//!     carry this process's random secret (`Proxy-Authorization`), so no other
//!     local program can borrow the circuits;
//!   * CONNECTs only to port 443, by host NAME: the exit resolves it, so no DNS
//!     query leaves this machine;
//!   * keeps one circuit family per proxy user name ("read", "account",
//!     "prove", "publish"): streams of different roles never share a circuit,
//!     so an exit or a server sees no link between them.
//!
//! Arti's state (guards, directory cache) lives in the directory `start` is
//! given; the panic wipe removes it.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{IsolationToken, StreamPrefs, TorClient};
use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tor_rtcompat::PreferredRuntime;

/// Roles: one circuit family each. A user name outside this list is refused.
pub const ROLES: [&str; 4] = ["read", "account", "prove", "publish"];

const MAX_HEAD: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Bootstrapping,
    Ready,
    Failed(String),
}

struct Shared {
    status: Mutex<Status>,
    /// One isolation token per role, made on first use.
    isolation: Mutex<HashMap<String, IsolationToken>>,
}

/// A running Tor client and its proxy. Dropping it does not stop the
/// background thread: it lives as long as the process (a send in flight
/// must not lose its circuit).
pub struct Tor {
    port: u16,
    secret: String,
    shared: Arc<Shared>,
}

impl Tor {
    /// Starts Arti with its state under `dir` and the proxy on a random local
    /// port. Returns at once; Tor bootstraps in the background
    /// (`wait_ready`), and a connection made before then waits for it.
    pub fn start(dir: &Path) -> Result<Tor> {
        let state = dir.join("state");
        let cache = dir.join("cache");
        std::fs::create_dir_all(&state).with_context(|| format!("creating {}", state.display()))?;
        std::fs::create_dir_all(&cache).with_context(|| format!("creating {}", cache.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let config = TorClientConfigBuilder::from_directories(&state, &cache)
            .build()
            .context("Tor configuration")?;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").context("binding the Tor proxy")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let mut secret = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let secret = hex::encode(secret);
        let shared = Arc::new(Shared { status: Mutex::new(Status::Bootstrapping), isolation: Mutex::new(HashMap::new()) });

        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
        let thread_shared = shared.clone();
        let thread_secret = secret.clone();
        std::thread::Builder::new()
            .name("zkmsg-tor".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.into()));
                        return;
                    }
                };
                rt.block_on(async move {
                    let client = match TorClient::with_runtime(PreferredRuntime::current().expect("tokio runtime"))
                        .config(config)
                        .create_unbootstrapped()
                    {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = ready_tx.send(Err(anyhow::anyhow!("starting Tor: {e}")));
                            return;
                        }
                    };
                    let listener = match TcpListener::from_std(listener) {
                        Ok(l) => l,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e.into()));
                            return;
                        }
                    };
                    let _ = ready_tx.send(Ok(()));
                    let boot_client = client.clone();
                    let boot_shared = thread_shared.clone();
                    tokio::spawn(async move {
                        let status = match boot_client.bootstrap().await {
                            Ok(()) => Status::Ready,
                            Err(e) => Status::Failed(e.to_string()),
                        };
                        *boot_shared.status.lock().unwrap() = status;
                    });
                    loop {
                        let Ok((stream, _)) = listener.accept().await else { continue };
                        let client = client.clone();
                        let shared = thread_shared.clone();
                        let secret = thread_secret.clone();
                        tokio::spawn(async move {
                            let _ = serve(stream, client, shared, secret).await;
                        });
                    }
                });
            })
            .context("starting the Tor thread")?;
        ready_rx.recv().context("the Tor thread died")??;
        Ok(Tor { port, secret, shared })
    }

    pub fn status(&self) -> Status {
        self.shared.status.lock().unwrap().clone()
    }

    /// Waits until Tor has bootstrapped (or failed, or `timeout` passed).
    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            match self.status() {
                Status::Ready => return Ok(()),
                Status::Failed(e) => bail!("Tor failed to start: {e}"),
                Status::Bootstrapping if start.elapsed() > timeout => {
                    bail!("Tor is still connecting after {} s", timeout.as_secs())
                }
                Status::Bootstrapping => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }

    /// The proxy URL for `role` (one of `ROLES`), with credentials, for
    /// `ureq::Proxy::new` or an `HTTPS_PROXY` environment variable.
    pub fn proxy_url(&self, role: &str) -> String {
        assert!(ROLES.contains(&role), "unknown Tor role {role}");
        format!("http://{role}:{}@127.0.0.1:{}", self.secret, self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// One proxy connection: authenticate, CONNECT host:443 through Tor on the
/// role's circuit family, then relay bytes.
async fn serve(mut local: TcpStream, client: Arc<TorClient<PreferredRuntime>>, shared: Arc<Shared>, secret: String) -> Result<()> {
    let head = read_head(&mut local).await?;
    let request = match parse_connect(&head, &secret) {
        Ok(r) => r,
        Err(Refusal { status, reason }) => {
            let extra = if status == 407 { "Proxy-Authenticate: Basic realm=\"zkmsg\"\r\n" } else { "" };
            let reply = format!("HTTP/1.1 {status} {reason}\r\n{extra}Content-Length: 0\r\n\r\n");
            local.write_all(reply.as_bytes()).await?;
            return Ok(());
        }
    };
    let token = {
        let mut map = shared.isolation.lock().unwrap();
        *map.entry(request.role.clone()).or_insert_with(IsolationToken::new)
    };
    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(token);
    let mut remote = match client.connect_with_prefs((request.host.as_str(), request.port), &prefs).await {
        Ok(s) => s,
        Err(e) => {
            let reply = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            local.write_all(reply.as_bytes()).await?;
            bail!("Tor connect to {}:{}: {e}", request.host, request.port);
        }
    };
    local.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    Ok(())
}

async fn read_head(local: &mut TcpStream) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(head.len() < MAX_HEAD, "proxy request head too long");
        let n = tokio::time::timeout(Duration::from_secs(10), local.read(&mut byte)).await??;
        anyhow::ensure!(n == 1, "proxy client closed early");
        head.push(byte[0]);
    }
    Ok(head)
}

#[derive(Debug, PartialEq, Eq)]
struct Connect {
    host: String,
    port: u16,
    role: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    status: u16,
    reason: &'static str,
}

fn refuse(status: u16, reason: &'static str) -> Refusal {
    Refusal { status, reason }
}

/// Parses a CONNECT request head and checks its credentials.
fn parse_connect(head: &[u8], secret: &str) -> std::result::Result<Connect, Refusal> {
    let text = std::str::from_utf8(head).map_err(|_| refuse(400, "Bad Request"))?;
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(_version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(refuse(400, "Bad Request"));
    };
    if method != "CONNECT" {
        return Err(refuse(405, "Method Not Allowed"));
    }
    let mut role = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let value = value.trim();
        let Some(b64) = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic ")) else { continue };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else { continue };
        let Ok(decoded) = String::from_utf8(decoded) else { continue };
        let Some((user, pass)) = decoded.split_once(':') else { continue };
        if constant_time_eq(pass.as_bytes(), secret.as_bytes()) && ROLES.contains(&user) {
            role = Some(user.to_string());
        }
    }
    let role = role.ok_or(refuse(407, "Proxy Authentication Required"))?;
    let (host, port) = target.rsplit_once(':').ok_or(refuse(400, "Bad Request"))?;
    let port: u16 = port.parse().map_err(|_| refuse(400, "Bad Request"))?;
    if port != 443 {
        return Err(refuse(403, "Forbidden"));
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return Err(refuse(400, "Bad Request"));
    }
    Ok(Connect { host: host.to_string(), port, role })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(target: &str, auth: Option<(&str, &str)>) -> Vec<u8> {
        let mut h = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some((u, p)) = auth {
            let b = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            h.push_str(&format!("Proxy-Authorization: Basic {b}\r\n"));
        }
        h.push_str("\r\n");
        h.into_bytes()
    }

    #[test]
    fn connect_parsing_and_checks() {
        let s = "s3cret";
        assert_eq!(
            parse_connect(&head("api.zan.top:443", Some(("read", s))), s),
            Ok(Connect { host: "api.zan.top".into(), port: 443, role: "read".into() })
        );
        assert_eq!(parse_connect(&head("api.zan.top:443", None), s).unwrap_err().status, 407);
        assert_eq!(parse_connect(&head("api.zan.top:443", Some(("read", "wrong"))), s).unwrap_err().status, 407);
        assert_eq!(parse_connect(&head("api.zan.top:443", Some(("nobody", s))), s).unwrap_err().status, 407);
        assert_eq!(parse_connect(&head("api.zan.top:80", Some(("read", s))), s).unwrap_err().status, 403);
        assert_eq!(parse_connect(&head("a b:443", Some(("read", s))), s).unwrap_err().status, 400);
        assert_eq!(parse_connect(b"GET / HTTP/1.1\r\n\r\n", s).unwrap_err().status, 405);
    }
}
