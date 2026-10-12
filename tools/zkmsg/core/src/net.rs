//! Where zkmsg's network traffic goes: straight out, or through Tor.
//!
//! The front end (CLI or GUI) starts Tor (`zkmsg-tor`) and hands this module
//! one proxy URL per role; from then on every HTTP request zkmsg makes
//! goes through the proxy of its role, and so do the subprocesses it starts
//! (the prover, sncast) through `HTTPS_PROXY`. Each role is its own Tor
//! circuit family, so no server or exit sees two roles share a path:
//!
//!   * `Read` — inbox scans, status, the registry and ticket logs;
//!   * `Account` — anything the member's own account signs (register, buy
//!     tickets, account deploy, funding);
//!   * `Prove` — send preparation and the prover's state reads;
//!   * `Publish` — the send's submission and its status polls.
//!
//! Once proxies are set they cannot be unset in this process: a request
//! that silently fell back to a direct connection would undo the point.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Read,
    Account,
    Prove,
    Publish,
}

impl Role {
    /// The name `zkmsg-tor` keys circuit isolation on.
    pub fn name(self) -> &'static str {
        match self {
            Role::Read => "read",
            Role::Account => "account",
            Role::Prove => "prove",
            Role::Publish => "publish",
        }
    }

    const ALL: [Role; 4] = [Role::Read, Role::Account, Role::Prove, Role::Publish];

    fn index(self) -> usize {
        self as usize
    }
}

struct Routing {
    /// Proxy URL per role (`Role::index`), when Tor is on.
    proxies: Option<[String; 4]>,
    agents: [ureq::Agent; 4],
}

static ROUTING: OnceLock<Routing> = OnceLock::new();

fn direct() -> Routing {
    Routing { proxies: None, agents: std::array::from_fn(|_| ureq::AgentBuilder::new().build()) }
}

/// Routes every later request through Tor: `proxy_url(role)` is the proxy
/// for each role. Set once, before any request; refused afterwards.
pub fn use_tor(proxy_url: impl Fn(Role) -> String) -> anyhow::Result<()> {
    let proxies: [String; 4] = std::array::from_fn(|i| proxy_url(Role::ALL[i]));
    let mut agents = Vec::with_capacity(4);
    for url in &proxies {
        agents.push(ureq::AgentBuilder::new().proxy(ureq::Proxy::new(url)?).build());
    }
    let routing = Routing { proxies: Some(proxies), agents: agents.try_into().map_err(|_| anyhow::anyhow!("agents"))? };
    ROUTING
        .set(routing)
        .map_err(|_| anyhow::anyhow!("network routing was already fixed before Tor started"))
}

fn routing() -> &'static Routing {
    ROUTING.get_or_init(direct)
}

/// Whether traffic goes through Tor.
pub fn tor() -> bool {
    routing().proxies.is_some()
}

/// The HTTP client for `role`.
pub fn agent(role: Role) -> &'static ureq::Agent {
    &routing().agents[role.index()]
}

/// Environment for a subprocess that makes `role`'s requests (reqwest-based
/// tools read these). Empty without Tor.
pub fn subprocess_env(role: Role) -> Vec<(&'static str, String)> {
    match &routing().proxies {
        None => vec![],
        Some(p) => {
            let url = p[role.index()].clone();
            vec![
                ("HTTPS_PROXY", url.clone()),
                ("https_proxy", url.clone()),
                ("HTTP_PROXY", url.clone()),
                ("http_proxy", url.clone()),
                ("ALL_PROXY", url),
                ("NO_PROXY", String::new()),
                ("no_proxy", String::new()),
            ]
        }
    }
}

/// Applies `subprocess_env(role)` to a command.
pub fn proxy_command(cmd: &mut std::process::Command, role: Role) {
    for (k, v) in subprocess_env(role) {
        cmd.env(k, v);
    }
}

/// Under the profile root: Arti's state (guards, directory cache).
pub const TOR_DIR: &str = "tor";
/// Under the profile root: this machine's network choice.
pub const SETTINGS_FILE: &str = "network.json";

/// The network choice, for every profile on this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetSettings {
    /// Route all traffic through Tor (`zkmsg-tor`).
    #[serde(default)]
    pub tor: bool,
}

impl NetSettings {
    pub fn load(root: &std::path::Path) -> Self {
        std::fs::read_to_string(root.join(SETTINGS_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, root: &std::path::Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(root)?;
        crate::config::write_atomic(&root.join(SETTINGS_FILE), serde_json::to_string_pretty(self)?.as_bytes(), 0o600)
    }
}
