//! `zkmsgd` — the zkmsg companion daemon. It holds the sender identity and
//! the funded account; a phone on the same private network composes and
//! monitors sends over HTTP. See docs/companion-protocol.md.
//!
//! Bind private (default 127.0.0.1; a Tailscale interface for a phone).
//! Every request needs the bearer token printed once at first start.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};

use zkmsg_core::config::Home;
use zkmsg_daemon::auth::{load_or_create_token, token_path};
use zkmsg_daemon::reads::LiveReads;
use zkmsg_daemon::runner::PipelineRunner;
use zkmsg_daemon::server::{self, AppState};

/// Where the daemon listens by default: loopback only. Point it at a private
/// interface (Tailscale/LAN) with `--addr` to let a phone reach it.
const DEFAULT_ADDR: &str = "127.0.0.1:8787";

struct Args {
    addr: String,
    home: PathBuf,
}

fn parse_args() -> Result<Args> {
    let mut addr = std::env::var("ZKMSG_DAEMON_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let mut home: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => addr = args.next().context("--addr needs a value")?,
            "--home" => home = Some(PathBuf::from(args.next().context("--home needs a value")?)),
            "-h" | "--help" => {
                println!(
                    "zkmsgd — zkmsg companion daemon\n\n\
                     USAGE:\n  zkmsgd [--addr HOST:PORT] [--home DIR]\n\n\
                     Defaults: --addr {DEFAULT_ADDR}, --home ~/.zkmsg (its current profile).\n\
                     Env: ZKMSG_DAEMON_ADDR overrides --addr.\n"
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other} (try --help)"),
        }
    }

    let home = match home {
        Some(h) => h,
        None => {
            let base = std::env::var("HOME").context("HOME not set")?;
            PathBuf::from(base).join(".zkmsg")
        }
    };
    Ok(Args { addr, home })
}

fn main() -> Result<()> {
    let args = parse_args()?;

    // Resolve a profile root to its current profile, exactly like the CLI, so
    // the daemon speaks for the same identity `zkmsg` does.
    let dir = zkmsg_core::profiles::resolve_cli_home(&args.home)?;
    let home = Home::new(dir);
    let config = home.load_config().context("load config.json — run `zkmsg init` first")?;

    let (token, created) = load_or_create_token(&home.dir)?;

    let runner = Arc::new(PipelineRunner);
    let reads = Arc::new(LiveReads::new(config.clone()));
    let app = Arc::new(AppState::new(home, config, token.clone(), runner, reads));

    // Populate the send list from disk so a restart lists and resumes prior sends.
    server::load_existing_sends(&app);

    let server = tiny_http::Server::http(&args.addr)
        .map_err(|e| anyhow::anyhow!("bind {}: {e}", args.addr))?;

    print_startup(&args.addr, &token, created, &token_path(&app.home.dir).display().to_string());

    // Thread per request: an SSE stream holds its thread for the life of the
    // stream, so a fixed pool would starve. Pipeline RUNS are still serialized
    // by the run_lock inside `spawn_run`.
    for request in server.incoming_requests() {
        let app = Arc::clone(&app);
        std::thread::spawn(move || {
            if let Err(e) = server::dispatch(&app, request) {
                eprintln!("request error: {e}");
            }
        });
    }
    Ok(())
}

fn print_startup(addr: &str, token: &str, created: bool, token_file: &str) {
    println!("zkmsgd listening on http://{addr}/v1");
    // The pairing base URL is the host root. The client owns the /v1 prefix, so
    // a base URL that already ends in /v1 would double it.
    if created {
        println!("\n  PAIRING (shown once)");
        println!("  base URL : http://{addr}");
        println!("  token    : {token}");
        println!("  Enter both on the phone to pair. The token is stored at {token_file} (0600).");
    } else {
        println!("  token: reusing {token_file} (delete it and restart to re-pair)");
    }
    println!("\n  Bind is private by default (loopback). For a phone, pass --addr <tailscale-ip>:8787.");
    println!("  The witness never leaves this host; the phone only composes and monitors.\n");
}
