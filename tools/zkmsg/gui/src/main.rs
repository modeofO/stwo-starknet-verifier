mod app;
mod compose_view;
mod delete_view;
mod inbox_view;
mod lock_view;
mod migrate_view;
mod retire_view;
mod send_flow;
mod session;
mod setup_flow;
mod wizard_view;
mod worker;

use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    // Raw launch path + profile override; classification (profile vs.
    // profile-root) happens inside `ZkmsgApp::new`. An explicit `--home`
    // suppresses the one-time migration screen — only the default home is
    // scanned for legacy layouts.
    let (launch_path, is_default_home) = match parse_home_arg() {
        Some(path) => (path, false),
        None => (default_home(), true),
    };
    let profile_override = parse_profile_arg();
    let tor = start_tor(&launch_path);
    let native = eframe::NativeOptions::default();
    eframe::run_native(
        "zkmsg",
        native,
        Box::new(move |_cc| {
            Ok(Box::new(app::ZkmsgApp::new(launch_path, profile_override, is_default_home, tor)))
        }),
    )
}

/// With Tor on (`network.json` under the profile root), starts it before
/// anything else and routes every request through it. Tor bootstraps in the
/// background while the lock screen is up; a request made before it is ready
/// waits for it. If Tor cannot start, the app still opens, and the error is
/// shown, but nothing goes out directly: routing is fixed to the proxy.
fn start_tor(launch_path: &std::path::Path) -> app::TorState {
    use zkmsg_core::net::{self, NetSettings};
    let root = zkmsg_core::profiles::profile_root(launch_path);
    if !NetSettings::load(&root).tor {
        return app::TorState::Off;
    }
    match zkmsg_tor::Tor::start(&root.join(net::TOR_DIR)) {
        Ok(tor) => match net::use_tor(|role| tor.proxy_url(role.name())) {
            Ok(()) => app::TorState::On(tor),
            Err(e) => app::TorState::Failed(format!("{e:#}")),
        },
        Err(e) => {
            // Fail closed: route to a proxy that does not exist rather than
            // fall back to direct connections.
            let _ = net::use_tor(|_| "http://unavailable:x@127.0.0.1:9".to_string());
            app::TorState::Failed(format!("{e:#}"))
        }
    }
}

fn default_home() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".zkmsg")
}

/// `--home <path>`, matching the CLI's global flag (cli/src/main.rs).
fn parse_home_arg() -> Option<PathBuf> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == "--home" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

/// `--profile <name>`, selecting the `.zkmsg-<name>` dir under the launch path.
fn parse_profile_arg() -> Option<String> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == "--profile" {
            return args.next();
        }
    }
    None
}
