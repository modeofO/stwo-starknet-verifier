mod app;
mod compose_view;
mod fromline;
mod inbox_view;
mod migrate_view;
mod pair_view;
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
    let native = eframe::NativeOptions::default();
    eframe::run_native(
        "zkmsg",
        native,
        Box::new(move |_cc| {
            Ok(Box::new(app::ZkmsgApp::new(launch_path, profile_override, is_default_home)))
        }),
    )
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
