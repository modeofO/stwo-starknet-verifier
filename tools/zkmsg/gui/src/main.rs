mod app;
mod compose_view;
mod inbox_view;
mod send_flow;
mod worker;

use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    let home_dir = parse_home_arg().unwrap_or_else(default_home);
    let home = zkmsg_core::config::Home::new(home_dir);
    let native = eframe::NativeOptions::default();
    eframe::run_native(
        "zkmsg",
        native,
        Box::new(|_cc| Ok(Box::new(app::ZkmsgApp::new(home)))),
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
