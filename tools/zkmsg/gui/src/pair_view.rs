//! The Pair tab: a convenience around the daemon for pairing a phone without
//! a camera or hand-typing. It reads the daemon's bearer token from the active
//! profile home (`<home>/daemon-token`), builds the same `zkmsg://pair` URI the
//! daemon prints, and offers to copy it or write a `.zkmsgpair` file (0600) the
//! user AirDrops. The daemon remains the source of truth; this only emits.

use eframe::egui;

use zkmsg_daemon::auth::token_path;
use zkmsg_daemon::pair::{pairing_uri, write_pair_file};

use crate::session::ProfileSession;

/// The daemon's default listen port (mirrors `zkmsgd`'s `DEFAULT_ADDR`). A
/// phone reaches the daemon on this port over the LAN or a tailnet.
const DEFAULT_PORT: u16 = 8787;

/// The pairing address the field starts on: the machine's primary LAN IP with
/// the default port, so a phone can reach it out of the box; the loopback
/// default if no LAN IP is found (the user then edits it). Loopback pairs only
/// a simulator on the same host — the field hint says so.
pub(crate) fn default_pair_addr() -> String {
    let ip = lan_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    format!("{ip}:{DEFAULT_PORT}")
}

/// The primary LAN IPv4 address, or `None`. It opens a UDP socket and asks the
/// OS which local address routes toward a public host; no packet is sent
/// (`connect` on UDP only sets the default peer). This picks the interface the
/// machine would use to reach the network, which is what a phone needs.
fn lan_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() {
        return None;
    }
    Some(ip.to_string())
}

impl ProfileSession {
    /// Renders the Pair tab. Reads the token, shows the current pairing URI,
    /// and offers Copy / Save. With no token it explains how to mint one.
    pub(crate) fn pair_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Pair a phone");
        ui.label(
            "The phone drives sends over the companion daemon. Start the daemon, then copy this \
             link or save the file and open it on the phone — no camera, no typing.",
        );
        ui.separator();

        // The address is confirmed first: it is both the daemon's `--addr` bind
        // and what the pairing URI points the phone at, so it must be right
        // before either Start or Copy/Save.
        ui.horizontal(|ui| {
            ui.label("daemon address (host:port):");
            ui.text_edit_singleline(&mut self.pair_addr);
        });
        ui.label(
            egui::RichText::new(
                "Use the desktop's LAN or Tailscale address — the one the daemon binds with \
                 --addr. Loopback (127.0.0.1) pairs only a simulator on this machine.",
            )
            .weak(),
        );

        // Own the trimmed address + home so the daemon controls and the
        // Copy/Save closures can each hold `&mut self` (for `self.daemon` and
        // `self.pair_saved`) without a live borrow of `self.pair_addr`.
        let addr = self.pair_addr.trim().to_string();
        let home = self.home_dir();

        // Daemon Start/Stop + live status. The user presses Start — nothing
        // auto-starts. Only `&mut self.daemon` is borrowed here.
        ui.separator();
        self.daemon.ui(ui, &addr, &home);

        // The pairing section needs the bearer token, minted by the daemon on
        // its first start. Re-read each frame so it appears the moment the
        // freshly started daemon writes it.
        ui.separator();
        let Some(token) = load_token(&home) else {
            ui.label("No daemon token yet — start the daemon above to mint it.");
            return;
        };

        if addr.is_empty() {
            ui.colored_label(egui::Color32::RED, "enter the daemon address to build a link");
            return;
        }
        let uri = pairing_uri(&addr, &token);
        let save_path = home.join("pair.zkmsgpair");

        ui.separator();
        ui.label("pairing link:");
        // Selectable so the user can also copy by hand; wraps rather than
        // overflowing the panel width.
        ui.add(egui::Label::new(egui::RichText::new(&uri).monospace()).wrap());

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("Copy pairing link").clicked() {
                ui.ctx().copy_text(uri.clone());
            }
            if ui.button("Save pairing file…").clicked() {
                self.pair_saved = Some(
                    write_pair_file(&save_path, &addr, &token)
                        .map(|()| save_path.clone())
                        .map_err(|e| e.to_string()),
                );
            }
        });

        match &self.pair_saved {
            Some(Ok(path)) => {
                ui.colored_label(
                    egui::Color32::from_rgb(0x2e, 0x7d, 0x32),
                    format!("saved {} (0600) — AirDrop it to the phone", path.display()),
                );
            }
            Some(Err(e)) => {
                ui.colored_label(egui::Color32::RED, format!("save failed: {e}"));
            }
            None => {}
        }
    }
}

/// Reads the daemon bearer token from `<home>/daemon-token`, trimmed. `None`
/// when the file is absent or empty (the daemon has not started yet).
fn load_token(home_dir: &std::path::Path) -> Option<String> {
    let raw = std::fs::read_to_string(token_path(home_dir)).ok()?;
    let token = raw.trim().to_string();
    (!token.is_empty()).then_some(token)
}
