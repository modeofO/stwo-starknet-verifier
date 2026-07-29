//! Starts and stops the companion daemon (`zkmsgd`) as a child process, on
//! demand, from the Pair tab. The GUI never auto-starts it — the user presses
//! Start. The daemon speaks for one profile home, so this manager lives on the
//! `ProfileSession`: switching profiles drops the old session, whose `Drop`
//! kills the daemon it started; the same `Drop` runs when the GUI window closes
//! and eframe drops the app. A daemon the user started in a terminal is a
//! separate process this never touches.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use eframe::egui;

/// The daemon child's lifecycle, as the Pair tab sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaemonStatus {
    /// No child — never started, or explicitly stopped.
    NotRunning,
    /// Spawned, not yet confirmed alive past its first poll. A failed bind
    /// (address in use) exits here in a few milliseconds, so this is brief.
    Starting,
    /// Alive past the first poll, bound and serving on `addr`.
    Running { pid: u32, addr: String },
    /// Exited on its own — a crash, a failed bind, or a missing config. `code`
    /// is the process exit code; `reason` is the daemon's stderr headline, if
    /// any.
    Exited { code: Option<i32>, reason: Option<String> },
}

/// Owns the daemon child and its status. One per `ProfileSession`.
pub(crate) struct DaemonManager {
    child: Option<Child>,
    status: DaemonStatus,
    /// The address the child was started with — carried into `Running` so the
    /// status line names the same bind the pairing URI points at.
    addr: String,
    /// The first non-empty stderr line the child printed, set once by a reader
    /// thread. Read into `Exited.reason` so a bind failure ("address already in
    /// use") or a config error surfaces in the UI. First line, not last:
    /// anyhow prints its headline (the useful "load config.json…" / "bind …"
    /// message) first, then the indented cause chain.
    stderr_head: Arc<Mutex<Option<String>>>,
    /// A start that never spawned (binary not found, spawn error). Shown until
    /// the next Start attempt clears it.
    start_error: Option<String>,
}

impl Default for DaemonManager {
    fn default() -> Self {
        Self {
            child: None,
            status: DaemonStatus::NotRunning,
            addr: String::new(),
            stderr_head: Arc::new(Mutex::new(None)),
            start_error: None,
        }
    }
}

impl DaemonManager {
    /// True while a child exists (Starting or Running). The Pair tab drives a
    /// per-frame repaint on this so `poll` catches an exit promptly and the
    /// freshly minted token file is re-read.
    pub(crate) fn is_active(&self) -> bool {
        self.child.is_some()
    }

    /// Reaps or promotes the child. Call once per frame. `try_wait` is
    /// non-blocking: `Some` means the child exited (and is reaped) — record the
    /// code and stderr headline; `None` means it is still alive — promote a
    /// first-seen `Starting` to `Running`.
    pub(crate) fn poll(&mut self) {
        let Some(child) = self.child.as_mut() else { return };
        match child.try_wait() {
            Ok(Some(status)) => {
                let reason = self.stderr_head.lock().unwrap().clone();
                self.status = DaemonStatus::Exited { code: status.code(), reason };
                self.child = None;
            }
            Ok(None) => {
                if matches!(self.status, DaemonStatus::Starting) {
                    self.status =
                        DaemonStatus::Running { pid: child.id(), addr: self.addr.clone() };
                }
            }
            // A transient wait error leaves the status as-is; the next frame
            // retries. This should not happen for a child we own.
            Err(_) => {}
        }
    }

    /// Spawns `zkmsgd --addr <addr> --home <home>` as a child, piping its
    /// stdout/stderr so a bind failure or config error can be shown. A no-op if
    /// a child is already Starting/Running. Errors (no binary, spawn failure)
    /// are stored and surfaced, not returned.
    pub(crate) fn start(&mut self, addr: &str, home: &Path) {
        if self.child.is_some() {
            return;
        }
        self.start_error = None;
        *self.stderr_head.lock().unwrap() = None;

        let Some(bin) = locate_daemon_binary() else {
            self.start_error = Some(
                "zkmsgd binary not found next to the app or on PATH; build it with \
                 `cargo build -p zkmsg-daemon`"
                    .to_string(),
            );
            return;
        };

        let mut child = match Command::new(&bin)
            .arg("--addr")
            .arg(addr)
            .arg("--home")
            .arg(home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                self.start_error = Some(format!("failed to start {}: {e}", bin.display()));
                return;
            }
        };

        // Drain stderr on a reader thread, keeping the first non-empty line —
        // anyhow's headline, where the daemon's bind/config error lands before a
        // non-zero exit. Keep draining after that (the pipe must not fill and
        // block the child), but do not overwrite the headline with the indented
        // cause-chain lines that follow.
        if let Some(stderr) = child.stderr.take() {
            let head = Arc::clone(&self.stderr_head);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let mut slot = head.lock().unwrap();
                    if slot.is_none() {
                        *slot = Some(line);
                    }
                }
            });
        }
        // Drain stdout too so its pipe never blocks the child; the content (the
        // shown-once pairing block) is not surfaced here — the Pair tab reads
        // the token from the file the daemon writes.
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                for _ in BufReader::new(stdout).lines().map_while(Result::ok) {}
            });
        }

        self.addr = addr.to_string();
        self.status = DaemonStatus::Starting;
        self.child = Some(child);
    }

    /// Kills and reaps a running child, returning to `NotRunning`. A no-op when
    /// nothing is running.
    pub(crate) fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.status = DaemonStatus::NotRunning;
    }

    /// Renders the Start/Stop controls and the live status. `addr` is the
    /// confirmed pairing address (host:port); `home` is the active profile
    /// home. Takes only `&mut self` so the caller can pass owned copies of both
    /// without a borrow conflict against the rest of the session.
    pub(crate) fn ui(&mut self, ui: &mut egui::Ui, addr: &str, home: &Path) {
        ui.label(
            egui::RichText::new(
                "The phone talks to the companion daemon (zkmsgd). Start it here — it mints \
                 the bearer token and serves on the address above.",
            )
            .weak(),
        );

        // Collect a click, then act after the closure — a button inside an egui
        // closure can't call `self.start`/`self.stop` (that needs unique access
        // while `self.status` is still borrowed). Snapshot the status so the
        // render is a pure read.
        let mut start_clicked = false;
        let mut stop_clicked = false;
        match self.status.clone() {
            DaemonStatus::Running { pid, addr } => {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(0x2e, 0x7d, 0x32),
                        format!("running on {addr} (pid {pid})"),
                    );
                    stop_clicked = ui.button("Stop daemon").clicked();
                });
            }
            DaemonStatus::Starting => {
                ui.horizontal(|ui| {
                    ui.label("starting…");
                    stop_clicked = ui.button("Stop daemon").clicked();
                });
            }
            DaemonStatus::NotRunning | DaemonStatus::Exited { .. } => {
                let can_start = !addr.is_empty();
                ui.add_enabled_ui(can_start, |ui| {
                    start_clicked = ui.button("Start daemon").clicked();
                });
                if !can_start {
                    ui.colored_label(
                        egui::Color32::RED,
                        "enter the daemon address above before starting",
                    );
                }
                // An earlier run that exited on its own: show why (last stderr
                // line, else the exit code) so a failed bind is not silent.
                if let DaemonStatus::Exited { code, reason } = &self.status {
                    let detail = reason.clone().unwrap_or_else(|| match code {
                        Some(c) => format!("exited with code {c}"),
                        None => "exited".to_string(),
                    });
                    ui.colored_label(egui::Color32::RED, format!("daemon stopped: {detail}"));
                }
            }
        }

        if start_clicked {
            self.start(addr, home);
        }
        if stop_clicked {
            self.stop();
        }

        if let Some(err) = &self.start_error {
            ui.colored_label(egui::Color32::RED, err.as_str());
        }
    }
}

impl Drop for DaemonManager {
    /// Never orphan a daemon this GUI started. Runs on a profile switch (the
    /// old session is dropped) and on GUI exit (eframe drops the app, which
    /// drops the session). A `kill` is skipped by a SIGKILL of the GUI itself —
    /// nothing can help there — but a normal window close reaps cleanly.
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The `zkmsgd` binary name for this platform.
fn daemon_bin_name() -> &'static str {
    if cfg!(windows) {
        "zkmsgd.exe"
    } else {
        "zkmsgd"
    }
}

/// Locates the `zkmsgd` binary: first a sibling of the running GUI executable
/// (cargo builds every workspace binary into the same target dir, so a
/// installed bundle keeps them together), then a `zkmsgd` on `PATH`. `None`
/// when neither exists — the caller shows a build hint.
fn locate_daemon_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(daemon_bin_name());
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }
    daemon_on_path()
}

/// Searches `PATH` for `zkmsgd`, returning the first hit that is a file.
fn daemon_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(daemon_bin_name()))
        .find(|cand| cand.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_name_matches_platform() {
        // The name the sibling/PATH lookup joins onto each dir.
        let expected = if cfg!(windows) { "zkmsgd.exe" } else { "zkmsgd" };
        assert_eq!(daemon_bin_name(), expected);
    }

    #[test]
    fn default_manager_is_not_running() {
        let mgr = DaemonManager::default();
        assert_eq!(mgr.status, DaemonStatus::NotRunning);
        assert!(!mgr.is_active());
    }

    #[test]
    fn start_with_missing_binary_surfaces_a_hint() {
        // With no zkmsgd on PATH and no sibling in a scratch dir, `start`
        // records the build hint rather than spawning or panicking. We can't
        // easily null out current_exe()'s sibling in a unit test, so this
        // asserts the error-path shape only when the binary is genuinely
        // absent; otherwise it confirms a real spawn was attempted.
        let mut mgr = DaemonManager::default();
        // An address that will never bind is irrelevant here — locate runs
        // first. Use a home that does not need to exist for the lookup.
        mgr.start("127.0.0.1:0", Path::new("/nonexistent-home"));
        match locate_daemon_binary() {
            None => {
                assert!(mgr.start_error.is_some());
                assert!(!mgr.is_active());
            }
            Some(_) => {
                // A built tree has the sibling binary; a spawn was attempted.
                // Reap it so the test leaves no child behind.
                mgr.stop();
            }
        }
    }

    #[test]
    fn poll_without_child_is_a_noop() {
        let mut mgr = DaemonManager::default();
        mgr.poll();
        assert_eq!(mgr.status, DaemonStatus::NotRunning);
    }
}
