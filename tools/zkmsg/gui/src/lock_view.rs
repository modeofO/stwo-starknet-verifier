//! The lock screen (app PIN, `zkmsg_core::applock`) and the panic-wipe
//! dialog. Nothing of any profile renders until the PIN is entered — or set,
//! on first use. The panic wipe is reachable from here without the PIN.

use std::path::Path;
use std::time::{Duration, Instant};

use eframe::egui;

use zkmsg_core::applock::{self, LockState, MAX_ATTEMPTS, MIN_PIN_LEN, Unlock};

pub enum LockOutcome {
    None,
    Unlocked,
    /// Open the panic-wipe dialog.
    Panic,
    /// The last allowed attempt failed and the panic wipe ran (its errors).
    Wiped(Vec<String>),
}

pub struct LockUi {
    /// Read on open and after every attempt (each read is a Keychain call).
    first_use: bool,
    fails: u32,
    wait_until: Option<Instant>,
    pin: String,
    again: String,
    message: Option<String>,
}

impl LockUi {
    pub fn new() -> Self {
        let mut ui = Self {
            first_use: false,
            fails: 0,
            wait_until: None,
            pin: String::new(),
            again: String::new(),
            message: None,
        };
        ui.refresh();
        ui
    }

    /// A line shown under the PIN field (e.g. what a wipe did).
    pub fn notice(&mut self, text: String) {
        self.message = Some(text);
    }

    fn refresh(&mut self) {
        match applock::state() {
            Ok(LockState::NotSet) => self.first_use = true,
            Ok(LockState::Locked { fails, wait_secs }) => {
                self.first_use = false;
                self.fails = fails;
                self.wait_until = (wait_secs > 0).then(|| Instant::now() + Duration::from_secs(wait_secs));
            }
            Ok(LockState::Unlocked) => self.first_use = false,
            Err(e) => self.message = Some(format!("{e:#}")),
        }
    }

    fn wait_left(&self) -> Option<u64> {
        let left = self.wait_until?.saturating_duration_since(Instant::now()).as_secs();
        (left > 0).then_some(left)
    }

    fn submit(&mut self, root: &Path) -> LockOutcome {
        let pin = std::mem::take(&mut self.pin);
        let again = std::mem::take(&mut self.again);
        if self.first_use {
            if let Err(e) = applock::validate_pin(&pin) {
                self.message = Some(format!("{e:#}"));
                return LockOutcome::None;
            }
            if pin != again {
                self.message = Some("the two entries differ".into());
                return LockOutcome::None;
            }
            return match applock::set_pin(&pin, root) {
                Ok(_) => LockOutcome::Unlocked,
                Err(e) => {
                    self.message = Some(format!("{e:#}"));
                    LockOutcome::None
                }
            };
        }
        let outcome = applock::unlock(&pin, root);
        self.refresh();
        match outcome {
            Ok(Unlock::Unlocked) => LockOutcome::Unlocked,
            Ok(Unlock::Wiped { errors }) => LockOutcome::Wiped(errors),
            Ok(Unlock::Wait { .. }) => LockOutcome::None,
            Ok(Unlock::Wrong { attempts_left, .. }) => {
                self.message = Some(format!("wrong PIN — {attempts_left} attempt(s) left"));
                LockOutcome::None
            }
            Err(e) => {
                self.message = Some(format!("{e:#}"));
                LockOutcome::None
            }
        }
    }

    pub fn update(&mut self, ctx: &egui::Context, root: &Path) -> LockOutcome {
        let mut outcome = LockOutcome::None;
        let wait = self.wait_left();
        if wait.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading("zkmsg");
                ui.add_space(12.0);
                let mut enter;
                if self.first_use {
                    ui.label(format!(
                        "Set an app PIN (at least {MIN_PIN_LEN} characters). It unlocks every \
                         profile on this computer. {MAX_ATTEMPTS} wrong entries in a row wipe them all."
                    ));
                    ui.add(egui::TextEdit::singleline(&mut self.pin).password(true).hint_text("new PIN"));
                    let r = ui.add(egui::TextEdit::singleline(&mut self.again).password(true).hint_text("again"));
                    enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("Set PIN").clicked() {
                        enter = true;
                    }
                } else {
                    ui.label("Enter the app PIN.");
                    let r = ui.add_enabled(
                        wait.is_none(),
                        egui::TextEdit::singleline(&mut self.pin).password(true).hint_text("PIN"),
                    );
                    enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.add_enabled(wait.is_none(), egui::Button::new("Unlock")).clicked() {
                        enter = true;
                    }
                    if let Some(secs) = wait {
                        ui.label(format!("too many wrong PINs — next try in {secs} s"));
                    }
                    if self.fails >= 5 {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 120, 0),
                            format!(
                                "{} attempt(s) left. The last one wipes every identity on this computer.",
                                MAX_ATTEMPTS.saturating_sub(self.fails)
                            ),
                        );
                    }
                }
                if enter && wait.is_none() {
                    outcome = self.submit(root);
                }
                if let Some(m) = &self.message {
                    ui.colored_label(egui::Color32::RED, m.as_str());
                }
                ui.add_space(40.0);
                if ui.button("Panic wipe…").clicked() {
                    outcome = LockOutcome::Panic;
                }
            });
        });
        outcome
    }
}

pub enum PanicOutcome {
    None,
    Cancelled,
    /// Done; the report's errors (if any) say what was not.
    Wiped(zkmsg_core::wipe::PanicReport),
}

/// The app PIN is the one confirmation (owner decision 2026-10-08); a wrong
/// one counts as an attempt. Before any PIN exists, a plain button.
pub struct PanicUi {
    needs_pin: bool,
    pin: String,
    message: Option<String>,
}

impl PanicUi {
    pub fn new() -> Self {
        let needs_pin = !matches!(applock::state(), Ok(LockState::NotSet));
        Self { needs_pin, pin: String::new(), message: None }
    }

    fn run(&mut self, root: &Path) -> PanicOutcome {
        use zkmsg_core::wipe::{PanicAttempt, PanicReport, panic_wipe_with_pin};
        let pin = std::mem::take(&mut self.pin);
        match panic_wipe_with_pin(root, &pin) {
            Ok(PanicAttempt::Wiped(r)) => PanicOutcome::Wiped(r),
            Ok(PanicAttempt::Wrong { attempts_left, .. }) => {
                self.message = Some(format!(
                    "wrong PIN — nothing wiped; {attempts_left} attempt(s) left (the last one wipes anyway)"
                ));
                PanicOutcome::None
            }
            Ok(PanicAttempt::Wait { secs }) => {
                self.message = Some(format!("too many wrong PINs — try again in {secs} s"));
                PanicOutcome::None
            }
            Err(e) => PanicOutcome::Wiped(PanicReport { errors: vec![format!("{e:#}")], ..Default::default() }),
        }
    }

    pub fn update(&mut self, ctx: &egui::Context, root: &Path) -> PanicOutcome {
        let mut outcome = PanicOutcome::None;
        let mut go = false;
        egui::Window::new("Panic wipe")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(
                    "Wipes EVERY identity on this computer now, for good: all profile keys, the \
                     app PIN, the profiles' account keys and zkmsg's files. No network needed. \
                     Balances and tickets are abandoned.",
                );
                if self.needs_pin {
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.pin).password(true).hint_text("app PIN to confirm"),
                    );
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        go = true;
                    }
                }
                if let Some(m) = &self.message {
                    ui.colored_label(egui::Color32::RED, m.as_str());
                }
                ui.horizontal(|ui| {
                    let wipe = egui::Button::new(egui::RichText::new("Wipe everything now").color(egui::Color32::WHITE))
                        .fill(egui::Color32::from_rgb(170, 30, 30));
                    if ui.add_enabled(!self.needs_pin || !self.pin.is_empty(), wipe).clicked() {
                        go = true;
                    }
                    if ui.button("Cancel").clicked() {
                        outcome = PanicOutcome::Cancelled;
                    }
                });
            });
        if go {
            outcome = self.run(root);
        }
        outcome
    }
}
