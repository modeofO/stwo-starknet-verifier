//! The one-time migration screen, shown on launch (default home only)
//! when legacy single-profile homes are found beside/at `~/.zkmsg`. It
//! renders the discovered sources with editable target names and returns
//! the user's choice; the actual planning/executing lives in `app.rs`,
//! which calls only `zkmsg_core::profiles`. This view never touches the
//! filesystem itself.

use eframe::egui;

use zkmsg_core::profiles::LegacySource;

/// State backing the migration screen: the discovered legacy sources each
/// paired with an editable target name (seeded from `suggested_name`), and
/// the last plan/execute error to surface inline.
pub struct MigrationUi {
    pub sources: Vec<(LegacySource, String)>,
    pub error: Option<String>,
}

/// What the user asked for this frame. `None` unless a button was clicked.
pub enum MigrateAction {
    None,
    Migrate,
    NotNow,
}

/// Renders the migration screen into `ui`, mutating the editable names in
/// place, and reports which button (if any) was clicked this frame.
pub fn render(ui: &mut egui::Ui, state: &mut MigrationUi) -> MigrateAction {
    let mut action = MigrateAction::None;
    ui.heading("One-time migration to the profile layout");
    ui.add_space(8.0);

    for (source, name) in &mut state.sources {
        ui.horizontal(|ui| {
            ui.label(source.dir.display().to_string());
            ui.add(egui::TextEdit::singleline(name));
        });
    }

    ui.add_space(8.0);
    ui.label("Files are moved with atomic renames — nothing is copied, deleted, or overwritten.");
    if let Some(err) = &state.error {
        ui.colored_label(egui::Color32::RED, err.as_str());
    }
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui.button("Migrate").clicked() {
            action = MigrateAction::Migrate;
        }
        if ui.button("Not now").clicked() {
            action = MigrateAction::NotNow;
        }
    });
    action
}
