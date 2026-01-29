pub use crate::tab_usage_control_stt::*;
use eframe::egui;
use egui_i18n::tr;

impl Default for TabUsageControl {
    fn default() -> Self {
        Self {
            open: false,
            usage_stats: String::new(),
        }
    }
}

impl TabUsageControl {
    pub fn update_usage_stats(&mut self, stats: String) {
        self.usage_stats = stats;
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(tr!("usage-control"));
        });
        ui.add_space(10.0);

        if self.usage_stats.is_empty() {
            ui.label(tr!("no-usage-stats"));
        } else {
            ui.label(tr!("usage-statistics"));
            ui.add_space(5.0);
            egui::ScrollArea::vertical()
                .max_height(500.0)
                .show(ui, |ui| {
                    ui.monospace(&self.usage_stats);
                });
        }
    }
}
