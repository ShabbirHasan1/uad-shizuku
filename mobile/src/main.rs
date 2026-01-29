use eframe::egui;
use egui_material3::theme::{
    load_fonts, load_themes, setup_local_fonts, setup_local_fonts_from_bytes, setup_local_theme,
    update_window_background,
};

fn main() -> eframe::Result<()> {
    // Initialize tracing subscriber for structured logging with log capture and reload support
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::reload;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    // Try to load user's log level from settings, default to "error" if not found
    let log_level = if let Ok(config) = uad_shizuku::Config::new() {
        if let Ok(settings) = config.load_settings() {
            settings.log_level.to_lowercase()
        } else {
            "error".to_string()
        }
    } else {
        "error".to_string()
    };

    // Create a reloadable filter layer for dynamic log level changes
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));
    let (filter, reload_handle) = reload::Layer::new(env_filter);

    // Store the reload handle for later use (type-erased via closure)
    uad_shizuku::log_capture::set_reload_fn(move |level: &str| {
        let new_filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("error"));
        if let Err(e) = reload_handle.reload(new_filter) {
            eprintln!("Failed to reload log filter: {}", e);
        }
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(uad_shizuku::log_capture::LogCaptureLayer)
        .init();

    // Set up database path before initializing anything that uses the database
    if let Ok(config) = uad_shizuku::Config::new() {
        let db_path = config.db_dir.join("uad.db");
        uad_shizuku::db::set_db_path(db_path.to_string_lossy().to_string());
    }

    // Initialize VirusTotal database upsert queue
    // This must be called AFTER setting the database path
    uad_shizuku::db_virustotal::init_upsert_queue();

    // Initialize Hybrid Analysis database upsert queue
    uad_shizuku::db_hybridanalysis::init_upsert_queue();

    // Initialize i18n
    uad_shizuku::init_i18n();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };

    eframe::run_native(
        "UAD-Shizuku",
        options,
        Box::new(|cc| {
            // Prepare themes from build-time constants
            setup_local_fonts_from_bytes(
                "NotoSansKr",
                include_bytes!("../resources/noto-sans-kr.ttf"),
            );
            setup_local_theme(Some("resources/material-theme.json")); // Use default theme
                                                                      // setup_google_fonts(Some("Google Sans Code"));
                                                                      // setup_google_fonts(Some("Nanum Gothic"));
            // setup_google_fonts(Some("Noto Sans KR"));
            // setup_google_fonts(Some("Material+Symbols+Outlined"));
            egui_extras::install_image_loaders(&cc.egui_ctx);
            // Load fonts and themes
            load_fonts(&cc.egui_ctx);
            load_themes();
            update_window_background(&cc.egui_ctx);

            // Restore saved custom font if configured
            if let Ok(config) = uad_shizuku::Config::new() {
                if let Ok(settings) = config.load_settings() {
                    if !settings.font_path.is_empty() {
                        setup_local_fonts(Some(&settings.font_path));
                        load_fonts(&cc.egui_ctx);
                    }
                }
            }

            Ok(Box::<UadShizukuDesktopApp>::default())
        }),
    )
}

struct UadShizukuDesktopApp {
    app: uad_shizuku::gui::UadShizukuApp,
}

impl Default for UadShizukuDesktopApp {
    fn default() -> Self {
        Self {
            app: uad_shizuku::gui::UadShizukuApp::default(),
        }
    }
}

impl eframe::App for UadShizukuDesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            self.app.ui(ui);
        });
    }
}
