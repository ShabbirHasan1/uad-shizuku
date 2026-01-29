#![allow(clippy::float_cmp)]
#![allow(clippy::manual_range_contains)]

#[cfg(target_os = "android")]
use android_activity::AndroidApp;
use eframe::{egui, NativeOptions};
use egui_material3::theme::{
    load_fonts, load_themes, setup_local_fonts, setup_local_fonts_from_bytes, setup_local_theme,
    update_window_background,
};

mod adb;
pub mod adb_stt;
mod android_packagemanager;
mod tab_apps_control;
pub mod tab_apps_control_stt;
mod tab_debloat_control;
pub mod tab_debloat_control_stt;
mod tab_scan_control;
pub mod tab_scan_control_stt;
mod tab_usage_control;
pub mod tab_usage_control_stt;
mod win_package_details_dialog;
pub mod win_package_details_dialog_stt;

pub mod api_apkmirror;
pub mod api_apkmirror_stt;
pub mod api_fdroid;
pub mod api_fdroid_stt;
mod api_googleplay;
pub mod api_googleplay_stt;
pub mod api_hybridanalysis;
pub mod api_hybridanalysis_stt;
mod api_virustotal;
pub mod api_virustotal_stt;
mod calc_apkmirror;
pub mod calc_apkmirror_stt;
mod calc_fdroid;
pub mod calc_fdroid_stt;
mod calc_googleplay;
pub mod calc_googleplay_stt;
mod calc_hybridanalysis;
pub mod calc_hybridanalysis_stt;
mod calc_izzyrisk;
mod calc_virustotal;
pub mod calc_virustotal_stt;
pub mod db;
pub mod db_apkmirror;
pub mod db_fdroid;
pub mod db_googleplay;
pub mod db_hybridanalysis;
pub mod db_package_cache;
pub mod db_virustotal;
mod models;
mod schema;

pub mod log_capture;
// mod android_wallpaper;
// mod android_screensize;

// Export modules for external use
pub use gui::{UadShizukuApp as GuiApp, View};
pub mod gui;
pub mod gui_stt;
pub mod svg_stt;

use anyhow::{Context, Result};
#[cfg(not(target_os = "android"))]
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub config_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub download_dir: PathBuf,
    pub db_dir: PathBuf,
    pub tmp_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub virustotal_apikey: String,
    pub hybridanalysis_apikey: String,
    #[serde(default)]
    pub virustotal_submit: bool,
    #[serde(default)]
    pub hybridanalysis_submit: bool,
    #[serde(default)]
    pub show_logs: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_theme_mode")]
    pub theme_mode: String,
    #[serde(default = "default_contrast_level")]
    pub contrast_level: String,
    #[serde(default = "default_display_size")]
    pub display_size: String,
    #[serde(default)]
    pub google_play_renderer: bool,
    #[serde(default)]
    pub fdroid_renderer: bool,
    #[serde(default)]
    pub apkmirror_renderer: bool,
    #[serde(default)]
    pub apkmirror_email: String,
    #[serde(default)]
    pub apkmirror_name: String,
    #[serde(default)]
    pub apkmirror_auto_upload: bool,
    #[serde(default = "default_language")]
    pub language: String,
    #[serde(default = "default_font_path")]
    pub font_path: String,
    #[serde(default = "default_override_text_style")]
    pub override_text_style: String,
}

#[allow(dead_code)]
fn default_true() -> bool {
    true
}

fn default_language() -> String {
    "en-US".to_string()
}

fn default_font_path() -> String {
    String::new()
}

fn default_override_text_style() -> String {
    String::new()
}

fn default_log_level() -> String {
    "Error".to_string()
}

fn default_theme_mode() -> String {
    "Auto".to_string()
}

fn default_contrast_level() -> String {
    "Normal".to_string()
}

fn default_display_size() -> String {
    "Phone (412x732)".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            virustotal_apikey: String::new(),
            hybridanalysis_apikey: String::new(),
            virustotal_submit: false,
            hybridanalysis_submit: false,
            show_logs: false,
            log_level: default_log_level(),
            theme_mode: default_theme_mode(),
            contrast_level: default_contrast_level(),
            display_size: default_display_size(),
            google_play_renderer: false,
            fdroid_renderer: false,
            apkmirror_renderer: false,
            apkmirror_email: String::new(),
            apkmirror_name: String::new(),
            apkmirror_auto_upload: false,
            language: default_language(),
            font_path: default_font_path(),
            override_text_style: default_override_text_style(),
        }
    }
}

impl Config {
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "android")]
        {
            // Android-specific paths
            let config_dir = PathBuf::from("/data/data/pe.nikescar.uad_shizuku/files");
            let cache_dir = PathBuf::from("/data/data/pe.nikescar.uad_shizuku/cache");
            let download_dir = PathBuf::from("/data/data/pe.nikescar.uad_shizuku/downloads");
            let db_dir = PathBuf::from("/data/data/pe.nikescar.uad_shizuku/dbs");
            let tmp_dir = PathBuf::from("/data/data/pe.nikescar.uad_shizuku/tmp");

            log::info!("Android config paths - config_dir: {:?}, cache_dir: {:?} download_dir: {:?}, db_dir: {:?}, tmp_dir: {:?}", config_dir, cache_dir, download_dir, db_dir, tmp_dir);

            // Create directories if they don't exist
            match fs::create_dir_all(&config_dir) {
                Ok(()) => log::info!("Successfully created config_dir: {:?}", config_dir),
                Err(e) => log::error!(
                    "Failed to create config_dir: {:?} - Error: {}",
                    config_dir,
                    e
                ),
            }
            match fs::create_dir_all(&cache_dir) {
                Ok(()) => log::info!("Successfully created cache_dir: {:?}", cache_dir),
                Err(e) => log::error!("Failed to create cache_dir: {:?} - Error: {}", cache_dir, e),
            }
            match fs::create_dir_all(&download_dir) {
                Ok(()) => log::info!("Successfully created download_dir: {:?}", download_dir),
                Err(e) => log::error!(
                    "Failed to create download_dir: {:?} - Error: {}",
                    download_dir,
                    e
                ),
            }
            match fs::create_dir_all(&db_dir) {
                Ok(()) => log::info!("Successfully created db_dir: {:?}", db_dir),
                Err(e) => log::error!("Failed to create db_dir: {:?} - Error: {}", db_dir, e),
            }
            match fs::create_dir_all(&tmp_dir) {
                Ok(()) => log::info!("Successfully created tmp_dir: {:?}", tmp_dir),
                Err(e) => log::error!("Failed to create tmp_dir: {:?} - Error: {}", tmp_dir, e),
            }

            Ok(Config {
                config_dir,
                cache_dir,
                download_dir,
                db_dir,
                tmp_dir,
            })
        }

        #[cfg(not(target_os = "android"))]
        {
            let proj_dirs = ProjectDirs::from("pe", "nikescar", "uad_shizuku")
                .context("Failed to get project directories")?;

            let config_dir = proj_dirs.config_dir().to_path_buf();
            let cache_dir = config_dir.join("cache");
            let download_dir = config_dir.join("downloads");
            let db_dir = config_dir.join("dbs");
            let tmp_dir = config_dir.join("tmp");

            // Create directories if they don't exist
            fs::create_dir_all(&config_dir)?;
            fs::create_dir_all(&cache_dir)?;
            fs::create_dir_all(&download_dir)?;
            fs::create_dir_all(&db_dir)?;
            fs::create_dir_all(&tmp_dir)?;

            Ok(Config {
                config_dir,
                cache_dir,
                download_dir,
                db_dir,
                tmp_dir,
            })
        }
    }

    pub fn load_settings(&self) -> Result<Settings> {
        let settings_path = self.config_dir.join("settings.txt");

        if !settings_path.exists() {
            return Ok(Settings::default());
        }

        let contents =
            fs::read_to_string(&settings_path).context("Failed to read settings file")?;

        let settings: Settings =
            serde_json::from_str(&contents).context("Failed to parse settings JSON")?;

        Ok(settings)
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        let settings_path = self.config_dir.join("settings.txt");

        let json =
            serde_json::to_string_pretty(settings).context("Failed to serialize settings")?;

        fs::write(&settings_path, json).context("Failed to write settings file")?;

        tracing::info!("Settings saved to {:?}", settings_path);
        Ok(())
    }
}

pub fn init_i18n() {
    let en_us = String::from_utf8_lossy(include_bytes!("../assets/languages/fluent/en-US.ftl"));
    let ko_kr = String::from_utf8_lossy(include_bytes!("../assets/languages/fluent/ko-KR.ftl"));

    egui_i18n::load_translations_from_text("en-US", en_us).unwrap();
    egui_i18n::load_translations_from_text("ko-KR", ko_kr).unwrap();

    egui_i18n::set_language("en-US");
    egui_i18n::set_fallback("en-US");
}

// Android entry point
#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: AndroidApp) {
    // Initialize tracing subscriber for Android with log capture and reload support
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::reload;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    // Try to load user's log level from settings, default to ERROR if not found
    let log_level = if let Ok(config) = Config::new() {
        if let Ok(settings) = config.load_settings() {
            settings.log_level.to_lowercase()
        } else {
            "error".to_string()
        }
    } else {
        "error".to_string()
    };

    // Create a reloadable filter layer for dynamic log level changes
    let env_filter = EnvFilter::try_new(&log_level).unwrap_or_else(|_| EnvFilter::new("error"));
    let (filter, reload_handle) = reload::Layer::new(env_filter);

    // Store the reload handle for later use (type-erased via closure)
    log_capture::set_reload_fn(move |level: &str| {
        let new_filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("error"));
        if let Err(e) = reload_handle.reload(new_filter) {
            eprintln!("Failed to reload log filter: {}", e);
        }
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(log_capture::LogCaptureLayer)
        .init();

    // Set up database path before initializing anything that uses the database
    if let Ok(config) = Config::new() {
        let db_path = config.db_dir.join("uad.db");
        db::set_db_path(db_path.to_string_lossy().to_string());
    }

    // Initialize VirusTotal database upsert queue
    // This must be called AFTER setting the database path
    db_virustotal::init_upsert_queue();

    // Initialize Hybrid Analysis database upsert queue
    db_hybridanalysis::init_upsert_queue();

    // Initialize i18n
    init_i18n();

    // Initialize Android logger with max level (actual filtering done by tracing)
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Trace)
            .with_tag("UAD-Shizuku"),
    );

    // Log initialization message to confirm logging is working
    log::info!("Android logger initialized successfully");
    log::info!("Starting mobile application with egui");

    // Also use println! as backup logging method
    println!("UAD-Shizuku: Application starting");
    eprintln!("UAD-Shizuku: Error stream test");

    // Set up panic handler to catch crashes
    std::panic::set_hook(Box::new(|panic_info| {
        log::error!("PANIC OCCURRED: {}", panic_info);
        eprintln!("UAD-Shizuku PANIC: {}", panic_info);
        if let Some(location) = panic_info.location() {
            log::error!("Panic location: {}:{}", location.file(), location.line());
            eprintln!(
                "UAD-Shizuku PANIC LOCATION: {}:{}",
                location.file(),
                location.line()
            );
        }
    }));

    std::env::set_var("RUST_BACKTRACE", "full");

    let options = NativeOptions {
        android_app: Some(app),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    match UadShizukuApp::run(options) {
        Ok(_) => {
            log::info!("UadShizukuApp exited successfully");
        }
        Err(e) => {
            log::error!("UadShizukuApp failed: {}", e);
            eprintln!("UadShizukuApp failed: {}", e);
        }
    }
}

pub struct UadShizukuApp {
    uad_shizuku_app: gui::UadShizukuApp,
}

impl Default for UadShizukuApp {
    fn default() -> Self {
        let uad_shizuku_app = gui::UadShizukuApp::default();
        Self { uad_shizuku_app }
    }
}

// Native desktop entry point
impl UadShizukuApp {
    pub fn run(options: NativeOptions) -> Result<(), eframe::Error> {
        eframe::run_native(
            "uad_shizuku_app",
            options,
            Box::new(|cc| {
                setup_local_theme(Some("resources/material-theme.json")); // Use default theme
                setup_local_fonts_from_bytes(
                    "NotoSansKr",
                    include_bytes!("../resources/noto-sans-kr.ttf"),
                );
                egui_extras::install_image_loaders(&cc.egui_ctx);
                load_fonts(&cc.egui_ctx);
                load_themes();
                update_window_background(&cc.egui_ctx);

                // Restore saved custom font if configured
                if let Ok(config) = Config::new() {
                    if let Ok(settings) = config.load_settings() {
                        if !settings.font_path.is_empty() {
                            setup_local_fonts(Some(&settings.font_path));
                            load_fonts(&cc.egui_ctx);
                        }
                    }
                }

                Ok(Box::<UadShizukuApp>::default())
            }),
        )
    }
}

impl eframe::App for UadShizukuApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // ctx.set_pixels_per_point(1.2);
            ctx.set_zoom_factor(0.8);
            self.uad_shizuku_app.ui(ui);
        });
    }
}

/// Detect narrow screens. This is used to show a simpler UI on mobile devices,
/// especially for the web demo at <https://egui.rs>.
pub fn is_mobile(ctx: &egui::Context) -> bool {
    let screen_size = ctx.screen_rect().size();
    screen_size.x < 1081.0
}

/// Check if a package ID has at least 2 domain levels (e.g., com.example)
/// Package IDs with less than 2 levels (e.g., com.android) are typically system
/// packages that won't be found on app stores or malware databases.
pub fn is_valid_package_id(package_id: &str) -> bool {
    package_id.split('.').count() >= 2
}
