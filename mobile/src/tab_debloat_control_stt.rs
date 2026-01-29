use crate::adb::PackageFingerprint;
use crate::calc_apkmirror::ApkMirrorQueue;
use crate::calc_apkmirror_stt::ApkMirrorUploadQueue;
use crate::calc_fdroid::FDroidQueue;
use crate::calc_googleplay::GooglePlayQueue;
use crate::gui::UadNgLists;
use crate::models::{ApkMirrorApp, FDroidApp, GooglePlayApp};
use crate::win_package_details_dialog::PackageDetailsDialog;
use eframe::egui;
use std::collections::{HashMap, HashSet};

pub enum AdbResult {
    Success(String), // package name
    Failure,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DebloatFilter {
    All,
    Recommended,
    Advanced,
    Expert,
    Unsafe,
    Unknown,
}

pub struct TabDebloatControl {
    pub open: bool,
    // Store reference to installed packages
    pub installed_packages: Vec<PackageFingerprint>,
    pub uad_ng_lists: Option<UadNgLists>,
    // Selection state - now using package names as keys for stability across sorting
    pub selected_packages: HashSet<String>,
    // Package details dialog
    pub package_details_dialog: PackageDetailsDialog,
    // Filter state
    pub active_filter: DebloatFilter,
    // Sort state
    pub sort_column: Option<usize>,
    pub sort_ascending: bool,
    // Device selection
    pub selected_device: Option<String>,
    // Version counter for table ID - incremented when packages are reloaded
    pub table_version: u64,
    // Google Play renderer settings
    pub google_play_renderer_enabled: bool,
    // Cache for Google Play app icons (package_id -> TextureHandle)
    pub google_play_textures: HashMap<String, egui::TextureHandle>,
    // Google Play fetch queue
    pub google_play_queue: Option<GooglePlayQueue>,
    // F-Droid renderer settings
    pub fdroid_renderer_enabled: bool,
    // Cache for F-Droid app icons (package_id -> TextureHandle)
    pub fdroid_textures: HashMap<String, egui::TextureHandle>,
    // F-Droid fetch queue
    pub fdroid_queue: Option<FDroidQueue>,
    // APKMirror renderer settings
    pub apkmirror_renderer_enabled: bool,
    // Cache for APKMirror app icons (package_id -> TextureHandle)
    pub apkmirror_textures: HashMap<String, egui::TextureHandle>,
    // APKMirror fetch queue
    pub apkmirror_queue: Option<ApkMirrorQueue>,
    // APKMirror upload queue for auto-uploading newer versions
    pub apkmirror_upload_queue: Option<ApkMirrorUploadQueue>,
    // APKMirror auto-upload enabled
    pub apkmirror_auto_upload_enabled: bool,
    // Cached app info from database (package_id -> app data)
    // Loaded once in update_packages, used for fast lookup in UI
    pub cached_google_play_apps: HashMap<String, GooglePlayApp>,
    pub cached_fdroid_apps: HashMap<String, FDroidApp>,
    pub cached_apkmirror_apps: HashMap<String, ApkMirrorApp>,
    // Filter to show only enabled (green) packages
    pub show_only_enabled: bool,
    // Filter to hide system apps
    pub hide_system_app: bool,
}
