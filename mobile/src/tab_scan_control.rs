use crate::adb::PackageFingerprint;
use crate::calc_hybridanalysis::{self};
use crate::calc_izzyrisk;
use crate::calc_virustotal::{self};
use crate::gui::UadNgLists;
pub use crate::tab_scan_control_stt::*;
use crate::win_package_details_dialog::PackageDetailsDialog;
use eframe::egui;
use egui_i18n::tr;
use egui_material3::{assist_chip, data_table, theme::get_global_color, MaterialButton};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// SVG icons as constants (moved to svg_stt.rs)
use crate::svg_stt::*;

impl Default for TabScanControl {
    fn default() -> Self {
        Self {
            open: false,
            installed_packages: Vec::new(),
            uad_ng_lists: None,
            selected_packages: Vec::new(),
            package_risk_scores: HashMap::new(),
            package_details_dialog: PackageDetailsDialog::new(),
            vt_scanner_state: None,
            vt_rate_limiter: None,
            vt_package_paths_cache: None,
            ha_scanner_state: None,
            ha_rate_limiter: None,
            ha_package_paths_cache: None,
            vt_api_key: None,
            ha_api_key: None,
            device_serial: None,
            virustotal_submit_enabled: false,
            hybridanalysis_submit_enabled: false,
            sort_column: None,
            sort_ascending: true,
            active_vt_filter: VtFilter::All,
            active_ha_filter: HaFilter::All,
            vt_scan_progress: Arc::new(Mutex::new(None)),
            vt_scan_cancelled: Arc::new(Mutex::new(false)),
            ha_scan_progress: Arc::new(Mutex::new(None)),
            ha_scan_cancelled: Arc::new(Mutex::new(false)),
            cached_google_play_apps: HashMap::new(),
            cached_fdroid_apps: HashMap::new(),
            cached_apkmirror_apps: HashMap::new(),
            app_textures: HashMap::new(),
            show_only_enabled: false,
            hide_system_app: false,
            google_play_renderer_enabled: false,
            fdroid_renderer_enabled: false,
            apkmirror_renderer_enabled: false,
        }
    }
}

impl TabScanControl {
    pub fn update_packages(&mut self, packages: Vec<PackageFingerprint>) {
        self.installed_packages = packages;
        // Resize selection vector to match package count
        self.selected_packages
            .resize(self.installed_packages.len(), false);
        // Calculate risk scores for all packages
        self.calculate_all_risk_scores();

        // Initialize VirusTotal scanner state
        if self.vt_api_key.is_some() && self.device_serial.is_some() {
            self.run_virustotal();
        }

        // Initialize Hybrid Analysis scanner state
        if self.ha_api_key.is_some() && self.device_serial.is_some() {
            self.run_hybridanalysis();
        }

        // Clear textures cache when packages are updated (will be reloaded on demand)
        self.app_textures.clear();
    }

    /// Update cached app info from TabDebloatControl
    /// This is called from gui.rs after TabDebloatControl loads the app info
    pub fn update_cached_app_info(
        &mut self,
        google_play_apps: &HashMap<String, crate::models::GooglePlayApp>,
        fdroid_apps: &HashMap<String, crate::models::FDroidApp>,
        apkmirror_apps: &HashMap<String, crate::models::ApkMirrorApp>,
    ) {
        self.cached_google_play_apps = google_play_apps.clone();
        self.cached_fdroid_apps = fdroid_apps.clone();
        self.cached_apkmirror_apps = apkmirror_apps.clone();
    }

    /// Load texture from base64 encoded icon data
    /// The data may be a data URI (e.g., "data:image/png;base64,ABC123...")
    /// or raw base64 data
    fn load_texture_from_base64(
        &mut self,
        ctx: &egui::Context,
        pkg_id: &str,
        base64_data: &str,
    ) -> Option<egui::TextureHandle> {
        // Check if already cached
        if let Some(texture) = self.app_textures.get(pkg_id) {
            return Some(texture.clone());
        }

        // Strip data URI prefix if present (e.g., "data:image/png;base64,")
        let raw_base64 = if let Some(comma_pos) = base64_data.find(",") {
            &base64_data[comma_pos + 1..]
        } else {
            base64_data
        };

        // Decode base64 and load image
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw_base64) {
            Ok(bytes) => match image::load_from_memory(&bytes) {
                Ok(image) => {
                    let size = [image.width() as _, image.height() as _];
                    let image_buffer = image.to_rgba8();
                    let pixels = image_buffer.as_flat_samples();
                    let color_image =
                        egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());
                    let texture = ctx.load_texture(
                        format!("app_icon_{}", pkg_id),
                        color_image,
                        egui::TextureOptions::LINEAR,
                    );
                    self.app_textures
                        .insert(pkg_id.to_string(), texture.clone());
                    return Some(texture);
                }
                Err(e) => {
                    tracing::debug!("Failed to load image for {}: {}", pkg_id, e);
                }
            },
            Err(e) => {
                tracing::debug!("Failed to decode base64 for {}: {}", pkg_id, e);
            }
        }
        None
    }

    /// Prepare app info data map for all visible packages
    /// Returns a HashMap of package_id -> (TextureHandle, title, developer, version)
    /// This is called once before rendering the table to avoid mutable borrow issues in the row loop
    pub fn prepare_app_info_for_display(
        &mut self,
        ctx: &egui::Context,
        package_ids: &[String],
        system_packages: &std::collections::HashSet<String>,
    ) -> HashMap<String, (Option<egui::TextureHandle>, String, String, Option<String>)> {
        let mut app_data_map = HashMap::new();

        // Only process if at least one renderer is enabled
        if !self.google_play_renderer_enabled
            && !self.fdroid_renderer_enabled
            && !self.apkmirror_renderer_enabled
        {
            return app_data_map;
        }

        // First pass: collect app data without loading textures
        // (package_id, icon_base64, title, developer, version)
        let mut apps_to_load: Vec<(String, Option<String>, String, String, Option<String>)> =
            Vec::new();

        for pkg_id in package_ids {
            let is_system = system_packages.contains(pkg_id);

            // For non-system apps: Check F-Droid first, then Google Play
            if !is_system {
                // Check F-Droid cache (only if fdroid renderer is enabled)
                if self.fdroid_renderer_enabled {
                    if let Some(fd_app) = self.cached_fdroid_apps.get(pkg_id) {
                        if fd_app.raw_response != "404" {
                            apps_to_load.push((
                                pkg_id.clone(),
                                fd_app.icon_base64.clone(),
                                fd_app.title.clone(),
                                fd_app.developer.clone(),
                                fd_app.version.clone(),
                            ));
                            continue;
                        }
                    }
                }

                // Check Google Play cache (only if google play renderer is enabled)
                if self.google_play_renderer_enabled {
                    if let Some(gp_app) = self.cached_google_play_apps.get(pkg_id) {
                        if gp_app.raw_response != "404" {
                            apps_to_load.push((
                                pkg_id.clone(),
                                gp_app.icon_base64.clone(),
                                gp_app.title.clone(),
                                gp_app.developer.clone(),
                                gp_app.version.clone(),
                            ));
                            continue;
                        }
                    }
                }
            } else {
                // For system apps: Check APKMirror (only if apkmirror renderer is enabled)
                if self.apkmirror_renderer_enabled {
                    if let Some(am_app) = self.cached_apkmirror_apps.get(pkg_id) {
                        if am_app.raw_response != "404" {
                            apps_to_load.push((
                                pkg_id.clone(),
                                am_app.icon_base64.clone(),
                                am_app.title.clone(),
                                am_app.developer.clone(),
                                am_app.version.clone(),
                            ));
                            continue;
                        }
                    }
                }
            }
        }

        // Second pass: load textures and build the data map
        for (pkg_id, icon_base64, title, developer, version) in apps_to_load {
            let texture = icon_base64
                .as_ref()
                .and_then(|b64| self.load_texture_from_base64(ctx, &pkg_id, b64));
            app_data_map.insert(pkg_id, (texture, title, developer, version));
        }

        app_data_map
    }

    fn run_virustotal(&mut self) {
        let package_names: Vec<String> = self
            .installed_packages
            .iter()
            .map(|p| p.pkg.clone())
            .collect();
        self.vt_scanner_state = Some(calc_virustotal::init_scanner_state(&package_names));

        // Create shared rate limiter if it doesn't exist
        if self.vt_rate_limiter.is_none() {
            self.vt_rate_limiter = Some(Arc::new(Mutex::new(calc_virustotal::RateLimiter::new(
                4,
                Duration::from_secs(60),
                Duration::from_secs(5),
            ))));
        }

        // Build package paths cache in background thread for faster scanning
        if let Some(ref device) = self.device_serial {
            let device_serial = device.clone();
            let mut installed_packages = self.installed_packages.clone();
            let scanner_state = self.vt_scanner_state.clone().unwrap();
            let api_key = self.vt_api_key.clone().unwrap();
            let rate_limiter = self.vt_rate_limiter.clone().unwrap();
            let virustotal_submit_enabled = self.virustotal_submit_enabled;
            let package_risk_scores = self.package_risk_scores.clone();

            let vt_scan_progress_clone = self.vt_scan_progress.clone();
            let vt_scan_cancelled_clone = self.vt_scan_cancelled.clone();

            // Initialize progress
            if let Ok(mut p) = vt_scan_progress_clone.lock() {
                *p = Some(0.0);
            }
            if let Ok(mut cancelled) = vt_scan_cancelled_clone.lock() {
                *cancelled = false;
            }

            tracing::info!(
                "Starting background thread to build package paths cache for {} packages",
                installed_packages.len()
            );

            std::thread::spawn(move || {
                // Sort installed packages by risk score (descending)
                installed_packages.sort_by(|a, b| {
                    let score_a = package_risk_scores.get(&a.pkg).copied().unwrap_or(0);
                    let score_b = package_risk_scores.get(&b.pkg).copied().unwrap_or(0);
                    score_b.cmp(&score_a) // Descending
                });

                // Get cached packages
                let cached_packages =
                    crate::db_package_cache::get_cached_packages_with_apk(&device_serial);

                // Create a map for faster lookup of cached packages
                // Using pkg_id as key
                let mut cached_packages_map: HashMap<String, crate::models::PackageInfoCache> =
                    HashMap::new();
                for cp in cached_packages {
                    cached_packages_map.insert(cp.pkg_id.clone(), cp);
                }

                let total = installed_packages.len();
                let mut skipped_cached = 0usize;

                for (i, package) in installed_packages.iter().enumerate() {
                    // Check if scan was cancelled
                    if let Ok(cancelled) = vt_scan_cancelled_clone.lock() {
                        if *cancelled {
                            tracing::info!("VirusTotal scan cancelled by user");
                            break;
                        }
                    }

                    // Update progress
                    if let Ok(mut p) = vt_scan_progress_clone.lock() {
                        *p = Some(i as f32 / total as f32);
                    }

                    let pkg_name = &package.pkg;

                    // Skip packages already completed from DB cache
                    {
                        let s = scanner_state.lock().unwrap();
                        if matches!(
                            s.get(pkg_name),
                            Some(calc_virustotal::ScanStatus::Completed(_))
                        ) {
                            skipped_cached += 1;
                            continue;
                        }
                    }

                    let mut paths_str = String::new();
                    let mut sha256sums_str = String::new();

                    // Check if we have it in cache
                    if let Some(cached_pkg) = cached_packages_map.get(pkg_name) {
                        if let (Some(path), Some(sha256)) =
                            (&cached_pkg.apk_path, &cached_pkg.apk_sha256sum)
                        {
                            paths_str = path.clone();
                            sha256sums_str = sha256.clone();
                        }
                    }

                    // If not in cache or missing fields, try from package info (though usually cache is more reliable for path)
                    if paths_str.is_empty() || sha256sums_str.is_empty() {
                        paths_str = package.codePath.clone();
                        sha256sums_str = package.pkgChecksum.clone();
                    }

                    if !paths_str.is_empty() && !sha256sums_str.is_empty() {
                        // Check if paths are directories (not ending with .apk)
                        // or if sha256sums are invalid (not 64 hex chars each)
                        // If so, get files and sha256sums from get_single_package_sha256sum
                        let paths: Vec<&str> = paths_str.split(' ').collect();
                        let sha256sums: Vec<&str> = sha256sums_str.split(' ').collect();
                        let needs_directory_scan = paths.iter().any(|p| !p.ends_with(".apk"));
                        let has_invalid_hashes = sha256sums.iter().any(|s| s.len() != 64);

                        let (final_paths_str, final_sha256sums_str) =
                            if needs_directory_scan || has_invalid_hashes {
                                match crate::adb::get_single_package_sha256sum(
                                    &device_serial,
                                    pkg_name,
                                ) {
                                    Ok((new_paths, new_sha256sums)) => {
                                        if !new_paths.is_empty() && !new_sha256sums.is_empty() {
                                            (new_paths, new_sha256sums)
                                        } else if !has_invalid_hashes {
                                            // Only fall back to cached values if they were valid
                                            (paths_str.clone(), sha256sums_str.clone())
                                        } else {
                                            // Don't use invalid cached hashes
                                            (String::new(), String::new())
                                        }
                                    }
                                    Err(e) => {
                                        if !has_invalid_hashes {
                                            tracing::warn!(
                                                "Failed to get sha256sums for {}: {}, using cached values",
                                                pkg_name,
                                                e
                                            );
                                            (paths_str.clone(), sha256sums_str.clone())
                                        } else {
                                            tracing::warn!(
                                                "Failed to get sha256sums for {}: {}, skipping (cached hashes were invalid)",
                                                pkg_name,
                                                e
                                            );
                                            // Don't use invalid cached hashes
                                            (String::new(), String::new())
                                        }
                                    }
                                }
                            } else {
                                (paths_str.clone(), sha256sums_str.clone())
                            };

                        // Parse space-separated values to build hashes vector
                        let final_paths: Vec<&str> = final_paths_str.split(' ').collect();
                        let final_sha256sums: Vec<&str> = final_sha256sums_str.split(' ').collect();

                        // Build hashes vector from paired paths and sha256sums
                        // Filter to only include valid entries (non-empty path and valid 64-char SHA256 hash)
                        let hashes: Vec<(String, String)> = final_paths
                            .iter()
                            .zip(final_sha256sums.iter())
                            .filter(|(p, s)| !p.is_empty() && s.len() == 64)
                            .map(|(p, s)| (p.to_string(), s.to_string()))
                            .collect();

                        tracing::info!(
                            "Analyzing package {} with {} files (Risk: {})",
                            pkg_name,
                            hashes.len(),
                            package_risk_scores.get(pkg_name).copied().unwrap_or(0)
                        );

                        // Pass all files at once to analyze_package
                        if let Err(e) = calc_virustotal::analyze_package(
                            &pkg_name,
                            hashes,
                            &scanner_state,
                            &rate_limiter,
                            &api_key,
                            &device_serial,
                            virustotal_submit_enabled,
                            &None,
                        ) {
                            tracing::error!("Error analyzing package {}: {}", pkg_name, e);
                        }
                    }
                }

                tracing::info!(
                    "VirusTotal scan complete: {} packages skipped (already cached), {} processed",
                    skipped_cached,
                    total - skipped_cached
                );

                // Clear progress when done
                if let Ok(mut p) = vt_scan_progress_clone.lock() {
                    *p = None;
                }
            });
        }
    }

    fn run_hybridanalysis(&mut self) {
        let package_names: Vec<String> = self
            .installed_packages
            .iter()
            .map(|p| p.pkg.clone())
            .collect();
        self.ha_scanner_state = Some(calc_hybridanalysis::init_scanner_state(&package_names));

        // Create shared rate limiter if it doesn't exist (3 second minimum interval)
        if self.ha_rate_limiter.is_none() {
            self.ha_rate_limiter = Some(Arc::new(Mutex::new(
                calc_hybridanalysis::RateLimiter::new(Duration::from_secs(3)),
            )));
        }

        // Build package paths cache in background thread for faster scanning
        if let Some(ref device) = self.device_serial {
            let device_serial = device.clone();
            let mut installed_packages = self.installed_packages.clone();
            let scanner_state = self.ha_scanner_state.clone().unwrap();
            let api_key = self.ha_api_key.clone().unwrap();
            let rate_limiter = self.ha_rate_limiter.clone().unwrap();
            let hybridanalysis_submit_enabled = self.hybridanalysis_submit_enabled;
            let package_risk_scores = self.package_risk_scores.clone();

            let ha_scan_progress_clone = self.ha_scan_progress.clone();
            let ha_scan_cancelled_clone = self.ha_scan_cancelled.clone();

            // Initialize progress and reset cancellation flag
            if let Ok(mut p) = ha_scan_progress_clone.lock() {
                *p = Some(0.0);
            }
            if let Ok(mut cancelled) = ha_scan_cancelled_clone.lock() {
                *cancelled = false;
            }

            tracing::info!("Starting background thread to build Hybrid Analysis package paths cache for {} packages (submit_enabled={})", installed_packages.len(), hybridanalysis_submit_enabled);

            std::thread::spawn(move || {
                // Check quota first
                let mut effective_submit_enabled = hybridanalysis_submit_enabled;
                tracing::info!(
                    "Checking Hybrid Analysis API quota (submit_enabled={})...",
                    effective_submit_enabled
                );
                match crate::api_hybridanalysis::check_quota(&api_key) {
                    Ok(quota) => {
                        if let Some(detonation) = quota.detonation {
                            if detonation.quota_reached {
                                tracing::warn!("Hybrid Analysis detonation quota reached! Disabling file uploads.");
                                effective_submit_enabled = false;
                            }
                            if let Some(apikey_info) = detonation.apikey {
                                if apikey_info.quota_reached {
                                    tracing::warn!("Hybrid Analysis API key detonation quota reached! Disabling file uploads.");
                                    effective_submit_enabled = false;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to check Hybrid Analysis quota: {}", e);
                        // Don't disable submit if check fails? Or be safe?
                        // Usually safe to proceed as individual uploads would fail if quota is strictly enforced by server differently
                        // But if we can't check quota, maybe it's better to log error and continue with user preference.
                    }
                }
                // Sort installed packages by risk score (descending)
                installed_packages.sort_by(|a, b| {
                    let score_a = package_risk_scores.get(&a.pkg).copied().unwrap_or(0);
                    let score_b = package_risk_scores.get(&b.pkg).copied().unwrap_or(0);
                    score_b.cmp(&score_a) // Descending
                });

                // Get cached packages
                let cached_packages =
                    crate::db_package_cache::get_cached_packages_with_apk(&device_serial);

                // Create a map for faster lookup of cached packages
                let mut cached_packages_map: HashMap<String, crate::models::PackageInfoCache> =
                    HashMap::new();
                for cp in cached_packages {
                    cached_packages_map.insert(cp.pkg_id.clone(), cp);
                }

                let total = installed_packages.len();
                let mut skipped_cached = 0usize;

                for (i, package) in installed_packages.iter().enumerate() {
                    // Check if scan was cancelled
                    if let Ok(cancelled) = ha_scan_cancelled_clone.lock() {
                        if *cancelled {
                            tracing::info!("Hybrid Analysis scan cancelled by user");
                            break;
                        }
                    }

                    // Update progress
                    if let Ok(mut p) = ha_scan_progress_clone.lock() {
                        *p = Some(i as f32 / total as f32);
                    }

                    let pkg_name = &package.pkg;

                    // Skip packages already completed from DB cache
                    {
                        let s = scanner_state.lock().unwrap();
                        if matches!(
                            s.get(pkg_name),
                            Some(calc_hybridanalysis::ScanStatus::Completed(_))
                        ) {
                            skipped_cached += 1;
                            continue;
                        }
                    }

                    let mut paths_str = String::new();
                    let mut sha256sums_str = String::new();

                    // Check if we have it in cache
                    if let Some(cached_pkg) = cached_packages_map.get(pkg_name) {
                        if let (Some(path), Some(sha256)) =
                            (&cached_pkg.apk_path, &cached_pkg.apk_sha256sum)
                        {
                            paths_str = path.clone();
                            sha256sums_str = sha256.clone();
                        }
                    }

                    // If not in cache or missing fields, try from package info
                    if paths_str.is_empty() || sha256sums_str.is_empty() {
                        paths_str = package.codePath.clone();
                        sha256sums_str = package.pkgChecksum.clone();
                    }

                    if !paths_str.is_empty() && !sha256sums_str.is_empty() {
                        // Check if paths are directories (not ending with .apk)
                        // or if sha256sums are invalid (not 64 hex chars each)
                        // If so, get files and sha256sums from get_single_package_sha256sum
                        let paths: Vec<&str> = paths_str.split(' ').collect();
                        let sha256sums: Vec<&str> = sha256sums_str.split(' ').collect();
                        let needs_directory_scan = paths.iter().any(|p| !p.ends_with(".apk"));
                        let has_invalid_hashes = sha256sums.iter().any(|s| s.len() != 64);

                        let (final_paths_str, final_sha256sums_str) =
                            if needs_directory_scan || has_invalid_hashes {
                                match crate::adb::get_single_package_sha256sum(
                                    &device_serial,
                                    pkg_name,
                                ) {
                                    Ok((new_paths, new_sha256sums)) => {
                                        if !new_paths.is_empty() && !new_sha256sums.is_empty() {
                                            (new_paths, new_sha256sums)
                                        } else if !has_invalid_hashes {
                                            // Only fall back to cached values if they were valid
                                            (paths_str.clone(), sha256sums_str.clone())
                                        } else {
                                            // Don't use invalid cached hashes
                                            (String::new(), String::new())
                                        }
                                    }
                                    Err(e) => {
                                        if !has_invalid_hashes {
                                            tracing::warn!(
                                                "Failed to get sha256sums for {}: {}, using cached values",
                                                pkg_name,
                                                e
                                            );
                                            (paths_str.clone(), sha256sums_str.clone())
                                        } else {
                                            tracing::warn!(
                                                "Failed to get sha256sums for {}: {}, skipping (cached hashes were invalid)",
                                                pkg_name,
                                                e
                                            );
                                            // Don't use invalid cached hashes
                                            (String::new(), String::new())
                                        }
                                    }
                                }
                            } else {
                                (paths_str.clone(), sha256sums_str.clone())
                            };

                        // Parse space-separated values to build hashes vector
                        let final_paths: Vec<&str> = final_paths_str.split(' ').collect();
                        let final_sha256sums: Vec<&str> = final_sha256sums_str.split(' ').collect();

                        // Filter to only include valid entries (non-empty path and valid 64-char SHA256 hash)
                        let hashes: Vec<(String, String)> = final_paths
                            .iter()
                            .zip(final_sha256sums.iter())
                            .filter(|(p, s)| !p.is_empty() && s.len() == 64)
                            .map(|(p, s)| (p.to_string(), s.to_string()))
                            .collect();

                        tracing::info!(
                            "Analyzing package {} with {} files (Risk: {})",
                            pkg_name,
                            hashes.len(),
                            package_risk_scores.get(pkg_name).copied().unwrap_or(0)
                        );

                        // Pass all files at once to analyze_package
                        if let Err(e) = calc_hybridanalysis::analyze_package(
                            &pkg_name,
                            hashes,
                            &scanner_state,
                            &rate_limiter,
                            &api_key,
                            &device_serial,
                            effective_submit_enabled,
                            &None,
                        ) {
                            tracing::error!("Error analyzing package {}: {}", pkg_name, e);
                        }
                    } else {
                        tracing::error!("Failed to get path and sha256 for package {}", pkg_name);
                    }
                }

                tracing::info!(
                    "Hybrid Analysis scan complete: {} packages skipped (already cached), {} processed",
                    skipped_cached,
                    total - skipped_cached
                );

                // Second pass: continuously poll pending jobs until all complete
                tracing::info!("First pass complete, checking for pending jobs...");
                loop {
                    // Check if scan was cancelled
                    if let Ok(cancelled) = ha_scan_cancelled_clone.lock() {
                        if *cancelled {
                            tracing::info!("Hybrid Analysis scan cancelled during pending jobs check");
                            break;
                        }
                    }

                    let pending_count = calc_hybridanalysis::check_pending_jobs(
                        &scanner_state,
                        &rate_limiter,
                        &api_key,
                        &None,
                    );

                    if pending_count == 0 {
                        tracing::info!("All pending jobs completed");
                        break;
                    }

                    tracing::info!("{} jobs still pending, waiting 30 seconds before next check", pending_count);

                    // Wait 30 seconds before checking again
                    for _ in 0..30 {
                        // Check cancellation during wait
                        if let Ok(cancelled) = ha_scan_cancelled_clone.lock() {
                            if *cancelled {
                                tracing::info!("Hybrid Analysis scan cancelled during wait");
                                break;
                            }
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                }

                // Clear progress when done
                if let Ok(mut p) = ha_scan_progress_clone.lock() {
                    *p = None;
                }
            });
        }
    }

    pub fn update_uad_ng_lists(&mut self, lists: UadNgLists) {
        self.uad_ng_lists = Some(lists);
    }

    /// Calculate risk scores for all installed packages, using cached values when available
    fn calculate_all_risk_scores(&mut self) {
        self.package_risk_scores.clear();

        let device_serial = match self.device_serial.as_deref() {
            Some(s) => s.to_string(),
            None => {
                // No device serial: calculate without caching
                for package in &self.installed_packages {
                    let risk_score = calc_izzyrisk::calculate_izzyrisk(package);
                    self.package_risk_scores
                        .insert(package.pkg.clone(), risk_score);
                }
                tracing::info!(
                    "Calculated risk scores for {} packages (no device serial, no caching)",
                    self.package_risk_scores.len()
                );
                return;
            }
        };

        // Load cached packages from database for cache lookups
        let cached_packages_map: HashMap<String, crate::models::PackageInfoCache> =
            crate::db_package_cache::get_all_cached_packages(&device_serial)
                .into_iter()
                .map(|cp| (cp.pkg_id.clone(), cp))
                .collect();

        let mut cache_hits = 0;
        let mut cache_misses = 0;

        for package in &self.installed_packages {
            let cached_pkg = cached_packages_map.get(&package.pkg);
            let risk_score = calc_izzyrisk::calculate_and_cache_izzyrisk(
                package,
                cached_pkg,
                &device_serial,
            );
            if cached_pkg.and_then(|c| c.izzyscore).is_some() {
                cache_hits += 1;
            } else {
                cache_misses += 1;
            }
            self.package_risk_scores
                .insert(package.pkg.clone(), risk_score);
        }

        tracing::info!(
            "Calculated risk scores for {} packages ({} cached, {} computed)",
            self.package_risk_scores.len(),
            cache_hits,
            cache_misses
        );
    }

    /// Get the risk score for a package by name
    fn get_risk_score(&self, package_name: &str) -> i32 {
        self.package_risk_scores
            .get(package_name)
            .copied()
            .unwrap_or(0)
    }

    /// Sort packages based on the current sort column and direction
    fn sort_packages(&mut self) {
        if let Some(col_idx) = self.sort_column {
            let scanner_state = self.vt_scanner_state.clone();
            let package_risk_scores = self.package_risk_scores.clone();

            self.installed_packages.sort_by(|a, b| {
                let ordering = match col_idx {
                    0 => {
                        // Package Name - sort by package name
                        let name_a = format!("{} ({})", a.pkg, a.versionName);
                        let name_b = format!("{} ({})", b.pkg, b.versionName);
                        name_a.cmp(&name_b)
                    }
                    1 => {
                        // IzzyRisk - sort by risk score
                        let risk_a = package_risk_scores.get(&a.pkg).copied().unwrap_or(0);
                        let risk_b = package_risk_scores.get(&b.pkg).copied().unwrap_or(0);
                        risk_a.cmp(&risk_b)
                    }
                    2 => {
                        // VirusTotal Results - sort by scanner status
                        // Mappings:
                        // Not Initialized: -4
                        // Pending: -3
                        // Scanning: -2
                        // Error: -1
                        // Completed: 0+ (threat count)

                        let get_vt_sort_key = |pkg_name: &str| -> i32 {
                            if let Some(ref state) = scanner_state {
                                let state_lock = state.lock().unwrap();
                                match state_lock.get(pkg_name) {
                                    Some(calc_virustotal::ScanStatus::Completed(result)) => result
                                        .file_results
                                        .iter()
                                        .map(|fr| fr.malicious + fr.suspicious)
                                        .sum::<i32>(),
                                    Some(calc_virustotal::ScanStatus::Error(_)) => -1,
                                    Some(calc_virustotal::ScanStatus::Scanning { .. }) => -2,
                                    Some(calc_virustotal::ScanStatus::Pending) => -3,
                                    None => -4,
                                }
                            } else {
                                -4 // Not initialized
                            }
                        };

                        let score_a = get_vt_sort_key(&a.pkg);
                        let score_b = get_vt_sort_key(&b.pkg);
                        score_a.cmp(&score_b)
                    }
                    3 => {
                        // HybridAnalysis Results - sort by scanner status and verdict severity
                        // Mappings:
                        // Not Initialized: -5
                        // Pending: -4
                        // Scanning: -3
                        // Error: -2
                        // Completed with "submitted": -1
                        // Completed with "whitelisted": 0
                        // Completed with "no-result": 1
                        // Completed with "no specific threat": 2
                        // Completed with "suspicious": 3
                        // Completed with "malicious": 4

                        let get_ha_sort_key = |pkg_name: &str| -> i32 {
                            if let Some(ref ha_state) = self.ha_scanner_state {
                                let state_lock = ha_state.lock().unwrap();
                                match state_lock.get(pkg_name) {
                                    Some(calc_hybridanalysis::ScanStatus::Completed(result)) => {
                                        // Get the highest severity verdict from all files
                                        let max_severity = result
                                            .file_results
                                            .iter()
                                            .map(|fr| match fr.verdict.as_str() {
                                                "malicious" => 4,
                                                "suspicious" => 3,
                                                "no specific threat" => 2,
                                                "no-result" => 1,
                                                "whitelisted" => 0,
                                                "submitted" => -1,
                                                _ => 1, // Unknown verdicts treated as no-result
                                            })
                                            .max()
                                            .unwrap_or(-1);
                                        max_severity
                                    }
                                    Some(calc_hybridanalysis::ScanStatus::Error(_)) => -2,
                                    Some(calc_hybridanalysis::ScanStatus::Scanning { .. }) => -3,
                                    Some(calc_hybridanalysis::ScanStatus::Pending) => -4,
                                    None => -5,
                                }
                            } else {
                                -5 // Not initialized
                            }
                        };

                        let score_a = get_ha_sort_key(&a.pkg);
                        let score_b = get_ha_sort_key(&b.pkg);
                        score_a.cmp(&score_b)
                    }
                    _ => std::cmp::Ordering::Equal,
                };

                if self.sort_ascending {
                    ordering
                } else {
                    ordering.reverse()
                }
            });
        }
    }

    fn get_vt_counts(&self) -> (usize, usize, usize, usize, usize) {
        let mut total = 0;
        let mut malicious = 0;
        let mut suspicious = 0;
        let mut safe = 0;
        let mut not_scanned = 0;

        if let Some(ref scanner_state) = self.vt_scanner_state {
            let state = scanner_state.lock().unwrap();
            for package in &self.installed_packages {
                // When counting VT stats, we should only consider packages visible under current HA filter
                if !self.should_show_package_ha(package) {
                    continue;
                }

                total += 1;
                match state.get(&package.pkg) {
                    Some(calc_virustotal::ScanStatus::Completed(result)) => {
                        let mal_count: i32 =
                            result.file_results.iter().map(|fr| fr.malicious).sum();
                        let sus_count: i32 =
                            result.file_results.iter().map(|fr| fr.suspicious).sum();

                        if mal_count > 0 {
                            malicious += 1;
                        } else if sus_count > 0 {
                            suspicious += 1;
                        } else {
                            safe += 1;
                        }
                    }
                    _ => not_scanned += 1,
                }
            }
        } else {
            // Even if scanner not initialized, we respect HA filter for total count
            for package in &self.installed_packages {
                if self.should_show_package_ha(package) {
                    total += 1;
                    not_scanned += 1;
                }
            }
        }

        (total, malicious, suspicious, safe, not_scanned)
    }

    fn get_ha_counts(&self) -> (usize, usize, usize, usize, usize) {
        let mut total = 0;
        let mut malicious = 0;
        let mut suspicious = 0;
        let mut safe = 0;
        let mut not_scanned = 0;

        if let Some(ref scanner_state) = self.ha_scanner_state {
            let state = scanner_state.lock().unwrap();
            for package in &self.installed_packages {
                // When counting HA stats, we should only consider packages visible under current VT filter
                if !self.should_show_package_vt(package) {
                    continue;
                }

                total += 1;
                match state.get(&package.pkg) {
                    Some(calc_hybridanalysis::ScanStatus::Completed(result)) => {
                        // Get max severity
                        let max_severity = result
                            .file_results
                            .iter()
                            .map(|fr| match fr.verdict.as_str() {
                                "malicious" => 2,
                                "suspicious" => 1,
                                _ => 0,
                            })
                            .max()
                            .unwrap_or(0);

                        match max_severity {
                            2 => malicious += 1,
                            1 => suspicious += 1,
                            0 => safe += 1,
                            _ => safe += 1,
                        }
                    }
                    _ => not_scanned += 1,
                }
            }
        } else {
            for package in &self.installed_packages {
                if self.should_show_package_vt(package) {
                    total += 1;
                    not_scanned += 1;
                }
            }
        }

        (total, malicious, suspicious, safe, not_scanned)
    }

    fn should_show_package_vt(&self, package: &PackageFingerprint) -> bool {
        match self.active_vt_filter {
            VtFilter::All => true,
            VtFilter::Malicious => {
                if let Some(ref scanner_state) = self.vt_scanner_state {
                    let state = scanner_state.lock().unwrap();
                    match state.get(&package.pkg) {
                        Some(calc_virustotal::ScanStatus::Completed(result)) => {
                            let mal_count: i32 =
                                result.file_results.iter().map(|fr| fr.malicious).sum();
                            mal_count > 0
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            VtFilter::Suspicious => {
                if let Some(ref scanner_state) = self.vt_scanner_state {
                    let state = scanner_state.lock().unwrap();
                    match state.get(&package.pkg) {
                        Some(calc_virustotal::ScanStatus::Completed(result)) => {
                            let mal_count: i32 =
                                result.file_results.iter().map(|fr| fr.malicious).sum();
                            let sus_count: i32 =
                                result.file_results.iter().map(|fr| fr.suspicious).sum();
                            mal_count == 0 && sus_count > 0
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            VtFilter::Safe => {
                if let Some(ref scanner_state) = self.vt_scanner_state {
                    let state = scanner_state.lock().unwrap();
                    match state.get(&package.pkg) {
                        Some(calc_virustotal::ScanStatus::Completed(result)) => {
                            let mal_count: i32 =
                                result.file_results.iter().map(|fr| fr.malicious).sum();
                            let sus_count: i32 =
                                result.file_results.iter().map(|fr| fr.suspicious).sum();
                            mal_count == 0 && sus_count == 0
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            VtFilter::NotScanned => {
                if let Some(ref scanner_state) = self.vt_scanner_state {
                    let state = scanner_state.lock().unwrap();
                    !matches!(
                        state.get(&package.pkg),
                        Some(calc_virustotal::ScanStatus::Completed(_))
                    )
                } else {
                    true
                }
            }
        }
    }

    fn should_show_package_ha(&self, package: &PackageFingerprint) -> bool {
        match self.active_ha_filter {
            HaFilter::All => true,
            HaFilter::Malicious => {
                if let Some(ref scanner_state) = self.ha_scanner_state {
                    let state = scanner_state.lock().unwrap();
                    match state.get(&package.pkg) {
                        Some(calc_hybridanalysis::ScanStatus::Completed(result)) => result
                            .file_results
                            .iter()
                            .any(|fr| fr.verdict == "malicious"),
                        _ => false,
                    }
                } else {
                    false
                }
            }
            HaFilter::Suspicious => {
                if let Some(ref scanner_state) = self.ha_scanner_state {
                    let state = scanner_state.lock().unwrap();
                    match state.get(&package.pkg) {
                        Some(calc_hybridanalysis::ScanStatus::Completed(result)) => {
                            !result
                                .file_results
                                .iter()
                                .any(|fr| fr.verdict == "malicious")
                                && result
                                    .file_results
                                    .iter()
                                    .any(|fr| fr.verdict == "suspicious")
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            HaFilter::Safe => {
                if let Some(ref scanner_state) = self.ha_scanner_state {
                    let state = scanner_state.lock().unwrap();
                    match state.get(&package.pkg) {
                        Some(calc_hybridanalysis::ScanStatus::Completed(result)) => !result
                            .file_results
                            .iter()
                            .any(|fr| fr.verdict == "malicious" || fr.verdict == "suspicious"),
                        _ => false,
                    }
                } else {
                    false
                }
            }
            HaFilter::NotScanned => {
                if let Some(ref scanner_state) = self.ha_scanner_state {
                    let state = scanner_state.lock().unwrap();
                    !matches!(
                        state.get(&package.pkg),
                        Some(calc_hybridanalysis::ScanStatus::Completed(_))
                    )
                } else {
                    true
                }
            }
        }
    }

    fn should_show_package(&self, package: &PackageFingerprint) -> bool {
        // If hide_system_app is true, hide packages with SYSTEM flag
        if self.hide_system_app && package.flags.contains("SYSTEM") {
            return false;
        }

        // If show_only_enabled is true, filter to only show packages with enabled=1 (ENABLED/green)
        // UPDATE: User wants to show all "Green" chips (ENABLED, DEFAULT, UNKNOWN)
        if self.show_only_enabled {
            let is_system = package.flags.contains("SYSTEM");
            let should_show = package
                .users
                .first()
                .map(|user| {
                    let enabled = user.enabled;
                    let installed = user.installed;

                    // Show if Green (ENABLED, DEFAULT, UNKNOWN)
                    // Hide if Red (DISABLED, DISABLED_USER, REMOVED_USER)
                    // REMOVED_USER logic: enabled == 0 && !installed && is_system
                    let is_removed_user = enabled == 0 && !installed && is_system;
                    let is_disabled = enabled == 2;
                    let is_disabled_user = enabled == 3;

                    !(is_removed_user || is_disabled || is_disabled_user)
                })
                .unwrap_or(false);

            if !should_show {
                return false;
            }
        }

        self.should_show_package_vt(package) && self.should_show_package_ha(package)
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        // Main UI content

        // debug!("Rendering with {} packages", self.installed_packages.len());
        // ui.horizontal(|ui| {
        //     // debug!("Rendering with {} packages", self.installed_packages.len());
        //     ui.heading(format!("Installed Packages: {}", self.installed_packages.len()));
        //     ui.add_space(10.0);
        //     ui.heading(format!("IzzyRisk Scores: "));
        //     // link to https://android.izzysoft.de/applists/perms
        //     let info_chip = assist_chip("")
        //                     .leading_icon_svg(INFO_SVG)
        //                     .elevated(true);
        //     if ui.add(info_chip.on_click(|| {
        //         tracing::info!("IzzySoft Info clicked");
        //     })).clicked() {
        //         {
        //             if let Err(err) = open::that("https://android.izzysoft.de/applists/perms") {
        //                 tracing::error!("Failed to open IzzySoft Permissions List: {}", err);
        //             }
        //         }
        //     }
        // });

        // VirusTotal Filter Buttons
        if !self.installed_packages.is_empty() {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(150.0);
                    ui.label(tr!("virustotal-filter"));

                    // Show progress bar if scanning
                    let vt_progress_value = if let Ok(progress) = self.vt_scan_progress.lock() {
                        *progress
                    } else {
                        None
                    };

                    if let Some(p) = vt_progress_value {
                        let progress_bar = egui::ProgressBar::new(p)
                            .show_percentage()
                            .desired_width(100.0)
                            .animate(true);
                        ui.horizontal(|ui| {
                            ui.add(progress_bar).on_hover_text(tr!("scanning-packages"));

                            // Stop button for virustotal scan
                            if ui.button("Stop").clicked() {
                                tracing::info!("Stop Virustotal scan clicked");
                                // Set cancellation flag to stop the scan
                                if let Ok(mut cancelled) = self.vt_scan_cancelled.lock() {
                                    *cancelled = true;
                                }
                                // Clear progress immediately for UI feedback
                                if let Ok(mut progress) = self.vt_scan_progress.lock() {
                                    *progress = None;
                                }
                            }
                        });
                    }
                });

                let (total, malicious, suspicious, safe, not_scanned) = self.get_vt_counts();

                // All
                let all_text = tr!("all", { count: total });
                let button = if self.active_vt_filter == VtFilter::All {
                    MaterialButton::filled(&all_text)
                } else {
                    MaterialButton::outlined(&all_text)
                };
                if ui.add(button).clicked() {
                    self.active_vt_filter = VtFilter::All;
                }

                // Malicious
                let mal_text = tr!("malicious", { count: malicious });
                let button = if self.active_vt_filter == VtFilter::Malicious {
                    MaterialButton::filled(&mal_text)
                    // .background_color(egui::Color32::from_rgb(211, 47, 47)) // if supported
                } else {
                    MaterialButton::outlined(&mal_text)
                };
                if ui.add(button).clicked() {
                    self.active_vt_filter = VtFilter::Malicious;
                }

                // Suspicious
                let sus_text = tr!("suspicious", { count: suspicious });
                let button = if self.active_vt_filter == VtFilter::Suspicious {
                    MaterialButton::filled(&sus_text)
                } else {
                    MaterialButton::outlined(&sus_text)
                };
                if ui.add(button).clicked() {
                    self.active_vt_filter = VtFilter::Suspicious;
                }

                // Safe
                let safe_text = tr!("safe", { count: safe });
                let button = if self.active_vt_filter == VtFilter::Safe {
                    MaterialButton::filled(&safe_text)
                } else {
                    MaterialButton::outlined(&safe_text)
                };
                if ui.add(button).clicked() {
                    self.active_vt_filter = VtFilter::Safe;
                }

                // Not Scanned
                let not_scanned_text = tr!("not-scanned", { count: not_scanned });
                let button = if self.active_vt_filter == VtFilter::NotScanned {
                    MaterialButton::filled(&not_scanned_text)
                } else {
                    MaterialButton::outlined(&not_scanned_text)
                };
                if ui.add(button).clicked() {
                    self.active_vt_filter = VtFilter::NotScanned;
                }
            });
            ui.add_space(5.0);

            // Hybrid Analysis Filter Buttons
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(150.0);
                    ui.label(tr!("hybrid-analysis-filter"));

                    // Show progress bar if scanning
                    let ha_progress_value = if let Ok(progress) = self.ha_scan_progress.lock() {
                        *progress
                    } else {
                        None
                    };

                    if let Some(p) = ha_progress_value {
                        let progress_bar = egui::ProgressBar::new(p)
                            .show_percentage()
                            .desired_width(100.0)
                            .animate(true);
                        ui.horizontal(|ui| {
                            ui.add(progress_bar).on_hover_text(tr!("scanning-packages"));

                            // Stop button for hybrid analysis scan
                            if ui.button("Stop").clicked() {
                                tracing::info!("Stop Hybrid Analysis scan clicked");
                                // Set cancellation flag to stop the scan
                                if let Ok(mut cancelled) = self.ha_scan_cancelled.lock() {
                                    *cancelled = true;
                                }
                                // Clear progress immediately for UI feedback
                                if let Ok(mut progress) = self.ha_scan_progress.lock() {
                                    *progress = None;
                                }
                            }
                        });
                    }
                });

                let (total, malicious, suspicious, safe, not_scanned) = self.get_ha_counts();

                // All
                let all_text = tr!("all", { count: total });
                let button = if self.active_ha_filter == HaFilter::All {
                    MaterialButton::filled(&all_text)
                } else {
                    MaterialButton::outlined(&all_text)
                };
                if ui.add(button).clicked() {
                    self.active_ha_filter = HaFilter::All;
                }

                // Malicious
                let mal_text = tr!("malicious", { count: malicious });
                let button = if self.active_ha_filter == HaFilter::Malicious {
                    MaterialButton::filled(&mal_text)
                } else {
                    MaterialButton::outlined(&mal_text)
                };
                if ui.add(button).clicked() {
                    self.active_ha_filter = HaFilter::Malicious;
                }

                // Suspicious
                let sus_text = tr!("suspicious", { count: suspicious });
                let button = if self.active_ha_filter == HaFilter::Suspicious {
                    MaterialButton::filled(&sus_text)
                } else {
                    MaterialButton::outlined(&sus_text)
                };
                if ui.add(button).clicked() {
                    self.active_ha_filter = HaFilter::Suspicious;
                }

                // Safe
                let safe_text = tr!("safe", { count: safe });
                let button = if self.active_ha_filter == HaFilter::Safe {
                    MaterialButton::filled(&safe_text)
                } else {
                    MaterialButton::outlined(&safe_text)
                };
                if ui.add(button).clicked() {
                    self.active_ha_filter = HaFilter::Safe;
                }

                // Not Scanned
                let not_scanned_text = tr!("not-scanned", { count: not_scanned });
                let button = if self.active_ha_filter == HaFilter::NotScanned {
                    MaterialButton::filled(&not_scanned_text)
                } else {
                    MaterialButton::outlined(&not_scanned_text)
                };
                if ui.add(button).clicked() {
                    self.active_ha_filter = HaFilter::NotScanned;
                }
            });
        }

        ui.add_space(10.0);

        if self.installed_packages.is_empty() {
            ui.label(tr!("no-packages-loaded"));
            return;
        }
        ui.add_space(10.0);

        // Show only enabled toggle
        ui.horizontal(|ui| {
            ui.label(tr!("show-only-enabled"));
            toggle_ui(ui, &mut self.show_only_enabled);
            ui.add_space(10.0);
            ui.label(tr!("hide-system-app"));
            toggle_ui(ui, &mut self.hide_system_app);
        });
        ui.add_space(10.0);

        // Apply Material theme styling to the table area
        let surface = get_global_color("surface");
        let on_surface = get_global_color("onSurface");
        let primary = get_global_color("primary");

        // Override table styling with Material theme
        let mut style = (*ui.ctx().style()).clone();
        style.visuals.widgets.noninteractive.bg_fill = surface;
        style.visuals.widgets.inactive.bg_fill = surface;
        style.visuals.widgets.hovered.bg_fill =
            egui::Color32::from_rgba_premultiplied(primary.r(), primary.g(), primary.b(), 20);
        style.visuals.widgets.active.bg_fill =
            egui::Color32::from_rgba_premultiplied(primary.r(), primary.g(), primary.b(), 40);
        style.visuals.selection.bg_fill = primary;
        style.visuals.widgets.noninteractive.fg_stroke.color = on_surface;
        style.visuals.widgets.inactive.fg_stroke.color = on_surface;
        style.visuals.widgets.hovered.fg_stroke.color = on_surface;
        style.visuals.widgets.active.fg_stroke.color = on_surface;
        style.visuals.striped = true;
        style.visuals.faint_bg_color = egui::Color32::from_rgba_premultiplied(
            on_surface.r(),
            on_surface.g(),
            on_surface.b(),
            10,
        );
        ui.ctx().set_style(style);

        // Sort packages before building the table if we have an active sort
        if self.sort_column.is_some() {
            self.sort_packages();
        }

        // Track if any package info button was clicked
        let clicked_package_idx = std::sync::Arc::new(std::sync::Mutex::new(None::<usize>));

        // Collect visible package IDs and build system packages set for app info lookup
        let visible_package_ids: Vec<String> = self
            .installed_packages
            .iter()
            .filter(|p| self.should_show_package(p))
            .map(|p| p.pkg.clone())
            .collect();

        let system_packages: std::collections::HashSet<String> = self
            .installed_packages
            .iter()
            .filter(|p| p.flags.contains("SYSTEM"))
            .map(|p| p.pkg.clone())
            .collect();

        // Prepare app info data for display (icons, titles, developers, versions)
        let app_data_map =
            self.prepare_app_info_for_display(ui.ctx(), &visible_package_ids, &system_packages);

        // Use the data_table widget
        let mut interactive_table = data_table()
            .id(egui::Id::new("scan_data_table"))
            .sortable_column(tr!("col-package-name"), 350.0, false)
            .sortable_column(tr!("col-izzy-risk"), 80.0, true)
            .sortable_column(tr!("col-virustotal"), 200.0, false)
            .sortable_column(tr!("col-hybrid-analysis"), 200.0, false)
            .sortable_column(tr!("col-tasks"), 170.0, false)
            .allow_selection(false);

        // Add rows dynamically from package data
        for (idx, package) in self.installed_packages.iter().enumerate() {
            // Apply filters
            if !self.should_show_package(package) {
                continue;
            }

            let _is_selected = self.selected_packages.get(idx).copied().unwrap_or(false);

            // Prepare cell content
            let package_name = format!("{} ({})", package.pkg, package.versionName);

            // Get app display info from prepared map
            let app_display_data = app_data_map.get(&package.pkg).cloned();
            let risk_score = self.get_risk_score(&package.pkg);
            let izzyrisk = risk_score.to_string();

            // Get VirusTotal scan result
            let vt_scan_result = if let Some(ref scanner_state) = self.vt_scanner_state {
                let state = scanner_state.lock().unwrap();
                state.get(&package.pkg).cloned()
            } else {
                None
            };

            // Get Hybrid Analysis scan result
            let ha_scan_result = if let Some(ref scanner_state) = self.ha_scanner_state {
                let state = scanner_state.lock().unwrap();
                state.get(&package.pkg).cloned()
            } else {
                None
            };

            let clicked_idx_clone = clicked_package_idx.clone();
            let vt_scan_result_clone = vt_scan_result.clone();
            let ha_scan_result_clone = ha_scan_result.clone();
            // Prepare variables for button actions
            let is_system = package.flags.contains("SYSTEM");
            let enabled = package
                .users
                .get(0)
                .map(|u| {
                    // Map enabled state to display string (similar to tab_debloat_control)
                    match u.enabled {
                        0 => {
                            if !u.installed && is_system {
                                "REMOVED_USER"
                            } else {
                                "DEFAULT"
                            }
                        }
                        1 => "ENABLED",
                        2 => "DISABLED",
                        3 => "DISABLED_USER",
                        _ => "UNKNOWN",
                    }
                })
                .unwrap_or("DEFAULT");
            let enabled_str = enabled.to_string();
            let package_name_for_buttons = package.pkg.clone();

            // Extract app display data for use in closure
            let (app_texture_id, app_title, app_developer, app_version) =
                if let Some((texture_opt, title, developer, version)) = &app_display_data {
                    (
                        texture_opt.as_ref().map(|t| t.id()),
                        Some(title.clone()),
                        Some(developer.clone()),
                        version.clone(),
                    )
                } else {
                    (None, None, None, None)
                };
            let package_name_for_cell = package_name.clone();

            interactive_table = interactive_table.row(|table_row| {
                // Render first column (Package Name) with app info if available
                let row_builder = if let (Some(title), Some(developer)) =
                    (app_title.clone(), app_developer.clone())
                {
                    // App data available - show icon, title, developer, version
                    let title = title.clone();
                    let developer = developer.clone();
                    let version_opt = app_version.clone();

                    table_row.widget_cell(move |ui: &mut egui::Ui| {
                        ui.horizontal(|ui| {
                            if let Some(tex_id) = app_texture_id {
                                ui.image((tex_id, egui::vec2(38.0, 38.0)));
                            }
                            ui.vertical(|ui| {
                                ui.style_mut().spacing.item_spacing.y = 0.1;
                                ui.label(egui::RichText::new(&title).strong());
                                ui.label(
                                    egui::RichText::new(&developer)
                                        .small()
                                        .color(egui::Color32::GRAY),
                                );
                                // if let Some(v) = &version_opt {
                                //     ui.label(egui::RichText::new(format!("v{}", v)).small());
                                // }
                            });
                        });
                    })
                } else {
                    // No app data available - show plain package name
                    // table_row.cell(&package_name_for_cell)
                    table_row.widget_cell(move |ui: &mut egui::Ui| {
                        ui.add(egui::Label::new(&package_name_for_cell).wrap());
                    })
                    // table_row.widget_cell(move |ui: &mut egui::Ui| {
                    //     // ui.set_width(200.0);
                    //     // ui.set_height(36.0);
                    //     egui::ScrollArea::vertical()
                    //         .id_salt(format!("vt_scroll_{}", idx))
                    //         // .auto_shrink([false, false])
                    //         // .max_height(36.0)
                    //         .show(ui, |ui| {
                    //             ui.set_max_width(200.0);
                    //             ui.set_height(36.0);
                    //             ui.add(egui::Label::new(&package_name_for_cell).wrap());
                    //         });
                    // })
                };
                let row_builder = row_builder
                    .cell(&izzyrisk)
                    .widget_cell(move |ui: &mut egui::Ui| {
                        // VirusTotal Results cell with scrollbar and colored chips
                        egui::ScrollArea::horizontal()
                            .id_salt(format!("ht_scroll_{}", idx))
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;

                                    match &vt_scan_result_clone {
                                        Some(calc_virustotal::ScanStatus::Pending) => {
                                            ui.label("Not scanned");
                                        }
                                        Some(calc_virustotal::ScanStatus::Scanning { scanned, total, operation: _ }) => {
                                            ui.label(format!("Scanning... ({}/{})", scanned, total));
                                        }
                                        Some(calc_virustotal::ScanStatus::Completed(result)) => {
                                            // Show chips for each file, or detailed message if empty
                                            // if result.file_results.is_empty() {
                                            //     let msg = if result.files_attempted == 0 {
                                            //         "No files to scan".to_string()
                                            //     } else if result.files_skipped_invalid_hash > 0 {
                                            //         format!(
                                            //             "No results ({} file(s) skipped: invalid hash)",
                                            //             result.files_skipped_invalid_hash
                                            //         )
                                            //     } else {
                                            //         format!(
                                            //             "No results ({} file(s) attempted)",
                                            //             result.files_attempted
                                            //         )
                                            //     };
                                            //     ui.label(msg);
                                            // }
                                            for (i, file_result) in result.file_results.iter().enumerate() {
                                                let (text, bg_color) = if let Some(ref _err) = file_result.error {
                                                    ("Error".to_string(), egui::Color32::from_rgb(211, 47, 47))
                                                } else if file_result.skipped {
                                                    ("skip".to_string(), egui::Color32::from_rgb(128, 128, 128))
                                                } else if file_result.not_found {
                                                    ("404 not found".to_string(), egui::Color32::from_rgb(128, 128, 128))
                                                } else if file_result.malicious > 0 {
                                                    (format!("malicious {}/{}", file_result.malicious + file_result.suspicious, file_result.total()), egui::Color32::from_rgb(211, 47, 47))
                                                } else if file_result.suspicious > 0 {
                                                    (format!("suspicious {}/{}", file_result.suspicious, file_result.total()), egui::Color32::from_rgb(255, 152, 0))
                                                } else {
                                                    (format!("clean {}/{}", file_result.total(), file_result.total()), egui::Color32::from_rgb(56, 142, 60))
                                                };

                                                let text_color = egui::Color32::WHITE;

                                                let inner_response = egui::Frame::new()
                                                    .fill(bg_color)
                                                    .corner_radius(8.0)
                                                    .inner_margin(egui::Margin::symmetric(12, 6))
                                                    .show(ui, |ui| {
                                                        ui.label(egui::RichText::new(&text).color(text_color).size(12.0))
                                                    });

                                                let response = ui.interact(
                                                    inner_response.response.rect,
                                                    ui.id().with(format!("vt_chip_{}_{}", idx, i)),
                                                    egui::Sense::click()
                                                );

                                                if let Some(ref err) = file_result.error {
                                                    response.on_hover_text(format!("{}\n{}", file_result.file_path, err));
                                                } else {
                                                    if response.clicked() {
                                                        #[cfg(not(target_os = "android"))]
                                                        {
                                                            if let Err(err) = open::that(&file_result.vt_link) {
                                                                tracing::error!("Failed to open VirusTotal link: {}", err);
                                                            }
                                                        }
                                                    }

                                                    // Show filename on hover
                                                    response.on_hover_text(&file_result.file_path);
                                                }
                                            }
                                        }
                                        Some(calc_virustotal::ScanStatus::Error(e)) => {
                                            ui.label(format!("Error: {}", e));
                                        }
                                        None => {
                                            ui.label("Not initialized");
                                        }
                                    }
                                });
                            });
                    })
                    .widget_cell(move |ui: &mut egui::Ui| {
                        // Hybrid Analysis Results cell with scrollbar and colored chips
                        egui::ScrollArea::horizontal()
                            .id_salt(format!("ha_scroll_{}", idx))
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;

                                    match &ha_scan_result_clone {
                                        Some(calc_hybridanalysis::ScanStatus::Pending) => {
                                            ui.label("Not scanned");
                                        }
                                        Some(calc_hybridanalysis::ScanStatus::Scanning { scanned, total, operation: _ }) => {
                                            ui.label(format!("Scanning... ({}/{})", scanned, total));
                                        }
                                        Some(calc_hybridanalysis::ScanStatus::Completed(result)) => {
                                            // Show chips for each file, or "No results" if empty
                                            if result.file_results.is_empty() {
                                                ui.label("No results");
                                            }
                                            for (i, file_result) in result.file_results.iter().enumerate() {
                                                let text = file_result.get_display_text();
                                                let bg_color = match file_result.verdict.as_str() {
                                                    "malicious" => egui::Color32::from_rgb(211, 47, 47),
                                                    "suspicious" => egui::Color32::from_rgb(255, 152, 0),
                                                    "whitelisted" => egui::Color32::from_rgb(56, 142, 60),
                                                    "no-result" => egui::Color32::from_rgb(158, 158, 158),
                                                    "rate_limited" => egui::Color32::from_rgb(156, 39, 176), // Purple for rate limited
                                                    "submitted" => egui::Color32::from_rgb(33, 150, 243), // Blue for submitted/waiting
                                                    "pending_analysis" => egui::Color32::from_rgb(255, 193, 7), // Amber for pending analysis
                                                    "analysis_error" => egui::Color32::from_rgb(211, 47, 47), // Red for errors
                                                    "upload_error" => egui::Color32::from_rgb(211, 47, 47), // Red for upload errors
                                                    "404 Not Found" => egui::Color32::from_rgb(128, 128, 128), // Gray for not found
                                                    _ => egui::Color32::from_rgb(158, 158, 158),
                                                };

                                                let text_color = egui::Color32::WHITE;

                                                let inner_response = egui::Frame::new()
                                                    .fill(bg_color)
                                                    .corner_radius(8.0)
                                                    .inner_margin(egui::Margin::symmetric(12, 6))
                                                    .show(ui, |ui| {
                                                        ui.label(egui::RichText::new(&text).color(text_color).size(12.0))
                                                    });

                                                let response = ui.interact(
                                                    inner_response.response.rect,
                                                    ui.id().with(format!("ha_chip_{}_{}", idx, i)),
                                                    egui::Sense::click()
                                                );

                                                if response.clicked() {
                                                    #[cfg(not(target_os = "android"))]
                                                    {
                                                        if let Err(err) = open::that(&file_result.ha_link) {
                                                            tracing::error!("Failed to open Hybrid Analysis link: {}", err);
                                                        }
                                                    }
                                                }

                                                // Show filename on hover
                                                response.on_hover_text(&file_result.file_path);
                                            }
                                        }
                                        Some(calc_hybridanalysis::ScanStatus::Error(e)) => {
                                            ui.label(format!("Error: {}", e));
                                        }
                                        None => {
                                            ui.label("Not initialized");
                                        }
                                    }
                                });
                            });
                    })
                    .widget_cell(move |ui: &mut egui::Ui| {
                        ui.horizontal(|ui| {
                            // Info button
                            let chip = assist_chip("")
                                .leading_icon_svg(INFO_SVG)
                                .elevated(true);
                            if ui.add(chip.on_click(move || {
                                tracing::info!("Opening package info dialog");
                            })).clicked() {
                                // open package_details_window
                                if let Ok(mut clicked) = clicked_idx_clone.lock() {
                                    *clicked = Some(idx);
                                }
                            }

                            // Uninstall button - only show if install_reason is NOT SYSTEM
                            if enabled_str.contains("DEFAULT") || enabled_str.contains("ENABLED")  {
                                let uninstall_chip = assist_chip("")
                                    .leading_icon_svg(TRASH_RED_SVG)
                                    .elevated(true);

                                let pkg_name_uninstall = package_name_for_buttons.clone();
                                if ui.add(uninstall_chip.on_click(move || {
                                    tracing::info!("Uninstall clicked for: {}", pkg_name_uninstall);
                                })).clicked() {
                                    // Signal that uninstall was clicked
                                    ui.data_mut(|data| {
                                        data.insert_temp(egui::Id::new("uninstall_clicked_package"), package_name_for_buttons.clone());
                                        data.insert_temp(egui::Id::new("uninstall_clicked_is_system"), is_system);
                                    });
                                }
                            }

                            // Show Enable button
                            if enabled_str.contains("REMOVED_USER") || enabled_str.contains("DISABLED_USER") || enabled_str.contains("DISABLED") {
                                let enable_chip = assist_chip("")
                                    .leading_icon_svg(ENABLE_GREEN_SVG)
                                    .elevated(true);

                                let pkg_name_enable = package_name_for_buttons.clone();
                                if ui.add(enable_chip.on_click(move || {
                                    tracing::info!("Enable clicked for: {}", pkg_name_enable);
                                })).clicked() {
                                    // Signal that enable was clicked
                                    ui.data_mut(|data| {
                                        data.insert_temp(egui::Id::new("enable_clicked_package"), package_name_for_buttons.clone());
                                    });
                                }
                            }

                            // Show Disable button (for DEFAULT, ENABLED, UNKNOWN)
                            if enabled_str.contains("DEFAULT") || enabled_str.contains("ENABLED")  {
                                let disable_chip = assist_chip("")
                                    .leading_icon_svg(DISABLE_RED_SVG)
                                    .elevated(true);

                                let pkg_name_disable = package_name_for_buttons.clone();
                                if ui.add(disable_chip.on_click(move || {
                                    tracing::info!("Disable clicked for: {}", pkg_name_disable);
                                })).clicked() {
                                    // Signal that disable was clicked
                                    ui.data_mut(|data| {
                                        data.insert_temp(egui::Id::new("disable_clicked_package"), package_name_for_buttons.clone());
                                    });
                                }
                            }
                        });
                    })
                    .id(format!("scan_table_row_{}", idx));

                row_builder
            });
        }

        // Set current sort state if any
        if let Some(sort_col) = self.sort_column {
            use egui_material3::SortDirection;
            let direction = if self.sort_ascending {
                SortDirection::Ascending
            } else {
                SortDirection::Descending
            };
            interactive_table = interactive_table.sort_by(sort_col, direction);
        }

        // Show the table and get the selection state back
        let table_response = interactive_table.show(ui);

        // Sync sort state from table response
        let (widget_sort_col, widget_sort_dir) = table_response.sort_state;
        let widget_sort_ascending =
            matches!(widget_sort_dir, egui_material3::SortDirection::Ascending);

        // If the widget's sort state differs from ours, update our state and sort our data
        if widget_sort_col != self.sort_column
            || (widget_sort_col.is_some() && widget_sort_ascending != self.sort_ascending)
        {
            self.sort_column = widget_sort_col;
            self.sort_ascending = widget_sort_ascending;
            if self.sort_column.is_some() {
                self.sort_packages();
            }
        }

        // Handle sorting clicks
        if let Some(clicked_col) = table_response.column_clicked {
            // Check if same column was clicked
            if self.sort_column == Some(clicked_col) {
                // Toggle sort direction
                self.sort_ascending = !self.sort_ascending;
            } else {
                // New column clicked
                self.sort_column = Some(clicked_col);
                self.sort_ascending = true;
            }
            // Sort the packages
            self.sort_packages();
        }

        // Sync the selection state back
        if table_response.selected_rows.len() == self.selected_packages.len() {
            self.selected_packages = table_response.selected_rows;
        }

        // Handle package info button click
        if let Ok(clicked) = clicked_package_idx.lock() {
            if let Some(idx) = *clicked {
                self.package_details_dialog.open(idx);
            }
        }

        // Handle button clicks and perform actions
        let mut uninstall_package: Option<String> = None;
        let mut uninstall_is_system: bool = false;
        let mut enable_package: Option<String> = None;
        let mut disable_package: Option<String> = None;

        ui.data_mut(|data| {
            if let Some(pkg) = data.get_temp::<String>(egui::Id::new("uninstall_clicked_package")) {
                uninstall_package = Some(pkg);
                uninstall_is_system = data
                    .get_temp::<bool>(egui::Id::new("uninstall_clicked_is_system"))
                    .unwrap_or(false);
                data.remove::<String>(egui::Id::new("uninstall_clicked_package"));
                data.remove::<bool>(egui::Id::new("uninstall_clicked_is_system"));
            }
            if let Some(pkg) = data.get_temp::<String>(egui::Id::new("enable_clicked_package")) {
                enable_package = Some(pkg);
                data.remove::<String>(egui::Id::new("enable_clicked_package"));
            }
            if let Some(pkg) = data.get_temp::<String>(egui::Id::new("disable_clicked_package")) {
                disable_package = Some(pkg);
                data.remove::<String>(egui::Id::new("disable_clicked_package"));
            }
        });

        // Perform uninstall if clicked
        if let Some(pkg_name) = uninstall_package {
            if let Some(ref device) = self.device_serial {
                {
                    let uninstall_result = if uninstall_is_system {
                        crate::adb::uninstall_app_user(&pkg_name, device, None)
                    } else {
                        crate::adb::uninstall_app(&pkg_name, device)
                    };

                    match uninstall_result {
                        Ok(output) => {
                            tracing::info!("App uninstalled successfully: {}", output);

                            // Update package list properly
                            let is_system = self
                                .installed_packages
                                .iter()
                                .find(|p| p.pkg == pkg_name)
                                .map(|p| p.flags.contains("SYSTEM"))
                                .unwrap_or(false);

                            if is_system {
                                // For system apps, just mark as uninstalled/removed for current user
                                if let Some(pkg) = self
                                    .installed_packages
                                    .iter_mut()
                                    .find(|p| p.pkg == pkg_name)
                                {
                                    for user in pkg.users.iter_mut() {
                                        // TODO: We should really only update the specific user we uninstalled from
                                        // But for now we don't track selected user precisely in the context of this action
                                        // Assuming current/default user context
                                        user.installed = false;
                                        user.enabled = 0; // Reset to default/unknown state
                                    }
                                }
                            } else {
                                // For user apps, remove from list
                                self.installed_packages.retain(|pkg| pkg.pkg != pkg_name);
                                if let Some(idx_to_remove) = self
                                    .installed_packages
                                    .iter()
                                    .position(|p| p.pkg == pkg_name)
                                {
                                    if idx_to_remove < self.selected_packages.len() {
                                        self.selected_packages.remove(idx_to_remove);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to uninstall app({}): {}", pkg_name, e);
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for uninstall");
            }
        }

        // Perform enable if clicked
        if let Some(pkg_name) = enable_package {
            if let Some(ref device) = self.device_serial {
                {
                    match crate::adb::enable_app(&pkg_name, device) {
                        Ok(output) => {
                            tracing::info!("App enabled successfully: {}", output);

                            tracing::info!("Package enabled: {}", pkg_name);

                            // Update package state
                            if let Some(pkg) = self
                                .installed_packages
                                .iter_mut()
                                .find(|p| p.pkg == pkg_name)
                            {
                                for user in pkg.users.iter_mut() {
                                    user.enabled = 1; // ENABLED
                                    user.installed = true; // Ensure it's marked as installed
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to enable app: {}", e);
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for enable");
            }
        }

        // Perform disable if clicked
        if let Some(pkg_name) = disable_package {
            if let Some(ref device) = self.device_serial {
                {
                    match crate::adb::disable_app_current_user(&pkg_name, device, None) {
                        Ok(output) => {
                            tracing::info!("App disabled successfully: {}", output);

                            tracing::info!("Package disabled: {}", pkg_name);

                            // Update package state
                            if let Some(pkg) = self
                                .installed_packages
                                .iter_mut()
                                .find(|p| p.pkg == pkg_name)
                            {
                                for user in pkg.users.iter_mut() {
                                    user.enabled = 3; // DISABLED_USER
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to disable app: {}", e);
                        }
                    }
                }
            } else {
                tracing::error!("No device selected for disable");
            }
        }

        // Show package details dialog
        self.package_details_dialog
            .show(ui.ctx(), &self.installed_packages, &self.uad_ng_lists);
    }
}

/// iOS-style toggle switch
fn toggle_ui(ui: &mut egui::Ui, on: &mut bool) -> egui::Response {
    let desired_size = ui.spacing().interact_size.y * egui::vec2(2.0, 1.0);
    let (rect, mut response) = ui.allocate_exact_size(desired_size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *on, "")
    });

    if ui.is_rect_visible(rect) {
        let how_on = ui.ctx().animate_bool_responsive(response.id, *on);
        let visuals = ui.style().interact_selectable(&response, *on);
        let rect = rect.expand(visuals.expansion);
        let radius = 0.5 * rect.height();
        ui.painter().rect(
            rect,
            radius,
            visuals.bg_fill,
            visuals.bg_stroke,
            egui::StrokeKind::Inside,
        );
        let circle_x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), how_on);
        let center = egui::pos2(circle_x, rect.center().y);
        ui.painter()
            .circle(center, 0.75 * radius, visuals.bg_fill, visuals.fg_stroke);
    }

    response
}
